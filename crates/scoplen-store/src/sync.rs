// SPDX-License-Identifier: AGPL-3.0-only
//! Durable primitives for the append-ordered sync store.
//!
//! This module deliberately stops at storage. Authentication, envelope validation, policy
//! filtering, and HTTP/CBOR representations belong to the sync service and its protocol crates.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use sqlx::{Row, Sqlite, Transaction};
use thiserror::Error;

use crate::{RelationalStore, SqliteStore};

/// Maximum envelope size from the sync protocol's default limits.
pub const MAX_ENVELOPE_BYTES: usize = 260 * 1024;
/// Maximum number of objects in one write batch.
pub const MAX_BATCH_OBJECTS: usize = 500;
/// Maximum combined envelope size in one write batch.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum page size from the sync protocol.
pub const MAX_PAGE_SIZE: u16 = 1_000;

/// A 16-byte vault identifier. UUID version and variant validation belongs to the protocol layer.
pub type VaultId = [u8; 16];
/// A 16-byte object identifier.
pub type ObjectId = [u8; 16];
/// A 16-byte enrolled device identifier.
pub type DeviceId = [u8; 16];

/// The vault classes currently defined by the sync protocol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VaultKind {
    /// A vault owned by one account.
    Personal,
    /// A vault shared by account members.
    Shared,
    /// A policy-authoritative organization vault.
    Organization,
}

impl VaultKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
            Self::Organization => "organization",
        }
    }
}

/// One opaque object write after the protocol layer has authenticated the caller.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectWrite {
    /// Object being created or replaced.
    pub object_id: ObjectId,
    /// Sequence the caller merged from, or `None` for a new object.
    pub base_sequence: Option<u64>,
    /// Encrypted envelope bytes. The store never interprets these bytes.
    pub envelope: Vec<u8>,
    /// Whether this write is a tombstone.
    pub tombstone: bool,
    /// Device that signed the envelope, when the caller has supplied the verified identity.
    pub signer_device_id: Option<DeviceId>,
}

/// A current object version returned by a change query or CAS conflict.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyncChange {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Server-assigned sequence number.
    pub sequence: u64,
    /// Opaque envelope bytes.
    pub envelope: Vec<u8>,
    /// Tombstone marker supplied by the writer.
    pub tombstone: bool,
    /// Verified signer device identifier, if one was supplied.
    pub signer_device_id: Option<DeviceId>,
}

/// One result from an accepted write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WriteReceipt {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Sequence assigned to this object in the batch.
    pub sequence: u64,
}

/// A page of current object versions at one vault snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChangePage {
    /// Current versions eligible after the caller's cursor.
    pub changes: Vec<SyncChange>,
    /// Cursor for the next request.
    pub next_cursor: u64,
    /// Whether another eligible current version exists at the same snapshot.
    pub more: bool,
}

/// A page of current object versions for full reconciliation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SnapshotPage {
    /// Current versions in snapshot order.
    pub objects: Vec<SyncChange>,
    /// Cursor for the next snapshot request.
    pub next_cursor: u64,
    /// Whether another current version exists at the same snapshot.
    pub more: bool,
}

/// The object state that caused a compare-and-swap conflict.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConflictEntry {
    /// Object supplied by the rejected write.
    pub object_id: ObjectId,
    /// Current object state, or `None` when the object is still absent.
    pub current: Option<SyncChange>,
}

/// Storage failures for sync operations.
#[derive(Debug, Error)]
pub enum SyncStoreError {
    /// The requested vault is not present.
    #[error("sync vault does not exist")]
    VaultNotFound,
    /// A vault with this identifier already exists or another schema constraint was violated.
    #[error("sync storage constraint failed: {0}")]
    Constraint(#[source] sqlx::Error),
    /// The write batch is empty.
    #[error("sync write batch must not be empty")]
    EmptyBatch,
    /// The write batch exceeds the protocol object count limit.
    #[error("sync write batch exceeds {MAX_BATCH_OBJECTS} objects")]
    BatchObjectLimit,
    /// The write batch exceeds the protocol byte limit.
    #[error("sync write batch exceeds {MAX_BATCH_BYTES} bytes")]
    BatchByteLimit,
    /// An envelope exceeds the protocol envelope limit or is empty.
    #[error("sync envelope must contain between 1 and {MAX_ENVELOPE_BYTES} bytes")]
    InvalidEnvelope,
    /// The batch contains an object more than once.
    #[error("sync write batch contains a duplicate object id")]
    DuplicateObject,
    /// One or more object bases no longer match the current state.
    #[error("sync compare-and-swap conflict")]
    Conflict { conflicts: Vec<ConflictEntry> },
    /// A sequence cannot be represented by SQLite's signed integer column.
    #[error("sync sequence is exhausted")]
    SequenceExhausted,
    /// A caller supplied a cursor before the purge horizon.
    #[error("sync cursor is below the purge horizon ({purge_horizon})")]
    CursorExpired { purge_horizon: u64 },
    /// A caller supplied a cursor after the vault's current sequence.
    #[error("sync cursor {cursor} is ahead of the current sequence {current}")]
    CursorAhead { cursor: u64, current: u64 },
    /// A change page size was outside the protocol range.
    #[error("sync page size must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    /// The requested object has no current or retained version.
    #[error("sync object does not exist")]
    ObjectNotFound,
    /// A stored row could not be represented by the public storage model.
    #[error("sync storage contains invalid row data: {0}")]
    CorruptRow(&'static str),
    /// The database operation failed.
    #[error("sync database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl SqliteStore {
    /// Create an empty sync vault with sequence and purge horizon set to zero.
    ///
    /// This method does not perform account or membership authorization.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::Constraint`] when the identifier is already present or violates
    /// a database constraint, and [`SyncStoreError::Database`] for other database failures.
    pub async fn create_sync_vault(
        &self,
        vault_id: VaultId,
        kind: VaultKind,
    ) -> Result<(), SyncStoreError> {
        sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, ?)")
            .bind(vault_id.as_slice())
            .bind(kind.as_str())
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(|error| match error {
                sqlx::Error::Database(_) => SyncStoreError::Constraint(error),
                other => SyncStoreError::Database(other),
            })
    }

    /// Write one authenticated batch atomically using compare-and-swap bases.
    ///
    /// A write transaction first takes SQLite's write lock by updating the vault counter with a
    /// no-op. It then validates every base before allocating a contiguous sequence range. Any
    /// conflict or constraint failure rolls back the whole batch, including the counter.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid batch, [`SyncStoreError::Conflict`] when any
    /// compare-and-swap base is stale, or [`SyncStoreError::Database`] for a database failure.
    pub async fn write_sync_batch(
        &self,
        vault_id: VaultId,
        writes: &[ObjectWrite],
    ) -> Result<Vec<WriteReceipt>, SyncStoreError> {
        validate_batch(writes)?;
        let mut transaction = self.pool().begin().await?;
        lock_vault(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state(&mut transaction, vault_id).await?;

        let mut current = HashMap::with_capacity(writes.len());
        for write in writes {
            let row = sqlx::query(
                "SELECT sequence, envelope, tombstone, signer_device_id FROM sync_objects \
                 WHERE vault_id = ? AND object_id = ?",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(row) = row {
                current.insert(write.object_id, change_from_row(write.object_id, &row)?);
            }
        }

        let conflicts = writes
            .iter()
            .filter_map(|write| {
                let existing = current.get(&write.object_id);
                let matches = match (write.base_sequence, existing) {
                    (None, None) => true,
                    (Some(base), Some(change)) => base == change.sequence,
                    _ => false,
                };
                (!matches).then(|| ConflictEntry {
                    object_id: write.object_id,
                    current: existing.cloned(),
                })
            })
            .collect::<Vec<_>>();
        if !conflicts.is_empty() {
            return Err(SyncStoreError::Conflict { conflicts });
        }

        let batch_len =
            u64::try_from(writes.len()).map_err(|_| SyncStoreError::SequenceExhausted)?;
        let first_sequence = current_seq.checked_add(1).ok_or(SyncStoreError::SequenceExhausted)?;
        let last_sequence =
            current_seq.checked_add(batch_len).ok_or(SyncStoreError::SequenceExhausted)?;
        let mut receipts = Vec::with_capacity(writes.len());
        for (offset, write) in writes.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| SyncStoreError::SequenceExhausted)?;
            let sequence =
                first_sequence.checked_add(offset).ok_or(SyncStoreError::SequenceExhausted)?;
            let sequence_sql = sequence_to_sql(sequence)?;
            let written_at_ms = now_ms()?;
            let change = SyncChange {
                object_id: write.object_id,
                sequence,
                envelope: write.envelope.clone(),
                tombstone: write.tombstone,
                signer_device_id: write.signer_device_id,
            };
            insert_version(&mut transaction, vault_id, &change, written_at_ms).await?;
            sqlx::query(
                "INSERT INTO sync_objects \
                 (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (vault_id, object_id) DO UPDATE SET \
                   sequence = excluded.sequence, envelope = excluded.envelope, \
                   tombstone = excluded.tombstone, signer_device_id = excluded.signer_device_id, \
                   written_at_ms = excluded.written_at_ms",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .bind(sequence_sql)
            .bind(&write.envelope)
            .bind(i64::from(write.tombstone))
            .bind(write.signer_device_id.as_ref().map(<DeviceId>::as_slice))
            .bind(written_at_ms)
            .execute(&mut *transaction)
            .await?;
            receipts.push(WriteReceipt { object_id: write.object_id, sequence });
        }
        sqlx::query("UPDATE sync_vaults SET current_seq = ? WHERE vault_id = ?")
            .bind(sequence_to_sql(last_sequence)?)
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(receipts)
    }

    /// Read current object versions after a cursor at one consistent vault snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorExpired`],
    /// [`SyncStoreError::CursorAhead`], [`SyncStoreError::InvalidPageSize`], or
    /// [`SyncStoreError::Database`] when the request cannot be served.
    pub async fn sync_changes(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<ChangePage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        let page = read_current_page(&mut transaction, vault_id, after, limit, true).await?;
        transaction.commit().await?;
        Ok(page)
    }

    /// Read a full-reconciliation page of current object versions.
    ///
    /// Snapshot paging uses the same ordering and cursor bounds as the change feed, but permits
    /// `after = 0` after purging so a client with an expired cursor can rebuild complete state.
    /// This is a storage operation; authorization and policy filtering remain service concerns.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorAhead`],
    /// [`SyncStoreError::InvalidPageSize`], or [`SyncStoreError::Database`] when the request
    /// cannot be served.
    pub async fn sync_snapshot(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<SnapshotPage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        let page = read_current_page(&mut transaction, vault_id, after, limit, false).await?;
        transaction.commit().await?;
        Ok(SnapshotPage { objects: page.changes, next_cursor: page.next_cursor, more: page.more })
    }

    /// Read the current version and retained history for one object in ascending sequence order.
    /// At most the current version and 20 retained previous versions are returned.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] for an unknown vault,
    /// [`SyncStoreError::ObjectNotFound`] when no version exists, or
    /// [`SyncStoreError::Database`] when the history cannot be read.
    pub async fn sync_versions(
        &self,
        vault_id: VaultId,
        object_id: ObjectId,
    ) -> Result<Vec<SyncChange>, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        vault_state(&mut transaction, vault_id).await?;
        let rows = sqlx::query(
            "SELECT sequence, envelope, tombstone, signer_device_id \
             FROM sync_object_versions WHERE vault_id = ? AND object_id = ? \
             ORDER BY sequence DESC LIMIT 21",
        )
        .bind(vault_id.as_slice())
        .bind(object_id.as_slice())
        .fetch_all(&mut *transaction)
        .await?;
        if rows.is_empty() {
            return Err(SyncStoreError::ObjectNotFound);
        }
        let mut versions = rows
            .iter()
            .map(|row| change_from_row(object_id, row))
            .collect::<Result<Vec<_>, SyncStoreError>>()?;
        versions.reverse();
        transaction.commit().await?;
        Ok(versions)
    }

    /// Record a device cursor after the client has applied changes.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] for an unknown vault, [`SyncStoreError::CursorAhead`]
    /// for a cursor beyond the vault, or [`SyncStoreError::Database`] when the acknowledgement
    /// cannot be stored. A cursor at or below the stored value is an idempotent no-op and returns
    /// that stored value.
    pub async fn ack_sync_cursor(
        &self,
        vault_id: VaultId,
        device_id: DeviceId,
        cursor: u64,
    ) -> Result<u64, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        lock_vault(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state(&mut transaction, vault_id).await?;
        if cursor > current_seq {
            return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
        }
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT cursor FROM sync_acks WHERE vault_id = ? AND device_id = ?",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .map(sequence_from_sql)
        .transpose()?;
        if let Some(existing) = existing
            && cursor <= existing
        {
            transaction.commit().await?;
            return Ok(existing);
        }
        sqlx::query(
            "INSERT INTO sync_acks (vault_id, device_id, cursor, acknowledged_at_ms) VALUES (?, ?, ?, ?) \
             ON CONFLICT (vault_id, device_id) DO UPDATE SET cursor = excluded.cursor, acknowledged_at_ms = excluded.acknowledged_at_ms",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .bind(sequence_to_sql(cursor)?)
        .bind(now_ms()?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(cursor)
    }
}

async fn read_current_page(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    after: u64,
    limit: u16,
    enforce_purge_horizon: bool,
) -> Result<ChangePage, SyncStoreError> {
    let (current_seq, purge_horizon) = vault_state(transaction, vault_id).await?;
    if enforce_purge_horizon && after < purge_horizon {
        return Err(SyncStoreError::CursorExpired { purge_horizon });
    }
    if after > current_seq {
        return Err(SyncStoreError::CursorAhead { cursor: after, current: current_seq });
    }

    let rows = sqlx::query(
        "SELECT object_id, sequence, envelope, tombstone, signer_device_id \
         FROM sync_objects WHERE vault_id = ? AND sequence > ? \
         ORDER BY sequence ASC LIMIT ?",
    )
    .bind(vault_id.as_slice())
    .bind(sequence_to_sql(after)?)
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut **transaction)
    .await?;
    let more = rows.len() > usize::from(limit);
    let changes = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| {
            let object_id_bytes: Vec<u8> = row.try_get("object_id")?;
            let object_id = id_from_bytes(&object_id_bytes, "object_id")?;
            change_from_row(object_id, &row)
        })
        .collect::<Result<Vec<_>, SyncStoreError>>()?;
    let next_cursor = changes
        .last()
        .map_or(current_seq, |change| if more { change.sequence } else { current_seq });
    Ok(ChangePage { changes, next_cursor, more })
}

async fn lock_vault(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
) -> Result<(), SyncStoreError> {
    let result = sqlx::query("UPDATE sync_vaults SET current_seq = current_seq WHERE vault_id = ?")
        .bind(vault_id.as_slice())
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(SyncStoreError::VaultNotFound);
    }
    Ok(())
}

async fn vault_state(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
) -> Result<(u64, u64), SyncStoreError> {
    let row = sqlx::query("SELECT current_seq, purge_horizon FROM sync_vaults WHERE vault_id = ?")
        .bind(vault_id.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
    Ok((
        sequence_from_sql(row.try_get("current_seq")?)?,
        sequence_from_sql(row.try_get("purge_horizon")?)?,
    ))
}

async fn insert_version(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    change: &SyncChange,
    written_at_ms: i64,
) -> Result<(), SyncStoreError> {
    sqlx::query(
        "INSERT INTO sync_object_versions \
         (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, written_at_ms) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(vault_id.as_slice())
    .bind(change.object_id.as_slice())
    .bind(sequence_to_sql(change.sequence)?)
    .bind(&change.envelope)
    .bind(i64::from(change.tombstone))
    .bind(change.signer_device_id.as_ref().map(<DeviceId>::as_slice))
    .bind(written_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_batch(writes: &[ObjectWrite]) -> Result<(), SyncStoreError> {
    if writes.is_empty() {
        return Err(SyncStoreError::EmptyBatch);
    }
    if writes.len() > MAX_BATCH_OBJECTS {
        return Err(SyncStoreError::BatchObjectLimit);
    }
    let mut ids = HashSet::with_capacity(writes.len());
    let mut total_bytes = 0_usize;
    for write in writes {
        if !ids.insert(write.object_id) {
            return Err(SyncStoreError::DuplicateObject);
        }
        if write.envelope.is_empty() || write.envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(SyncStoreError::InvalidEnvelope);
        }
        total_bytes =
            total_bytes.checked_add(write.envelope.len()).ok_or(SyncStoreError::BatchByteLimit)?;
    }
    if total_bytes > MAX_BATCH_BYTES {
        return Err(SyncStoreError::BatchByteLimit);
    }
    Ok(())
}

fn change_from_row(
    object_id: ObjectId,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SyncChange, SyncStoreError> {
    Ok(SyncChange {
        object_id,
        sequence: sequence_from_sql(row.try_get("sequence")?)?,
        envelope: row.try_get("envelope")?,
        tombstone: bool_from_sql(row.try_get("tombstone")?)?,
        signer_device_id: row
            .try_get::<Option<Vec<u8>>, _>("signer_device_id")?
            .map(|bytes| id_from_bytes(&bytes, "signer_device_id"))
            .transpose()?,
    })
}

fn id_from_bytes(bytes: &[u8], field: &'static str) -> Result<[u8; 16], SyncStoreError> {
    bytes.try_into().map_err(|_| SyncStoreError::CorruptRow(field))
}

fn bool_from_sql(value: i64) -> Result<bool, SyncStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SyncStoreError::CorruptRow("tombstone")),
    }
}

fn sequence_from_sql(value: i64) -> Result<u64, SyncStoreError> {
    value.try_into().map_err(|_| SyncStoreError::CorruptRow("sequence"))
}

fn sequence_to_sql(value: u64) -> Result<i64, SyncStoreError> {
    value.try_into().map_err(|_| SyncStoreError::SequenceExhausted)
}

fn now_ms() -> Result<i64, SyncStoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SyncStoreError::CorruptRow("system time"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| SyncStoreError::SequenceExhausted)
}
