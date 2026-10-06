// SPDX-License-Identifier: AGPL-3.0-only
//! Synchronization storage boundary and foundation.
//!
//! The public authenticated HTTP service, policy filtering, and notification endpoints remain
//! roadmap gate V5 work; this crate currently exposes the storage primitives needed by that
//! service.

#![forbid(unsafe_code)]

pub use scoplen_store::sync::{
    ChangePage, ConflictEntry, DeviceId, MAX_BATCH_BYTES, MAX_BATCH_OBJECTS, MAX_ENVELOPE_BYTES,
    MAX_PAGE_SIZE, ObjectId, ObjectWrite, SnapshotPage, SyncChange, SyncStoreError, VaultId,
    VaultKind, WriteReceipt,
};

/// Sync contract marker.
pub const COMPONENT: &str = "sync";
