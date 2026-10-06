// SPDX-License-Identifier: AGPL-3.0-only

use std::{path::PathBuf, time::Duration};

use scoplen_store::{
    RelationalStore, SqliteStore,
    sync::{ObjectWrite, SyncStoreError, VaultKind},
};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-sync-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create isolated test directory");
    path
}

async fn remove_test_directory(path: PathBuf) {
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("remove test directory {}: {error}", path.display()),
        }
    }
}

fn write(object_id: u8, base_sequence: Option<u64>, envelope: u8) -> ObjectWrite {
    ObjectWrite {
        object_id: [object_id; 16],
        base_sequence,
        envelope: vec![envelope, envelope + 1],
        tombstone: false,
        signer_device_id: Some([9; 16]),
    }
}

#[tokio::test]
async fn writes_and_pages_return_only_current_versions() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [1; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    let receipts = store
        .write_sync_batch(vault, &[write(1, None, 10), write(2, None, 20), write(3, None, 30)])
        .await
        .expect("initial batch");
    assert_eq!(receipts.iter().map(|receipt| receipt.sequence).collect::<Vec<_>>(), vec![1, 2, 3]);

    let first_page = store.sync_changes(vault, 0, 2).await.expect("first page");
    assert_eq!(first_page.changes.len(), 2);
    assert!(first_page.more);
    assert_eq!(first_page.next_cursor, 2);
    assert_eq!(first_page.changes[0].object_id, [1; 16]);
    assert_eq!(first_page.changes[1].object_id, [2; 16]);

    let updated = store.write_sync_batch(vault, &[write(1, Some(1), 40)]).await.expect("update");
    assert_eq!(updated[0].sequence, 4);
    let all = store.sync_changes(vault, 0, 10).await.expect("all current versions");
    assert_eq!(all.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![2, 3, 4]);
    assert!(!all.more);
    assert_eq!(all.next_cursor, 4);
    assert_eq!(all.changes[2].envelope, vec![40, 41]);

    let after_two = store.sync_changes(vault, 2, 10).await.expect("after cursor");
    assert_eq!(
        after_two.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(),
        vec![3, 4]
    );
    let caught_up = store.sync_changes(vault, 4, 10).await.expect("caught up");
    assert_eq!(caught_up.changes.len(), 0);
    assert_eq!(caught_up.next_cursor, 4);

    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sync_object_versions WHERE vault_id = ?")
            .bind(vault.as_slice())
            .fetch_one(store.pool())
            .await
            .expect("version rows");
    assert_eq!(version_count, 4);

    let device = [7; 16];
    assert_eq!(store.ack_sync_cursor(vault, device, 4).await.expect("ack current cursor"), 4);
    assert_eq!(store.ack_sync_cursor(vault, device, 3).await.expect("lower ack is no-op"), 4);
    assert!(matches!(
        store.ack_sync_cursor(vault, [8; 16], 5).await,
        Err(SyncStoreError::CursorAhead { cursor: 5, current: 4 })
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn compare_and_swap_conflicts_are_atomic_and_report_current_state() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [2; 16];
    store.create_sync_vault(vault, VaultKind::Shared).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial write");

    let error = store
        .write_sync_batch(vault, &[write(1, None, 20), write(2, None, 30)])
        .await
        .expect_err("stale batch must be rejected");
    let SyncStoreError::Conflict { conflicts } = error else {
        panic!("expected CAS conflict");
    };
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].object_id, [1; 16]);
    assert_eq!(conflicts[0].current.as_ref().map(|change| change.sequence), Some(1));

    let next = store
        .write_sync_batch(vault, &[write(2, None, 30)])
        .await
        .expect("rejected batch did not consume a sequence");
    assert_eq!(next[0].sequence, 2);
    let missing = store
        .write_sync_batch(vault, &[write(3, Some(99), 40)])
        .await
        .expect_err("a base for an absent object must conflict");
    assert!(matches!(missing, SyncStoreError::Conflict { .. }));
    let page = store.sync_changes(vault, 0, 10).await.expect("read current state");
    assert_eq!(page.changes.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![1, 2]);

    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("snapshot");
    assert_eq!(
        snapshot.objects.iter().map(|change| change.sequence).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let versions = store.sync_versions(vault, [1; 16]).await.expect("version history");
    assert_eq!(versions.iter().map(|change| change.sequence).collect::<Vec<_>>(), vec![1]);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn concurrent_batches_share_one_gap_free_sequence() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [3; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    let left_write = [write(1, None, 10)];
    let right_write = [write(2, None, 20)];
    let (left, right) = tokio::join!(
        store.write_sync_batch(vault, &left_write),
        store.write_sync_batch(vault, &right_write),
    );
    let left = left.expect("left concurrent write");
    let right = right.expect("right concurrent write");
    let mut sequences = vec![left[0].sequence, right[0].sequence];
    sequences.sort_unstable();
    assert_eq!(sequences, vec![1, 2]);

    let page = store.sync_changes(vault, 0, 10).await.expect("read concurrent state");
    assert_eq!(page.changes.len(), 2);
    assert_eq!(page.next_cursor, 2);
    assert!(!page.more);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn expired_and_ahead_cursors_fail_closed() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [4; 16];
    store.create_sync_vault(vault, VaultKind::Organization).await.expect("create vault");
    store.write_sync_batch(vault, &[write(1, None, 10)]).await.expect("initial write");
    sqlx::query("UPDATE sync_vaults SET purge_horizon = 1 WHERE vault_id = ?")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("set purge horizon for test");

    assert!(matches!(
        store.sync_changes(vault, 0, 10).await,
        Err(SyncStoreError::CursorExpired { purge_horizon: 1 })
    ));
    assert!(matches!(
        store.sync_changes(vault, 2, 10).await,
        Err(SyncStoreError::CursorAhead { cursor: 2, current: 1 })
    ));
    assert!(store.sync_changes(vault, 1, 10).await.is_ok());
    let snapshot = store.sync_snapshot(vault, 0, 10).await.expect("snapshot starts at zero");
    assert_eq!(snapshot.objects.len(), 1);

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn invalid_batches_and_unknown_vaults_fail_closed() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let vault = [5; 16];
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("create vault");

    assert!(matches!(store.write_sync_batch(vault, &[]).await, Err(SyncStoreError::EmptyBatch)));
    let duplicate = [write(1, None, 10), write(1, None, 20)];
    assert!(matches!(
        store.write_sync_batch(vault, &duplicate).await,
        Err(SyncStoreError::DuplicateObject)
    ));
    let empty_envelope = ObjectWrite { envelope: Vec::new(), ..write(2, None, 20) };
    assert!(matches!(
        store.write_sync_batch(vault, &[empty_envelope]).await,
        Err(SyncStoreError::InvalidEnvelope)
    ));
    assert!(matches!(store.sync_changes(vault, 0, 0).await, Err(SyncStoreError::InvalidPageSize)));
    assert!(matches!(
        store.sync_changes(vault, 0, 1_001).await,
        Err(SyncStoreError::InvalidPageSize)
    ));
    assert!(matches!(
        store.sync_changes([99; 16], 0, 10).await,
        Err(SyncStoreError::VaultNotFound)
    ));
    assert!(matches!(
        store.sync_versions(vault, [99; 16]).await,
        Err(SyncStoreError::ObjectNotFound)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}
