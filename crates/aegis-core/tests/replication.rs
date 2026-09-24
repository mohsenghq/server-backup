//! End-to-end replication: a real backup into a local repository, mirrored
//! to a second directory, then a full restore from the mirror proving the
//! mirror is a usable repository on its own.

use aegis_core::{LocalBackend, ReplicateMode, Repository};

const PASS: &str = "replication-test-pass";

#[tokio::test]
async fn backup_replicate_restore_from_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let (src_path, dst_path, data_path, out_path) = (
        dir.path().join("src-repo"),
        dir.path().join("mirror-repo"),
        dir.path().join("data"),
        dir.path().join("out"),
    );
    tokio::fs::create_dir_all(&data_path).await.unwrap();
    tokio::fs::write(data_path.join("hello.txt"), b"hello replication")
        .await
        .unwrap();
    tokio::fs::write(data_path.join("more.bin"), vec![7u8; 50_000])
        .await
        .unwrap();

    // Real backup into the source repo.
    Repository::init_local(&src_path, aegis_core::chunk::ChunkerConfig::default(), PASS)
        .await
        .unwrap();
    let src = Repository::open_local(&src_path, PASS).await.unwrap();
    let snap = src
        .backup(std::slice::from_ref(&data_path))
        .await
        .expect("backup into source");

    // Mirror to the second backend.
    let source = LocalBackend::new(&src_path);
    let target = LocalBackend::new(&dst_path);
    let stats = aegis_core::replication::replicate(&source, &target, ReplicateMode::Mirror)
        .await
        .expect("replicate");
    assert!(stats.copied > 0);

    // The mirror is a standalone repository: open it and restore.
    let mirror = Repository::open_local(&dst_path, PASS).await.unwrap();
    let listed = mirror.list_snapshots().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, snap.id);
    let out = out_path.join("restored");
    mirror
        .restore(&snap.id, &out)
        .await
        .expect("restore from mirror");

    assert_eq!(
        tokio::fs::read(out.join("data").join("hello.txt"))
            .await
            .unwrap(),
        b"hello replication"
    );
    assert_eq!(
        tokio::fs::read(out.join("data").join("more.bin"))
            .await
            .unwrap(),
        vec![7u8; 50_000]
    );

    // A second backup + re-replicate moves only the delta.
    tokio::fs::write(data_path.join("new.txt"), b"new file")
        .await
        .unwrap();
    let _second = Repository::open_local(&src_path, PASS)
        .await
        .unwrap()
        .backup(std::slice::from_ref(&data_path))
        .await
        .unwrap();
    let stats2 = aegis_core::replication::replicate(&source, &target, ReplicateMode::Mirror)
        .await
        .unwrap();
    assert!(stats2.copied > 0, "delta must transfer: {stats2:?}");
    assert!(stats2.skipped > stats2.copied, "most objects are shared");

    // The mirror now sees both snapshots.
    let mirror = Repository::open_local(&dst_path, PASS).await.unwrap();
    assert_eq!(mirror.list_snapshots().await.unwrap().len(), 2);
}
