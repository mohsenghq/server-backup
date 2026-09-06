//! SFTP backend integration tests, run against the in-process SFTP server in
//! [`mod@sftp_server`]. These exercise the full russh stack — SSH transport,
//! authentication, subsystem negotiation and SFTP operations — not a mock.

mod sftp_server;

use std::path::Path;

use aegis_core::backend::Backend;
use aegis_core::chunk::ChunkerConfig;
use aegis_core::repo::Repository;
use aegis_core::sftp::{
    parse_location, HostKeyPolicy, RepoLocation, SftpAuth, SftpBackend, SftpTarget,
};
use sftp_server::{connected_backend, USERNAME};

const PASS: &str = "repo-passphrase";

fn chunker() -> ChunkerConfig {
    ChunkerConfig {
        min_size: 512,
        avg_size: 4096,
        max_size: 16384,
    }
}

fn write_tree(root: &Path) {
    let dir = root.join("source");
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    std::fs::write(dir.join("hello.txt"), b"hello over sftp").unwrap();
    std::fs::write(dir.join("nested").join("data.bin"), vec![7u8; 5000]).unwrap();
}

fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root.join("source"))
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(root.join("source"))
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, std::fs::read(entry.path()).unwrap()));
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn backend_crud_over_sftp() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, _port) = connected_backend(dir.path().to_path_buf()).await.unwrap();

    assert!(!backend.exists("blobs/ab/cd").await.unwrap());
    backend.put("blobs/ab/cd", b"payload").await.unwrap();
    assert!(backend.exists("blobs/ab/cd").await.unwrap());
    assert_eq!(backend.get("blobs/ab/cd").await.unwrap(), b"payload");

    // Nested directories are created on demand.
    backend
        .put("snapshots/deep/deeper/key.json", b"{\"v\":1}")
        .await
        .unwrap();
    let mut keys = backend.list("blobs").await.unwrap();
    keys.sort();
    assert_eq!(keys, vec!["blobs/ab/cd"]);

    // put replaces atomically (temp file + rename)…
    backend.put("blobs/ab/cd", b"payload2").await.unwrap();
    assert_eq!(backend.get("blobs/ab/cd").await.unwrap(), b"payload2");

    // …and the temp file is gone.
    let all = backend.list("").await.unwrap();
    assert!(
        all.iter().all(|k| !k.contains(".tmp-")),
        "temp files leaked: {all:?}"
    );

    backend.delete("blobs/ab/cd").await.unwrap();
    assert!(!backend.exists("blobs/ab/cd").await.unwrap());
    // Deleting a missing key is not an error.
    backend.delete("blobs/ab/cd").await.unwrap();

    // Listing a missing prefix is empty, not an error.
    assert!(backend.list("no-such-prefix").await.unwrap().is_empty());
}

#[tokio::test]
async fn init_backup_restore_over_sftp() {
    let src = tempfile::tempdir().unwrap();
    let remote = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write_tree(&src.path());

    let (backend, port) = connected_backend(remote.path().to_path_buf())
        .await
        .unwrap();
    let repo = Repository::init(Box::new(backend), chunker(), PASS)
        .await
        .unwrap();

    let snapshot = repo.backup(&[src.path().join("source")]).await.unwrap();
    repo.verify(&snapshot, false).await.unwrap();

    // Reopen over the wire and restore.
    let (backend2, _) = connected_backend(remote.path().to_path_buf())
        .await
        .unwrap();
    let repo2 = Repository::open(Box::new(backend2), PASS).await.unwrap();
    assert_eq!(repo2.list_snapshots().await.unwrap().len(), 1);
    repo2
        .restore(&snapshot.id, out.path().join("restored"))
        .await
        .unwrap();

    assert_eq!(
        read_tree(&out.path().join("restored")),
        read_tree(&src.path()),
    );
    let _ = port;
}

#[tokio::test]
async fn sftp_repo_urls_parse_and_resolve() {
    let loc = parse_location("sftp://u@h:2200/r").unwrap();
    assert!(matches!(loc, RepoLocation::Sftp(_)));
    assert!(matches!(
        parse_location("/plain/path").unwrap(),
        RepoLocation::Local(_)
    ));

    // Bad credentials must surface as an SSH error, not a hang or panic.
    let dir = tempfile::tempdir().unwrap();
    let backend = SftpBackend::new(
        SftpTarget {
            user: USERNAME.into(),
            host: "127.0.0.1".into(),
            port: sftp_server::spawn_sftp_server(dir.path().to_path_buf())
                .await
                .unwrap(),
            path: dir.path().to_string_lossy().into_owned(),
        },
        SftpAuth::Password("definitely-wrong".into()),
    )
    .with_host_key_policy(HostKeyPolicy::AcceptAny);

    let err = Repository::init(Box::new(backend), chunker(), PASS)
        .await
        .err()
        .expect("init with wrong credentials must fail");
    assert!(
        matches!(err, aegis_core::Error::Ssh(_)),
        "expected Ssh, got {err:?}"
    );
}

#[tokio::test]
async fn prune_over_sftp() {
    let src = tempfile::tempdir().unwrap();
    let remote = tempfile::tempdir().unwrap();
    let src_dir = src.path().join("source");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("f.txt"), b"prune me over sftp").unwrap();

    let (backend, _) = connected_backend(remote.path().to_path_buf())
        .await
        .unwrap();
    let repo = Repository::init(Box::new(backend), chunker(), PASS)
        .await
        .unwrap();

    let s1 = repo.backup(std::slice::from_ref(&src_dir)).await.unwrap();
    let s2 = repo.backup(std::slice::from_ref(&src_dir)).await.unwrap();
    assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);

    // Keep only the newest snapshot.
    let report = repo
        .prune(
            &aegis_core::retention::RetentionPolicy {
                keep_last: 1,
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(report.deleted_snapshots.len(), 1);
    assert_eq!(report.deleted_snapshots[0], s1.id);

    // The surviving snapshot must still fully verify and restore.
    let snapshots = repo.list_snapshots().await.unwrap();
    assert_eq!(snapshots.len(), 1);
    let survivor = &snapshots[0];
    repo.verify(survivor, true).await.unwrap();
    assert_eq!(survivor.id, s2.id);

    let out = tempfile::tempdir().unwrap();
    repo.restore(&s2.id, out.path()).await.unwrap();
    assert_eq!(read_tree(&out.path())[0].1, b"prune me over sftp".to_vec());
    let _ = report;
}

#[tokio::test]
async fn wrong_repo_passphrase_over_sftp() {
    let src = tempfile::tempdir().unwrap();
    let remote = tempfile::tempdir().unwrap();
    write_tree(&src.path());

    let (backend, _) = connected_backend(remote.path().to_path_buf())
        .await
        .unwrap();
    let repo = Repository::init(Box::new(backend), chunker(), PASS)
        .await
        .unwrap();
    let _snapshot = repo.backup(&[src.path().join("source")]).await.unwrap();
    drop(repo);

    let (backend2, _) = connected_backend(remote.path().to_path_buf())
        .await
        .unwrap();
    let err = Repository::open(Box::new(backend2), "wrong")
        .await
        .err()
        .expect("open with wrong passphrase must fail");
    assert!(
        matches!(err, aegis_core::Error::WrongPassphrase),
        "expected WrongPassphrase, got {err:?}"
    );
}
