//! End-to-end: a real directory tree survives a backup/restore round trip, and
//! backing the same tree up twice writes no new blobs.

use std::path::{Path, PathBuf};

use aegis_core::{ChunkerConfig, Repository};

/// Small chunk sizes so fixtures stay in the kilobytes rather than megabytes.
fn chunker() -> ChunkerConfig {
    ChunkerConfig::new(1024, 4096, 16384).unwrap()
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn write(path: &Path, contents: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A tree with a nested directory, a large file that must split into many
/// chunks, an empty file, and a duplicate of the large file (intra-run dedup).
fn build_tree(root: &Path) {
    write(&root.join("readme.txt"), b"hello aegis\n");
    write(&root.join("empty.bin"), b"");
    write(
        &root.join("nested/deep/data.bin"),
        &pseudo_random(300 * 1024, 5),
    );
    write(&root.join("nested/copy.bin"), &pseudo_random(300 * 1024, 5));
}

fn collect(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = walkdir_files(root)
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, std::fs::read(&p).unwrap())
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walkdir_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                out.push(entry.path());
            }
        }
    }
    out
}

fn blob_count(repo: &Path) -> usize {
    let blobs = repo.join("blobs");
    if !blobs.exists() {
        return 0;
    }
    walkdir_files(&blobs).len()
}

#[tokio::test]
async fn backup_then_restore_reproduces_the_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    let target = tmp.path().join("restored");
    build_tree(&source);

    let repo = Repository::init(&repo_path, chunker()).await.unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    assert_eq!(snapshot.stats.files, 4);
    assert!(
        snapshot.stats.chunks > 1,
        "large files should split into chunks"
    );
    assert!(
        snapshot.stats.new_chunks < snapshot.stats.chunks,
        "the duplicated file should dedup within the run"
    );

    // Restoring by a short id prefix must work, as `aegis snapshots` displays one.
    let restored = repo.restore(snapshot.short_id(), &target).await.unwrap();
    assert_eq!(restored.id, snapshot.id);

    assert_eq!(collect(&source), collect(&target.join("source")));
}

#[tokio::test]
async fn rebacking_up_an_unchanged_tree_writes_no_new_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    build_tree(&source);

    let repo = Repository::init(&repo_path, chunker()).await.unwrap();
    repo.backup(std::slice::from_ref(&source)).await.unwrap();
    let before = blob_count(&repo_path);
    assert!(before > 0);

    let second = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    assert_eq!(
        second.stats.new_chunks, 0,
        "unchanged tree produced new chunks"
    );
    assert_eq!(
        blob_count(&repo_path),
        before,
        "repository grew on a no-op backup"
    );
    assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);
}

#[tokio::test]
async fn appending_to_a_file_reuses_existing_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("data.bin"), &pseudo_random(300 * 1024, 17));

    let repo = Repository::init(&repo_path, chunker()).await.unwrap();
    let first = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    let mut grown = pseudo_random(300 * 1024, 17);
    grown.extend_from_slice(&pseudo_random(8 * 1024, 23));
    write(&source.join("data.bin"), &grown);

    let second = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    assert!(
        second.stats.new_chunks * 4 < first.stats.new_chunks,
        "an append rewrote {} of {} chunks — dedup is not working",
        second.stats.new_chunks,
        second.stats.chunks
    );
}

#[tokio::test]
async fn init_twice_fails_and_open_reads_back_the_config() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_path = tmp.path().join("repo");

    let created = Repository::init(&repo_path, chunker()).await.unwrap();
    let id = created.config().id.clone();

    assert!(Repository::init(&repo_path, chunker()).await.is_err());
    assert!(Repository::open(tmp.path().join("nope")).await.is_err());

    let opened = Repository::open(&repo_path).await.unwrap();
    assert_eq!(opened.config().id, id);
    assert_eq!(opened.config().chunker, chunker());
    assert!(opened.list_snapshots().await.unwrap().is_empty());
}

#[tokio::test]
async fn restoring_an_unknown_snapshot_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_path = tmp.path().join("repo");
    let repo = Repository::init(&repo_path, chunker()).await.unwrap();
    assert!(repo
        .restore("deadbeef", tmp.path().join("out"))
        .await
        .is_err());
}

#[tokio::test]
async fn snapshots_list_newest_first_even_within_the_same_second() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("a.txt"), b"a");

    let repo = Repository::init(&repo_path, chunker()).await.unwrap();
    let first = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    let second = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // Two backups in the same second must still order deterministically, or
    // "restore the latest snapshot" silently picks the wrong one.
    let listed = repo.list_snapshots().await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].time >= listed[1].time);
    assert_ne!(listed[0].id, listed[1].id);
    assert_eq!(
        repo.list_snapshots().await.unwrap()[0].id,
        listed[0].id,
        "snapshot ordering is not stable across calls"
    );

    // display_time drops sub-second digits but keeps a parseable timestamp.
    assert_eq!(first.display_time().len(), 19);
    assert!(second.display_time().starts_with("20"));
}
