//! End-to-end: a real directory tree survives a backup/restore round trip
//! against the encrypted Merkle-tree repository format, dedup holds within
//! runs and across snapshots (including subtree renames), the per-snapshot
//! index matches what the tree actually references, and the crypto refuses
//! wrong passphrases, tampered blobs, and blob swaps.

use std::path::{Path, PathBuf};

use aegis_core::{ChunkerConfig, Node, Repository};

const PASS: &str = "test-passphrase";

/// Small chunk sizes so fixtures stay in the kilobytes rather than megabytes.
fn chunker() -> ChunkerConfig {
    ChunkerConfig::new(1024, 4096, 16384).unwrap()
}

/// Fast Argon2id params for tests; production defaults live in
/// `KdfParams::default` and are exercised only by the crypto unit tests.
fn fast_kdf() -> aegis_core::crypto::KdfParams {
    aegis_core::crypto::KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
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

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
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
    assert!(
        snapshot.stats.new_tree_nodes > 0,
        "the tree itself has node blobs"
    );

    // Restoring by a short id prefix must work, as `aegis snapshots` displays one.
    let restored = repo.restore(snapshot.short_id(), &target).await.unwrap();
    assert_eq!(restored.id, snapshot.id);

    assert_eq!(collect(&source), collect(&target.join("source")));
}

#[tokio::test]
async fn stored_files_are_ciphertext_not_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    let marker = b"THE-SECRET-MUST-NOT-APPEAR-IN-THE-REPO";
    write(&source.join("secret.txt"), marker);

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // docs/10-security-model.md: the storage backend never sees plaintext.
    // Scan every stored file for the marker bytes.
    for path in walkdir_files(&repo_path) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "plaintext marker found in stored file {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn wrong_passphrase_is_rejected_on_open() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_path = tmp.path().join("repo");
    Repository::init_local_with_kdf(&repo_path, chunker(), "right", fast_kdf())
        .await
        .unwrap();

    let err = match Repository::open_local(&repo_path, "wrong").await {
        Err(e) => e,
        Ok(_) => panic!("opening with a wrong passphrase must fail"),
    };
    assert!(
        matches!(err, aegis_core::Error::WrongPassphrase),
        "expected WrongPassphrase, got {err:?}"
    );
}

#[tokio::test]
async fn tampered_blob_fails_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("data.bin"), &pseudo_random(64 * 1024, 3));

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // Flip a byte inside one stored blob (past the 5-byte envelope header).
    let blob_path = walkdir_files(&repo_path.join("blobs"))
        .pop()
        .expect("repo has blobs");
    let mut bytes = std::fs::read(&blob_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&blob_path, bytes).unwrap();

    let err = repo
        .restore(&snapshot.id, tmp.path().join("out"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            aegis_core::Error::DecryptFailed(_)
                | aegis_core::Error::DecompressFailed(_)
                | aegis_core::Error::MalformedBlob(_)
        ),
        "expected an integrity error, got {err:?}"
    );
}

#[tokio::test]
async fn swapping_blobs_between_addresses_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    // Two distinct files → two distinct chunk blobs.
    write(&source.join("a.bin"), &pseudo_random(32 * 1024, 11));
    write(&source.join("b.bin"), &pseudo_random(32 * 1024, 22));

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // Swap the contents of two blob files on disk (the "swap attack": both
    // ciphertexts are valid, just at the wrong addresses).
    let mut blobs = walkdir_files(&repo_path.join("blobs"));
    blobs.sort();
    assert!(blobs.len() >= 2, "expected at least two blobs");
    let a = std::fs::read(&blobs[0]).unwrap();
    let b = std::fs::read(&blobs[1]).unwrap();
    std::fs::write(&blobs[0], &b).unwrap();
    std::fs::write(&blobs[1], &a).unwrap();

    // Restore must fail: AAD binds each ciphertext to its own address, so at
    // least one of the swapped blobs cannot authenticate. (If both chunks
    // happened to be identical there would be nothing to detect — the
    // different seeds make that impossible here.)
    let result = repo.restore(&snapshot.id, tmp.path().join("out")).await;
    assert!(result.is_err(), "a blob swap must not restore cleanly");
}

#[tokio::test]
async fn key_add_lets_both_passphrases_open_the_repository() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("a.txt"), b"content");

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), "first", fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    drop(repo);

    let new_slot = aegis_core::keys::key_add(&repo_path, "first", "second")
        .await
        .unwrap();
    assert_eq!(new_slot, "key1");

    // The original passphrase still works...
    let repo = Repository::open_local(&repo_path, "first").await.unwrap();
    repo.restore(&snapshot.id, tmp.path().join("out1"))
        .await
        .unwrap();
    drop(repo);
    // ...and so does the new one, against the same data.
    let repo = Repository::open_local(&repo_path, "second").await.unwrap();
    repo.restore(&snapshot.id, tmp.path().join("out2"))
        .await
        .unwrap();
    assert_eq!(
        collect(&tmp.path().join("out1/source")),
        collect(&tmp.path().join("out2/source"))
    );
}

#[tokio::test]
async fn empty_file_is_captured_and_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("zero.bin"), b"");

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    repo.restore(&snapshot.id, tmp.path().join("out"))
        .await
        .unwrap();

    let restored = tmp.path().join("out/source/zero.bin");
    assert!(restored.is_file(), "empty file must exist after restore");
    assert_eq!(std::fs::read(&restored).unwrap(), b"");
}

#[tokio::test]
async fn deep_nesting_and_unicode_names_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("a/b/c/d/e/f/deep.txt"), b"deep");
    write(&source.join("ünïcodé/φάκελος/日本語.txt"), b"unicode");

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    repo.restore(&snapshot.id, tmp.path().join("out"))
        .await
        .unwrap();

    assert_eq!(collect(&source), collect(&tmp.path().join("out/source")));
}

#[tokio::test]
async fn rebacking_up_an_unchanged_tree_writes_no_new_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    build_tree(&source);

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    repo.backup(std::slice::from_ref(&source)).await.unwrap();
    let before = blob_count(&repo_path);
    assert!(before > 0);

    let second = repo.backup(std::slice::from_ref(&source)).await.unwrap();
    assert_eq!(
        second.stats.new_chunks, 0,
        "unchanged tree produced new data chunks"
    );
    assert_eq!(
        second.stats.new_tree_nodes, 0,
        "unchanged tree produced new tree nodes"
    );
    assert_eq!(
        blob_count(&repo_path),
        before,
        "repository grew on a no-op backup"
    );
    assert_eq!(repo.list_snapshots().await.unwrap().len(), 2);
}

#[tokio::test]
async fn renaming_a_parent_dir_reuses_every_child_tree_node() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    build_tree(&source);

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let first = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // Rename the top directory: every path changes but no content does.
    let renamed = tmp.path().join("renamed");
    std::fs::rename(&source, &renamed).unwrap();

    let second = repo.backup(std::slice::from_ref(&renamed)).await.unwrap();
    assert_eq!(
        second.stats.new_chunks, 0,
        "a pure rename must not rewrite data chunks"
    );
    // The renamed root's own node differs (its name is inside it), but every
    // node below it is shared with the first snapshot.
    let shared_below_root = subtree_dedup(&first, &second);
    assert!(
        shared_below_root,
        "all non-root tree nodes should be reused after a rename"
    );
}

/// Check that the second snapshot's tree references the same node blobs below
/// its top-level path directories as the first one did: renaming `source` to
/// `renamed` changes the synthetic root, the renamed dir's own node, and
/// nothing else — every descendant must be shared.
fn subtree_dedup(first: &aegis_core::Snapshot, second: &aegis_core::Snapshot) -> bool {
    // Descendant hashes of a node, excluding the node itself.
    fn descendant_hashes(node: &Node, out: &mut Vec<String>) {
        if let Node::Dir { children, .. } = node {
            for c in children {
                out.push(c.hash_hex());
                descendant_hashes(c, out);
            }
        }
    }
    // Start below the top-level per-path dir (the renamed one).
    fn below_top(snapshot: &aegis_core::Snapshot) -> Vec<String> {
        let mut out = Vec::new();
        if let Node::Dir { children, .. } = &snapshot.root {
            for top in children {
                descendant_hashes(top, &mut out);
            }
        }
        out.sort();
        out
    }
    let a = below_top(first);
    let b = below_top(second);
    !a.is_empty() && a == b
}

#[tokio::test]
async fn appending_to_a_file_reuses_existing_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("data.bin"), &pseudo_random(300 * 1024, 17));

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
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

    let created = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let id = created.config().id.clone();

    assert!(
        Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
            .await
            .is_err()
    );
    assert!(Repository::open_local(tmp.path().join("nope"), PASS)
        .await
        .is_err());

    let opened = Repository::open_local(&repo_path, PASS).await.unwrap();
    assert_eq!(opened.config().id, id);
    assert_eq!(opened.config().chunker, chunker());
    assert!(opened.config().encrypted, "new repos are encrypted");
    assert!(opened.list_snapshots().await.unwrap().is_empty());
}

#[tokio::test]
async fn restoring_an_unknown_snapshot_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_path = tmp.path().join("repo");
    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
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

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
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

#[tokio::test]
async fn snapshot_index_lists_every_referenced_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    build_tree(&source);

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    let index = repo.snapshot_index(&snapshot).await.unwrap();
    assert_eq!(index.snapshot_id, snapshot.id);

    // Every hash the tree references must be in the index...
    let mut chunks = Vec::new();
    snapshot.root.collect_chunk_hashes(&mut chunks);
    for c in &chunks {
        assert!(
            index.blobs.iter().any(|b| &b.hash == c),
            "chunk {c} missing from index"
        );
    }
    // ...and every indexed chunk must exist as a blob in the repository.
    for b in &index.blobs {
        assert!(
            b.hash.len() == 64 && b.hash.bytes().all(|c| c.is_ascii_hexdigit()),
            "index contains a malformed hash: {}",
            b.hash
        );
        assert!(
            repo.backend()
                .exists(&aegis_core::repo_test_hooks::blob_key_for(&b.hash))
                .await
                .unwrap(),
            "indexed blob {} missing from repository",
            b.hash
        );
    }
    // Sizes are known for blobs this run wrote.
    assert!(
        index.blobs.iter().all(|b| b.size.is_some()),
        "sizes must be recorded for every indexed blob"
    );
}

#[tokio::test]
async fn snapshot_index_fallback_walks_the_tree_when_index_is_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let repo_path = tmp.path().join("repo");
    write(&source.join("data.bin"), &pseudo_random(64 * 1024, 31));

    let repo = Repository::init_local_with_kdf(&repo_path, chunker(), PASS, fast_kdf())
        .await
        .unwrap();
    let snapshot = repo.backup(std::slice::from_ref(&source)).await.unwrap();

    // Simulate a pre-index manifest: remove the index file behind the backend's
    // back, then ask for the index again.
    let index_path = repo_path
        .join("index")
        .join(format!("{}.json", snapshot.id));
    std::fs::remove_file(&index_path).unwrap();
    assert!(!index_path.exists());

    let derived = repo.snapshot_index(&snapshot).await.unwrap();
    assert!(!derived.blobs.is_empty(), "fallback walk found nothing");
    for b in &derived.blobs {
        assert!(
            repo.backend()
                .exists(&aegis_core::repo_test_hooks::blob_key_for(&b.hash))
                .await
                .unwrap(),
            "fallback-derived blob {} does not exist",
            b.hash
        );
    }
}
