//! Repository key rotation, end to end: add a passphrase, list the slots,
//! revoke one, and prove throughout that the data is never re-encrypted and
//! the remaining passphrases still open every snapshot.

mod sftp_server;

use aegis_core::backend::Backend;
use aegis_core::chunk::ChunkerConfig;
use aegis_core::crypto::KdfParams;
use aegis_core::keys::{key_add_backend, key_list_backend, key_remove_backend, KeySlot};
use aegis_core::repo::Repository;
use aegis_core::LocalBackend;

const P0: &str = "passphrase-zero";
const P1: &str = "passphrase-one";
const P2: &str = "passphrase-two";

/// Real-key KDF params are 64 MiB x 3 rounds, which would make every one of
/// these tests take seconds. The params are recorded per key file, so using
/// cheap ones here exercises the same code paths.
fn fast_params() -> KdfParams {
    KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

fn slot_names(slots: &[KeySlot]) -> Vec<&str> {
    slots.iter().map(|s| s.slot.as_str()).collect()
}

/// Back up `data_path` and return the path a later restore should target, so a
/// test can re-restore after a rotation and compare.
async fn seed(
    repo: &std::path::Path,
    data_path: &std::path::PathBuf,
) -> (String, std::path::PathBuf) {
    Repository::init_local_with_kdf(repo, ChunkerConfig::default(), P0, fast_params())
        .await
        .unwrap();
    let snap = Repository::open_local(repo, P0)
        .await
        .unwrap()
        .backup(std::slice::from_ref(data_path))
        .await
        .expect("backup into repo");
    (snap.id, data_path.parent().unwrap().join("restored"))
}

#[tokio::test]
async fn rotate_add_list_and_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let (repo, data) = (dir.path().join("repo"), dir.path().join("data"));
    tokio::fs::create_dir_all(&data).await.unwrap();
    tokio::fs::write(data.join("hello.txt"), b"survives rotation")
        .await
        .unwrap();
    let (snap, out) = seed(&repo, &data).await;

    // --- add: the new passphrase opens the repository, the old one still does.
    let added = key_add_backend(Box::new(LocalBackend::new(&repo)), P0, P1)
        .await
        .expect("add a key slot");
    assert_eq!(added, "key1");
    Repository::open_local(&repo, P0)
        .await
        .expect("original passphrase still opens the repo");
    Repository::open_local(&repo, P1)
        .await
        .expect("new passphrase opens the repo");

    // --- list: both slots, and the config's slot flagged active.
    let slots = key_list_backend(&LocalBackend::new(&repo)).await.unwrap();
    assert_eq!(slot_names(&slots), vec!["default", "key1"]);
    assert!(slots[0].active, "config still names 'default'");
    assert!(!slots[1].active);
    assert_eq!(slots[0].kdf, fast_params());

    // Rotation does not touch the data: a restore under the *new* passphrase
    // is byte-identical.
    Repository::open_local(&repo, P1)
        .await
        .unwrap()
        .restore(&snap, &out)
        .await
        .expect("restore under the new passphrase");
    assert_eq!(
        tokio::fs::read(out.join("data").join("hello.txt"))
            .await
            .unwrap(),
        b"survives rotation"
    );

    // --- revoke: the removed passphrase is dead, the survivor is untouched.
    key_remove_backend(&LocalBackend::new(&repo), "key1", P0)
        .await
        .expect("revoke key1");
    assert!(
        Repository::open_local(&repo, P1).await.is_err(),
        "a revoked passphrase must not open the repository"
    );
    let survivor = Repository::open_local(&repo, P0).await.unwrap();
    assert_eq!(survivor.list_snapshots().await.unwrap()[0].id, snap);
    // `key1` was not the configured slot, so `default` stays the active one.
    let slots = key_list_backend(&LocalBackend::new(&repo)).await.unwrap();
    assert_eq!(slot_names(&slots), vec!["default"]);
    assert!(slots[0].active);

    // Revoking did not rewrite a single blob, so the snapshot still verifies
    // deep: every chunk re-downloads, re-hashes, and authenticates.
    survivor
        .verify(&survivor.find_snapshot(&snap).await.unwrap(), true)
        .await
        .expect("deep verify after rotation");
}

/// Revoking the slot the repository `config` names must re-point the config at
/// a survivor, so it never references a slot that no longer exists.
#[tokio::test]
async fn revoking_the_configured_slot_repoints_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let backend = LocalBackend::new(&repo);
    Repository::init_local_with_kdf(&repo, ChunkerConfig::default(), P0, fast_params())
        .await
        .unwrap();
    key_add_backend(Box::new(LocalBackend::new(&repo)), P0, P1)
        .await
        .unwrap();

    key_remove_backend(&backend, "default", P1)
        .await
        .expect("revoke the configured slot");
    let slots = key_list_backend(&backend).await.unwrap();
    assert_eq!(slot_names(&slots), vec!["key1"]);
    assert!(
        slots[0].active,
        "config must now name the surviving slot: {:?}",
        slots[0]
    );
    Repository::open_local(&repo, P1)
        .await
        .expect("the survivor still opens the repository");
    assert!(
        Repository::open_local(&repo, P0).await.is_err(),
        "the revoked passphrase must be dead"
    );
}

/// Rotating *from* an already-added passphrase must work. The add path used to
/// read only the slot named in `config`, so the second rotation of a rotated
/// repository failed with a wrong-passphrase error.
#[tokio::test]
async fn add_key_using_a_previously_added_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    Repository::init_local_with_kdf(&repo, ChunkerConfig::default(), P0, fast_params())
        .await
        .unwrap();

    assert_eq!(
        key_add_backend(Box::new(LocalBackend::new(&repo)), P0, P1)
            .await
            .unwrap(),
        "key1"
    );
    // P1 is not the configured slot — this used to fail here.
    assert_eq!(
        key_add_backend(Box::new(LocalBackend::new(&repo)), P1, P2)
            .await
            .expect("rotate again from the added passphrase"),
        "key2"
    );

    for pass in [P0, P1, P2] {
        Repository::open_local(&repo, pass)
            .await
            .unwrap_or_else(|e| panic!("{pass} must open the repository: {e}"));
    }
    assert_eq!(
        slot_names(&key_list_backend(&LocalBackend::new(&repo)).await.unwrap()),
        vec!["default", "key1", "key2"]
    );
}

#[tokio::test]
async fn revoke_is_guarded() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let backend = LocalBackend::new(&repo);
    Repository::init_local_with_kdf(&repo, ChunkerConfig::default(), P0, fast_params())
        .await
        .unwrap();

    // The repository's only key cannot be revoked — that would leave nothing
    // able to open it.
    let err = key_remove_backend(&backend, "default", P0)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("only key slot"),
        "unexpected error: {err}"
    );
    Repository::open_local(&repo, P0)
        .await
        .expect("repo still openable");

    key_add_backend(Box::new(LocalBackend::new(&repo)), P0, P1)
        .await
        .unwrap();

    // Revoking requires proving you hold a passphrase that opens the repo.
    assert!(matches!(
        key_remove_backend(&backend, "key1", "not-a-passphrase").await,
        Err(aegis_core::Error::WrongPassphrase)
    ));
    // An unknown slot is a clear error, not a silent no-op.
    let err = key_remove_backend(&backend, "key9", P0).await.unwrap_err();
    assert!(err.to_string().contains("no key slot 'key9'"), "{err}");

    // An operator may revoke the slot their own passphrase lives in, as long
    // as another slot remains to fall back on.
    key_remove_backend(&backend, "key1", P1)
        .await
        .expect("revoke the slot the supplied passphrase opens");
    assert!(Repository::open_local(&repo, P1).await.is_err());
    Repository::open_local(&repo, P0)
        .await
        .expect("fallback passphrase still opens");
}

/// Key rotation on a repository that lives on a backup host, over the real
/// SFTP stack. Each step opens its own connection, the way separate `aegis
/// key-*` invocations do.
#[tokio::test]
async fn rotation_over_sftp() {
    let dir = tempfile::tempdir().unwrap();
    let connect = || sftp_server::connected_backend(dir.path().to_path_buf());
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("f.bin"), vec![3u8; 4096]).unwrap();
    let key = |s: &str| format!("keys/{s}.json");

    Repository::init_with_kdf(
        Box::new(connect().await.unwrap().0),
        ChunkerConfig::default(),
        P0,
        fast_params(),
    )
    .await
    .unwrap();
    assert!(connect()
        .await
        .unwrap()
        .0
        .exists(&key("default"))
        .await
        .unwrap());

    assert_eq!(
        key_add_backend(Box::new(connect().await.unwrap().0), P0, P1)
            .await
            .unwrap(),
        "key1"
    );
    let slots = key_list_backend(&connect().await.unwrap().0).await.unwrap();
    assert_eq!(slot_names(&slots), vec!["default", "key1"]);

    key_remove_backend(&connect().await.unwrap().0, "key1", P0)
        .await
        .unwrap();
    let backend = connect().await.unwrap().0;
    assert!(!backend.exists(&key("key1")).await.unwrap());
    assert!(backend.exists(&key("default")).await.unwrap());
}
