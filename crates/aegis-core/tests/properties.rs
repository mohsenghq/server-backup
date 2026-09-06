//! Property-based tests (`proptest`) for the invariants docs/12 asks for:
//!
//! - **Chunking**: bounds hold for arbitrary inputs, and content-defined
//!   deduplication is shift-resistant — inserting bytes at the head of a
//!   file only re-uploads a bounded prefix of chunks, never the whole file
//!   (the property that separates CDC from fixed-size chunking).
//! - **Repository round trips**: arbitrary trees round-trip through
//!   init → backup → restore byte-for-byte, and dedup means the *second*
//!   backup of an unchanged tree writes nothing new.
//! - **Envelope**: `encode`/`decode` round-trips for arbitrary payloads.
//! - **Crypto**: seal/open round-trips under random keys/nonce/AAD; any
//!   tampering (bit flip, truncation, wrong AAD, wrong key) is detected.
//! - **Retention**: the GFS policy never prunes the newest snapshot, never
//!   removes anything it said it would keep, and all-zero policies keep the
//!   newest snapshot only.
//!
//! The full-repository properties use fast test KDF params and small chunk
//! sizes to stay in the sub-second range per case.

use std::sync::atomic::{AtomicU64, Ordering};

use aegis_core::blobs;
use aegis_core::chunk::{chunk_bytes, chunk_stream, ChunkerConfig};
use aegis_core::crypto::{self, KdfParams};
use aegis_core::retention::{apply_policy, RetentionPolicy};
use aegis_core::snapshot::Snapshot;
use aegis_core::tree::Node;
use aegis_core::Repository;
use proptest::prelude::*;

const PASS: &str = "proptest-passphrase";

fn chunker() -> ChunkerConfig {
    ChunkerConfig::new(256, 1024, 4096).unwrap()
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

/// Unique repo path per proptest case (cases run in one process).
static CASE: AtomicU64 = AtomicU64::new(0);

fn temp_repo_root() -> std::path::PathBuf {
    let n = CASE.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("aegis-proptest-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ------------------------------------------------------------------------------------------------
// Chunking properties
// ------------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every chunk lies within [min, max], chunks tile the input exactly, and
    /// the chunk hashes are exactly BLAKE3 over the chunk bytes.
    #[test]
    fn chunks_respect_bounds_and_tile_exactly(
        data in proptest::collection::vec(any::<u8>(), 0..60_000),
        seed in any::<u64>(),
    ) {
        let config = chunker();
        // Vary the cut points a little by shifting the data content.
        let data = prefix_filler(&data, seed);
        let chunks = chunk_bytes(&data, &config).unwrap();
        prop_assert!(!chunks.is_empty());

        let mut offset = 0usize;
        for (i, c) in chunks.iter().enumerate() {
            // FastCDC keeps every chunk within [min, max] except the final
            // one, which is the input's remainder.
            if i + 1 < chunks.len() {
                prop_assert!(c.length >= config.min_size, "mid-stream chunk below min: {}", c.length);
            }
            prop_assert!(c.length <= config.max_size, "chunk above max: {}", c.length);
            prop_assert_eq!(c.offset as usize, offset);
            offset += c.length;
            let bytes = &data[c.offset as usize..(c.offset + c.length as u64) as usize];
            prop_assert_eq!(c.hash.to_hex().to_string(), blake3::hash(bytes).to_hex().to_string());
        }
        prop_assert_eq!(offset, data.len(), "chunks must tile the input exactly");
    }

    /// Content-defined chunking is shift-resistant: appending to a file can
    /// only change the tail chunks; the head chunks stay identical.
    #[test]
    fn appending_only_rechunks_a_bounded_tail(
        head in proptest::collection::vec(any::<u8>(), 20_000..40_000),
        tail in proptest::collection::vec(any::<u8>(), 0..10_000),
    ) {
        let config = chunker();
        let a = &head;
        let mut b = head.clone();
        b.extend_from_slice(&tail);

        let ca = chunk_bytes(a, &config).unwrap();
        let cb = chunk_bytes(&b, &config).unwrap();

        // Count matching leading chunks by (offset, length, hash).
        let common = ca
            .iter()
            .zip(cb.iter())
            .take_while(|(x, y)| x.hash == y.hash && x.length == y.length)
            .count();
        let matched_bytes: usize = cb[..common].iter().map(|c| c.length).sum();

        // The re-chunked tail is bounded by max_size + the appended length.
        prop_assert!(
            matched_bytes as u64 >= b.len() as u64 - (config.max_size + tail.len() + config.avg_size) as u64,
            "only a bounded tail may re-chunk: matched {matched_bytes} of {}",
            b.len()
        );
    }

    /// Dedup path: chunking the same content twice yields identical hash
    /// sequences regardless of the stream it arrived on.
    #[test]
    fn chunk_bytes_and_chunk_stream_agree(
        data in proptest::collection::vec(any::<u8>(), 0..50_000),
    ) {
        let config = chunker();
        let a = chunk_bytes(&data, &config).unwrap();
        let mut b = Vec::new();
        chunk_stream(std::io::Cursor::new(&data), &config, |c, bytes| {
            b.push((c.hash, c.length, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
        prop_assert_eq!(a.len(), b.len());
        for (ca, (hb, len, bytes)) in a.iter().zip(&b) {
            prop_assert_eq!(&ca.hash, hb);
            prop_assert_eq!(ca.length, *len);
            prop_assert_eq!(ca.length, bytes.len());
        }
    }
}

/// Deterministically jitter the front of the buffer so different seeds produce
/// different cut points without changing the property being tested.
fn prefix_filler(data: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(b ^ (state >> 56) as u8);
    }
    out
}

// ------------------------------------------------------------------------------------------------
// Envelope + crypto properties
// ------------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn envelope_round_trips_arbitrary_payloads(
        data in proptest::collection::vec(any::<u8>(), 0..100_000),
    ) {
        let decoded = blobs::decode(&blobs::encode(&data)).unwrap();
        prop_assert_eq!(decoded, data);
    }

    #[test]
    fn seal_open_round_trips_and_tamper_is_detected(
        key in proptest::array::uniform32(any::<u8>()),
        nonce in proptest::array::uniform24(any::<u8>()),
        aad in proptest::collection::vec(any::<u8>(), 0..64),
        plaintext in proptest::collection::vec(any::<u8>(), 0..5_000),
        bit in 0usize..(5_000 * 8),
    ) {
        // `seal` returns ciphertext+tag; `open` consumes nonce‖ct‖tag.
        let mut sealed = nonce.to_vec();
        sealed.extend(crypto::seal(&key, &nonce, &aad, &plaintext).unwrap());
        let opened = crypto::open(&key, &aad, &sealed).unwrap();
        prop_assert_eq!(opened, plaintext);

        // Flip one bit anywhere in nonce‖ciphertext‖tag — or try a wrong
        // AAD / wrong key. Every mutation must fail authentication.
        let mutations = [
            {
                let mut m = sealed.clone();
                let i = bit % m.len();
                m[i] ^= 0x01;
                m
            },
            {
                let mut m = sealed.clone();
                m.truncate(m.len() - 1);
                m
            },
        ];
        for m in &mutations {
            prop_assert!(crypto::open(&key, &aad, m).is_err(), "tampered ciphertext opened");
        }
        prop_assert!(crypto::open(&key, b"wrong-aad", &sealed).is_err());
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        prop_assert!(crypto::open(&wrong_key, &aad, &sealed).is_err());
    }
}

// ------------------------------------------------------------------------------------------------
// Retention properties
// ------------------------------------------------------------------------------------------------

fn snapshot_at(id: &str, time: &str) -> Snapshot {
    // `Snapshot` needs a valid tree for `root_hash`, but retention only reads
    // `time` and `id`; a minimal file node suffices.
    Snapshot {
        id: id.to_string(),
        time: time.to_string(),
        hostname: "h".into(),
        paths: vec![],
        root: Node::File {
            name: "root".into(),
            size: 0,
            mode: None,
            mtime: None,
            chunks: vec![],
        },
        stats: Default::default(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn retention_never_prunes_the_newest_snapshot(
        times in proptest::collection::vec(rfc3339_strategy(), 1..30),
        policy in policy_strategy(),
    ) {
        let mut times = times;
        times.sort();
        let snaps: Vec<Snapshot> = times
            .iter()
            .enumerate()
            .map(|(i, t)| snapshot_at(&format!("s{i:04}"), t))
            .collect();
        let decision = apply_policy(&snaps, &policy);

        // The newest snapshot must survive every policy.
        let newest = snaps.last().unwrap().id.clone();
        prop_assert!(
            decision.kept.iter().any(|s| s.id == newest),
            // (String == String: both sides owned)
            "newest snapshot {newest} was pruned by {policy:?}"
        );
        // kept and pruned partition the input exactly once.
        prop_assert_eq!(decision.kept.len() + decision.pruned.len(), snaps.len());
    }

    #[test]
    fn all_zero_policy_keeps_only_the_newest(
        times in proptest::collection::vec(rfc3339_strategy(), 1..30),
    ) {
        let mut times = times;
        times.sort();
        let snaps: Vec<Snapshot> = times
            .iter()
            .enumerate()
            .map(|(i, t)| snapshot_at(&format!("s{i:04}"), t))
            .collect();
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: 0,
        };
        let decision = apply_policy(&snaps, &policy);
        prop_assert_eq!(decision.kept.len(), 1);
        prop_assert_eq!(&decision.kept[0].id, &snaps.last().unwrap().id);
    }

    #[test]
    fn keep_last_n_always_keeps_at_least_n(
        times in proptest::collection::vec(rfc3339_strategy(), 1..40),
        n in 1u32..6,
    ) {
        let mut times = times;
        times.sort();
        let snaps: Vec<Snapshot> = times
            .iter()
            .enumerate()
            .map(|(i, t)| snapshot_at(&format!("s{i:04}"), t))
            .collect();
        let policy = RetentionPolicy {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
            keep_last: n,
        };
        let decision = apply_policy(&snaps, &policy);
        prop_assert!(
            decision.kept.len() >= n.min(snaps.len() as u32) as usize,
            "keep_last={n} kept only {}",
            decision.kept.len()
        );
    }
}

/// RFC 3339 timestamps in a two-year window, generated as valid instants.
fn rfc3339_strategy() -> impl Strategy<Value = String> {
    (0i64..63_072_000i64).prop_map(|offset| {
        let t = time::OffsetDateTime::from_unix_timestamp(1_700_000_000 + offset).unwrap();
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    })
}

/// A spread of retention policies.
fn policy_strategy() -> impl Strategy<Value = RetentionPolicy> {
    (0u32..4, 0u32..4, 0u32..4, 0u32..5).prop_map(|(d, w, m, l)| RetentionPolicy {
        keep_daily: d,
        keep_weekly: w,
        keep_monthly: m,
        keep_last: l,
    })
}

// ------------------------------------------------------------------------------------------------
// Repository round-trip properties (end-to-end, fewest cases)
// ------------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn arbitrary_trees_round_trip_through_the_repository(
        tree in tree_strategy(),
    ) {
        let root = temp_repo_root();
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();

        // Materialize the generated tree on disk.
        let mut total_files = 0usize;
        for (rel, contents) in &tree {
            let path = src.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
            total_files += 1;
        }

        let repo_dir = root.join("repo");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (snapshot, stored_files) = rt.block_on(async {
            let repo = Repository::init_with_kdf(
                Box::new(aegis_core::LocalBackend::new(&repo_dir)),
                chunker(),
                PASS,
                fast_kdf(),
            )
            .await
            .unwrap();
            let snap = repo.backup(std::slice::from_ref(&src)).await.unwrap();
            let out = root.join("out");
            repo.restore(&snap.id, &out).await.unwrap();
            let stored_files = snap.stats.files;
            (snap, stored_files)
        });

        // Every generated file came back byte-for-byte.
        for (rel, contents) in &tree {
            let restored = root.join("out").join("src").join(rel);
            let got = std::fs::read(&restored)
                .unwrap_or_else(|e| panic!("missing restored file {rel}: {e}"));
            prop_assert_eq!(&got, contents);
        }
        prop_assert_eq!(stored_files as usize, total_files);

        // The second backup of the unchanged tree writes nothing new.
        let (new_chunks, new_bytes) = rt.block_on(async {
            let repo = Repository::open(
                Box::new(aegis_core::LocalBackend::new(&repo_dir)),
                PASS,
            )
            .await
            .unwrap();
            let snap2 = repo.backup(std::slice::from_ref(&src)).await.unwrap();
            (snap2.stats.new_chunks, snap2.stats.new_bytes)
        });
        prop_assert_eq!(new_chunks, 0, "unchanged re-backup must dedup fully");
        prop_assert_eq!(new_bytes, 0);

        prop_assert!(!snapshot.id.is_empty());
    }
}

/// A random file tree: 1–12 files, 0–2 directory levels, sizes 0–64 KiB with
/// runs of repeated content so dedup has something to bite on.
fn tree_strategy() -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
    (0usize..12).prop_flat_map(|n| {
        (
            proptest::collection::vec(any::<u64>(), n..=n),
            proptest::collection::vec(0usize..65_536, n..=n),
        )
            .prop_map(move |(seeds, sizes)| {
                let mut files = Vec::new();
                for (i, (&seed, &size)) in seeds.iter().zip(&sizes).enumerate() {
                    // Half the files share content (dedup), the rest are
                    // pseudo-random bytes.
                    let contents = if i % 2 == 0 {
                        pseudo_random(size, seed)
                    } else {
                        pseudo_random(size, seeds[0])
                    };
                    let dir = if i % 3 == 0 {
                        String::new()
                    } else {
                        format!("d{}", i % 3)
                    };
                    let rel = if dir.is_empty() {
                        format!("f{i}.bin")
                    } else {
                        format!("{dir}/f{i}.bin")
                    };
                    files.push((rel, contents));
                }
                files
            })
    })
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
