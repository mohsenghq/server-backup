//! Criterion benchmarks for the hot paths (`docs/11-performance-targets.md`):
//!
//! - **Chunking + hashing** — the target is ≥ 400–500 MB/s per core.
//! - **Envelope** (zstd compress/decompress) — applied to every blob.
//! - **AEAD seal/open** — applied to every blob on encrypted repositories.
//! - **Merkle tree build** — serialization + hashing of tree nodes.
//! - **Repository round trip** — init/backup/restore on a local backend with
//!   a fixed synthetic tree (wall-clock end-to-end reference).
//!
//! Run with `cargo bench -p aegis-core`. Baselines live under
//! `target/criterion`; `critcmp` or the `--save-baseline` flag compares runs.

use std::hint::black_box;

use aegis_core::blobs;
use aegis_core::chunk::{chunk_bytes, ChunkerConfig};
use aegis_core::crypto::{self, KdfParams};
use aegis_core::tree::{self, Node};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Default-ish production chunk sizes (64 KiB average keeps bench file sizes
/// reasonable while exercising the same code path).
fn bench_chunker() -> ChunkerConfig {
    ChunkerConfig::new(16 * 1024, 64 * 1024, 256 * 1024).unwrap()
}

/// Deterministic pseudo-random bytes (xorshift), so every run benches the
/// same input.
fn deterministic(len: usize, seed: u64) -> Vec<u8> {
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

/// Highly compressible data (repeated text) to expose the zstd path.
fn compressible(len: usize) -> Vec<u8> {
    let unit = b"the quick brown fox jumps over the lazy dog. ".repeat(8);
    unit.iter().copied().cycle().take(len).collect()
}

fn bench_chunking(c: &mut Criterion) {
    let config = bench_chunker();
    let mut group = c.benchmark_group("chunking");
    for &size in &[1usize << 20, 8 << 20, 32 << 20] {
        let data = deterministic(size, 42);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("chunk_bytes", size), &data, |b, d| {
            b.iter(|| chunk_bytes(black_box(d), &config).unwrap())
        });
    }
    group.finish();
}

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    for &size in &[1usize << 20, 8 << 20] {
        let data = deterministic(size, 7);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("blake3", size), &data, |b, d| {
            b.iter(|| blake3::hash(black_box(d)))
        });
    }
    group.finish();
}

fn bench_envelope(c: &mut Criterion) {
    let mut group = c.benchmark_group("envelope");
    for &size in &[64usize << 10, 1 << 20, 8 << 20] {
        let random = deterministic(size, 11);
        let text = compressible(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("encode_random", size), |b| {
            b.iter(|| blobs::encode(black_box(&random)))
        });
        group.bench_function(BenchmarkId::new("encode_compressible", size), |b| {
            b.iter(|| blobs::encode(black_box(&text)))
        });

        let encoded = blobs::encode(&random);
        group.bench_function(BenchmarkId::new("decode_random", size), |b| {
            b.iter(|| blobs::decode(black_box(&encoded)).unwrap())
        });

        let encoded_text = blobs::encode(&text);
        group.bench_function(BenchmarkId::new("decode_compressible", size), |b| {
            b.iter(|| blobs::decode(black_box(&encoded_text)).unwrap())
        });
    }
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0x99u8; 24];
    let aad = b"aegis/bench";
    let mut group = c.benchmark_group("aead");
    for &size in &[64usize << 10, 1 << 20, 8 << 20] {
        let data = deterministic(size, 13);
        let sealed = crypto::seal(&key, &nonce, aad, &data).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("seal", size), |b| {
            b.iter(|| crypto::seal(&key, &nonce, aad, black_box(&data)).unwrap())
        });
        group.bench_function(BenchmarkId::new("open", size), |b| {
            b.iter(|| crypto::open(&key, aad, black_box(&sealed)).unwrap())
        });
    }
    group.finish();
}

fn bench_tree_build(c: &mut Criterion) {
    // A directory of 256 files x 64 KiB: every file node holds 1-2 chunk
    // hashes, the root dir node serializes past the inline limit.
    let config = bench_chunker();
    let files: Vec<Node> = (0..256)
        .map(|i| {
            let data = deterministic(64 * 1024, i as u64);
            let chunks = chunk_bytes(&data, &config)
                .unwrap()
                .into_iter()
                .map(|c| c.hash.to_hex().to_string())
                .collect();
            Node::File {
                name: format!("f{i}.bin"),
                size: data.len() as u64,
                mode: Some(0o644),
                mtime: Some(1_700_000_000),
                chunks,
            }
        })
        .collect();
    let root = Node::Dir {
        name: "root".into(),
        children: files,
    };

    c.bench_function("tree/build_stored/256_files", |b| {
        b.iter(|| tree::build_stored(black_box(root.clone())).unwrap())
    });
}

fn bench_repo_round_trip(c: &mut Criterion) {
    // One-shot end-to-end reference: a fresh repo per iteration would dominate
    // the measurement with Argon2id, so the repo is initialized once outside
    // the timed loop and each iteration backs up a freshly re-written tree
    // (all-new content forces the full write path).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = bench_chunker();

    let make_src = |run: u64| {
        let src = dir.path().join(format!("src{run}"));
        std::fs::create_dir_all(&src).unwrap();
        for i in 0..8u64 {
            std::fs::write(
                src.join(format!("f{i}.bin")),
                deterministic(256 * 1024, run * 100 + i),
            )
            .unwrap();
        }
        src
    };

    let kdf = KdfParams {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };
    let (repo, src0) = rt.block_on(async {
        let repo = aegis_core::Repository::init_with_kdf(
            Box::new(aegis_core::LocalBackend::new(dir.path().join("repo"))),
            config,
            "bench-passphrase",
            kdf,
        )
        .await
        .unwrap();
        let src0 = make_src(0);
        // Warm-up backup so the timed iterations measure steady state.
        repo.backup(std::slice::from_ref(&src0)).await.unwrap();
        (repo, src0)
    });

    let mut group = c.benchmark_group("repository");
    group.throughput(Throughput::Bytes(8 * 256 * 1024));
    group.bench_function("backup_2mib_new_content", |b| {
        let mut run = 1u64;
        b.iter(|| {
            let src = make_src(run);
            run += 1;
            rt.block_on(async { repo.backup(std::slice::from_ref(&src)).await })
                .unwrap();
            let _ = black_box(&src0);
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_chunking,
    bench_hashing,
    bench_envelope,
    bench_aead,
    bench_tree_build,
    bench_repo_round_trip,
);
criterion_main!(benches);
