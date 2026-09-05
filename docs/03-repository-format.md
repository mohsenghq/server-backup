# Repository (Storage) Format

A repository is a content-addressable store, backend-agnostic (same format on local disk, SFTP, or S3):

```
repo/
  config                 # repo id, chunker params, kdf params (encrypted)
  keys/                  # wrapped master key(s), one per passphrase/identity
  blobs/<xx>/<hash>      # content-addressed, compressed+encrypted chunks (2-char shard prefix)
  snapshots/<id>.json    # manifest: host, path, timestamp, tree root hash, stats
  index/                 # packed blob→location index for fast repo rebuild
```

- Files are split via FastCDC into variable-size chunks (default 512KB–8MB range).
- Each chunk is hashed with BLAKE3 → deduplicated against the local index before upload.
- New chunks are zstd-compressed, then encrypted with the repo master key, then written as `blobs/<hash>`.
- A snapshot is a Merkle tree of chunk references (files → chunk lists, directories → child trees), rooted in a single hash stored in the snapshot manifest.
- `aegis verify` recomputes hashes and re-derives the tree to detect corruption.
- `aegis prune` applies retention rules and garbage-collects unreferenced blobs. Blob writes are append-only; `prune` is the only destructive path, and it must be explicit and logged (see `docs/10-security-model.md`).

## Fast-path for unchanged data

Before falling back to full content hashing, check mtime + size against the last snapshot. Only re-chunk/re-hash files that changed. This is what makes an unchanged-tree backup approach the speed of a metadata-only walk (see `docs/11-performance-targets.md`).
