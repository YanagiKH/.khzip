# .khzip binary format

This document describes container version 2. Readers retain compatibility with version 1 password and device-key archives.

All integers are little-endian.

## Fixed header

The first 128 bytes begin with `KHZIP001`.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic |
| 8 | 2 | Container version (`2`) |
| 10 | 1 | Archive format |
| 11 | 1 | Compression mode |
| 12 | 4 | Flags |
| 16 | 16 | Archive salt |
| 32 | 16 | Primary nonce prefix |
| 48 | 16 | Secondary nonce prefix |
| 64 | 8 | Manifest record offset |
| 72 | 8 | Clear chunk count, zero when encrypted |
| 80 | 8 | Clear file count, zero when encrypted |
| 88 | 8 | Key-slot area length |
| 96 | 32 | BLAKE3 hash of the key-slot area |

Version 1 treats bytes 88–127 as reserved zero bytes and has no key slots.

## Flags

- bit 0: encrypted records
- bit 1: two record-encryption layers
- bit 2: local device key
- bit 3: versioned key-slot area

Unknown flags are rejected.

## Key-slot area

The optional key-slot area immediately follows the fixed header. It starts with `KHKS0001`, a slot format version, and a bounded slot count. Each entry contains:

- slot kind: password, X25519, ML-KEM-768, or X-Wing;
- 32-byte recipient fingerprint, zero for password slots;
- encapsulated-key length;
- wrapped-key length;
- encapsulated key or password nonce;
- authenticated wrapped 32-byte archive master key.

The complete key-slot area is limited to 4 MiB and 64 entries. Its BLAKE3 hash and length are included in every encrypted record's associated data. A slot alteration therefore cannot decrypt existing records; deletion can still cause denial of recovery.

## Records

Records use a 64-byte `KHR1` header followed by a bounded payload. Clear record framing contains type, flags, ordinal, and payload size. For encrypted records, codec, plaintext length, content ID, compressed bytes, and manifest data are inside authenticated ciphertext.

The nonce is the archive's random 16-byte prefix concatenated with the monotonically increasing 64-bit record ordinal. `.khaz` applies a second independently keyed XChaCha20-Poly1305 layer with a second prefix.

## Manifest and integrity

The manifest is postcard-serialized, Zstandard-compressed, and stored as the final record. It contains paths, file metadata, chunk indexes, and the BLAKE3 Merkle root.

A 48-byte trailer contains `KHTRLR01`, the manifest offset, and a BLAKE3 checksum over the entire preceding container. The checksum detects corruption; for an unencrypted archive it is not an authenticity proof against an attacker able to rewrite the whole file.

## Compatibility

- Version 2 readers accept version 1 containers.
- Version 1 readers reject version 2 containers rather than guessing around the key-slot area.
- Manifest schema version remains 1 because recipient slots do not change file or chunk semantics.
- Format or cryptographic changes require a version bump, updated vectors, and migration documentation.
