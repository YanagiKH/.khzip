# Threat Model

## Security goals

For password-encrypted `.khz` and `.khx`, `.khaz`, and `.khcz` archives:

- Hide file contents, names, paths, sizes, chunk identities, and index offsets from a cloud provider or storage attacker.
- Detect record modification, reordering, substitution, truncation, and wrong-key use before releasing a record.
- Detect accidental corruption across the complete container.
- Prevent archive paths from escaping the selected extraction directory.
- Avoid nonce reuse inside one archive.
- Avoid memory-unsafe parser code by forbidding unsafe Rust in the project.

## Adversaries considered

- A third-party cloud provider that can read, copy, delete, truncate, or modify archive bytes.
- An attacker who obtains an encrypted archive but not its password or device key.
- A malicious archive attempting absolute-path or `..` extraction.
- Accidental bit rot, incomplete upload, or missing `.khx` part.

## Out of scope

- A compromised endpoint while the archive is unlocked.
- Keyloggers, screen capture, malware, swap/hibernation capture, or a hostile kernel.
- Weak or reused user passwords.
- Traffic analysis outside the archive, including cloud object names, upload time, and total object size.
- Secure deletion from SSDs, cloud snapshots, or filesystem journals.
- Authenticity for `.khpak` or other unencrypted archives against an attacker able to recompute hashes.
- Hardware-enforced non-exportability of `.khcz` keys. The current device key is a protected local file.
- Deniability, steganography, or resistance to coercion.

## Important design decisions

### Compress before encrypt

Compression and deduplication run before encryption. Encrypted records reveal neither the chunk ID nor codec metadata without successful manifest and record authentication. Total archive size remains observable.

### Independent record authentication

Each record is an independent AEAD message. Random access does not require decrypting all previous records, and corruption is localized. The nonce is deterministic only after a random archive prefix is selected; the prefix plus ordinal pair is unique within the archive.

### `.khaz` layering

Two independent XChaCha20-Poly1305 layers are applied with domain-separated keys and nonce prefixes. This adds defense in depth but does not replace password strength, implementation review, or backups. Multiple encryption is not assumed to double a security level.

### `.khcz` device binding

`.khcz` derives its archive keys from a random local `device.key` and archive salt. The device key is created with owner-only permissions on Unix. Anyone who copies the key can decrypt the archive. Anyone who loses it cannot recover the archive.

### No public-key claims yet

HPKE/X25519 and ML-KEM-768 are not implemented in v1. Publishing recipient encryption without a stable key-slot specification, test vectors, downgrade protection, and independent review would create a misleading security promise.

## Security checklist before stable release

- Independent cryptographic and parser review.
- Coverage-guided fuzzing of header, record, manifest, split-part, and extraction paths.
- Cross-platform KAT/compatibility vectors.
- Large-file, interrupted-write, low-disk, and out-of-memory testing.
- Side-channel review of password failure and record parsing.
- Recovery exercises for passwords and `.khcz` device-key backups.
- Signed release provenance and reproducible-build investigation.
