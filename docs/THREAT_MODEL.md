# Threat model

## Protected

For encrypted archives, `.khzip` is designed to protect file contents, paths, sizes, chunk identities, compression metadata, and the manifest from a storage provider or attacker who possesses only the archive.

Authenticated encryption detects record modification under the correct unlock key. Recipient slots let the random archive master key be recovered through a password, X25519, ML-KEM-768, or X-Wing identity.

## Observable

An observer can see the container version, selected format and mode, flags, total object size, key-slot count and approximate slot sizes, recipient algorithm identifiers, truncated recipient fingerprints, record boundaries, record kinds, ordinals, ciphertext lengths, and manifest location. Splitting reveals part count and part sizes.

## Not protected

- A compromised endpoint while plaintext or keys are in use.
- Keyloggers, malicious kernels, debugger access, or hostile firmware.
- Loss of every password, device key, and recipient secret key.
- Denial of service through deletion, truncation, or slot removal.
- Traffic analysis from archive timing and size.
- Authenticity of fully rewritten unencrypted archives.
- Long-term cryptographic guarantees without future review and migration.

## Algorithm guidance

- X25519 provides classical security and compact interoperability.
- ML-KEM-768 provides a pure post-quantum KEM based on the current standard family.
- X-Wing combines ML-KEM-768 and X25519 and is the default recommendation where larger key material is acceptable.

Post-quantum implementations and specifications can still change. Support does not replace independent review, ecosystem interoperability testing, or future algorithm migration.

## Parser and extraction boundaries

- Fixed maximum record plaintext and payload sizes.
- Fixed maximum key-slot count and area size.
- Unknown versions, algorithms, flags, codecs, and trailing slot bytes are rejected.
- Absolute paths, parent components, NUL paths, and symbolic links are rejected.
- Existing output files are not overwritten unless explicitly requested.
- Archive creation uses a temporary file and atomic replacement where available.

## Operational requirements

Users should keep redundant archives, keep recovery credentials separately, run `khzip verify`, perform a test extraction, and retain source data until restoration has been confirmed.
