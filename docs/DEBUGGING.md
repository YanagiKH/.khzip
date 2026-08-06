# Debugging and Recovery Manual

Run these commands before changing or deleting an archive:

```bash
khzip doctor
khzip verify PATH_TO_ARCHIVE
```

Add `--password` or `--password-env NAME` for password-encrypted archives.

## `archive checksum mismatch`

The complete byte stream differs from the value stored in the trailer. Common causes are an incomplete upload, a truncated download, a modified byte, or incorrectly concatenated `.khx` parts.

1. Compare local and remote file sizes.
2. For `.khx`, confirm numbering starts at `.001` and has no missing number.
3. Download all parts again into an empty directory.
4. Run `khzip verify name.khx.001`.
5. Do not try to repair encrypted ciphertext manually. Restore a known-good copy.

## `authentication failed: wrong key or modified archive`

The password/device key is wrong, or the encrypted record was changed.

1. Confirm Caps Lock, keyboard layout, and password-manager entry.
2. Use `--password-env` to rule out terminal input issues.
3. For `.khcz`, run `khzip device-key path` and confirm the expected key file exists.
4. Verify the archive checksum. A checksum failure indicates damaged bytes; a passing checksum with authentication failure usually indicates the wrong key or a maliciously rewritten complete archive.

Passwords and device keys are not recoverable from the archive.

## `device key not found`

Initialize a new key only for new archives:

```bash
khzip device-key init
```

A new key cannot decrypt older `.khcz` files. Restore the original `device.key` backup to the exact path printed by:

```bash
khzip device-key path
```

Do not use `--force` unless replacing the key is intentional and all existing `.khcz` archives have another recovery path.

## `refusing to overwrite`

Extraction is non-destructive by default. Select an empty directory or pass `--overwrite` after confirming the destination.

```bash
khzip extract archive.khz --output restore-test --overwrite --password
```

Files are written to temporary sibling paths and renamed only after size and chunk verification complete.

## `unsafe archive path`

The manifest contains an absolute path, `..`, `.`, a platform prefix, or another unsupported component. Treat this as a malformed or hostile archive. Do not bypass the check.

## Compression appears ineffective

Already-compressed formats such as JPEG, MP4, ZIP, 7z, and many game assets often cannot be compressed further. `.khzip` stores a chunk uncompressed when compression would add overhead. Deduplication may still reduce repeated data.

Inspect the summary:

```bash
khzip list archive.khz --password
```

Compare `original bytes` and `unique bytes` to see deduplication savings. The on-disk file size also includes record headers, authentication tags, index data, and the trailer.

## Slow `.khaz` or `.khcz` creation

Extreme mode uses Brotli quality 11 or LZMA2 level 9 and is intentionally CPU intensive. Use `.khz --mode balanced` for routine work. Password archives also run Argon2id with a substantial memory cost.

## Build failures

```bash
rustup update stable
cargo clean
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

GUI builds additionally require platform windowing dependencies. See [INSTALL.md](INSTALL.md).

## Collect a diagnostic report

```bash
khzip doctor > khzip-doctor.txt
cargo --version >> khzip-doctor.txt
rustc --version >> khzip-doctor.txt
```

Do not include passwords, environment-variable values, device-key contents, decrypted filenames, or private archive samples in public issues.

## Report a bug

Include:

- operating system and architecture
- `.khzip` version
- exact command with secrets removed
- complete error text
- whether the issue reproduces with a newly generated non-sensitive sample
- whether `khzip verify` passes

Security vulnerabilities must follow [SECURITY.md](../SECURITY.md), not a public issue.
