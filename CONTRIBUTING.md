# Contributing

## Development checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo check --features gui --bin khzip-gui
```

## Rules

- Keep `unsafe_code = "forbid"`.
- Do not add a cryptographic algorithm, key-slot type, KDF parameter change, or format flag without test vectors and a format-document update.
- Do not weaken path validation or overwrite defaults.
- Avoid logging passwords, keys, plaintext chunks, or decrypted manifest data.
- Add regression tests for parser and extraction defects.
- Preserve backward readability for released format versions.

## Commit and pull request format

Use concise English commit subjects. Pull requests must describe behavior, security impact, compatibility, and the checks run.
