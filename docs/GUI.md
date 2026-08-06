# Desktop interface

Build the native creator with:

```bash
cargo build --release --features gui --bin khzip-gui
```

The interface follows three stages: Content, Archive policy, and Access. It supports file/folder selection, all archive formats, compression modes, password protection, and multiple recipient public keys.

The GUI creates archives only. Listing, verification, extraction, recipient identity selection, device-key administration, and automation remain available through the CLI so errors and recovery behavior are explicit.

On Linux, install GTK 3 and XKB development packages before building. The file dialog uses the platform-native or portal backend selected by `rfd`.
