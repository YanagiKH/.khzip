# Installation

`.khzip` version 0.2 requires Rust 1.88 or newer.

## Cargo installation

```bash
cargo install --git https://github.com/YanagiKH/.khzip
```

Desktop creator:

```bash
cargo install --git https://github.com/YanagiKH/.khzip --features gui --bin khzip-gui
```

## Linux build dependencies

Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config liblzma-dev libgtk-3-dev libxkbcommon-dev
```

The CLI can be built without GTK packages. The GUI file dialog can use XDG Desktop Portal or GTK depending on the selected `rfd` backend and desktop environment.

## macOS

Install the Rust toolchain through rustup, then build with Cargo. Xcode Command Line Tools are required for native linking.

```bash
xcode-select --install
cargo build --release
```

## Windows

Install Rust with the MSVC target and Visual Studio Build Tools with the C++ workload.

```powershell
cargo build --release
cargo build --release --features gui --bin khzip-gui
```

## GitHub Release installers

The scripts in `install/` select a matching release asset and verify its published SHA-256 file. They require an existing GitHub Release; source builds remain available before the first release is published.

## Shell integration

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File install/windows-context-menu.ps1
```

Linux:

```bash
./install/linux-desktop-integration.sh
```
