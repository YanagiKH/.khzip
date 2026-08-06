# Installation

## Supported targets

The CLI is intended for current stable Rust on Windows, macOS, and Linux. The desktop binary uses `eframe` and `rfd` and therefore requires native windowing libraries.

## Release scripts

The scripts under `install/` query the latest GitHub Release, download the matching archive and checksum file, verify SHA-256, and install the binaries into a user-writable directory.

Linux/macOS default destination: `$HOME/.local/bin`.

Windows default destination: `%LOCALAPPDATA%\Programs\khzip`.

## Linux build dependencies

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev libgtk-3-dev libxkbcommon-dev
```

Fedora:

```bash
sudo dnf install -y gcc gcc-c++ pkgconf-pkg-config openssl-devel gtk3-devel libxkbcommon-devel
```

Arch Linux:

```bash
sudo pacman -S --needed base-devel pkgconf openssl gtk3 libxkbcommon
```

Then:

```bash
cargo build --release
cargo build --release --features gui --bin khzip-gui
```

## macOS

Install Xcode Command Line Tools and Rust:

```bash
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build --release
cargo build --release --features gui --bin khzip-gui
```

## Windows

Install Rust using `rustup-init.exe` and select the MSVC toolchain. Install Visual Studio Build Tools with Desktop development with C++.

```powershell
cargo build --release
cargo build --release --features gui --bin khzip-gui
```

Optional right-click registration:

```powershell
powershell -ExecutionPolicy Bypass -File install\windows-context-menu.ps1
```

## Verify a source installation

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```
