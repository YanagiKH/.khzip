# Desktop UI and Shell Integration

The optional `khzip-gui` binary provides a native file/folder picker and controls for archive format, compression mode, output path, and password.

## Build

```bash
cargo build --release --features gui --bin khzip-gui
```

## Use

1. Select **Add files** or **Add folder**.
2. Choose `.khz`, `.khpak`, `.khx`, `.khaz`, or `.khcz`.
3. Choose a compression mode. `.khaz` and `.khcz` are normalized to extreme mode by the core library.
4. Choose an output path.
5. Enter a password when the selected format permits or requires one.
6. Create the archive, then verify it with the CLI before deleting any source data.

The desktop window calls the same Rust library used by the CLI. It does not invoke a shell command with the password.

## Windows right-click

`install/windows-context-menu.ps1` registers per-user entries for files, folders, and folder backgrounds. It does not require administrator rights. The selected path is passed directly to `khzip-gui`.

Remove the entries with:

```powershell
powershell -ExecutionPolicy Bypass -File install\windows-context-menu-uninstall.ps1
```

## Linux desktop

`install/linux-desktop-integration.sh` installs a `.desktop` launcher and a Nautilus script under the current user. The Nautilus script opens selected files in the GUI when `NAUTILUS_SCRIPT_SELECTED_FILE_PATHS` is available.

## macOS Finder

The binary accepts selected paths as positional arguments. Create a Finder Quick Action in Automator that runs:

```bash
/usr/local/bin/khzip-gui "$@"
```

Pass input as arguments and adjust the binary path to the installed location.

## Current limitations

- The GUI creates archives; list, verify, and extract remain CLI-first in v0.1.0.
- Progress reporting and cancellation are not yet implemented.
- Password confirmation and platform keychain integration are not yet implemented.
- Context-menu installers assume the binaries are already installed.
