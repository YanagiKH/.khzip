#!/bin/sh
set -eu
GUI=$(command -v khzip-gui || true)
[ -n "$GUI" ] || { echo "khzip-gui is not installed or not in PATH" >&2; exit 1; }
APP_DIR="$HOME/.local/share/applications"
SCRIPT_DIR="$HOME/.local/share/nautilus/scripts"
mkdir -p "$APP_DIR" "$SCRIPT_DIR"
cat > "$APP_DIR/khzip.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=.khzip
Comment=Create secure compressed archives
Exec=$GUI %F
Terminal=false
Categories=Utility;Archiving;
MimeType=inode/directory;application/octet-stream;
DESKTOP
cat > "$SCRIPT_DIR/Compress with .khzip" <<SCRIPT
#!/bin/sh
printf '%s\n' "\${NAUTILUS_SCRIPT_SELECTED_FILE_PATHS:-}" | sed '/^$/d' | xargs -r "$GUI"
SCRIPT
chmod +x "$SCRIPT_DIR/Compress with .khzip"
update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
printf '.khzip desktop integration installed.\n'
