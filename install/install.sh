#!/bin/sh
set -eu

REPO="YanagiKH/.khzip"
INSTALL_DIR="${KHZIP_INSTALL_DIR:-$HOME/.local/bin}"
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux) TARGET_OS="linux" ;;
  Darwin) TARGET_OS="macos" ;;
  *) echo "Unsupported operating system: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) TARGET_ARCH="x86_64" ;;
  arm64|aarch64) TARGET_ARCH="aarch64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

API="https://api.github.com/repos/$REPO/releases/latest"
TAG=$(curl -fsSL "$API" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
[ -n "$TAG" ] || { echo "Could not determine latest release" >&2; exit 1; }

ASSET="khzip-${TAG#v}-${TARGET_OS}-${TARGET_ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET"
curl -fsSL "$BASE/$ASSET.sha256" -o "$TMP/$ASSET.sha256"
(
  cd "$TMP"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$ASSET.sha256"
  else
    shasum -a 256 -c "$ASSET.sha256"
  fi
)

tar -xzf "$TMP/$ASSET" -C "$TMP"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/khzip" "$INSTALL_DIR/khzip"
if [ -f "$TMP/khzip-gui" ]; then
  install -m 0755 "$TMP/khzip-gui" "$INSTALL_DIR/khzip-gui"
fi
printf 'Installed .khzip to %s\n' "$INSTALL_DIR"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'Add %s to PATH.\n' "$INSTALL_DIR" ;;
esac
