#!/bin/sh
# Silk installer.
# The SHA-256 of every build below was taken from a release manifest signed by
# the Silk release key (pinned in the binary) and recorded on the public
# ledger. This script refuses any download that does not match it, then the
# installed binary re-verifies the release signature and ledger inclusion.
set -eu
VERSION="__VERSION__"
release_for() {
  case "$1" in
__CASES__
    *) return 1 ;;
  esac
}
DEST="${SILK_INSTALL_DIR:-$HOME/.local/bin}"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "silk: unsupported architecture $arch" >&2; exit 1 ;;
esac
plat="${os}-${arch}"
if ! release_for "$plat"; then
  echo "silk: no build for ${plat} (Windows: download silk-windows-amd64.exe listed at /v2/release/manifest)" >&2
  exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading silk ${VERSION} for ${plat}..."
curl -fsSL "$url" -o "$tmp/silk"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/silk" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/silk" | cut -d' ' -f1); fi
if [ "$got" != "$sum" ]; then echo "silk: checksum mismatch; refusing to install" >&2; exit 1; fi
chmod 0755 "$tmp/silk"
SILK_HOME="$tmp/home" "$tmp/silk" self-verify
mkdir -p "$DEST"
mv "$tmp/silk" "$DEST/silk"
echo "Installed $DEST/silk"
case ":$PATH:" in *":$DEST:"*) ;; *) echo "Add $DEST to your PATH, e.g.: export PATH=\"$DEST:\$PATH\"";; esac
echo
echo "Next: silk init --label <name> [--handle <public-name>] [--passphrase]"
