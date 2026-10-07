#!/bin/sh
# Silk installer: downloads the signed release for this platform, checks its
# SHA-256 against the release manifest, then has the binary verify itself
# against the release signature and the relay's public ledger.
set -eu
RELAY="${SILK_RELAY:-https://silk-relay.vercel.app}"
DEST="${SILK_INSTALL_DIR:-$HOME/.local/bin}"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "silk: unsupported architecture $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin|linux) ;;
  *) echo "silk: unsupported OS $os (Windows: download silk-windows-amd64.exe from the manifest)" >&2; exit 1 ;;
esac
plat="$os-$arch"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$RELAY/v2/release/manifest" -o "$tmp/manifest.json"
url=$(sed -n "s/.*\"$plat\":{\"url\":\"\([^\"]*\)\".*/\1/p" "$tmp/manifest.json")
sum=$(sed -n "s/.*\"$plat\":{\"url\":\"[^\"]*\",\"sha256\":\"\([0-9a-f]*\)\".*/\1/p" "$tmp/manifest.json")
if [ -z "$url" ] || [ -z "$sum" ]; then echo "silk: no build for $plat" >&2; exit 1; fi
echo "Downloading silk for ${plat}..."
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
echo "Next: silk init --label <name> [--handle <public-name>]"
