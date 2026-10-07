#!/usr/bin/env bash
# Cross-compile static silk binaries (pure Go, no cgo) for every supported platform.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${1:?usage: build_release.sh VERSION}"
out="$root/dist/release/$ver"
rm -rf "$out" && mkdir -p "$out"
for plat in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  os="${plat%/*}"; arch="${plat#*/}"; ext=""; [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -C "$root" -trimpath -ldflags "-s -w -X main.version=$ver" -o "$out/silk-$os-$arch$ext" ./cmd/silk
done
ls -la "$out"
