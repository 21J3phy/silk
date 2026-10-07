#!/usr/bin/env bash
# Publish a built release (scripts/build_release.sh VERSION first):
#   1. upload binaries to the relay project's public Blob store
#   2. sign the manifest with the release key and record it on the relay's ledger
#   3. rebuild the relay bundle so install.sh pins the new hashes, and deploy it
# Needs: the release signing key, and a Vercel login with access to the relay project.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${1:?usage: publish_release.sh VERSION [NOTES]}"
notes="${2:-}"
key="${SILK_RELEASE_KEY_FILE:-$HOME/.silk-relay-secrets/release-key}"
dir="$root/dist/release/$ver"
[ -d "$dir" ] || { echo "build it first: scripts/build_release.sh $ver" >&2; exit 1; }
umask 077
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
(cd "$root/deploy/vercel" && mkdir -p "$tmp/link" && cp -R .vercel "$tmp/link/" && cd "$tmp/link" && vercel env pull --environment production --yes "$tmp/prod.env" >/dev/null 2>&1)
token="$(grep '^BLOB_READ_WRITE_TOKEN=' "$tmp/prod.env" | cut -d= -f2- | tr -d '"')"
[ -n "$token" ] || { echo "no Blob token in the relay project's production env" >&2; exit 1; }
map="$dir.urls.json"
printf '{' > "$map"; sep=""
for f in "$dir"/silk-*; do
  n=$(basename "$f")
  u=$(cd "$tmp/link" && vercel blob put "$f" --pathname "silk/v$ver/$n" --access public --add-random-suffix=false \
        --content-type application/octet-stream --rw-token "$token" 2>&1 | grep -Eo 'https://[^ ]+' | head -1)
  [ -n "$u" ] || { echo "upload failed: $n" >&2; exit 1; }
  printf '%s\n "%s": "%s"' "$sep" "$n" "$u" >> "$map"; sep=","
done
printf '\n}\n' >> "$map"
token=""
go run -C "$root" ./cmd/silk release-publish --version "$ver" --key "$key" --dir "$dir" --url-map "$map" --notes "$notes" --record "$root/releases"
"$root/scripts/bundle_relay_vercel.sh" >/dev/null
(cd "$root/dist/relay-vercel" && vercel deploy --prod --yes >/dev/null)
echo "Published $ver; install.sh now pins $(grep -c 'url=' "$root/dist/relay-vercel/install.sh") builds."
