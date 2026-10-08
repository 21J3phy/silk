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
# GitHub Release: binaries, Claude Desktop bundle and checksums. Publishing it
# triggers .github/workflows/publish-mcp.yml, which lists the bundle in the MCP Registry.
"$root/scripts/build_mcpb.sh" "$ver" >/dev/null
sums="$root/dist/release/SHA256SUMS-$ver"
(cd "$dir" && shasum -a 256 silk-* && cd "$root/dist/release" && shasum -a 256 "silk-$ver.mcpb") > "$sums"
gh release create "v$ver" -R 21J3phy/silk --target "$(git -C "$root" rev-parse HEAD)" --title "Silk $ver" --notes "$notes

**Install** (macOS, Linux): \`curl -fsSL https://silk-relay.vercel.app/install.sh | sh\`, then \`silk init --label <name> --passphrase\` and \`claude mcp add silk -- silk mcp\`.
**Update:** \`silk update\` installs a release only if it is signed with the pinned release key and recorded on the public ledger.
**Claude Desktop:** download \`silk-$ver.mcpb\` and open it.
**Verify by hand:** SHA-256 sums are in \`SHA256SUMS\`; the signed manifest is at https://silk-relay.vercel.app/v2/release/manifest." \
  "$dir"/silk-* "$root/dist/release/silk-$ver.mcpb" "$sums#SHA256SUMS" >/dev/null
echo "Published $ver; install.sh now pins $(grep -c 'url=' "$root/dist/relay-vercel/install.sh") builds; GitHub release v$ver created."
