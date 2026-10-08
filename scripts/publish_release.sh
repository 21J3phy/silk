#!/usr/bin/env bash
# Publish a built release (scripts/build_release.sh VERSION first):
#   1. create the GitHub release with the binaries, Claude Desktop bundle and checksums
#   2. sign a manifest pointing at those release assets and record it on the relay's ledger
#   3. rebuild the relay bundle so install.sh pins the new hashes, and deploy it
# Binaries are served from GitHub Releases (the relay's Blob store was suspended
# in October 2026). Clients check every download against the signed SHA-256s, so
# the host is not trusted. Publishing the GitHub release triggers
# .github/workflows/publish-mcp.yml, which lists the bundle in the MCP Registry.
# Needs: the release signing key, gh, and a Vercel login with access to the relay project.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${1:?usage: publish_release.sh VERSION [NOTES]}"
notes="${2:-}"
key="${SILK_RELEASE_KEY_FILE:-$HOME/.silk-relay-secrets/release-key}"
dir="$root/dist/release/$ver"
[ -d "$dir" ] || { echo "build it first: scripts/build_release.sh $ver" >&2; exit 1; }
[ -d "$root/deploy/vercel/.vercel" ] || { echo "link the relay project first: (cd deploy/vercel && vercel link)" >&2; exit 1; }
umask 077
"$root/scripts/build_mcpb.sh" "$ver" >/dev/null
sums="$root/dist/release/SHA256SUMS-$ver"
(cd "$dir" && shasum -a 256 silk-* && cd "$root/dist/release" && shasum -a 256 "silk-$ver.mcpb") > "$sums"
gh release create "v$ver" -R 21J3phy/silk --target "$(git -C "$root" rev-parse HEAD)" --title "Silk $ver" --notes "$notes

**Install** (macOS, Linux): \`curl -fsSL https://silk-relay.vercel.app/install.sh | sh\`, then \`silk init --label <name> --passphrase\` and \`silk setup\` (adds Silk to Claude Code, Codex, Cursor, Gemini CLI, Grok Build, Muse Code, VS Code and more). Agents on their own cloud computers (Grok Bot, OpenAI Dots, Meta Muse): \`silk owner\`, then point them at https://silk-relay.vercel.app/skill.md. Cloud chats (grok.com, ChatGPT, claude.ai): \`silk mcp --http --tunnel\`. Guide: https://github.com/21J3phy/silk/blob/main/docs/v2/CONNECT.md
**Update:** \`silk update\` installs a release only if it is signed with the pinned release key and recorded on the public ledger.
**Claude Desktop:** download \`silk-$ver.mcpb\` and open it.
**Verify by hand:** SHA-256 sums are in \`SHA256SUMS\`; the signed manifest is at https://silk-relay.vercel.app/v2/release/manifest." \
  "$dir"/silk-* "$root/dist/release/silk-$ver.mcpb" "$sums#SHA256SUMS" >/dev/null
map="$dir.urls.json"
printf '{' > "$map"; sep=""
for f in "$dir"/silk-*; do
  n=$(basename "$f")
  printf '%s\n "%s": "https://github.com/21J3phy/silk/releases/download/v%s/%s"' "$sep" "$n" "$ver" "$n" >> "$map"; sep=","
done
printf '\n}\n' >> "$map"
go run -C "$root" ./cmd/silk release-publish --version "$ver" --key "$key" --dir "$dir" --url-map "$map" --notes "$notes" --record "$root/releases"
"$root/scripts/bundle_relay_vercel.sh" >/dev/null
(cd "$root/dist/relay-vercel" && vercel deploy --prod --yes >/dev/null)
echo "Published $ver; GitHub release v$ver created; install.sh now pins $(grep -c 'url=' "$root/dist/relay-vercel/install.sh") builds."
