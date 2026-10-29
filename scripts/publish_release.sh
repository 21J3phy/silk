#!/usr/bin/env bash
# Publish a built release (scripts/build_release.sh VERSION first):
#   1. create a DRAFT GitHub release with binaries, desktop bundle and checksums
#   2. sign a manifest pointing at those release assets and record it on the relay's ledger
#   3. upload a verified public release bundle and pinned installer to GitHub
# Binaries are served from GitHub Releases (the relay's Blob store was suspended
# in October 2026). Clients check every download against the signed SHA-256s, so
# the host is not trusted. Publishing the GitHub release triggers
# .github/workflows/publish-mcp.yml, which lists the bundle in the MCP Registry.
# Needs: the release signing key, gh, and access to the selected live relay.
# No Vercel CLI/login/deployment is required. This does not deploy a relay.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${1:?usage: publish_release.sh VERSION [NOTES]}"
notes="${2:-}"
key="${SILK_RELEASE_KEY_FILE:-$HOME/.silk-relay-secrets/release-key}"
dir="$root/dist/release/$ver"
relay="${SILK_RELEASE_RELAY:-https://silk-relay.vercel.app}"
[ -d "$dir" ] || { echo "build it first: scripts/build_release.sh $ver" >&2; exit 1; }
umask 077
"$root/scripts/build_mcpb.sh" "$ver" >/dev/null
sums="$root/dist/release/SHA256SUMS-$ver"
(cd "$dir" && shasum -a 256 silk-* && cd "$root/dist/release" && shasum -a 256 "silk-$ver.mcpb") > "$sums"
gh release create "v$ver" --draft -R 21J3phy/silk --target "$(git -C "$root" rev-parse HEAD)" --title "Silk $ver" --notes "$notes

**Install** (macOS, Linux): \`curl -fsSL https://github.com/21J3phy/silk/releases/download/v$ver/install.sh | sh\`, then \`silk init --label <name> --passphrase\` and \`silk setup\` (adds Silk to Claude Code, Codex, Cursor, Gemini CLI, Grok Build, Muse Code, VS Code and more). Agents on their own cloud computers (Grok Bot, OpenAI Dots, Meta Muse): \`silk owner\`, then point them at https://raw.githubusercontent.com/21J3phy/silk/main/skills/silk/SKILL.md. Cloud chats (grok.com, ChatGPT, claude.ai): \`silk mcp --http --tunnel\`. Guide: https://github.com/21J3phy/silk/blob/main/docs/v2/CONNECT.md
**Update:** \`silk update\` installs a release only if it is signed with the pinned release key and recorded on the public ledger.
**Claude Desktop:** download \`silk-$ver.mcpb\` and open it.
**Verify by hand:** SHA-256 sums are in \`SHA256SUMS\`; the signed release and ledger evidence are in \`release-bundle.json\`. The installer verifies them offline." \
  "$dir"/silk-* "$root/dist/release/silk-$ver.mcpb" "$sums#SHA256SUMS" >/dev/null
map="$dir.urls.json"
printf '{' > "$map"; sep=""
for f in "$dir"/silk-*; do
  n=$(basename "$f")
  printf '%s\n "%s": "https://github.com/21J3phy/silk/releases/download/v%s/%s"' "$sep" "$n" "$ver" "$n" >> "$map"; sep=","
done
printf '\n}\n' >> "$map"
go run -C "$root" ./cmd/silk release-publish --relay "$relay" --version "$ver" --key "$key" --dir "$dir" --url-map "$map" --notes "$notes" --record "$root/releases"
go run -C "$root" ./cmd/silk release-bundle --relay "$relay" --version "$ver" --out "$dir/release-bundle.json"
python3 "$root/scripts/build_github_distribution.py" "$ver" "$dir/install.sh"
gh release upload "v$ver" -R 21J3phy/silk "$dir/release-bundle.json" "$dir/install.sh"
gh release edit "v$ver" -R 21J3phy/silk --draft=false
echo "Published $ver; GitHub release assets include install.sh and verified release-bundle.json. No relay deployment performed."
