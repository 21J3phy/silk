#!/usr/bin/env bash
# Package a built release as an MCP Bundle (.mcpb) for one-click install in
# Claude Desktop and listing in the MCP Registry:
#   scripts/build_release.sh VERSION && scripts/build_mcpb.sh VERSION
# Output: dist/release/silk-VERSION.mcpb (macOS universal, Linux amd64, Windows amd64).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ver="${1:?usage: build_mcpb.sh VERSION}"
dir="$root/dist/release/$ver"
[ -d "$dir" ] || { echo "build it first: scripts/build_release.sh $ver" >&2; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/server"
lipo -create -output "$work/server/silk" "$dir/silk-darwin-arm64" "$dir/silk-darwin-amd64"
cp "$dir/silk-linux-amd64" "$work/server/silk-linux"
cp "$dir/silk-windows-amd64.exe" "$work/server/silk.exe"
chmod 755 "$work/server/silk" "$work/server/silk-linux"
python3 -I - "$ver" "$work/manifest.json" <<'PY'
import json, sys
ver, out = sys.argv[1], sys.argv[2]
tools = [
    ("silk_whoami", "Show this agent's Silk address, relay, conversations, and pending contact requests."),
    ("silk_inbox", "Fetch and decrypt new messages, contact requests, and delivery receipts; optionally wait for new ones."),
    ("silk_send", "Send an end-to-end encrypted message within an approved conversation."),
    ("silk_ack", "Record a signed acknowledgment for a received message."),
    ("silk_request_contact", "Ask another agent's owner for permission to converse (with a proof-of-work stamp)."),
    ("silk_conversations", "List approved conversations with remaining budgets and expiry."),
    ("silk_message_status", "Check whether a sent message is pending, acknowledged, expired, or revoked."),
    ("silk_revoke", "End a conversation and purge its undelivered messages."),
    ("silk_audit", "Verify the relay's public ledger and this agent's messages on it."),
]
m = {
    "manifest_version": "0.3",
    "name": "silk",
    "display_name": "Silk",
    "version": ver,
    "description": "Message other people's AI agents with their owners' consent: end-to-end encrypted, on a public ledger.",
    "long_description": ("Silk lets your agent message other people's agents after their owners approve. Messages are end-to-end "
        "encrypted (post-quantum hybrid handshake, fresh keys every turn), every event is recorded on a public transparency ledger, "
        "and unsolicited contact costs proof-of-work postage.\n\nOne-time setup: a human runs `silk init --label <name> --passphrase` "
        "in a terminal (install the CLI with `curl -fsSL https://silk-relay.vercel.app/install.sh | sh`). Until then every tool "
        "explains what to do. Agents can never approve contact requests; the owner runs `silk accept`."),
    "author": {"name": "21J3phy", "url": "https://github.com/21J3phy"},
    "repository": {"type": "git", "url": "https://github.com/21J3phy/silk.git"},
    "homepage": "https://silk-landing-sepia.vercel.app",
    "documentation": "https://silk-landing-sepia.vercel.app/agents.html",
    "support": "https://github.com/21J3phy/silk/issues",
    "server": {
        "type": "binary",
        "entry_point": "server/silk",
        "mcp_config": {
            "command": "${__dirname}/server/silk",
            "args": ["mcp"],
            "platform_overrides": {
                "win32": {"command": "${__dirname}/server/silk.exe", "args": ["mcp"]},
                "linux": {"command": "${__dirname}/server/silk-linux", "args": ["mcp"]},
            },
        },
    },
    "tools": [{"name": n, "description": d} for n, d in tools],
    "keywords": ["agents", "messaging", "a2a", "end-to-end-encryption", "post-quantum", "consent", "transparency-log"],
    "license": "Apache-2.0",
    "privacy_policies": ["https://silk-relay.vercel.app/privacy.txt"],
    "compatibility": {"platforms": ["darwin", "win32", "linux"]},
}
json.dump(m, open(out, "w"), indent=2)
PY
out="$root/dist/release/silk-$ver.mcpb"
rm -f "$out"
(cd "$work" && zip -qrX "$out" manifest.json server)
shasum -a 256 "$out"
