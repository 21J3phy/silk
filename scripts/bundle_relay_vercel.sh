#!/usr/bin/env bash
# Assemble the minimal source bundle for the hosted relay (Vercel Go Function).
# Only the relay's Go packages are included: no website, Python, tests, or data.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist/relay-vercel"
version="${1:-$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)}"
rm -rf "$out"
mkdir -p "$out/api"
cp "$root/go.mod" "$root/go.sum" "$out/"
cp "$root/deploy/vercel/vercel.json" "$root/deploy/vercel/llms.txt" "$out/"
# install.sh carries the URL and SHA-256 of each build of the newest published
# release (releases/<version>.json, written by `silk release-publish`).
python3 - "$root" "$out/install.sh" <<'PY'
import json, pathlib, re, sys
root, dest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def key(p): return [int(x) for x in re.findall(r"\d+", p.stem)]
manifests = sorted((root / "releases").glob("*.json"), key=key)
if not manifests:
    sys.exit("no published release in releases/; publish one before bundling")
m = json.loads(manifests[-1].read_text())
cases = "\n".join(f'    {plat}) url="{f["url"]}"; sum="{f["sha256"]}" ;;' for plat, f in sorted(m["files"].items()) if not plat.startswith(("windows", "relay-")))
tmpl = (root / "deploy/vercel/install.sh").read_text()
dest.write_text(tmpl.replace("__VERSION__", m["version"]).replace("__CASES__", cases))
dest.chmod(0o755)
PY
mkdir -p "$out/benchmarks"
python3 "$root/bench/make_report.py" >/dev/null && cp "$root/bench/report.html" "$out/benchmarks/index.html"
# Privacy notice and security contact (RFC 9116) for the hosted relay.
cp "$root/docs/v2/PRIVACY.md" "$out/privacy.txt"
mkdir -p "$out/.well-known"
expires=$(date -u -v+180d +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -d '+180 days' +%Y-%m-%dT00:00:00Z)
printf 'Contact: https://github.com/21J3phy/silk/security/advisories/new\nExpires: %s\nPreferred-Languages: en\nPolicy: https://github.com/21J3phy/silk/blob/main/docs/v2/SECURITY.md\nCanonical: https://silk-relay.vercel.app/.well-known/security.txt\n' "$expires" > "$out/.well-known/security.txt"
# Agent skill for agents that use the command line instead of MCP.
cp "$root/skills/silk/SKILL.md" "$out/skill.md"
mkdir -p "$out/skills/silk" && cp "$root/skills/silk/SKILL.md" "$out/skills/silk/SKILL.md"
mkdir -p "$out/compare"
python3 "$root/bench/make_compare.py" >/dev/null && cp "$root/bench/compare.html" "$out/compare/index.html"

# Never upload local env files, agent tooling, or lockfiles written into the bundle by CLIs.
printf '.env*\n*.test\n.agents/\n.claude/\nskills-lock.json\n' > "$out/.vercelignore"
sed "s/const Version = \"dev\"/const Version = \"$version\"/" "$root/deploy/vercel/api/index.go" > "$out/api/index.go"
for pkg in wire seal pow ledger kv kv/pgkv relay; do
  mkdir -p "$out/pkg/$pkg"
  find "$root/pkg/$pkg" -maxdepth 1 -name '*.go' ! -name '*_test.go' -exec cp {} "$out/pkg/$pkg/" \;
done
# Keep the Vercel project link outside the disposable bundle.
if [ -d "$root/deploy/vercel/.vercel" ]; then cp -R "$root/deploy/vercel/.vercel" "$out/"; fi
# The bundle must build on its own.
(cd "$out" && GOFLAGS=-mod=mod go build ./api/ >/dev/null)
echo "$out"
