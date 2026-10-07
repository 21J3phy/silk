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
cp "$root/deploy/vercel/vercel.json" "$root/deploy/vercel/install.sh" "$root/deploy/vercel/llms.txt" "$out/"
mkdir -p "$out/benchmarks"
python3 "$root/bench/make_report.py" >/dev/null && cp "$root/bench/report.html" "$out/benchmarks/index.html"

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
