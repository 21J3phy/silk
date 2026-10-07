#!/usr/bin/env bash
# Recreate the v1 baseline benchmark from scratch and write
#   bench/results/v1-broker.json and bench/results/v1-mailbox.json
#
# Usage (from anywhere):  bench/v1/run_all.sh
# Env knobs (defaults):   BENCH_BROKER_PORT=8765 BENCH_MAILBOX_PORT=8790
#                         BENCH_REQUESTS=2000 BENCH_WARMUP=100 BENCH_RT_SAMPLES=300
#                         BENCH_LEVELS=1,4,16,64 BENCH_KEEP=1 (keep temp DBs/logs)
# Requires: uv, macOS or Linux, the two ports free. Nothing is committed or deployed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VENV="$HERE/.venv"
PY="$VENV/bin/python"
export BENCH_BROKER_PORT="${BENCH_BROKER_PORT:-8765}"
export BENCH_MAILBOX_PORT="${BENCH_MAILBOX_PORT:-8790}"
cd "$REPO"

listening() { lsof -nP -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true; }

cleanup() {
  # Only processes this benchmark started: every server it spawns gets a --db
  # inside a silk-bench-* temp directory.
  pkill -f -- "--db .*silk-bench-" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for port in "$BENCH_BROKER_PORT" "$BENCH_MAILBOX_PORT"; do
  if [ -n "$(listening "$port")" ]; then
    echo "port $port is in use; stop that process or set BENCH_*_PORT" >&2
    exit 1
  fi
done

started=$(date +%s)

echo "== venv: $VENV (Python 3.12)"
uv venv --no-project --clear -q --python 3.12 "$VENV"
if ! uv pip install -q --python "$PY" -r requirements-dev.txt -r services/mailbox/requirements.txt psutil==7.2.2; then
  echo "full install failed; retrying without the optional psycopg line" >&2
  tmpreq="$(mktemp)"
  grep -v '^psycopg' services/mailbox/requirements.txt > "$tmpreq"
  uv pip install -q --python "$PY" -r requirements-dev.txt -r "$tmpreq" psutil==7.2.2
  rm -f "$tmpreq"
fi
"$PY" -c "import platform, sqlite3; print('python', platform.python_version(), '| sqlite', sqlite3.sqlite_version)"

echo "== install footprint (fresh per-server venvs, deleted afterwards)"
"$PY" "$HERE/footprint.py"

echo "== v1 broker"
"$PY" "$HERE/bench_broker.py"

echo "== v1 mailbox"
"$PY" "$HERE/bench_mailbox.py"

cleanup
sleep 0.5
leftover=0
for port in "$BENCH_BROKER_PORT" "$BENCH_MAILBOX_PORT"; do
  if [ -n "$(listening "$port")" ]; then
    echo "WARNING: something is still listening on port $port" >&2
    leftover=1
  fi
done
if pgrep -f -- "--db .*silk-bench-" >/dev/null 2>&1; then
  echo "WARNING: benchmark server processes still running" >&2
  leftover=1
fi
[ "$leftover" = 0 ] && echo "no benchmark servers left running"

echo "== done in $(( $(date +%s) - started ))s"
echo "results: bench/results/v1-broker.json bench/results/v1-mailbox.json"
exit "$leftover"
