"""Benchmark-only launcher for the AMP relay (fg-amp, ``amp-relay``).

Lifts three protective limits *inside this process only* by rebinding module
globals of ``fg_amp.transport.relay`` before the app is built, then runs the
unmodified ``fg_amp.transport.relay.main()`` (same argparse, FastAPI app,
uvicorn defaults incl. access log, in-memory or ``--db`` SQLite state, Ed25519
verification of every send/pull/ack). No installed file is edited. The relay
reads these names from module globals at call time (``_RateLimiter.__init__``
and ``RelayState.enqueue``), so the rebinding is what its checks see.

    _RATE_MAX_REQUESTS  240  -> 1_000_000  per signed source per 60 s, on send/pull/ack/ws-auth
    _MAX_PER_SENDER     512  -> 1_000_000  undelivered envelopes one sender may hold in a mailbox
    _MAX_MAILBOX_SIZE   4096 -> 1_000_000  undelivered envelopes per mailbox

Everything else (1 MiB envelope cap, 30 s lease, 12 delivery attempts, 120 s
pull freshness, single-use pull signatures) is untouched.

Run with the AMP venv interpreter in isolated mode (script dir not on sys.path):

    /tmp/silk-competitors/amp/.venv/bin/python -I relay_launch.py \
        --host 127.0.0.1 --port 8404 --db /tmp/x/relay.sqlite3 --audience amp-bench
"""
import sys

import fg_amp.transport.relay as relay

OVERRIDES = {
    "_RATE_MAX_REQUESTS": 1_000_000,
    "_MAX_PER_SENDER": 1_000_000,
    "_MAX_MAILBOX_SIZE": 1_000_000,
}

for name, value in OVERRIDES.items():
    if not hasattr(relay, name):
        raise SystemExit(f"fg_amp.transport.relay.{name} not found; benchmark override is stale")
    setattr(relay, name, value)

if __name__ == "__main__":
    sys.argv[0] = "amp-relay"
    relay.main()
