"""Benchmark-only launcher for the v1 local broker (``python -m silk``).

It lifts three protective limits *inside this process only* by rebinding
module globals of ``silk.service`` before the server object is built, then runs
the unmodified ``silk.server.main()`` (same argument parsing, ThreadingHTTPServer,
500 ms dispatcher, SQLite settings, Ed25519 verification). No source file is
edited. ``service.py`` imported these names with ``from .protocol import ...``,
so the copies bound in ``silk.service`` are the ones its checks read.

    RATE_PER_MINUTE  6    -> 1_000_000  (_receive: per sender->recipient rolling minute)
    MAX_TURNS        8    -> 1_000_000  (create_invitation: max accepted max_turns)
    MAX_MESSAGES     1000 -> 1_000_000  (_receive: local message storage cap)

Usage: python bench/v1/launch_broker.py --port 8765 --db /tmp/x.sqlite3
"""
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import silk.service  # noqa: E402

OVERRIDES = {"RATE_PER_MINUTE": 1_000_000, "MAX_TURNS": 1_000_000, "MAX_MESSAGES": 1_000_000}

for name, value in OVERRIDES.items():
    if not hasattr(silk.service, name):
        raise SystemExit(f"silk.service.{name} not found; benchmark override is stale")
    setattr(silk.service, name, value)

from silk.server import main  # noqa: E402

if __name__ == "__main__":
    sys.argv[0] = "silk"
    main()
