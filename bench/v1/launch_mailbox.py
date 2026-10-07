"""Benchmark-only launcher for the v1 MCP mailbox (services/mailbox).

Builds the app exactly like services/mailbox/tests/test_mcp_roundtrip.py:
``create_app(settings, SQLiteFixtureStore(...), JWTAccessTokenVerifier(...),
testing=True)``. The *real* JWT verifier is used; only its JWKS fetcher is the
injected trusted test dependency (returns the local public JWKS bytes), because
the verifier only accepts pinned https:// DNS URLs with TLS verification, which
cannot be served from 127.0.0.1 without altering trust stores. Every request
still gets full RS256 signature + claim verification.

Served by uvicorn the way services/mailbox/README.md documents
(``--no-access-log``; default log level, h11, asyncio loop).

The only non-default configuration is SQLiteFixtureStore capacity arguments
(see mailbox_fixture.CAPACITIES). No module is patched.

Usage: python bench/v1/launch_mailbox.py --port 8790 --db X.sqlite3 --jwks jwks.json
"""
import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "services" / "mailbox"))

import uvicorn  # noqa: E402

from silk_live.app import create_app  # noqa: E402
from silk_live.auth import JWTAccessTokenVerifier  # noqa: E402
from silk_live.config import Settings  # noqa: E402
from silk_live.storage import SQLiteFixtureStore  # noqa: E402

import mailbox_fixture as F  # noqa: E402


def build(db: str, jwks_path: str):
    settings = Settings(F.ISSUER, F.RESOURCE, F.JWKS_URL, (F.CLIENT_ID,))
    store = SQLiteFixtureStore(db, **F.CAPACITIES)
    jwks = Path(jwks_path).read_bytes()

    async def fetcher(url):
        if url != settings.jwks_url:
            raise ValueError("unexpected JWKS URL")
        return jwks

    verifier = JWTAccessTokenVerifier(
        issuer=settings.issuer_url, resource=settings.resource_url, jwks_url=settings.jwks_url,
        allowed_client_ids=set(settings.allowed_client_ids), jwks_fetcher=fetcher,
    )
    return create_app(settings, store, verifier, testing=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--db", required=True)
    parser.add_argument("--jwks", required=True)
    args = parser.parse_args()
    app = build(args.db, args.jwks)
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
