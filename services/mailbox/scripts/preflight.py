#!/usr/bin/env python3
"""Configuration-only checks by default; optional approved read-only DB check.

Never creates roles, applies migrations, provisions identities, or issues tokens.
Never prints environment values, DSNs, tokens, or raw connection errors.
"""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from silk_live.config import Settings


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-database',action='store_true',help='After approval/configuration, connect using the runtime role and perform read-only schema/capacity checks')
    args=parser.parse_args()
    needed=('SILK_ISSUER_URL','SILK_RESOURCE_URL','SILK_JWKS_URL','SILK_ALLOWED_CLIENT_IDS','SILK_POSTGRES_DSN')
    missing=[name for name in needed if not os.environ.get(name)]
    if missing:
        print('Not configured. Missing variable names: '+', '.join(missing));return 2
    try:
        Settings(os.environ['SILK_ISSUER_URL'],os.environ['SILK_RESOURCE_URL'],os.environ['SILK_JWKS_URL'],tuple(x.strip() for x in os.environ['SILK_ALLOWED_CLIENT_IDS'].split(',') if x.strip()),tuple(x.strip() for x in os.environ.get('SILK_ALLOWED_ORIGINS','').split(',') if x.strip()))
    except Exception:
        print('Configuration format invalid. No values or connection details are printed.');return 2
    print('Required configuration is present and URL/client policy formats passed. No identity/provider verification implied.')
    if not args.check_database:
        print('Database, OAuth flow, hosted transport, and agent clients were not contacted.');return 0
    try:
        import psycopg
        from silk_live.storage import PostgresStore
        def connect():
            return psycopg.connect(os.environ['SILK_POSTGRES_DSN'],sslmode='verify-full',sslrootcert=os.environ.get('SILK_POSTGRES_CA','system'),connect_timeout=5,autocommit=False)
        result=PostgresStore(connect).check_readiness()
        assert result['ready'] is True
        print('Read-only PostgreSQL schema/capacity check passed. Permissions, concurrency, OAuth, and live round trip still require verification.');return 0
    except Exception:
        print('PostgreSQL check did not pass. Review the approved driver, TLS configuration, runtime role, schema, and connection separately. No underlying error is printed.');return 1


if __name__=='__main__':raise SystemExit(main())
