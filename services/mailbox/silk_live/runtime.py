"""Deployment wiring, activated only by explicitly supplied approved configuration.

This module creates no accounts, credentials, roles, tables, bindings, or grants.
It never loads a .env file, connects to a fixture DB, or issues OAuth tokens.
"""
from __future__ import annotations

import os
from .app import create_app
from .config import Settings

PUBLIC_REQUIRED = ("SILK_ISSUER_URL", "SILK_RESOURCE_URL", "SILK_JWKS_URL", "SILK_ALLOWED_CLIENT_IDS")


def build_from_environment(environ=None):
    env = os.environ if environ is None else environ
    if not all(env.get(key) for key in (*PUBLIC_REQUIRED, "SILK_POSTGRES_DSN")):
        return create_app()
    try:
        settings = Settings(
            issuer_url=env["SILK_ISSUER_URL"], resource_url=env["SILK_RESOURCE_URL"], jwks_url=env["SILK_JWKS_URL"],
            allowed_client_ids=tuple(item.strip() for item in env["SILK_ALLOWED_CLIENT_IDS"].split(",") if item.strip()),
            allowed_origins=tuple(item.strip() for item in env.get("SILK_ALLOWED_ORIGINS", "").split(",") if item.strip()),
        )
        from .auth import JWTAccessTokenVerifier
        from .storage import PostgresStore
        verifier = JWTAccessTokenVerifier(issuer=settings.issuer_url, resource=settings.resource_url, jwks_url=settings.jwks_url, allowed_client_ids=set(settings.allowed_client_ids))
        dsn = env["SILK_POSTGRES_DSN"]
        # Public CA trust material, not a private key. "system" requires a
        # compatible libpq and is checked by the operator in preflight.
        root_cert = env.get("SILK_POSTGRES_CA", "system")
        def connect():
            import psycopg
            return psycopg.connect(dsn, sslmode="verify-full", sslrootcert=root_cert, connect_timeout=5, autocommit=False)
        return create_app(settings, PostgresStore(connect), verifier)
    except Exception:
        # Never echo DSNs, JWTs, provider values, or the underlying exception.
        return create_app()
