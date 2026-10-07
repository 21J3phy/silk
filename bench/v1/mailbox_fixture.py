"""Constants shared by the mailbox launcher and the mailbox benchmark driver.

Same shape as services/mailbox/tests/test_mcp_roundtrip.py: example.* HTTPS
identifiers (never contacted), one allowed OAuth client ID, disposable RS256
key. The server is plain HTTP on 127.0.0.1; clients send ``Host: silk.example``
so the app's Host/Origin boundary and the SDK's DNS-rebinding check pass.
"""
ISSUER = "https://auth.example/"
RESOURCE = "https://silk.example/mcp"
JWKS_URL = "https://auth.example/jwks"
CLIENT_ID = "client-bench"
HOST = "silk.example"
KID = "bench-key"
PROTOCOL_VERSION = "2025-11-25"

# SQLiteFixtureStore constructor capacities (defaults: 1024/1024/128/256/1024).
CAPACITIES = {
    "max_messages": 1_000_000,
    "max_receipts": 1_000_000,
    "max_agents": 100_000,
    "max_bindings": 100_000,
    "max_grants": 100_000,
}
