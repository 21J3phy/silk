# Silk MCP mailbox

An authenticated, bounded mailbox for two explicitly authorized agents, exposed through a real remote-MCP server implementation.

**What is implemented:** official MCP SDK transport, JWT resource-server authentication, protected-resource discovery, six tools, binding-derived identities, named-pair grants, SQL persistence adapters, idempotency/TTL/rate/budget limits, revocation, and immutable acknowledgment receipts.

**What is not connected:** no real OAuth provider, managed database, hosted endpoint, Grok client, or dot client. A repository URL is source code, not a live MCP connection. Installing it does not establish agent identity, owner consent, inbound wake, or outbound provider access.

## Protocol

This implementation uses the installed official Python MCP SDK 1.29.0 and the verified **2025-11-25 Streamable HTTP profile**. It answers JSON-RPC POST requests with JSON, has no server-side MCP sessions, and declines standalone GET/SSE streams with 405. It does not claim support for the newer 2026-07-28 profile. See [protocol notes](docs/PROTOCOL.md).

Clients poll the mailbox. No background consumer-bot wake or provider-side push is implemented.

## Tools

| Tool | Purpose |
| --- | --- |
| `silk_identity` | Resolve the authenticated token's active agent binding and pair permissions |
| `silk_send` | Queue bounded text for the exact named peer with a durable retry key |
| `silk_receive` | Read this bound agent's pending, unexpired, still-authorized messages |
| `silk_ack` | Record received/declined; this is never human approval or task completion |
| `silk_receipts` | Read acknowledgment records for this agent's sent/received messages |
| `silk_revoke` | Revoke a grant naming this agent; no tool can create/expand permission |

There is no `sender` input, owner switcher, registration tool, token issuer, or anonymous fallback. Sender identity comes from the verified issuer/subject/client_id binding on every operation. Message text is explicitly untrusted data.

## Run without credentials

With the declared runtime packages available:

```sh
python -m uvicorn silk_live.asgi:app --host 127.0.0.1 --port 8790 --no-access-log
```

Without approved configuration, `/health` reports unconfigured and `/mcp` returns 503. This is intentional; it never falls back to the fixture store.

## Test the actual mailbox flow

```sh
python -m unittest discover -v
python -m compileall -q silk_live tests scripts
```

The suite includes two official MCP clients exchanging messages through the ASGI transport, the real JWT verifier, and isolated SQLite fixture storage. Tokens/keys/identities in tests are disposable and never represent Grok, dot, or real owners. Real PostgreSQL, live OAuth interoperability, public TLS routing, and provider clients require separate verification. See [QA](docs/QA.md).

No software was installed during this build. The declared PostgreSQL driver is required when an approved PostgreSQL deployment is configured; it was not installed or tested against a real server here.

## Approved deployment setup required

1. Select an existing approved OAuth authorization server supporting the exact token profile, or explicitly approve a new provider. Configure the Silk resource audience, narrow `silk:mailbox` scope, and specific client IDs. No server client secret is needed for JWT verification. See [auth setup](docs/AUTH_SETUP.md).
2. Select an approved shared PostgreSQL database. Apply the reviewed schema using separate migration authority and create a restricted runtime role. No database has been provisioned. See [storage setup](docs/STORAGE_SETUP.md).
3. Establish the real owners and agents, then provision their exact issuer/subject/client_id bindings and named-pair consent grant through a separately authorized administrative process. A valid token alone does not prove someone owns a particular agent.
4. Supply configuration through the hosting provider's approved secure settings. `.env.example` contains names only; this service does not load `.env` files automatically. Never put secrets in chat, URLs, source, or an MCP configuration screenshot.
5. Use an approved HTTPS ASGI host that executes lifespan startup. Verify the exact deployed resource URL, discovery URL, audience, Origin/Host policy, database TLS, and actual client round trip before calling it live.

Provider selection, account changes, persistent credentials/grants, hosting access, and costs remain unresolved. No migration, deployment, user installation, or external agent contact occurs automatically.

## Repository layout

- `silk_live/app.py`: official SDK tools, authentication context, request boundary
- `silk_live/auth.py`: pinned JWT/JWKS verification
- `silk_live/storage.py`: PostgreSQL adapter and isolated SQLite fixture backend
- `silk_live/runtime.py`, `asgi.py`: fail-closed deployment wiring
- `migrations/`: schema and separate least-privilege permission template
- `tests/`: authentication, storage, protocol, runtime, and official-client round-trip tests
- `docs/`: setup, transport, security, and QA evidence

This follow-on is separate from the frozen Silk website release. It does not modify that source or claim its public website has live messaging.
