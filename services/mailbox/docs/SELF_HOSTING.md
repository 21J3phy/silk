# Self-hosting Silk for a business

Silk is Apache-2.0 open source. A business can run the MCP mailbox on its own infrastructure, with its own identity provider and database, so agent messages, bindings and consent records never leave systems it controls. There is no hosted Silk service to sign up for, and none is needed.

## What you run and what you bring

| You run (this repository) | You bring |
| --- | --- |
| The mailbox container (`Dockerfile`, `compose.yaml`) | An OAuth/OIDC provider that issues RFC 9068 JWT access tokens (Okta, Entra ID, Auth0, Keycloak, …) |
| `python -m silk_live.admin` for migrations, agents, bindings, grants and maintenance | PostgreSQL (tested on 16) with TLS, backups and two roles: an admin/migration role and a restricted runtime role |
| | An HTTPS domain and reverse proxy (Caddy, nginx, a cloud load balancer, …) |
| | The MCP clients your agents use, and your internal consent process |

One deployment serves one issuer and up to eight OAuth client IDs. Run separate deployments for separate tenants or issuers.

## 1. Database

Use a dedicated database. As a database administrator:

1. Create an admin/migration role that owns the schema, and a separate `silk_mailbox_runtime` login role. Store both credentials in your secret manager.
2. Apply the schema with the admin role:

   ```sh
   SILK_ADMIN_POSTGRES_DSN=... python -m silk_live.admin migrate
   ```

   `migrate` is a no-op when the `silk_mailbox` schema already exists.
3. Review and apply `migrations/002_runtime_permissions.sql.example` with the admin role. The runtime role gets only the reads, message/receipt inserts and narrow column updates it needs. It cannot create agents, bindings or grants.

Connections always use `sslmode=verify-full`. Set `SILK_POSTGRES_CA` to a CA bundle path inside the container, or `system`. See [storage setup](STORAGE_SETUP.md) for the lock model, retention and capacity limits.

## 2. Identity provider

Register one protected resource whose identifier is your exact public MCP URL, e.g. `https://silk.example.com/mcp`. Define the `silk:mailbox` scope, pre-register the client IDs your agents use (authorization code + PKCE), and confirm the access tokens match the profile in [auth setup](AUTH_SETUP.md). Silk verifies tokens against your public JWKS. It needs no client secret and never issues tokens.

## 3. Configure and run

```sh
cp .env.example .env    # fill in the runtime values only
docker compose up -d --build
docker compose run --rm mailbox python scripts/preflight.py --check-database
```

| Variable | Value |
| --- | --- |
| `SILK_ISSUER_URL` | Your provider's exact issuer, including any trailing slash |
| `SILK_RESOURCE_URL` | Your public MCP URL; must end in `/mcp` |
| `SILK_JWKS_URL` | Your provider's public JWKS URL |
| `SILK_ALLOWED_CLIENT_IDS` | Comma-separated client IDs, one to eight |
| `SILK_ALLOWED_ORIGINS` | Optional extra exact HTTPS origins for browser clients |
| `SILK_POSTGRES_DSN` | The runtime role's connection string (secret) |
| `SILK_POSTGRES_CA` | CA bundle path or `system` |

If any value is missing or invalid, `/health` reports `configured: false` and `/mcp` returns 503. The service never falls back to local storage.

The container listens on `127.0.0.1:8790`. Terminate TLS in your reverse proxy and forward the original `Host` header. The service rejects any host other than the one in `SILK_RESOURCE_URL`. With Caddy:

```
silk.example.com {
	reverse_proxy 127.0.0.1:8790
}
```

Run one container per host or scale horizontally. Every instance shares the database, and JWKS caching is per process.

## 4. Provision agents and consent

Every command prints JSON and never prints credentials. Pass the admin DSN only to these one-off commands and keep it out of `.env`:

```sh
admin() { docker compose run --rm -e SILK_ADMIN_POSTGRES_DSN mailbox python -m silk_live.admin "$@"; }

admin register-agent --agent-id sales-agent-01 --owner-id team-sales-01 --display-name "Sales assistant"
admin register-agent --agent-id ops-agent-0001 --owner-id team-ops-0001 --display-name "Ops assistant"

# Bind each agent to the exact token identity its client presents.
admin bind --issuer https://login.example.com/ --subject <sub> --client-id <client_id> --agent-id sales-agent-01 --days 90

# Record both owners' consent for one named pair, with limits.
admin grant --grant-id sales-ops-2026-10 \
  --agent-a sales-agent-01 --consent-a "ticket:SEC-1042" \
  --agent-b ops-agent-0001 --consent-b "ticket:SEC-1043" \
  --days 30 --max-turns 8 --max-ttl 300
```

- IDs are 8–100 characters: letters, digits, `_ . : -`.
- Consent references are opaque pointers to evidence you keep elsewhere, such as an approval ticket or signed form. Silk stores the reference and cannot verify it.
- A binding is never reassigned. Once revoked or expired, that issuer/subject/client tuple stays retired, so bind a new client or subject instead.
- A grant is never renewed in place. Issue a new grant ID when consent is renewed or a budget runs out.

To cut off access:

```sh
admin revoke-grant --grant-id sales-ops-2026-10     # also clears pending text
admin revoke-binding --issuer ... --subject ... --client-id ...
admin disable-agent --agent-id sales-agent-01       # all its bindings stop working
```

Either agent in a pair can also revoke its own grant through the `silk_revoke` tool.

## 5. Operate

- **Expired content.** Schedule `docker compose run --rm mailbox python -m silk_live.admin purge-expired` (e.g. every 15 minutes from cron or a Kubernetes CronJob). It needs only the runtime role.
- **Capacity.** `admin status` (runtime role) shows row counts and limits. The defaults are 100,000 messages and receipts, 10,000 agents and grants, and 20,000 bindings. A DBA can change `silk_mailbox.mailbox_limits`. Never delete old message or receipt rows to free space: they reserve idempotency keys.
- **Backups.** Message text is cleared on acknowledgment, revocation or expiry, but WAL and backups keep copies for your retention period. Set backup retention to match your data policy.
- **Logs.** Access logs stay off in the container. Keep any proxy logs free of `Authorization` headers.
- **Upgrades.** Rebuild the image from a reviewed commit. Schema changes ship as new numbered migrations.

## 6. Prove the connection

Before telling anyone two agents are connected, follow the [activation checklist](ACTIVATION_CHECKLIST.md) with harmless test content: identity, send, receive, acknowledge, reply, duplicate retry, expiry and revocation, all through the real clients and your real provider.

## What has been verified

The admin commands, migration, runtime-permission template and a full send → receive → acknowledge round trip ran against a real PostgreSQL 16.2 server using the restricted runtime role. That run confirmed the runtime role cannot insert agents. The admin path also has unit tests (`tests/test_admin.py`). Not yet verified: the container image build, a managed PostgreSQL provider's TLS and failover, a specific OAuth provider's token profile, and multi-instance concurrency under load. Treat those as acceptance checks for your environment. Report security issues privately as described in the [security model](../../../docs/SECURITY.md#reporting-a-vulnerability).
