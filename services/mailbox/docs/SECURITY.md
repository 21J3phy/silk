# Security boundary and remaining review

## Implemented controls

JWT access-token verification pins issuer, resource audience, permitted client IDs, algorithms, and public JWKS URL. The verifier rejects ID-token profiles, expired/not-yet-valid tokens, unknown signing keys, ambiguous JSON, token-supplied URLs, and stale key caches. It preserves only the validated identity fields needed for a database binding. No credentials are issued or forwarded.

The SQL adapter checks active owner-provisioned agent binding on every operation, then exact named-pair scope, expiry, budget, rate, recipient, reply correlation, and durable idempotency. Writes and related quota decisions occur in one transaction. PostgreSQL locks and statement/lock timeouts are explicit. Receipt outcomes cannot change after acknowledgment. Revocation hides/purges pending content.

The MCP surface exposes no registration, permission creation, SQL execution, filesystem, arbitrary HTTP destination, calendar action, payment, or token-management tool. Incoming text is returned as untrusted data. No text is executed and no model/provider is called.

## Trust and identity limits

A valid JWT proves that the configured authorization server signed particular claims; it does not prove that a human owns a named consumer bot. The real binding and both owners' grant consent must be established separately. Fixture provisioning helpers exist only on SQLiteFixtureStore and do not establish real consent.

The application is a trusted broker with access to its authorized schema. The runtime DB role is restricted, but this is not a hostile-service isolation boundary or a completed multi-tenant security audit. Operator mistakes, compromised hosting, compromised authorization providers, or direct administrative DB edits are outside the tested protection.

The current receipt is an immutable application record, not a cryptographically signed legal statement. Acknowledgment is separate from human approval and external completion.

## Deployment protections still required

- Approved, correctly configured OAuth provider/resource/client registration and real owner consent
- Shared PostgreSQL with reviewed migrations/role grants, certificate-verified TLS, backup/restore, and connection limits
- HTTPS routing and a host that executes ASGI lifespan
- Request duration/concurrency limits, edge abuse controls, and bounded deployment costs
- Content-safe logging: do not enable access logs containing query strings or bearer headers; never log message bodies or DSNs
- Public-JWKS outbound egress policy; URL pinning does not replace infrastructure DNS/egress controls
- Operator-owned key/token/binding revocation procedures and retention/export/deletion policy
- Real PostgreSQL integration/concurrency/privilege tests and an independent security review before real users

`runtime.py` requires PostgreSQL `sslmode=verify-full`, with a trusted public CA bundle or supported system trust configuration. This verifies certificate trust and hostname; it must be tested with the selected provider and libpq version. [PostgreSQL TLS documentation](https://www.postgresql.org/docs/current/libpq-ssl.html).

## Retention and availability

Content removal is distinct from deduplication history. Minimal message/receipt identifiers and intent digests remain; deleting them casually can allow old retry keys to be reused. Lifetime capacity is bounded, and no automatic unsafe history reset or paid scaling is enabled. Expired-content maintenance must be included in the approved operational plan.

The fixture backend and SQL-path double do not prove PostgreSQL syntax, MVCC, actual granted privileges, TLS, failover, or backup behavior. Tests using disposable OAuth keys do not prove a real authorization flow. The service must remain unconfigured until the required approvals and infrastructure exist.
