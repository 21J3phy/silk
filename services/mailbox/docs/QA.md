# Verification report

Verified in the authorized cloud workspace on 2026-10-06. No user computer, real provider account, real OAuth token, managed database, deployment, or external agent was used.

## Actual results

**133 tests passed**, plus Python compilation.

- 38 authentication tests: disposable RSA/P-256 signatures, issuer/audience/client binding, token type, dates, malformed/duplicate JSON, canonical encoding, header URL injection, unknown keys, JWKS limits/cache/outage/rotation/cooldown, concurrent refresh, safe HTTPS request configuration, minimal returned claims
- 54 storage tests: 23 SQLite fixture cases and 31 PostgreSQL SQL-path DB-API-double cases; binding/recipient isolation, strict text/TTL/IDs, grant bounds, pair-wide rate across renewals, concurrency/idempotency/capacity races, revocation, expiry, content removal, immutable receipts, current duplicate status, separate message/ACK digests, rollback and ambiguous-commit recovery
- 23 SDK transport tests: initialization/version, six tool schemas/annotations, protected-resource discovery, 401/403 scope handling, exact Host/Origin, content-type/Accept rules, size/JSON bounds, sender-spoof rejection, notifications, no standalone stream/session, errors, strict limits, safe failure messages, unconfigured 503, and fixture-deployment prohibition
- 6 configuration/runtime tests: incomplete or invalid settings fail closed, canonical resource/issuer URLs, explicit client/origin lists, no sensitive-value echo
- 4 official-client round-trip tests: two official MCP SDK clients, actual JWT verifier, ASGI transport, and disposable SQLite storage; identity → send → receive → acknowledgment → shared receipt → correlated reply, idempotent retry, pair revocation, and binding revocation with an otherwise valid JWT
- 8 independent boundary-regression tests: malformed tool names, huge/non-ASCII Content-Length, nullable-ID coercion, malformed notification privacy, lone-surrogate request IDs, and total request-body timeout

Commands:

```sh
python -m unittest discover -v
python -m compileall -q silk_live tests scripts
```

The installed SDK emits dependency deprecation/forward-reference warnings in this environment. These did not fail the tests. They are not evidence of compatibility with a newer SDK or protocol revision.

## Meaning of the round trip

The tests exercise actual official MCP client/server code and the real verifier/storage logic, rather than a website animation or a hardcoded 503 handler. The two clients and their RSA issuer are disposable fixtures. This is **not** a Grok → dot connection, an actual OAuth authorization flow, or a real PostgreSQL deployment.

## Concrete fixes from independent review

- A malformed list/dict tool name could raise a membership TypeError; it now receives a bounded protocol error.
- An excessively long Content-Length could raise during integer conversion; it is now bounded ASCII decimal before conversion.
- The SDK could coerce the string `"null"` in a nullable reply ID into JSON null; raw input is now checked before SDK coercion.
- The SDK logged private malformed notification data inside Pydantic warning messages. The boundary now prevalidates the SDK's own public message models and emits fixed errors before those logging paths. A log-capture regression verifies no submitted sentinel is retained.
- Lone Unicode surrogates in decoded strings are rejected before response encoding or SDK logging.
- Total request-body reading is time-bounded in addition to byte-bounded.

These fixes do not constitute a completed production penetration test or formal protocol certification.

## PostgreSQL verification limit

The workspace has no installed `postgres`, `initdb`, `pg_ctl`, or `psql`; no Docker/Podman route; and no psycopg/psycopg2, embedded PostgreSQL, or PostgreSQL parser. No approved external test database was supplied. Real PostgreSQL compatibility therefore could not be tested without new software/services or additional setup.

The DB-API double checks the adapter's SQL path, parameter binding, transaction/locking statements, and application semantics over a SQLite-backed fixture. It does **not** prove PostgreSQL syntax, MVCC/row-lock behavior, actual role privileges, TLS, pooling, failure recovery, or provider quotas. The real-database release checklist remains mandatory.

## Still unverified

- Selected OAuth provider's RFC 9068 token/profile support, authorization/PKCE/refresh/revocation flow, and actual client registration
- Real owner/agent identity and both owners' recorded consent
- Real PostgreSQL migrations, privileges, TLS, concurrency, backup/restore, operational cleanup, and cost
- Hosted HTTPS endpoint, ASGI lifecycle support, proxy routing/headers, deployment access controls, and scale/abuse behavior
- Grok, dot, Cursor, or any other consumer-agent client's ability to authenticate and perform the tool round trip
- Autonomous agent wake, background polling, or provider push

No actual deployment, installation, credential issuance, database migration, or external communication was performed. The frozen Silk website source and previous artifacts remain unchanged.
