# Attach a standalone relay to an existing PostgreSQL ledger

The standalone Go v2 HTTP relay can run on any approved host while retaining the existing
PostgreSQL `silk_kv` schema, data, ledger and signing identity. It does not create a
database, generate credentials, provision an agent, or deploy anything merely by
being checked into GitHub. Hosting requires separate approval.

## Required secure configuration

| Variable | Value / handling |
|---|---|
| `SILK_POSTGRES_DSN` | Existing PostgreSQL direct/unpooled connection, appropriate TLS verification; secret input only. Never put the value in a command argument or repo. |
| `SILK_LEDGER_KEY` | Existing private ledger signer; secure secret input only. Never generate a replacement for migration. |
| `SILK_EXPECTED_LEDGER_KEY` | Existing **public** verifier key copied from a previously trusted checkpoint/client pin. Full string must match; its historical origin name need not match the new hostname. |
| `SILK_RELEASE_KEYS` | Existing comma-separated **public** release signing keys. |
| `PORT` | Host-provided HTTP listen port. |

`--store postgres` requires an explicit existing signing key and expected public
verifier. It opens the existing `silk_kv` table without DDL and rejects an empty
ledger. It never creates a database, table or signing key in this mode. This
prevents common accidental blank-database/new-identity starts; it does not prove
that the chosen database is the latest correct copy. Verify checkpoint
consistency separately as below.

## Cutover gates (owner approval required)

1. Confirm the approved host, cost/limits and allowed network access. No disk is needed
   for this relay because PostgreSQL holds its durable state. Agent MCP services
   need **separate** protected durable storage and approval.
2. Securely configure the existing secrets; do not export them through chat,
   logs, GitHub, screenshots or this repo. First verify the database identity and
   trusted ledger public key without exposing private values.
3. Take an application-consistent native PostgreSQL backup. Record a trusted
   signed checkpoint and ledger size/root before changing traffic.
4. For a copied database, **stop/quiesce the old relay's writes first**, take the
   final consistent copy, and keep the old endpoint read-only/offline. Never run
   two independently copied writable databases with the same ledger key.
5. If both endpoints temporarily share the exact same live database, pgkv's
   existing global advisory lock serializes their writes. That is not permission
   to run two deployments: explicitly approve overlap and retirement. Prefer a
   controlled cutover and verify both use the exact same signer/configuration.
6. Start the new endpoint, check `/healthz`, verify its public key exactly, and
   prove its signed checkpoint extends the trusted pre-cutover checkpoint.
   Verify known agent certificates/handles still match. Do not silently repin a
   different key or initialize fresh identities to hide migration failures.
7. Change clients to the approved endpoint, preserving keys and stored
   checkpoints. Verify harmless request/send/receive/ack/revoke end-to-end only
   after owner approval. Retire the old writer after successful cutover.

Example startup, after securely configuring the variables above:

```sh
silk relay --store postgres --addr "0.0.0.0:$PORT" \
  --dsn-env SILK_POSTGRES_DSN --key-env SILK_LEDGER_KEY \
  --expected-ledger-key "$SILK_EXPECTED_LEDGER_KEY" \
  --release-keys "$SILK_RELEASE_KEYS"
```

Do not enable shell tracing. Leave `--trust-proxy` off until the host's trusted
client-IP behavior is verified. Per-IP protection may group requests behind an
edge proxy; do not enable arbitrary forwarded-header trust as a shortcut. Use
HTTPS at the host's ingress and require approved explicit deployment changes.

## Local checks

Run `go test ./cmd/silk ./pkg/kv/pgkv`, `go test ./...`, and `go vet ./...`.
A real PostgreSQL migration/integration test needs an isolated approved test DB;
unit tests cover absent/mismatched keys, missing configuration, redacted errors
and the no-DDL bootstrap statement. Never aim test helpers that drop tables at
the production database.
