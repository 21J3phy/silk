# Durable mailbox storage groundwork

## Implemented and verified

`silk_live.storage.PostgresStore(connection_factory)` is a concrete synchronous
PostgreSQL DB-API adapter. It implements identity, send, receive, ack, receipts
and revoke with the same transaction/validation code exercised by the isolated
fixture suite. It does not issue tokens, create accounts, install a driver,
connect during construction, run migrations, provision bindings/consent, send
external messages or execute message text.

The current run passed 54 storage tests using Python's installed `unittest`:

    python -m unittest tests.test_storage tests.test_storage_postgres -v

23 tests exercise isolated SQLite files. 31 exercise the actual PostgreSQL
adapter's DB-API path using a clearly labeled SQLite-backed connection double,
including its SQL parameters, lock statement order, rollback, sanitized failures,
and recovery after an ambiguous commit. Parallel fixture tests cover duplicate
and conflicting requests, turn budgets, rolling rate limits, capacity and ACK
races. They do **not** establish PostgreSQL MVCC, row-lock semantics, SQL syntax,
role privileges, crash durability, performance, failover or provider behavior.
No PostgreSQL server/`initdb` was found in PATH or the standard
`/usr/lib/postgresql` installation directory; neither psycopg nor psycopg2 was
installed. No software was installed. **Real PostgreSQL integration is unrun and
is a release gate before production use.**

## Production prerequisites and approvals

The following remain unselected/unperformed:

1. An approved PostgreSQL provider/database, region, storage/backups policy,
   private network/TLS configuration and spending ceiling. Actual cost is unknown.
   SQL capacity defaults are not a provider or spending authorization.
2. Separately approved database account/role provisioning and secure persistent
   credential configuration. Do not put credentials in chat, source, command-line
   arguments, logs, test fixtures or the MCP request body.
3. A trusted installed PostgreSQL DB-API driver and dependency lock verified in
   the deployment. This adapter expects `%s` parameters and ordinary tuple rows.
4. Explicit approval to run migrations with a separate migration authority.
5. Verified operator/owner registration for each agent, its exact authenticated
   `(issuer, subject, client_id)` binding, and separate actual consent by the
   owners of both named agents for each grant's scope, expiry, turn and TTL limits.
   A valid token or subject does not itself establish agent identity or consent.
6. The selected external OAuth authorization server and protected MCP deployment
   from the main application setup; this storage module creates neither.

The adapter needs only an injected factory that returns a fresh, idle, exclusively
checked-out DB-API connection. The caller must configure an approved runtime
credential, certificate-verified TLS, bounded connect timeout and tuple-row
cursor behavior. Do not use a shared connection concurrently. The adapter sets
autocommit false, READ COMMITTED, a five-second lock timeout and a ten-second
statement timeout. It commits/rolls back and closes every connection. A pool
wrapper may make `close()` return that connection only after transaction cleanup.
A driver/pool that cannot satisfy this contract must fail closed.

There is no SQLite fallback. `SQLiteFixtureStore.durable_for_deployment` is false;
`PostgresStore.durable_for_deployment` is true as a backend capability marker,
**not evidence that a deployment has been provisioned or validated**.

`PostgresStore.check_readiness()` uses SELECT projections to verify required
columns and a capacity row. It returns:

    {"ready": true, "backend": "postgresql", "check": "schema_and_capacity_read_only"}

It does not write or apply DDL, create consent, or test all privileges/end-to-end
message delivery. Failure is a bounded `storage_unavailable` error; raw SQL,
connection strings and driver exceptions are not returned to clients.

## Migrations and authority separation

`migrations/001_mailbox.sql` creates a dedicated `silk_mailbox` schema. The
unexecuted `002_runtime_permissions.sql.example` is an operator-review template
for an already approved runtime role, not an account-creation script. Review the
provider's existing privileges before applying it.

- The migration/admin authority owns schema and tables.
- Runtime has schema USAGE and mailbox-table SELECT. It may INSERT messages and
  receipts; UPDATE only message content (for erasure), grant used-turn/revocation
  state, and inert lock sentinel columns. Sentinel privileges allow row-locking
  SELECTs without letting runtime change identities, bindings or capacity.
- Runtime has no CREATE, CREATEROLE, SUPERUSER, BYPASSRLS, owner-role membership,
  identity/binding/grant INSERT, receipt UPDATE, DELETE or TRUNCATE privileges.
- Check ambient database/public-schema privileges and role inheritance separately.
  Do not revoke privileges from unrelated users on a shared database blindly.
- End clients never receive the database credential. Application ownership checks
  enforce the mailbox boundary. This design does not claim row-level-security
  isolation from a compromised trusted server or migration authority.

The schema uses C collation for identity keys and canonical sorted agent pairs.
A pair ID is SHA-256 of the UTF-8 compact JSON array of the two sorted agent IDs
(`ensure_ascii=False`, separators `,` and `:`). Every renewal reuses this pair row.
Grant schema constraints require two nonempty consent-evidence references and
reject fixture-only references. References point to separately retained consent
evidence; no owner emails, private conversations or raw consent documents belong
in a message receipt.

An approved admin provisioner must verify both actual owners before inserting a
grant. It must acquire the `mailbox_limits` singleton FOR UPDATE **first**, then
bindings/agents and pair rows consistently, before changing registration or
consent state. Enforce the configured agent/binding/grant capacity too. Preserve
these invariants:

- Bindings cannot silently reassign an existing tuple to another agent/owner.
  Rebinding/renewal requires separately verified authority and must not resurrect
  retired access accidentally.
- A grant's pair, scope and consent envelope are immutable. Renew consent by
  inserting a new grant ID, never by resetting used turns, un-revoking a grant or
  changing endpoints. Keep the existing pair quota row and history.
- `used_turns` is monotonic; revocation changes only from null to its timestamp.
- No provisioning helpers or admin actions are exposed through MCP.

## Transaction and concurrency model

Every public storage operation resolves a currently active binding for all three
validated principal claims, then resolves the registered agent. Caller fields
cannot choose a sender, owner or mailbox. Writes recheck ownership and active
state in the same transaction.

Mutations first lock the capacity singleton. This intentionally serializes
admissions/ACKs/revokes across this small bounded deployment and makes missing-key
idempotency admission plus global capacity atomic. Send then locks the persistent
pair quota row **before** checking/admitting grant turn and rate budgets, then
locks/rechecks its grant. The rolling limit is six admitted messages per named
pair in `(now - 60 seconds, now]`, in either direction, across all renewals.
Stored future timestamps also count conservatively if the server clock goes
backwards. Exact duplicates do not consume a turn or rate slot. Grant budget is
one to 32 sends, message TTL at most 300 seconds and no later than grant expiry.

Binding and agent SHARE locks prevent an admin revocation/disabling operation
from racing their authorization checks. Receive is state-read-only: it resolves
only the caller's mailbox and locks relevant active grants before reading
unacknowledged content. Concurrent operations linearize at their transactional
checks; a read already in progress can finish before a concurrent revocation.
No new read after committed revocation can see that grant's pending content.

READ COMMITTED plus explicit row locks is deliberate: PostgreSQL documents that
lock-taking reads wait for conflicting row changes and read the updated row.
See [PostgreSQL explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html)
and [transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html).
The global singleton is a conservative throughput bottleneck, not a scaling
claim. Benchmark the actual provider and revise only with real race/integration
coverage before higher-volume use.

Runtime privilege choices follow PostgreSQL's column-level grants and row-lock
privilege requirements; see [GRANT](https://www.postgresql.org/docs/current/sql-grant.html)
and [privileges](https://www.postgresql.org/docs/current/ddl-priv.html).

## Replay, receipts and trust

Send requires exactly `grant_id`, `recipient_agent_id`, `text`, `ttl_seconds`,
`idempotency_key` and nullable `reply_to`. Unknown/missing fields are rejected.
IDs are 8–100 restricted ASCII characters. Integers reject booleans. Text is
1–2000 characters, at most 4096 UTF-8 bytes, with Unicode control/format/surrogate
characters rejected. A reply target must be a message previously sent by the
named peer to this sender within the same grant.

Idempotency is scoped to the resolved sender across all grants and binds the
semantic message intent: grant, recipient, text, TTL and reply target. First
admission returns `status: queued` and `duplicate: false`. Exact replay returns
the same message ID/expiry, `duplicate: true`, and current bounded state with this
precedence: `acknowledged`, `revoked`, `expired`, `queued`. It never re-enqueues,
re-runs work or consumes quota. A different intent for the same key conflicts.
Replays can succeed after grant/message expiry or revocation, but the caller's
binding must still be active. A queued status is only mailbox state.

ACK requires the recipient's active binding. The first ACK additionally requires
an active grant and pending/unexpired message. It immutably records either
`received` or `declined`. A retry must use the original idempotency key and the
same decision; it returns the original receipt even after grant expiry/revoke.
Changed outcomes conflict. A fresh key for an already-recorded decision conflicts
rather than creating unbounded alias rows. ACK key reuse across different
messages also conflicts.

A receipt's public `request_digest` is the original admitted message-intent
SHA-256 digest, matching that message's stored `intent_digest`. Separate internal
`acknowledgment_digest` hashes the ACK's message ID and outcome for replay checks;
it is not returned. Digests detect mismatched retry requests; they are **not
cryptographic signatures**, trusted timestamps, human approvals, legal evidence
certification or proof of external execution. Low-entropy content can be guessed
against a digest, so protect these records as private metadata.

Every receipt states `effect: mailbox_acknowledgment_only`. Every received message
states `content_trust: untrusted_data`. ACK means only that the recipient client
acknowledged data. There is no automatic wake, tool execution, external agent call,
human authorization or real-world completion implied by this adapter.

## Retention and capacity

Message text is cleared immediately when ACKed or its grant is revoked. Expired
content is cleared during new send/ACK writes and by the internal operator-only
`purge_expired_content(now)` maintenance method. It is **not** a public MCP tool.
Choose and approve a maintenance schedule before deployment; no scheduler was
provisioned. Without traffic/maintenance, expired text remains stored but is never
returned by receive. Logical erasure does not purge database WAL, old MVCC tuples
or backups; choose provider backup retention and privacy policy explicitly.

Minimal message tombstones retain IDs/pair, sender/recipient, timestamps, original
intent digest, idempotency key and reply ID. Receipts retain the corresponding
IDs, decision, time and the two digests/key; no message content, credentials,
JWT claims, IP addresses, raw tools or execution logs are added. Tombstones remain
available for lifetime replay safety and pair-rate history. There is no automatic
metadata deletion or archive path in this implementation. Do not delete old keys
merely to make room: that would re-enable old requests and violate the contract.

Production defaults are 100,000 lifetime messages, 100,000 receipts, 10,000 agents,
20,000 bindings and 10,000 grants; schema-configurable within explicit upper
ceilings. These are row-count limits, not a guarantee of database byte usage or
price. On full capacity new admissions fail closed; valid existing exact retries
still work. An operator must plan approved capacity changes or namespace retirement
without breaking retained replay semantics. A future archive design would have to
keep archived dedupe keys queryable and is not implemented here.

## Isolated fixtures only

`SQLiteFixtureStore(path, *, max_messages=1024, max_receipts=1024, max_agents=128,
max_bindings=256, max_grants=1024)` requires a file in an isolated local/cloud test
workspace. It does not support connection-local `:memory:`. It uses SQLite WAL,
foreign keys, bound SQL and `BEGIN IMMEDIATE` for fixture write serialization.
Existing fixture settings persist when reopened.

Test-only helpers, absent from PostgresStore:

- `provision_agent(agent_id, owner_id, display_name)`
- `provision_binding(principal, agent_id, *, expires_at, now=0)`
- `provision_grant(grant_id, agent_a, agent_b, *, expires_at, max_turns=8, max_ttl=300, now=0)`
- `revoke_binding(principal, *, now=0)`
- `inspect_counts()`

All times are trusted server-supplied integer Unix seconds. Fixture provisioning
writes unmistakable `fixture-only:` consent references, which the production
schema rejects. None of this establishes real identities or owner consent.

## Required real-database release checks

Using a separately approved disposable PostgreSQL database and real runtime role:
apply the migration with admin authority, provision only synthetic fixtures, then
run the behavior/race suite against genuine connections. Verify failed direct
identity/consent/capacity writes and receipt mutation, exact column privileges,
committed-revocation visibility, grant/binding admin-vs-client races, independent
processes, lock/statement timeouts, restart/replay behavior, ambiguous commit
recovery, and content retention. Test TLS enforcement, provider failover and
capacity/performance independently. Readiness alone does not satisfy these gates.
