# Architecture and decisions

## Narrow useful outcome

Two separately represented owners coordinate one candidate meeting without giving each other's agent an entire calendar. The sender authorizes an invitation and a proposed set of times. The recipient authorizes a directional messaging grant, then separately approves a result. The only external-looking effects are local simulated records.

The product centers on **owner-controlled contact and bounded coordination**, not unconstrained agent chat. A DM-like mailbox is useful only if an owner can see who may contact their agent, why, with what scope, and for how long.

## Components and trust boundaries

```text
Browser fixture owner control
  | same-origin session + CSRF
  v
Local broker / SQLite  <--- signed envelope ingress
  | schema + signature + recipient + grant + deadline + quota validation
  v
Durable queue
  | revalidate before invocation
  v
Local deterministic adapter
  | candidate proposal only
  v
Recipient owner approval
  | atomic decision + signed receipt
  v
Both owners' projected mailboxes
```

Every component currently runs in one trusted local process, with SQLite serializing state mutations. The wire ingress is separately authenticated by Ed25519 signatures and grant scope, but the built-in fixtures also live inside the broker. This is a development trust boundary, not actual provider separation.

## State machines

Invitation:

```text
pending -> accepted | declined | expired
accepted -> one directional grant (never two on retry)
```

Grant:

```text
active -> revoked | expired
```

Request:

```text
queued -> awaiting_approval -> approved | declined
   |             |
   +-------------+-> expired | cancelled
   |
   +-> rejected (no matching option, invalid stored data, or adapter failure)
```

`message.delivered` is a recorded handoff to the local adapter, followed in the same transaction by a proposal or rejection. It is not proof of a remote provider receiving anything. There is no separately durable “delivered but unprocessed” transport state. Approved/declined are terminal and yield one stable signed receipt; repeating the same decision is idempotent, while changing it is rejected.

A request budget counts admitted unique requests, even if subsequently declined, rejected, revoked, or expired. A retry does not spend another turn. A receipt is a terminal broker result and cannot trigger another agent turn. Thus the demo has no automatic echo loop.

## Persistence and concurrency

SQLite stores keys, invites, grants, signed envelopes, replay nonces, idempotency intent hashes, counters, decisions, receipts, and audit metadata. `BEGIN IMMEDIATE` is acquired before admission checks to prevent check-then-write races across Service instances. Mutations and corresponding audit events commit together.

The deterministic adapter runs while the broker transaction is held. That is acceptable only because it does no network I/O and returns immediately. A real adapter must use durable job claiming, leases/fencing, bounded timeouts, outcome reconciliation, and permission/deadline revalidation at commit. Do not merely replace its body with an HTTP request.

The single background dispatcher checks every 500 ms. Process interruption rolls back incomplete local transitions. Persisted queued messages are examined again on restart. Runtime sessions disappear on restart. No “exactly once” claim is made for future external execution.

## Identity and consent assumptions

Alice, Bob, Atlas, and Nova are fictional fixture identities. Ed25519 keys are generated on database initialization and survive restart. The directory displays public keys. Agent proofs authenticate bytes from a fixture key; the broker's persona control supplies simulated owner consent. Anyone who can open this demo can switch personas. Replacing this with actual owners requires authenticating people, binding agents to verified owners, controlling key lifecycle, and enforcing tenant isolation.

## Deliberately excluded

- Open-ended message bodies that are executed as instructions
- Model APIs or provider account connections
- Persistent consumer-assistant inbox integrations without a verified supported API
- Webhooks, inbound external wakeups, and outbound provider delivery
- Automatic calendar reads/writes or booking
- Payments, escrow, custody, orders, and financial commitments
- Public discovery, search ranking, social graphs, or public deployment
- A2A compatibility/certification claims

## Next justified slice

Before adding features, select **one provider with documented inbound wake and outbound messaging surfaces**, and establish owner authentication and real agent-key registration. An outbound API alone is not enough. Then test one consensual cross-process adapter using disposable test identities, durable outbox/inbox, revocation-at-use, bounded provider timeouts, and an owner-visible audit trail. An internet pilot additionally needs production transport, tenant/security review, operational monitoring, retention/deletion controls, and abuse handling.
