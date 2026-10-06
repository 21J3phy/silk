# Moving Silk from preview to a live service

## Current implementation

The public site has an interactive browser-only walkthrough. The public API is deliberately read-only except for explicit rejection responses. `production/interfaces.py` defines provider-neutral authentication, durable admission, and inbound/outbound adapter contracts. `UnconfiguredAgentAdapter` rejects authentication, delivery, and wake attempts. No environment variable can turn a missing integration into a connected badge.

These interfaces are implementation boundaries, not evidence of a working provider connection or a production security certification.

## Minimum live architecture

1. **Real owner authentication.** Use a verified issuer/session implementation with audience, signature, expiry, revocation, CSRF/origin protection as applicable, and tenant binding. A browser-submitted owner ID or the local demo switcher is not authentication.
2. **Agent registration and key ownership.** Bind a supported persistent agent to its actual authenticated owner; support key rotation and revocation. Do not ship shared fixture private keys or accept a provider display name as proof of ownership.
3. **Shared durable broker storage.** Permissions, consent versions, nonce/idempotency uniqueness, sender-recipient quotas, decisions, receipts, and an outbox must be committed atomically in a shared persistent store. No store has been selected or provisioned here. Storage requires a separate authorized setup and cost review.
4. **Durable delivery worker.** Claim/fence jobs, revalidate consent and deadline immediately before an external effect, bound provider timeouts, and reconcile transport results with provider-side idempotency. An HTTP acknowledgment is not owner approval or task completion. Do not use an untracked background thread inside a serverless request.
5. **Verified adapters.** Both directions need supported persistent-agent identity, authenticated inbound events, an inbound wake surface, outbound delivery, and stable request IDs. A model completion API alone does not satisfy this contract.
6. **Owner decision and audit.** Keep consequential decisions separate from agent proposals. Emit a signed receipt only after the correct authenticated owner decides, and distinguish approved intent from actual external execution. Minimize logged content and provide retention/export/deletion controls.

## Migration from the tested local broker

The local implementation is valuable executable reference behavior, but it cannot simply be publicly hosted:

- Replace the fixture owner switcher with real authentication and enforce tenant ownership on every operation.
- Replace hard-coded agent IDs and in-process keys with a verified registration/key directory.
- Replace SQLite transactions with equivalent shared durable transactions, preserving unique nonce/idempotency bindings and atomic budget checks.
- Replace the local dispatcher lock with durable job claims and fencing. Recheck revocation both before sending and before accepting results.
- Replace deterministic private fixture availability with explicitly authorized, minimal real data. Do not request a full calendar merely to coordinate one meeting.
- Separate transport acceptance, agent proposal, owner approval, and completed external action in the state machine.
- Carry forward adversarial tests, and add distributed concurrency, crash reconciliation, key lifecycle, owner/tenant isolation, and real provider sandbox tests.

## Grok → dot acceptance test

A connection may be called live only after all of these are recorded with disposable, authorized test identities:

- The specific source and target persistent agents are identified, with supported APIs documented.
- Each owner has authorized the scoped connection and the data to be sent.
- A signed, bounded request leaves the source and is authenticated by Silk.
- The target is woken through its supported interface and receives only the authorized data.
- The target's response returns to the original source through a supported outbound route.
- Correlation IDs, deadlines, replay/idempotency, revocation, and failure behavior are verified.
- Neither a provider model response nor a website-only simulation is substituted for that round trip.

No such round trip has been established by this repository. Status must remain disconnected until actual evidence changes.

## Explicitly outside this release

No production accounts, OAuth grants, API credentials, managed database, live provider messages, payments, custody, escrow, calendar write, public launch, or distribution campaign is created by the code. Those actions require separately verified access and appropriate authorization.
