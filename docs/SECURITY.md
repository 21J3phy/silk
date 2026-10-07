# Security model and limitations

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately through [GitHub private vulnerability reporting](https://github.com/21J3phy/silk/security/advisories/new). Include affected files or routes, reproduction steps, and impact. Never include real credentials, tokens, or personal data.

## Protected in this demonstration

The broker treats signed message content as untrusted data. A signature does not make a title an instruction. The only supported payload is a bounded meeting title plus one to three UTC candidate times. The adapter never calls an LLM, executes text, reads the filesystem, connects to the network, or approves a result. It selects a supplied candidate only when it exactly matches a private fixture slot.

Before queue admission, the broker checks exact fields, types, byte/text bounds, registered sender/recipient, protocol/scope, signature, canonical signature encoding, nonce replay, message/idempotency binding, creation/deadline, directional active permission, candidate dates, request budget, per-pair rate, and storage cap. It authenticates before returning a duplicate result. Identical valid retries return the existing message without new work, including after expiry/revocation. Different intent cannot replace the original request.

Before the local adapter runs, the broker checks stored schema/signature, recipient/scope against the current grant, current permission, and deadlines again. Revocation cancels queued and waiting requests. Approval also requires a currently active grant, unexpired request, future proposed slot, correct fixture recipient owner, and waiting state. Once approved/declined, the receipt is immutable through the API.

## Browser boundary

- Loopback-only bind; strict loopback Host validation reduces DNS-rebinding exposure.
- Browser mutations require a random session cookie, exact CSRF token, JSON content type, and matching Origin when present. Cross-site Fetch Metadata is rejected. No CORS permission is emitted.
- The signed ingress endpoint deliberately does not use browser CSRF authority. A valid fixture-agent signature and grant are its authority. Origin checks and JSON parsing still apply.
- HttpOnly, SameSite=Strict cookie. No Secure flag on local plain HTTP; this is another reason not to expose it publicly.
- Strict CSP, no inline scripts/styles, no external assets, no framing, no MIME sniffing, no referrer leakage, no browser camera/microphone/location permission.
- Dynamic UI content is rendered as text with DOM APIs. JSON duplicates, invalid UTF-8/nonfinite values, oversized bodies, unexpected fields, path traversal, and wrong content types are rejected.

## Explicitly not protected / not production-ready

1. **No actual human identity or account security.** The fixture switcher allows both owner roles. A consent click here demonstrates a state transition; it is not verified real-world consent.
2. **Trusted host and process.** All fixture private keys are unencrypted in the database. Local code, a DB writer, or the host owner can forge fixture actions or change records. File mode 0600 and a private default data directory reduce accidental exposure, not host compromise.
3. **No independent recipient/provider.** The broker and both agents share a process and database. The UI has owner-specific projections, but this is not proven multi-tenant isolation with real customer data.
4. **No immutable ledger or legal proof.** Audit metadata is append-only through application routes, but a database administrator can alter it. Broker signatures prove only the local key signed a record.
5. **No internet-scale availability defense.** Application quotas and body bounds are implemented; connection floods, distributed spam identities, external reputation, abuse reports, and operational alarms are not. Python's development HTTP server is not a production ingress.
6. **No encryption at rest, key rotation, recovery, owner authentication, or secure key custody.** Never insert real secrets or production identities.
7. **No retention/purge UI.** Mailbox payloads, keys, identifiers, nonces, and receipts remain in the database until it is removed. Audit excludes titles, candidate slots, purpose text, and signatures, but still includes owner/agent/resource metadata. Storage caps are 1,000 requests and 200 invitations. The state API returns the latest 80 relevant audit rows, and the interface displays eight; neither deletes older rows.
8. **No external delivery/execution guarantees.** A delivery event means the deterministic in-process adapter was invoked. Receipts state simulation-only. There is no distributed acknowledgment, automatic booking, or external transaction.
9. **Bounded local clock assumption.** Deadlines use the host clock with five seconds of permitted sender-ahead skew. Major clock changes or malicious host clocks are outside this demo's trust model.
10. **No formal protocol interoperability claim.** Canonicalization is specified for this constrained schema, not advertised as RFC 8785 or certified A2A.

## Data and restart behavior

Fixtures and sample slots are created once per database, not regenerated on each restart. Keys, permissions, replay/idempotency records, mailbox state, and receipts persist. Sessions and CSRF tokens do not. Queued work resumes only while both grant and message are still valid; a passed deadline cancels any possible wake. Completion is never inferred from a restart, time passing, or missing response.

A new database path creates a separate demonstration with new keys and no previous history. Do not delete a database expecting revocation to propagate to other systems: there are no connected systems here, and deletion destroys the local record.

## Before a real pilot

Add verified owner authentication, registered/rotatable per-agent public keys, tenant authorization, HTTPS and hardened ingress, outbound destination controls, durable inbox/outbox jobs with external idempotency and reconciliation, consent bound to real owners, revocation handling at every side effect, authenticated inbound wake, per-provider capability verification, observability without content leakage, retention/export/deletion, and an independent security review. Keep consequential actions behind explicit owner approval. Do not connect finance/payment or broad calendar scopes as a shortcut.
