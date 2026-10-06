# Silk local wire protocol v1

This constrained protocol is implemented and tested for the two local fixtures. It is not advertised as a standard, A2A certification, or a live provider integration.

## Signed envelope

`POST /api/envelopes` accepts exactly these JSON fields:

```json
{
  "version": 1,
  "id": "msg_example_001",
  "sender": "atlas",
  "recipient": "nova",
  "grant_id": "grant_example_001",
  "scope": "meeting.coordinate",
  "created_at": 1791302400,
  "expires_at": 1791302700,
  "nonce": "nonce_example_unique_001",
  "idempotency_key": "request_example_001",
  "payload": {
    "kind": "meeting.proposal",
    "title": "Design catch-up",
    "options": [
      {"start": "2026-10-07T15:00:00Z", "duration_minutes": 30}
    ]
  },
  "signature": "REPLACE_WITH_A_REAL_FIXTURE_SIGNATURE"
}
```

This is a structural example, **not a sendable signed request**. Dates, grants, keys, and IDs must match the current local database and clock.

### Encoding and signature

1. Remove `signature` from the object.
2. Serialize as JSON with keys sorted lexicographically, no extra whitespace, Unicode encoded directly as UTF-8, and JSON's ordinary required escaping. All numeric fields in this schema are integers; booleans are not accepted as integers. The reference implementation is `protocol.canonical` using Python's `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
3. Sign those bytes with the sender's Ed25519 fixture private key.
4. Encode the 64-byte signature as unpadded base64url (86 characters). Alternative representations with nonzero padding bits are rejected.

Public keys are unpadded base64url of 32 raw Ed25519 public-key bytes. They are available in the authenticated fixture state directory. The 16-character directory fingerprint is a short SHA-256 display fingerprint of the encoded key, not identity verification.

The constrained encoding is not a general-purpose JSON canonicalization standard. Interoperability with other runtimes must be verified using cross-language test vectors before any real adapter is enabled.

### Bounds

- Exactly the defined fields; no extra instructions or capability extensions.
- Canonical envelope ≤ 4,096 UTF-8 bytes. HTTP request body ≤ 8,192 bytes.
- Opaque request, grant, nonce, and idempotency identifiers: 8–100 characters in `[A-Za-z0-9._:-]`.
- Registered fixture sender and distinct registered recipient.
- Only protocol version 1, scope `meeting.coordinate`, and kind `meeting.proposal`.
- Title: 1–120 characters, no leading/trailing whitespace, ASCII control characters, DEL, or unpaired Unicode surrogates.
- One to three distinct meeting options, strict valid UTC timestamps in `YYYY-MM-DDTHH:MM:SSZ` form, and duration 15, 30, 45, or 60 minutes.
- Candidate times must be after admission time and within 30 days.
- Message lifetime: 1–300 seconds, creation at most five seconds ahead of broker clock, and expiry no later than grant expiry.
- Grant budget: 1–8 admitted unique requests; rate: six per rolling minute per sender-recipient pair across grants.
- Local storage cap: 1,000 requests, 200 invitations. Invitation spam guard: one pending directional invitation per pair and five invitations/minute per sender fixture.

### Deduplication and replay

After schema and signature verification:

- Same message ID and exact canonical signed content returns the existing result.
- Same sender and idempotency key with the same intent returns the existing result even if the signed retry has a new nonce or timestamps. Intent comprises sender, recipient, grant, scope, and payload.
- Reusing either identifier for different content/intent is a conflict.
- A consumed sender nonce with a new request and idempotency key is a replay conflict.
- Successful exact/semantic retries do not consume budget, create another receipt, or invoke the adapter again.
- A retry may retrieve an existing expired/cancelled result. It cannot resurrect work.

These bindings persist across restart. Invalid or rejected-at-admission envelopes are not retained or logged with their payloads.

## Browser convenience endpoint

`POST /api/messages` accepts `{grant_id,title,options,idempotency_key}` from a valid fixture session with a CSRF token. The broker verifies that the selected owner controls the grant's sender, builds an envelope, signs it with that fixture key, and submits it through the same admission logic.

This endpoint exists solely for demonstrating two owners on one computer. A production server should not impersonate every independent owner/agent by keeping all their keys and a freely selectable persona.

## Local delivery and adapter contract

`AgentAdapter.propose(recipient=..., payload=..., availability=...)` receives only a validated request payload plus the recipient fixture's private sample slots. It returns either `None` or:

```json
{
  "selected_option": {"start": "2026-10-07T15:00:00Z", "duration_minutes": 30},
  "explanation": "A short bounded explanation."
}
```

The broker rejects an option outside the request or an invalid result shape. The current deterministic implementation matches a candidate exactly; it never parses title text as instructions. The owner must then explicitly approve or decline before a receipt exists.

No agent-generated arbitrary result messages or follow-up loops are implemented. Adapter failure is terminal `rejected` with a bounded failure code; raw exception text is not included in the audit.

## Result receipt

The broker signs a record with version, receipt ID, message ID, grant ID, SHA-256 digest of the complete signed request, decision, fixture deciding owner, decision timestamp, selected option or null, and `execution: "simulation_only_no_calendar_write"`.

Verification uses the broker public key from `/api/state` and the same `verify_record` signature scheme. It proves a local broker key signed these bytes. It does not prove real identity, legal consent, remote delivery, a calendar booking, payment, or other external execution.

## Error responses

HTTP errors use `{ "error": { "code": "stable_code", "message": "Readable explanation" } }`. Representative codes include `invalid_signature`, `grant_mismatch`, `grant_inactive`, `message_expired`, `replay_detected`, `idempotency_conflict`, `turn_budget_exhausted`, `rate_limited`, and `csrf_failed`. No sensitive payload or private key is included in errors.

See `CONTRACT.md` for browser route details and `SECURITY.md` for trust and deployment limits.
