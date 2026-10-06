# Browser HTTP API contract (v1)

Local-only demo. Python 3.12 + SQLite + installed cryptography (Ed25519), plain web UI. Never contact providers, calendars, real agents, or payment services. Fixture owner switching is deliberately not real login. Runtime keys authenticate fixture messages, not human consent. Only the `meeting.coordinate` scope is implemented.

All timestamps are integer Unix seconds, except meeting option `start`, which is a UTC ISO string (`2026-10-07T14:00:00Z`). IDs are opaque strings. Errors: `{error:{code,message}}` with appropriate HTTP status. API requests/responses use JSON.

## Browser HTTP API

- GET `/api/session`: `{csrf_token,current_owner,owners:[{id,name}],demo:true}`. Sets HttpOnly SameSite=Strict session cookie. Current owner starts as `alice`.
- POST `/api/session` `{owner_id:"alice"|"bob"}` switches fixture owner; returns the session shape above. State is then reloaded. All browser POST routes require `X-CSRF-Token`, JSON Content-Type, and same-origin requests. UI must update CSRF from any session response.
- GET `/api/state`: snapshot below.
- POST `/api/invitations` `{from_agent:"atlas",to_agent:"nova",purpose:string,max_turns:4,expires_in:3600}`. Sender must be selected owner's agent. Creates an invitation; no messages are authorized yet.
- POST `/api/invitations/{id}/accept` `{}`: recipient owner accepts, creates directional scope grant. Decline via `/decline`.
- POST `/api/grants/{id}/revoke` `{}`: either owner revokes. Queued/unapproved requests become cancelled, no future wake/approval allowed.
- POST `/api/messages` `{grant_id,title,options:[{start,duration_minutes}],idempotency_key:string}`: selected sender owner authorizes its fixture agent to sign and queue a request. The idempotency key must be reused for a network retry. Response `{message,duplicate:boolean}`. Local background dispatcher validates again before invoking mock recipient; changes queued to awaiting_approval (or rejected/expired/cancelled). It never approves on a person's behalf.
- POST `/api/messages/{id}/approve` `{}`: recipient owner approves the mock agent's selected option; creates immutable result receipt, **simulates coordination only**. `/decline` declines. Repeated same decisions are idempotent; conflicting decisions are rejected. Never writes a calendar.
- POST `/api/envelopes`: wire envelope; signed fixture message ingress, independent from browser fixture-signing convenience endpoint. See PROTOCOL.md for the implemented envelope format.
- GET `/health`: `{status:"ok",mode:"local-fixture"}` (no session required).

All POST browser mutation responses (except session/messages) return the created/changed resource directly, but UI can simply reload `/api/state`. UI polls state every 2 seconds to observe mock dispatch. Owner change must clear stale action state and pending form input.

## State snapshot

```
{
  demo:true,
  current_owner:{id:"alice",name:"Alice Chen"},
  owners:[{id:"alice",name:"Alice Chen"},{id:"bob",name:"Bob Rivera"}],
  agents:[{id:"atlas",owner_id:"alice",name:"Atlas",provider:"Local fixture",description:"Alice's coordination assistant",fingerprint:"..."},{id:"nova",owner_id:"bob",name:"Nova",provider:"Local fixture",description:"Bob's coordination assistant",fingerprint:"..."}],
  invitations:[{id,from_agent,to_agent,purpose,scope:"meeting.coordinate",status:"pending"|"accepted"|"declined"|"expired",created_at,expires_at,max_turns}],
  grants:[{id,invitation_id,from_agent,to_agent,scope,status:"active"|"revoked"|"expired",created_at,expires_at,max_turns,turns_used,rate_per_minute:6,ttl_seconds:300}],
  messages:[{id,grant_id,sender,recipient,created_at,expires_at,status:"queued"|"awaiting_approval"|"approved"|"declined"|"rejected"|"expired"|"cancelled",payload:{kind:"meeting.proposal",title,options:[{start,duration_minutes}]},proposal:null|{selected_option:{start,duration_minutes},explanation:string},receipt:null|{id,message_id,decision:"approved"|"declined",selected_option:null|{start,duration_minutes},decided_at,signature},failure_code:null|string}],
  audit:[{id,occurred_at,event,entity_id,actor_id}],
  suggested_options:[{start,duration_minutes:30},...],
  private_availability:[{start,duration_minutes:30},...],
  server_time:integer,
  limits:{max_payload_bytes:4096,max_options:3,rate_per_minute:6,max_ttl_seconds:300}
}
```

`messages`, `grants`, `invitations`, and `audit` are filtered to the selected owner's fixtures. `private_availability` contains only that owner's canned sample availability. `suggested_options` are public sample candidate times (not another owner's calendar). All owner controls are demo persona controls, never production authorization.

