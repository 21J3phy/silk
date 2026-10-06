# Silk · Consent before contact

A clean, independent local MVP of cross-owner agent messaging. Two fixture owners can discover each other's agents, agree on a narrow permission, exchange an authenticated coordination request, and review a signed result receipt.

**This is a working local demonstration, not a live agent network.** Atlas and Nova are deterministic local fixtures. The owner switcher is a demonstration control, not authentication. There are no connected providers, real accounts, calendars, payments, custody, escrow, or external messages. Approving a result does not book a meeting.

## Run

Requires Python 3.12+ and `cryptography` (the build used Python 3.12.14 and the already-installed cryptography 50.0.0). No frontend build or npm dependencies are needed.

```sh
cd silk-rebuild
# If needed, create an environment and install the one declared dependency:
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m silk --port 8765
```

Open http://127.0.0.1:8765 in a browser. The server binds only to loopback. It must not be exposed with a tunnel, public bind, or reverse proxy. The default database is `var/silk.sqlite3`; choose another with `--db /path/to/demo.sqlite3`.

If the dependency is already available, only `python -m silk --port 8765` is required. No software was installed during this build.

## Try the complete flow

1. As **Alice / Atlas**, invite **Bob / Nova** to coordinate a meeting. The interface offers four requests over one hour; the API supports smaller budgets and other bounded lifetimes.
2. Switch to **Bob**. Read the invitation's scope and purpose, then accept it. Acceptance creates a directional Atlas → Nova permission.
3. Switch to **Alice**. Send a titled meeting request using the public sample candidate times.
4. The broker authenticates and admits the request. The local mock recipient chooses a matching candidate from Bob's private sample availability. The request becomes **Awaiting approval**; the mock cannot approve it.
5. Switch to **Bob**. Approve or decline the proposed result. Both owners can see the same signed receipt. No calendar changes.
6. Revoke the permission from either owner. Queued and unapproved work is cancelled; completed receipts stay intact. Future requests are blocked.

The persisted sample times are tomorrow at 14:00, 15:00, and 16:00 UTC when a fresh database is first created. Alice's fixture is available for the first two; Bob's for the last two. These are invented fixtures, not real calendar data. They do not silently roll forward after restart. Use a **new database path** when those sample dates pass; existing records are preserved.

## What is implemented

- Owner-visible fixture directory with Ed25519 public keys and short key fingerprints
- Pending invitations, explicit recipient acceptance/decline, one implemented scope: `meeting.coordinate`
- Directional, expiring, revocable grants with a 1–8 request budget
- Ed25519-authenticated structured envelopes, immutable accepted intent, recipient/scope/deadline checks
- Durable nonce replay protection and idempotency, six requests/minute per sender-recipient pair, five-minute request TTL
- Persistent queue, second validation before mock adapter invocation, explicit owner decision, broker-signed result receipts
- Metadata-only activity log; request content lives in mailbox records, not the audit log
- SQLite transactions reserving the write lock before quota checks, including across broker instances
- Strict JSON/schema/size validation, same-origin browser actions, CSRF tokens, strict CSP, text-only rendering of inbound content
- Browser UI with fixture owner switching, consent controls, mailbox, receipts, permission revocation, and responsive layout

“Transaction” in this MVP means a request/approval/result workflow only. No financial execution exists.

## Verify

```sh
python -m unittest discover -v
python -m compileall -q silk tests scripts
node --check web/app.js
node web/ui-state-test.cjs
```

The mock-DOM test checks UI state transitions and retry behavior; it is not a browser rendering test.

The optional browser checks use Playwright and Chromium if already installed:

```sh
python scripts/browser_smoke.py
```

See `docs/QA.md` for the tested environment, actual results, screenshots, and remaining limitations. Browser screenshots are review artifacts; they do not imply public hosting.

## Structure

```text
silk/
  protocol.py     strict wire schema, canonical bytes, signatures
  service.py      SQLite broker, permissions, replay/rate/TTL guards, receipts
  adapters.py     narrow adapter interface and deterministic local implementation
  server.py       loopback HTTP server, sessions, origin and CSRF controls
  __main__.py     local entry point
web/             dependency-free browser interface
scripts/         repeatable demo/verification helpers
tests/           unit, integration, concurrency, and transport tests
docs/            architecture, protocol, security, and QA notes
```

## Important boundaries

- Fixture keys prove only possession of local fixture keys. They do not prove real human identity, ownership, or consent.
- The server stores all fixture private keys unencrypted in the demo SQLite database. Keep the database private. Never load real credentials into it.
- The switcher lets any local viewer act as either fixture owner. It intentionally demonstrates a consent experience without claiming production authorization.
- The service is not an internet-hardened multi-tenant system. Python's development HTTP transport is local-only.
- Persistence is local SQLite schema v1, with no migration tooling, not a distributed queue. There is no provider execution retry, network delivery acknowledgment, webhook, consumer-bot wakeup, or general agent loop.
- No GrokBot → dot, ChatGPT, OpenAI, xAI, or other live integration is claimed. Model inference APIs are not equivalent to persistent consumer-agent inboxes. A2A-inspired concepts do not imply protocol certification or compatibility.
- Receipts authenticate the local broker's account of the simulated decision. They are not legal signatures or proof an external meeting or transaction happened.
- Records, keys, nonces, and idempotency bindings persist until the database is removed outside the app. There is no automatic retention/deletion policy or purge UI. Message storage is capped at 1,000 and invitations at 200; the state API returns the latest 80 relevant audit events and the interface displays the latest eight.
- Sessions and CSRF tokens are memory-only and expire after one hour; restarting requires a fresh browser session. Queued messages resume only if their original permission and five-minute deadline remain valid. Expired work does not run.

Read `docs/SECURITY.md` before considering real users or external adapters.
