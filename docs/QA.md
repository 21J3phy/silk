# Independent verification

Reviewed 2026-10-06. This verification applies to the new, local-only Silk fixture implementation. Every test uses synthetic owners, generated fixture keys, and temporary SQLite data. No real agent, account, provider, calendar, or payment service was contacted.

## Results

- `python -m unittest discover -v`: **88 passed**.
- `node --check web/app.js`: **passed**.
- `node web/ui-state-test.cjs`: **passed**. This dependency-free mock-DOM harness executes the actual frontend script and verifies startup/render state, uncertain-send retry keys, close/reopen, same-owner reconnect, changed-intent keys, success reset, stale snapshot rejection after owner switch, and prior-owner draft clearing. It does not run a browser or verify visual layout.
- `python -m py_compile silk/*.py scripts/browser_smoke.py tests/*.py`: **passed**.
- `python scripts/browser_smoke.py --browser-executable /usr/bin/chromium`: **blocked before the first browser check**, exit 2. Installed Chromium could not create its process socket (`Operation not permitted`) in this execution environment. The supported cloud-browser route separately rejected the loopback page with `net::ERR_BLOCKED_BY_CLIENT`.
- **No browser, visual, mobile-layout, or screenshot pass is claimed.** The browser test script is included for execution in a permitted local environment and has been syntax-checked only beyond its verified blocked-launch/reporting path.

The 88 automated checks comprise 25 consent/lifecycle tests, 24 signed-ingress/adapter tests, 15 protocol tests, 19 real loopback HTTP tests, and 5 frontend source-level checks. They are focused implementation checks, not a complete security audit or production-readiness certification.

## Verified coverage

### Consent and lifecycle

- Invitations create no messaging authority until the recipient owner accepts.
- Sender and recipient owner gates, directional scope, bounded invitation fields, one pending invitation, and invitation rate limiting.
- Separate request admission, mock agent proposal, and recipient approval; neither the sender nor the adapter can approve on the recipient's behalf.
- Idempotent repeated invitation responses and decisions; conflicting decisions fail.
- Revocation before dispatch and before approval cancels pending work; completed receipts remain unchanged.
- Message TTL and grant expiry prevent late dispatch and late approval.
- Unique-message turn counting, request-content conflict detection, restart persistence, and isolated owner availability projections.

### Wire protocol, persistence, and adapters

- Ed25519 verification covers every signed field; unknown signing keys and altered payloads fail.
- Exact envelope/payload schemas; bounded identifiers, signature size, title, timestamps, candidate count, duration, and TTL; booleans do not pass integer validation.
- Canonical signature representation, finite JSON numbers, valid UTF-8 text, duplicate-option rejection, and structured titles treated as data.
- Durable nonce replay protection across restart and a replacement grant; exact and semantic retries return the original request without using another turn.
- Rolling sender/recipient rate limits persist across restart and cannot be reset by a fresh grant.
- Concurrent unique requests and concurrent retries preserve budgets and one-message admission. Separate `Service` instances share an atomic SQLite quota check.
- Broker-signed receipts verify with the public broker key and explicitly identify execution as simulation-only.
- The mock adapter runs once per admitted request. No match, an out-of-request option, or an exception fails closed; exception text is redacted.

### HTTP boundary

- Real HTTP end-to-end invitation, owner switch, acceptance, signed request, dispatch, approval, and decision retry.
- Session requirement, distinct session owner state, HttpOnly/SameSite=Strict cookies, CSRF enforcement, and CSRF rotation on owner switch.
- Host and Origin validation, cross-site Fetch Metadata rejection, and rejection of duplicate Host, Origin, Content-Length, and Content-Type headers.
- JSON content type and size limits, malformed UTF-8/JSON, duplicate JSON keys, nonfinite numbers, deep nesting, and unknown fields fail closed.
- Signature-only envelope ingress is independent of browser sessions; cross-origin requests are still rejected.
- Security headers on tested JSON success/error routes, no permissive CORS, static-path isolation, and refusal to bind publicly.

### Frontend source-level checks

- JavaScript parses; static IDs are unique and expected controls exist.
- No inline scripts, style attributes, event-handler attributes, or external asset URLs.
- No HTML insertion or dynamic-code execution sinks; untrusted text uses text-only rendering.
- Source review of epoch/sequence checks, abort handling, busy controls, CSRF refresh, and retry-key retention. Automated source-presence checks supplement this review but do not prove browser behavior.
- The separate mock-DOM state/request harness above exercised the actual JavaScript control flow for interrupted, repeated, and owner-switch cases; visual rendering and browser-specific event/network behavior remain unverified.

## Issues found and fixed during review

1. **Cross-instance turn-budget race:** two `Service` instances using one database could each admit a request against a one-turn grant. SQLite now reserves its write transaction with `BEGIN IMMEDIATE` before reading consent/quota state. The concurrent two-instance regression passes.
2. **Noncanonical signature aliases:** different final base64url characters could decode to the same Ed25519 signature. Verification now checks that re-encoding produces the exact supplied signature string. The alias regression passes.
3. **Audit ordering:** the UI compared numeric audit IDs lexicographically when timestamps matched, potentially hiding newer entries. It now compares IDs numerically. Source review and a static regression confirm the fix; rendered behavior remains unverified because browser access was blocked.

## Browser script still to run

`scripts/browser_smoke.py` starts an isolated loopback server with a fresh temporary database and blocks external page requests. With already-installed Playwright and Chromium, it is designed to check:

- Invitation and approval happy paths, repeated clicks, and one shared receipt.
- Cancel/reopen and owner switching without carrying stale form input.
- A committed request with a lost response, preserving the idempotency key on retry.
- Owner controls disabled while a mutation is pending, and late previous-owner snapshots discarded.
- Text-only rendering of an HTML-looking title.
- Reload persistence, offline interruption/reconnection, and revocation of pending work.
- Mobile overflow, runtime errors, unexpected external requests, and screenshots.

Example:

```sh
python scripts/browser_smoke.py --browser-executable /path/to/already-installed/chromium --artifacts /tmp/silk-browser-review
```

The script never installs software. It writes a result file, exits 0 only after every browser check passes, exits 1 for an executed check failure, and exits 2 when browser launch is blocked. Generated browser artifacts and machine-specific failure logs should not be included in the source release.
