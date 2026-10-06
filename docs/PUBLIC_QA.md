# Silk public-boundary QA

Verified on 2026-10-06 in the cloud build workspace. This report covers the deployable public preview and its separation from the local fixture broker. It does **not** certify a hosted Vercel build, real browser rendering, owner authentication, a durable production store, or live Grok ↔ dot delivery.

## Result

- **138 Python tests passed:** 88 original local-broker tests and 50 new public-boundary tests.
- **Public build guard passed:** four static assets and three public API entry points.
- **Public JavaScript syntax passed.**
- **Public walkthrough model/mock-DOM harness passed:** 22 checks, including consent order, duplicate actions, decline, revocation before/after approval, deadline boundaries, countdown/resume, reset/focus, and status-service failure or invalid-data fallbacks. This is not a browser rendering pass.
- **Original local UI state harness passed:** eight reported categories.
- No credentials were used, accounts connected, external agents contacted, external messages sent, or deployment performed by this QA work.

The deployable surface is an explicitly labeled browser simulation plus truthful readiness information. It does not expose the fixture owner switcher or create a real connection. POST requests to connection/message endpoints always return HTTP 503, including requests carrying forged identity, session, and authorization values.

## Reproduce

From the repository root:

```sh
python -m unittest discover -v
python scripts/check_deploy.py
python -m compileall -q production api production_tests silk tests scripts
node --check public/app.js
node scripts/test_public_ui.cjs
node --check web/app.js
node web/ui-state-test.cjs
```

The original broker tests require the development dependency in `requirements-dev.txt`. The public production modules use Python's standard library only. No dependency was installed for this verification.

## Coverage

### Interfaces: 13 tests

- Both unconfigured adapters advertise no authenticated inbox, wake, delivery, idempotency, identity, or evidence.
- Every inbound authentication, delivery, and wake attempt rejects before inspecting the job.
- Unknown provider identifiers reject rather than silently selecting a fixture or another adapter.
- All declared capabilities and supporting evidence are needed for the structural capability check.
- Identity, admitted jobs, and capabilities are immutable dataclasses.
- Authentication is required first; missing, false, and merely truthy durability values reject.
- A durable flag alone cannot pass: admission, revalidation, and result-recording methods must be callable.
- Claimed adapter capabilities alone cannot pass: inbound authentication and outbound delivery/wake methods must be callable.
- The structural gate performs no authentication, storage, or provider call itself.
- Transport acceptance remains distinct from owner approval or external execution.

The structural gate only checks the interface shape. A mock satisfying it is not authentication, secure persistence, or evidence of an operational provider. Public mutation routes do not invoke that gate to enable delivery; they remain closed unconditionally.

### Readiness and API transport: 10 tests

- Readiness consistently reports development preview, no live messaging, no configured owner authentication/store, and both requested providers disconnected/unverified.
- Environment flags and synthetic key/database values cannot fabricate a connected status or appear in responses.
- Returned status objects are independent; mutating one cannot change later responses.
- Readiness and route rejection perform no file or network I/O.
- Unknown route names return 404; unsupported known-route methods return 405.
- The actual exported Python handlers were exercised over loopback HTTP, including GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, and CONNECT.
- HEAD returns metadata without a body. Wrong methods include the appropriate Allow header.
- Message/connection POST always returns 503 for absent input, forged owner/authorization/session input, invalid JSON, invalid UTF-8, and an oversized synthetic body.
- Rejections do not echo submitted content, set cookies, allow cross-origin access, or change later readiness.
- JSON responses include no-store, CSP, nosniff, frame denial, and no-referrer protections.

These checks execute the public handlers locally. Hosted routing and Vercel-added headers still require deployment verification.

### Deployment source boundary: 8 tests

- Static output is restricted to `public/`; public source/log exposure is disabled; no legacy build/routes/rewrites override the reviewed layout.
- Every public function is covered by exclusions for fixture code, the development UI, tests, scripts, artifacts, databases, and local runtime state.
- Deployment upload exclusions are present.
- Only the readiness, message-rejection, and connection-rejection Python entry points are present, including nested-path checks.
- Public assets contain no fixture session/state routes or owner-switcher controls.
- Public files have only reviewed asset types, with no hidden files, symlinks, databases, server code, credentials, or private-key markers.
- HTML scripts/styles/icons resolve within the public tree and do not require inline scripts.
- Public Python code imports neither the fixture broker, SQLite, nor local signing dependencies.

### Build-guard negative tests: 14 tests

Tests create temporary synthetic trees and confirm the guard rejects each of these regressions:

- An unexpected database/static file
- A private-key marker in an otherwise allowed asset
- Public file and directory symlinks
- A fixture API endpoint at the root or inside a nested directory
- An import from the local fixture broker
- A browser call to the fixture session endpoint
- A dynamic HTML injection sink or inline event handler
- Output pointed at the repository root
- Public source/log exposure enabled
- Missing function-bundle exclusions

A clean minimal public fixture also passes. No actual secret or real database was used in the negative fixtures.

### Local public-preview isolation: 5 tests

The local public-preview server was exercised over loopback HTTP. It serves the public index/styles/script and readiness/rejection endpoints. Fixture code, the development UI, SQLite paths, environment/configuration files, server source, fixture API routes, and traversal/encoded-path attempts all return 404.

This is a source-level/local transport test, not proof that Vercel serves the same route map.

## Findings fixed during review

1. The dependency gate initially accepted a durable flag or claimed capabilities without corresponding callable operations. Required storage and adapter operations are now checked, with regression tests.
2. TRACE and CONNECT initially fell through to the standard HTTP handler's default error response. They now use the same closed JSON/error-header path, with transport tests.
3. The build guard initially checked only top-level API Python files. It now rejects unreviewed nested endpoints.
4. The build guard initially checked symlinked files only. It now also rejects symlinked directories before collecting static files.

## Vercel configuration evidence

Vercel documents `outputDirectory` as the directory used for build output. Its `public` property controls public access to source/log views, so that property is kept false. [Official configuration reference](https://vercel.com/docs/project-configuration/vercel-json)

Python functions include reachable project files by default and do not automatically tree-shake unused source. The explicit `functions` / `excludeFiles` boundary is therefore needed in addition to the static output directory. Python handlers may subclass `BaseHTTPRequestHandler`. [Official Python runtime documentation](https://vercel.com/docs/functions/runtimes/python)

The `.vercelignore` file provides a separate upload exclusion boundary. [Official deployment exclusion documentation](https://vercel.com/docs/deployments/vercel-ignore)

These sources establish the intended configuration semantics. No Vercel-generated function bundle was inspected during this local QA pass.

## Still unverified / release checks

- A successful Vercel build for the exact intended repository commit, project, and environment
- Hosted GET `/api/status`, HEAD, method rejection, POST `/api/messages`, and POST `/api/connections`
- Hosted 404 responses for `/api/session`, `/api/state`, `/web/index.html`, `/silk/server.py`, and `/var/silk.sqlite3`
- Hosted function bundle contents and actual response security headers
- Real desktop/mobile browser rendering, focus behavior, layout, and accessibility; mock-DOM tests are not substitutes for a rendered browser pass
- Real provider identity, owner-to-agent binding, consent enforcement across owners, shared durable storage, and a demonstrated provider round trip
- Any claim of autonomous wake-up, message receipt, owner approval, external scheduling, or other real-world execution

No blocked browser route was retried or bypassed. No screenshots of a new public deployment were produced in this pass. The UI must remain labeled as a simulation until separate end-to-end evidence establishes a live feature.
