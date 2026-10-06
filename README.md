# Silk

Agent-to-agent coordination, with people in control.

Silk is being built around scoped invitations, explicit owner consent, authenticated messages, bounded conversations, and inspectable result receipts. This repository contains a deployable public website and a separately isolated working local broker.

**Current status:** the public experience is a development preview with a functional browser-only walkthrough. Live Grok → dot messaging is not connected. Owner authentication, shared durable storage, and supported persistent-agent integrations have not been configured or verified. The public API fails closed instead of accepting real messages.

## Two surfaces, separate boundaries

| Surface | Location | What works | Must not imply |
| --- | --- | --- | --- |
| Public website | `public/` | Product page, interactive consent walkthrough, truthful connection status | Real accounts, live agent messaging, or external execution |
| Public API | `api/`, `production/` | Readiness reporting and explicit 503 responses for unavailable live actions | A configured production broker |
| Local development broker | `silk/`, `web/` | Signed fixture messages, persisted consent, approvals, receipts, anti-replay/rate/TTL guards | Production identity, public authentication, or live provider integration |

The local broker is excluded from the Vercel upload/function bundle and is never a public website route.

## Preview the public website

Python 3.12+; no third-party runtime dependencies:

```sh
python scripts/serve_public.py --port 8787
```

Open http://127.0.0.1:8787. The walkthrough is an in-memory simulation. It creates no accounts, stores no messages, and contacts no provider. `/api/status` reports actual readiness; `/api/messages` and `/api/connections` reject POST with HTTP 503.

## Run the local broker

The local broker uses the separate development dependency:

```sh
python -m pip install -r requirements-dev.txt
python -m silk --port 8765
```

Open http://127.0.0.1:8765. Fictional Alice/Atlas and Bob/Nova demonstrate invitation → consent → signed request → proposal → owner decision → signed local receipt. The owner switcher is explicitly a fixture control, not real sign-in. Data persists in `var/silk.sqlite3` on that local machine only.

See [the local demo guide](docs/LOCAL_DEMO.md), [protocol](docs/PROTOCOL.md), and [security model](docs/SECURITY.md). No previous implementation or runtime database is required.

## Test

```sh
python -m unittest discover -v
node --check web/app.js
node web/ui-state-test.cjs
node --check public/app.js
node scripts/test_public_ui.cjs
python scripts/check_deploy.py
python scripts/demo.py
```

See [public verification](docs/PUBLIC_QA.md) and [local broker verification](docs/QA.md). Tests distinguish real HTTP behavior, mock-DOM state tests, and browser rendering. An unrun or blocked browser test is not a visual pass.

## Vercel deployment boundary

- Framework: Other (`framework: null`)
- Output directory: `public`
- Python API handlers: status, messages, connections
- Public runtime dependencies: standard library only
- Build command: `python3 scripts/check_deploy.py`
- No database file, owner switcher, fixture key, local broker, background thread, or real message endpoint is deployed
- Source/log public exposure is disabled in configuration

The deployment script creates an explicit allowlist bundle for review. Do not deploy the working directory wholesale through a custom uploader that ignores the boundary.

See [deployment instructions](docs/DEPLOYMENT.md) and [production migration requirements](docs/PRODUCTION.md). Deployment still requires access to the intended Vercel account/team and a plan appropriate for the intended use. This repository does not create accounts, accept new terms, enable billing, or provision storage.

## Live connection requirements

A model inference endpoint does not by itself expose a persistent consumer agent's inbox or wake mechanism. A real Grok → dot connection needs verified, supported inbound and outbound interfaces for the specific agents, owner-to-agent identity binding, explicit consent, durable admission/replay/budget controls, and a successful round trip. Until that exists, the public status stays disconnected and mutation routes stay disabled.

No payments, custody, escrow, financial execution, calendar booking, or distribution messages are implemented.
