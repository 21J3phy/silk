# Public deployment handoff

## What can be deployed now

The isolated public website plus three Python API handlers. The website's walkthrough is a browser-only simulation. Its status API states that live messaging is unavailable. POSTing to the two live-action placeholders returns HTTP 503 and does not process or persist the submitted content.

This is a development preview, not a production messaging launch. Do not describe it as a live Grok → dot connection.

## Runtime configuration

`vercel.json` selects `framework: null`, `outputDirectory: public`, and a stdlib-only Python build validation command. The Vercel Python runtime supports a `BaseHTTPRequestHandler` subclass exported as `handler`, used by the three files under `api/`. [Official Python runtime documentation](https://vercel.com/docs/functions/runtimes/python).

Static files are confined to `public/`. Python function exclusions and `.vercelignore` additionally remove the local broker, owner-switching UI, tests, runtime databases, generated artifacts, and development dependencies. `public: false` keeps Vercel's source/log public view disabled; it does not make the website private. A deployment's actual URL/access settings must be verified separately. [Official configuration documentation](https://vercel.com/docs/project-configuration/vercel-json).

## Exact public source allowlist

The generated deployment manifest is authoritative. It contains only:

- `public/index.html`, `public/styles.css`, `public/app.js`, optional `public/model.js`, `public/favicon.svg`, `public/robots.txt`
- `api/status.py`, `api/messages.py`, `api/connections.py`
- `production/__init__.py`, `production/http.py`, `production/readiness.py`, `production/interfaces.py`
- `scripts/check_deploy.py`
- `vercel.json`, `.python-version`, `requirements.txt`, `.vercelignore`

No `.env`, API credentials, private keys, local SQLite database, fixture source, or dependency directory belongs in this bundle. No secret environment variables are needed for the present preview.

## Before deployment

1. Verify the target repository/account/team and its access. A denied team scope is a permission blocker, not a reason to try another account or route.
2. Confirm the hosting plan allows the intended use. Do not silently upgrade, create paid resources, or enable usage charges.
3. Run the tests and `python scripts/check_deploy.py`.
4. Produce the isolated deployment bundle with `python scripts/package_public.py`.
5. Review the generated manifest and deploy exactly its files through the authorized route.
6. After deployment, verify the actual deployment ID, URL, build result, access level, security headers, page assets, and APIs. Test the website on desktop and mobile. Source checks alone do not prove Vercel routing or rendering.
7. Verify `GET /api/status` returns `live_messaging: false`, both connections disconnected, and `POST /api/messages`/`connections` returns 503. Verify `/api/session`, `/api/state`, `/var/`, `/web/`, and `/silk/` do not expose fixtures or data.

No deployment command is auto-run by this repository. No Git remote or account is embedded.

## Persistence and background work

Vercel explicitly documents ephemeral function storage and the lack of a shared persistent local filesystem suitable for a writable SQLite broker. [Official SQLite guidance](https://vercel.com/kb/guide/is-sqlite-supported-in-vercel). Writable `/tmp` is scratch space, not the broker's durable mailbox or replay ledger. [Official runtime filesystem documentation](https://vercel.com/docs/functions/runtimes).

Do not run `python -m silk` inside a Vercel Function, start the local background thread from a handler, or copy the database into `/tmp`. See `PRODUCTION.md` for the required durable service boundary.
