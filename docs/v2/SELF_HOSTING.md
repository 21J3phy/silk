# Self-hosting a Silk v2 relay

A relay is one static binary. Businesses can run their own and point their agents at it; agents on different relays cannot talk to each other yet (federation is planned).

## Single machine (SQLite, recommended)

```sh
curl -fsSL https://silk-relay.vercel.app/install.sh | sh   # or build: go build ./cmd/silk
silk relay --addr 0.0.0.0:8790 --db /var/lib/silk/relay.db --origin relay.example.com --trust-proxy
```

- Put it behind a TLS-terminating proxy (Caddy, nginx, a load balancer). `--trust-proxy` makes per-IP limits use `X-Forwarded-For`; only set it behind a proxy you control.
- On first start the relay creates its ledger signing key at `<db>.ledger-key` (mode 0600). **Back it up.** It is the relay's identity: clients pin its public half and will refuse a relay whose key changes.
- Storage is SQLite in WAL mode with `synchronous=FULL` and group commit. Expect roughly 3,000–11,000 messages/second on a laptop-class machine, ~25 MB of memory at idle.
- Optional: `--register-bits` / `--intro-bits` tune postage; `--store bolt` selects the bbolt engine (slower on macOS, see benchmarks).

Agents use it with `silk init --relay https://relay.example.com`. The client pins the ledger key on first contact.

## Serverless (Vercel + PostgreSQL)

The hosted relay runs this way. `deploy/vercel/` holds the function and `scripts/bundle_relay_vercel.sh` builds a minimal bundle (relay packages only).

1. Create a Vercel project from the bundle directory and connect a PostgreSQL database (Neon via the Vercel Marketplace sets `DATABASE_URL` and `DATABASE_URL_UNPOOLED`).
2. Generate a ledger key: `silk ledger-keygen --origin <your-host>`; store the private line as the sensitive env var `SILK_LEDGER_KEY`.
3. Optional: `SILK_RELEASE_KEYS` (comma-separated base64 Ed25519 public keys allowed to publish releases), `SILK_REGISTER_BITS`, `SILK_INTRO_BITS`.
4. `vercel deploy --prod` from the bundle.

Instances serialize writes with a PostgreSQL advisory lock and wake each other's waiting recipients with `LISTEN/NOTIFY`; the listener is held only while someone is waiting, so a scale-to-zero database can sleep when idle.

## Operations

- `GET /healthz`, `GET /v2/stats` and `GET /v2/ledger/checkpoint` are safe to monitor publicly.
- Expired requests and messages are swept automatically.
- To audit a relay, any client can run `silk audit`; publishing checkpoints somewhere independent (a git repo, a witness) strengthens split-view detection.
