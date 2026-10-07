# v1 baseline benchmark

Reproducible performance baseline for the two existing Python v1 implementations, measured over
real localhost HTTP against the unmodified code, so a v2 implementation can be compared with them.

| System | What runs | Results |
| --- | --- | --- |
| `v1-broker` | `python -m silk` (`silk/server.py`, `silk/service.py`, `silk/protocol.py`): signed Ed25519 envelope ingress at `POST /api/envelopes`, 500 ms background dispatcher | `bench/results/v1-broker.json` |
| `v1-mailbox` | `services/mailbox` (`silk_live`): MCP Streamable HTTP JSON-RPC at `POST /mcp`, tools `silk_send` / `silk_receive` / `silk_ack`, real JWT verifier, `SQLiteFixtureStore`, served by uvicorn | `bench/results/v1-mailbox.json` |

## Run

```sh
bench/v1/run_all.sh
```

The script, in order:

1. recreates `bench/v1/.venv` with `uv venv --no-project --clear --python 3.12` and installs
   `requirements-dev.txt`, `services/mailbox/requirements.txt` and `psutil==7.2.2` (psutil is used
   only by the benchmark client to read server RSS/CPU). If the install fails, it retries without
   the `psycopg` line.
2. runs `footprint.py`: fresh per-server venvs, `du -sk` of their site-packages, an import smoke
   test, then deletes them.
3. runs `bench_broker.py`, then `bench_mailbox.py`.
4. kills any server it started and checks that nothing is still listening on the two ports.

A full run takes about 4 minutes. Nothing is committed, pushed or deployed. Temporary SQLite DBs
and server logs go to `$TMPDIR/silk-bench-*` and are deleted afterwards unless `BENCH_KEEP=1` is
set.

Environment knobs (defaults): `BENCH_BROKER_PORT=8765`, `BENCH_MAILBOX_PORT=8790`,
`BENCH_REQUESTS=2000`, `BENCH_WARMUP=100`, `BENCH_RT_SAMPLES=300`, `BENCH_LEVELS=1,4,16,64`,
`BENCH_KEEP=1`. Each script refuses to start if its port is already in use.

## Files

| File | Purpose |
| --- | --- |
| `run_all.sh` | Single entry point; recreates everything |
| `launch_broker.py` | Benchmark-only broker launcher: rebinds three limit globals, then calls the unmodified `silk.server.main()` |
| `launch_mailbox.py` | Benchmark-only mailbox launcher: `create_app(Settings, SQLiteFixtureStore, JWTAccessTokenVerifier, testing=True)` under `uvicorn.run(..., access_log=False)` |
| `mailbox_fixture.py` | Shared mailbox identifiers (issuer, resource, Host header) and store capacities |
| `bench_broker.py`, `bench_mailbox.py` | Drivers: cold start, throughput, roundtrip, wire bytes, RSS, CPU |
| `common.py` | Raw asyncio HTTP client, closed-loop runner, process lifecycle, psutil monitor, statistics |
| `footprint.py` | Install footprint |

## Limit overrides (exact)

Overrides apply only inside the benchmark server processes. No source file is edited.

**v1-broker**: `launch_broker.py` rebinds these module globals of `silk.service` before the server
object is built. `service.py` imports them with `from .protocol import ...`, so the names bound in
`silk.service` are the ones its checks read.

| Name | Default | Benchmark | Where it is enforced |
| --- | --- | --- | --- |
| `silk.service.RATE_PER_MINUTE` | 6 | 1,000,000 | `Service._receive`: per sender→recipient rolling-minute limit |
| `silk.service.MAX_TURNS` | 8 | 1,000,000 | `Service.create_invitation`: largest accepted `max_turns` |
| `silk.service.MAX_MESSAGES` | 1000 | 1,000,000 | `Service._receive`: local message storage cap |

The benchmark grant is created through the real HTTP flow (`GET /api/session`, `POST
/api/invitations` as alice with `max_turns=1000000`, switch to bob, `POST
/api/invitations/<id>/accept`).

Invitation limits (5 per minute, 200 stored) and the session cap (128) are untouched. One grant is
created per server.

**v1-mailbox**: no module is patched.

* `SQLiteFixtureStore` capacities are passed as its own constructor arguments:
  `max_messages` 1024→1,000,000, `max_receipts` 1024→1,000,000, `max_agents` 128→100,000,
  `max_bindings` 256→100,000, `max_grants` 1024→100,000.
* The 6 sends per minute per agent pair is the hard-coded literal `if rate >= 6` in
  `storage.py`. The 32-turn grant budget is a SQLite `CHECK(max_turns BETWEEN 1 AND 32)` plus
  `provision_grant` validation. Neither is a module constant, so neither is patched. The
  workload avoids them instead. The fixture is a star: one sender agent, plus one recipient agent
  and one 32-turn grant per 6 sends. Send *i* uses pair *i // 6*. Every rate, budget and capacity
  check still executes on every request, and none trips.

Everything else is the code as written: signature and JWT verification, validation, SQLite
transactions, journal modes, the `synchronous` default (FULL), thread pools, logging, the
dispatcher interval, and the socket backlog.

## What is measured

All servers are separate processes on `127.0.0.1`. The load generator is a single Python 3.12
asyncio process. It writes pre-built request bytes on raw sockets and parses responses minimally,
with no httpx. Broker envelopes are Ed25519-signed and every request is fully built before timing
starts. The client's own CPU use is reported in the notes. In the committed run it stayed at or
below 13% of one core.

| Metric | Definition |
| --- | --- |
| `send_throughput` | For each concurrency c ∈ {1, 4, 16, 64}: a fresh server and empty DB, 100 untimed warmup sends, then N=2000 timed sends in a closed loop (each worker sends its next request as soon as its previous response is fully read). `msgs_per_sec` = accepted sends / wall seconds. p50/p90/p99 are over accepted sends. `errors` = timed sends not accepted, never retried. |
| `roundtrip_ms` | 300 sequential samples after a short warmup. **Broker:** t0, then `POST /api/envelopes`, then poll `GET /api/state` as bob (the endpoint the web UI polls every 2 s; here a 5 ms gap after each response) until that message is `awaiting_approval`, then t1. An untimed U(0, 500 ms) pause before each sample spreads sends evenly across the dispatcher's 500 ms cycle (see caveats). **Mailbox:** t0, then `silk_send`, then the recipient's `silk_receive` must contain that message, then `silk_ack`, then t3. |
| `wire_bytes` | HTTP bytes only, both directions: request line, headers and body, plus status line, headers and body. TCP/IP framing is excluded. Clients send only the headers each protocol needs (broker: Host, Content-Type, Content-Length, plus Cookie for state; mailbox: Host, Authorization, Accept, Content-Type, MCP-Protocol-Version, Content-Length). **Broker roundtrip** = send + the one `/api/state` response that observed the message, on a fresh DB holding only that message. The empty polls before it are excluded but quantified in the notes. **Mailbox roundtrip** = send + receive + ack. |
| `rss_mb` | psutil RSS of the server process. `idle` = median across the throughput servers, taken 1 s after the first healthy `/health`. `peak` = maximum sampled every 20 ms during warmup, the timed run and (for the broker) the dispatcher drain, across all levels. |
| `cpu_ms_per_msg` | Server user+sys CPU delta across the c=16 timed run ÷ accepted sends. For the broker this includes dispatcher work done during the run. The notes also give the figure including the post-run drain. |
| `cold_start_ms` | Median of 5 runs, timed from `Popen` to the first HTTP 200 from `GET /health`, with a new DB file each time. Broker: the real unpatched `python -m silk --port 8765 --db <new>`. Mailbox: `launch_mailbox.py`, because the repo's `silk_live.asgi` without Postgres configuration only serves the fail-closed app. |
| `install_mb` | `du -sk` of site-packages in a fresh 3.12 venv holding only that server's requirements file. `.pyc` files and the interpreter (56 MB) are excluded. The mailbox figure includes `psycopg[binary]` (17.7 MB), which deployment needs but the SQLite fixture server does not use. |

## Fidelity: what is real and what is approximated

* **Mailbox auth** uses the real `JWTAccessTokenVerifier` on every request: header and claim
  allowlists, RS256 2048-bit signature, and iss/aud/client_id/iat/exp checks. Only its JWKS
  fetcher is the injected trusted dependency the tests use. The verifier accepts only pinned
  `https://` DNS URLs with TLS verification, which `127.0.0.1` cannot serve without altering trust
  stores. JWKS is cached for 300 s, so after the first request the cost is the same.
* **Mailbox Host:** settings mirror the tests (`https://silk.example/mcp`). Clients connect to
  `127.0.0.1:8790` and send `Host: silk.example`, so the app's Host/Origin boundary and the SDK's
  DNS-rebinding check run and pass. TLS is not part of the measurement.
* **Mailbox logging:** the MCP SDK's default INFO logging (one "Processing request" line per
  call) stays on, with stderr redirected to a temp log file.
* **No MCP `initialize` per call.** The server is stateless. A real SDK client initializes once
  per session and then sends exactly one POST per tool call, which is what is timed.
* **Broker signing keys** are fixture seeds stored in the broker's own SQLite DB. The client reads
  the atlas seed read-only and signs with `silk.protocol.sign_record`, the same function
  `Service.fixture_envelope` uses in the tests.
* **Broker growth:** with limits lifted, some per-request queries grow with the number of stored
  messages:
  * the rate-limit `COUNT` covers every message from the last minute
  * `SELECT COUNT(*) FROM messages` runs on every send
  * `_expire()` scans queued and awaiting rows on every send and every `/api/state`

  The unpatched system never stores more than 6 messages per minute per pair or 1000 rows in
  total, so it never pays this. `/api/state` returns the recipient's full history: about 3.9 KB
  with 1 message and about 260 KB after 305.

## Caveats found while measuring

* **Broker connection resets at c ≥ 8.** `ThreadingHTTPServer` listens with socketserver's
  default backlog of 5 (`request_queue_size`), and `silk/server.py` leaves it unchanged. macOS
  answers accept-queue overflow with RST at `connect()`. The run includes a probe that isolates
  this from app work: `GET /health` from 4 / 8 / 16 concurrent connectors gives roughly 0% / 30% /
  50% resets. These count as throughput `errors` and are not retried. No message is admitted, so
  retrying would be safe.
* **Dispatcher phase-lock.** The broker dispatcher wakes every 500 ms. A purely back-to-back
  sequential client sends right after each dispatch and always waits a full cycle: about 505 ms
  per sample in a trial run. The seeded random pause before each sample removes this artifact, so
  the reported roundtrip is about U(0, 500 ms) plus processing.
* **Mailbox tail latency at c ≥ 16.** Every store call opens its own SQLite connection in anyio's
  worker pool (up to 40 threads) and uses `BEGIN IMMEDIATE` with `busy_timeout=10 s`. SQLite's
  busy handler sleeps in growing steps of up to 100 ms. This is the likely cause of the
  multi-hundred-millisecond p99s, but it was not separately instrumented.
* **Noise.** The machine was a shared desktop (Apple M2 Pro, 12 cores, 16 GB) with load average
  about 5–7 from unrelated processes and nearly full disk. Nothing else was stopped. Expect about
  ±20% run-to-run on throughput. The notes in each JSON record per-run details, and two
  consecutive full runs are compared at the end of this file.
* **Versions.** Both servers ran from one venv with cryptography 50.0.0 (pinned by the mailbox
  requirements). The broker-only footprint venv resolves cryptography 50.0.2.

## Comparing v2

Use the same conventions so numbers are comparable:

* a fresh server per concurrency level
* 100 warmup + 2000 timed sends, closed loop
* pre-built requests with the minimal header set
* connection-per-request only if the server forces it; otherwise keep-alive
* HTTP-only byte counting
* RSS sampled every 20 ms
* CPU delta over the c=16 timed run
* cold start = spawn → first healthy `/health`, median of 5

Report errors instead of retrying.
