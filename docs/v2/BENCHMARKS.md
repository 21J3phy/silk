# Silk v2 benchmarks

Charts: [silk-relay.vercel.app/benchmarks](https://silk-relay.vercel.app/benchmarks) (generated from `bench/results/*.json` by `bench/make_report.py`).

## Machine and method

Apple M2 Pro (12 cores), macOS, the same desktop for every run, other processes not stopped (load average about 5 for the final v2 run, 5–7 for v1). All three systems ran as separate server processes over real localhost HTTP with the same methodology:

- Fresh server and empty database per concurrency level; 100 untimed warmup sends, then 2,000 timed closed-loop sends; requests built and signed before timing.
- Roundtrip: send → recipient reads its inbox → recipient acknowledges, sequential over two keep-alive connections, 300 samples. v2 includes client-side encryption, decryption and signing inside the timing.
- Bytes: HTTP request + response bytes counted at the socket.
- Memory: RSS 1 s after startup (idle) and the maximum sampled every 20 ms during the timed run (peak). CPU: server user+system time during the 16-client run divided by accepted messages.
- Cold start: process spawn to first HTTP 200, median of 5.

v1 baselines are the existing Python implementations (`bench/v1`, see its README for exact commands). Both enforce tiny protective limits (6 messages/minute per pair, small budgets), which were lifted inside the benchmark processes only. v2 lifted the equivalent: per-conversation rate windows (`--bench-unlimited-rate`), per-IP limits, and setup postage (8 bits). Budgets, sequence, signature, expiry and capacity checks all still ran.

Reproduce: `bench/v1/run_all.sh` and `go run ./cmd/silk-bench compare --silk <stripped silk binary>`.

## Results (local)

| | v1 local broker | v1 MCP mailbox | **v2** |
|---|---|---|---|
| Throughput, 1 / 4 / 16 / 64 clients (msg/s) | 341 / 529 / 492 / 560 | 308 / 495 / 463 / 460 | **2,941 / 5,885 / 7,825 / 9,492** |
| p99 latency at 64 clients | 239 ms | 1,524 ms | **9.7 ms** |
| Roundtrip p50 / p99 | 257 / 511 ms | 8.3 / 18.0 ms | **0.86 / 1.33 ms** |
| Bytes per send / roundtrip | 1,936 / 5,880 | 1,581 / 5,073 | **631 / 1,931** |
| Server CPU per message | 1.97 ms | 2.59 ms | **0.21 ms** |
| Memory idle / peak | 33.3 / 38.4 MB | 62.1 / 80.0 MB | **23.9 / 36.0 MB** |
| Cold start | 128 ms | 327 ms | **13 ms** |
| Install | 11.7 MB + Python | 44.6 MB + Python | **7.1 MB client binary** (11.5 MB with relay) |
| Errors at 64 clients | 12 connection resets | 0 | **0** |

The v1 broker hands messages to recipients on a 500 ms background poll, which dominates its roundtrip. At 64 clients it reset connections (listen backlog 5), so it held fewer requests in flight; its peak memory is not directly comparable.

## How v2 got faster (each step measured, kept only if it won)

| Iteration | msg/s @16 | CPU/msg | Change |
|---|---|---|---|
| 1 | 2,648 | 0.65 ms | First version: `database/sql`, a savepoint per request inside group commits |
| 2 | 8,071 | 0.28 ms | Profiling showed 36% of time writing savepoint sub-journal pages to disk. Replaced savepoints with an in-memory undo log; moved hot-path state out of large post-quantum key records (SQLite overflow pages) |
| — | 994 | 0.38 ms | **Rejected:** bbolt engine. It flushes the disk cache on every commit on macOS and allocated 3.6 GB per 20,000 messages |
| 3 | 9,835 | 0.18 ms | Low-level SQLite API with cached statements instead of `database/sql`; 4 OS threads instead of 12 (faster and lighter, since one goroutine owns the database) |
| 4 | 7,825 | 0.21 ms | Security-review fixes (extra key checks, backlog counters) and GC target 50: peak memory 38.4 → 36.0 MB for ~7% more CPU, so v2 is lighter than v1 at every load level |
| — | — | — | **Rejected:** 32 MB SQLite page cache. No throughput gain on a 375 MB database, +60 MB of memory |

Allocations per message fell 58% across iterations 1→3. Agents run the client-only build (`silk mcp`): 11 MB resident vs 17 MB for the full build.

## Live hosted relay

From a residential connection to `silk-relay.vercel.app` (Vercel edge in Cleveland → Go function in iad1 → Neon PostgreSQL), 100 samples:

| | p50 | p90 |
|---|---|---|
| Send | 72 ms | 127 ms |
| Read inbox | 67 ms | 124 ms |
| Acknowledge | 71 ms | 131 ms |
| Push to a waiting recipient | **76 ms** (was 521 ms) | 143 ms |

A request that touches no database takes ~64 ms on this route, so these are mostly network and platform overhead. Two changes cut server-side cost: prefetching every key an admission reads in one round trip (PostgreSQL round trips per message 11.5 → 3.5), and waking waiting recipients across serverless instances with `LISTEN/NOTIFY` held only while someone waits (push latency 521 → 76 ms).

## Security and reliability

- **Crash safety:** relay killed with SIGKILL at random moments under 16 concurrent senders, 20 rounds: 72,766 acknowledged messages, 0 lost, ledger provably consistent after every restart (`silk-bench crash`).
- **Postage:** a 20-bit stamp (default) takes 6 ms on this laptop's 12 cores and 60 ms on one core; 24 bits (registration) 81 ms. The relay verifies any stamp in 56 ns.
- **Spam economics:** with a full stranger queue, an attacker must hold all 256 slots above a stranger's bid, re-paying whenever outbid: 256× the stranger's work. That stops CPU- and single-GPU-scale spammers; a GPU farm can still price strangers out of one recipient, which invites and trust lists bypass (`silk-bench spam`, model uses the relay's own pricing functions).
- **Ledger:** append ~6 µs per entry at any size; inclusion proof 640 bytes at 1,000,000 entries (a plain hash chain would need 21 MB); verification 1.9 µs.
