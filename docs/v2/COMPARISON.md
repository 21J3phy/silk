# Silk compared with other agent messaging systems

Charts: [silk-relay.vercel.app/compare](https://silk-relay.vercel.app/compare) (built from `bench/results/competitors/*.json` by `bench/make_compare.py`).

## What was compared

| System | What it is | Version measured |
|---|---|---|
| **Silk 2.1** | This project: consent-gated, post-quantum end-to-end encrypted agent messaging with a public ledger | 2.1.0 release binaries |
| [A2A](https://a2a-protocol.org) | Linux Foundation agent-to-agent protocol; the remote agent runs an HTTP server | `a2a-sdk` 1.2.2 (Python), `a2a-go/v2` 2.6.0 (Go), official SDK servers with their in-memory task store |
| [XMTP](https://xmtp.org) | MLS-based messaging network with an agent SDK | `@xmtp/node-sdk` 6.1.0 on the public **dev** network |
| [AMP](https://github.com/Fareground/agent-messaging) | Consent-based, end-to-end encrypted agent messaging (double ratchet) | `fg-amp` 0.12.1, its relay with SQLite |
| [MCP Agent Mail](https://github.com/Dicklesworthstone/mcp_agent_mail) | MCP server giving coding agents inboxes (SQLite + Git archive) | git `3fad5ec` |

AgentMail (hosted email for agents) and Meta/Sierra's Personal Agent Protocol (agent-to-business, spec not yet published) were not measured: the first is a paid hosted email API, the second has no implementation yet.

## Method

**Same machine.** Every server ran as its own process on one Apple M2 Pro laptop, driven by one load generator (`silk-bench foreign`, `silk-bench external` for AMP, whose encryption lives in its client library) with Silk's published method: fresh server per concurrency level, 100 untimed warmup and 2,000 timed closed-loop sends, one keep-alive connection per client, server memory and CPU read from the server process, bytes counted at the socket. All runs were back to back in one session (background load from other apps was present for all of them).

**Over the internet.** Two agent processes per system on the same home connection, in the same session: Silk's `silk mcp` (what Claude Code and Codex run) through the hosted relay, and XMTP's Node SDK through its dev network. Delivery is measured to a recipient that is already waiting; the reply round trip has both sides listening, as agents do.

Reproduce: `bench/competitors/*/` hold each server, spec and driver; `go run ./cmd/silk-bench foreign --spec bench/competitors/a2a-go/spec.json --out ...`.

## Results

<!-- results:start -->
**Same machine, same load** (each system's faster of two back-to-back runs):

| | Silk 2.1 | A2A Go SDK | A2A Python SDK | MCP Agent Mail | AMP (Fareground) |
|---|---|---|---|---|---|
| Throughput, 16 clients (msg/s) | 7,732 | 29,431 | 1,364 | 6.2 | 1,704 |
| Throughput, 64 clients (msg/s) | 9,374 | 30,537 | 1,287 | 0.6 | 1,871 |
| p99 latency, 64 clients | 14.5 ms | 5.9 ms | 137.5 ms | 58,789.6 ms | 59.5 ms |
| Deliver + acknowledge, p50 | 0.72 ms | 0.10 ms | 0.86 ms | 105.84 ms | 3.81 ms |
| Bytes to send | 680 B | 904 B | 920 B | 2,077 B | – |
| Bytes to deliver + acknowledge | 2,029 B | 904 B | 920 B | 5,058 B | 5,479 B |
| Server CPU per message | 0.205 ms | 0.160 ms | 0.720 ms | 119.435 ms | 2.133 ms |
| Server memory idle / peak | 23.8 / 36.8 MB | 10.7 / 22.6 MB | 52.7 / 149.5 MB | 131.3 / 212.5 MB | 68.1 / 80.6 MB |
| Cold start | 14 ms | 6.4 ms | 198 ms | 885 ms | 277 ms |
| Install | 11.4 MB | 6.3 MB | 40.8 MB | 238.0 MB | 40.6 MB |

**Over the internet** (medians, the back-to-back pair):

| | Silk (hosted relay) | XMTP (dev network) |
|---|---|---|
| Send | 73 ms | 49 ms |
| Delivery to a waiting recipient | 79 ms | 52 ms |
| Ask and get a reply | 204 ms | 126 ms |
| New identity ready | 689 ms | 474 ms |
| Agent ready from existing identity | 8.4 ms | 256.2 ms |
| Client memory, peak | 22 MB | 115 MB |
| Client CPU per message | 4.5 ms | 6.3 ms |
| Network bytes per message sent | 557 B | 1,336 B |
| Client install | 6.2 MB | 147.2 MB |
<!-- results:end -->

## Read the numbers with this in mind

- **Silk does more per message than most.** Each accepted Silk message has its Ed25519 signature verified, budget and sequence checked, post-quantum end-to-end ciphertext stored with an fsync, and a ledger entry appended. The A2A servers keep nothing (in-memory, no signatures, no encryption beyond optional TLS), so A2A's Go server is faster and lighter than Silk on raw throughput, latency, CPU and memory. That is the price of durability and verification, and the charts show it.
- **A2A is a different shape.** An A2A server *is* the receiving agent, so one request delivers the message and returns the reply, and the recipient must be online with a public endpoint. Silk is store-and-forward: a send is the deposit, and the recipient picks it up later.
- **MCP Agent Mail's main cost is Git.** Each message is also written as Markdown files and committed; the Git child processes are not counted in its server CPU and memory, so its numbers are, if anything, flattering.
- **AMP's numbers include its Python client** (encryption, signing, receipts), because that is where its protocol runs.
- **XMTP ran on its dev network** in AWS us-east-2; Silk's relay runs on Vercel (iad1) with Neon Postgres (us-east-1). Both are about 22 ms from the test machine. Silk's hosted relay is serverless: each request pays about 40 ms of platform overhead (the relay's own work is 7–9 ms, visible in its `Server-Timing` header), while XMTP keeps one gRPC connection open. That is why XMTP sends and delivers faster over the internet today.
- **The protections table** lists the properties Silk was designed around, scored from each project's documentation; it is not a neutral feature survey.
