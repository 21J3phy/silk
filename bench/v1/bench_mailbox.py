"""v1 MCP mailbox benchmark (services/mailbox over uvicorn, MCP Streamable HTTP).

Writes bench/results/v1-mailbox.json. Run via bench/v1/run_all.sh.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time

import common as C

sys.path.insert(0, str(C.REPO / "services" / "mailbox"))
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from silk_live.domain import Principal  # noqa: E402
from silk_live.storage import SQLiteFixtureStore  # noqa: E402

import mailbox_fixture as F  # noqa: E402

PY = sys.executable
PORT = int(os.environ.get("BENCH_MAILBOX_PORT", "8790"))
LEVELS = [int(x) for x in os.environ.get("BENCH_LEVELS", "1,4,16,64").split(",")]
N = int(os.environ.get("BENCH_REQUESTS", "2000"))
WARMUP = int(os.environ.get("BENCH_WARMUP", "100"))
RT_SAMPLES = int(os.environ.get("BENCH_RT_SAMPLES", "300"))
RT_WARMUP = 6
COLD_RUNS = 5
SENDS_PER_PAIR = 6   # storage.py: `if rate >= 6` (hard-coded literal, per agent pair, rolling 60 s)
GRANT_TURNS = 32     # schema CHECK(max_turns BETWEEN 1 AND 32); provision_grant enforces the same
TEXT = "Can we coordinate a time? This is untrusted message data."  # from tests/test_mcp_roundtrip.py

LIMITS_OVERRIDDEN = [
    "SQLiteFixtureStore constructor capacities (configuration arguments, no code patch): max_messages 1024 -> 1000000, max_receipts 1024 -> 1000000, max_agents 128 -> 100000, max_bindings 256 -> 100000, max_grants 1024 -> 100000",
    "Not patched, avoided by workload shape: the 6 sends/minute per agent pair (hard-coded literal in storage.py _MailboxStore.send) and the 32-turn per-grant budget (SQLite CHECK constraint + provision_grant validation) are not module constants, so no code was changed. Instead the fixture is a star: 1 sender agent and one recipient agent + one 32-turn grant per 6 sends, and send i uses pair i // 6. Every rate/budget/capacity check still executes on every request; none trips.",
]


# ----------------------------------------------------------------------------- fixture

class Keys:
    def __init__(self, workdir: Path):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid=F.KID, alg="RS256", use="sig", key_ops=["verify"])
        self.jwks_path = workdir / "jwks.json"
        self.jwks_path.write_text(json.dumps({"keys": [jwk]}))

    def token(self, subject: str, now: int) -> str:
        return jwt.encode(
            {"iss": F.ISSUER, "aud": F.RESOURCE, "sub": subject, "client_id": F.CLIENT_ID,
             "iat": now - 1, "exp": now + 3600, "scope": "silk:mailbox"},
            self.key, algorithm="RS256", headers={"typ": "at+jwt", "kid": F.KID})


def provision(db: Path, pairs: int, recipient_bindings: bool, now: int):
    """Fixture provisioning with the store's own test-only helpers (as tests do)."""
    store = SQLiteFixtureStore(db, **F.CAPACITIES)
    store.provision_agent("agent-sender", "owner-sender", "Bench sender")
    store.provision_binding(Principal(F.ISSUER, "subject-sender", F.CLIENT_ID), "agent-sender", expires_at=now + 7200, now=now)
    recipients = []
    for k in range(pairs):
        agent, grant, subject = f"agent-r{k:05d}", f"grant-r{k:05d}", f"subject-r{k:05d}"
        store.provision_agent(agent, f"owner-r{k:05d}", f"Bench recipient {k}")
        store.provision_grant(grant, "agent-sender", agent, expires_at=now + 7200, max_turns=GRANT_TURNS, max_ttl=300, now=now)
        if recipient_bindings:
            store.provision_binding(Principal(F.ISSUER, subject, F.CLIENT_ID), agent, expires_at=now + 7200, now=now)
        recipients.append((agent, grant, subject))
    return recipients


def rpc(identifier: int, tool: str, arguments: dict) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                       "params": {"name": tool, "arguments": arguments}}, separators=(",", ":")).encode()


def mcp_request(token: str, body: bytes) -> bytes:
    """Per-call headers an MCP Streamable HTTP client sends after initialize
    (stateless server: no Mcp-Session-Id)."""
    return C.build_request("POST", "/mcp", F.HOST, [
        ("Authorization", "Bearer " + token),
        ("Accept", "application/json, text/event-stream"),
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", F.PROTOCOL_VERSION),
    ], body)


def send_args(recipient, key: str) -> dict:
    agent, grant, _ = recipient
    return {"grant_id": grant, "recipient_agent_id": agent, "text": TEXT, "idempotency_key": key, "ttl_seconds": 300}


def tool_result(response):
    if not isinstance(response, C.Response) or response.status != 200:
        return None
    result = response.json().get("result")
    if not result or result.get("isError"):
        return None
    # Same decoding as tests/test_mcp_roundtrip.py: structuredContent if present,
    # else the JSON text content (FastMCP returns `-> dict` tools as text).
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def send_ok(response) -> bool:
    content = tool_result(response)
    return content is not None and content.get("status") == "queued" and content.get("duplicate") is False


def error_kinds(results) -> dict:
    kinds = Counter()
    for result in results:
        if send_ok(result):
            continue
        if not isinstance(result, C.Response):
            kinds[type(result).__name__] += 1
            continue
        try:
            body = result.json()
            if body.get("result", {}).get("isError"):
                kinds["tool error " + body["result"]["content"][0]["text"].split(":", 1)[0]] += 1
            else:
                kinds[f"HTTP {result.status}"] += 1
        except Exception:
            kinds[f"HTTP {result.status}"] += 1
    return dict(kinds)


def message_count(db: Path) -> int:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try:
        return con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    finally:
        con.close()


def launch(db: Path, keys: Keys, log: Path):
    return C.spawn([PY, str(C.HERE / "launch_mailbox.py"), "--port", str(PORT), "--db", str(db), "--jwks", str(keys.jwks_path)], log)


async def send(conn, request):
    return await conn.request(request)


# ----------------------------------------------------------------------------- phases

def cold_start(workdir: Path, keys: Keys):
    times = []
    for run in range(COLD_RUNS):
        started = time.perf_counter()
        proc = launch(workdir / f"cold-{run}.sqlite3", keys, workdir / "cold.log")
        try:
            healthy = C.wait_health(proc, PORT, F.HOST)
        finally:
            C.stop(proc)
        times.append((healthy - started) * 1000)
    return times


async def throughput_level(concurrency: int, workdir: Path, keys: Keys) -> dict:
    db = workdir / f"mailbox-c{concurrency}.sqlite3"
    now = int(time.time())
    total = WARMUP + N
    t_prov = time.perf_counter()
    recipients = provision(db, math.ceil(total / SENDS_PER_PAIR), False, now)
    provision_s = time.perf_counter() - t_prov
    token = keys.token("subject-sender", now)
    t_build = time.perf_counter()
    requests = [mcp_request(token, rpc(i + 1, "silk_send", send_args(recipients[i // SENDS_PER_PAIR], f"send-c{concurrency}-{i:06d}"))) for i in range(total)]
    build_ms = (time.perf_counter() - t_build) * 1000
    proc = launch(db, keys, workdir / f"mailbox-c{concurrency}.log")
    monitor = None
    try:
        C.wait_health(proc, PORT, F.HOST)
        monitor = C.Monitor(proc.pid)
        await asyncio.sleep(1.0)
        idle_mb = monitor.rss_mb()
        _, warm_results, _, _ = await C.closed_loop(concurrency, requests[:WARMUP], send, keepalive_port=PORT)
        warm_ok = sum(map(send_ok, warm_results))
        cpu0 = monitor.cpu_seconds()
        latency, results, wall, client_cpu = await C.closed_loop(concurrency, requests[WARMUP:], send, keepalive_port=PORT)
        cpu1 = monitor.cpu_seconds()
        await asyncio.sleep(0.2)
        peak_mb = monitor.peak_mb()
        stored = message_count(db)
    finally:
        if monitor:
            monitor.close()
        C.stop(proc)
    ok = [send_ok(r) for r in results]
    accepted_n = sum(ok)
    stats = C.percentiles_ms([lat for lat, flag in zip(latency, ok) if flag])
    return {
        "concurrency": concurrency, "requests": N, "seconds": round(wall, 3),
        "msgs_per_sec": round(accepted_n / wall, 1), "p50_ms": stats["p50"], "p90_ms": stats["p90"],
        "p99_ms": stats["p99"], "errors": N - accepted_n,
        "_accepted": accepted_n, "_warm_ok": warm_ok, "_errors": error_kinds(results), "_stored": stored,
        "_idle_mb": idle_mb, "_peak_mb": peak_mb, "_server_cpu_run": cpu1 - cpu0, "_client_cpu": client_cpu,
        "_build_ms": build_ms, "_provision_s": provision_s, "_pairs": len(recipients),
        "_token_bytes": len(token), "_request_bytes": len(requests[WARMUP]),
    }


async def roundtrip(workdir: Path, keys: Keys) -> dict:
    db = workdir / "mailbox-rt.sqlite3"
    now = int(time.time())
    total = RT_WARMUP + RT_SAMPLES
    recipients = provision(db, math.ceil(total / SENDS_PER_PAIR), True, now)
    sender_token = keys.token("subject-sender", now)
    recipient_tokens = [keys.token(subject, now) for _, _, subject in recipients]
    proc = launch(db, keys, workdir / "mailbox-rt.log")
    try:
        C.wait_health(proc, PORT, F.HOST)
        sender = await C.KeepAlive(PORT).open()
        receiver = await C.KeepAlive(PORT).open()
        samples, parts, wire = [], [], None
        for j in range(total):
            k = j // SENDS_PER_PAIR
            rpc_id = 3 * j + 1
            send_request = mcp_request(sender_token, rpc(rpc_id, "silk_send", send_args(recipients[k], f"send-rt-{j:06d}")))
            receive_request = mcp_request(recipient_tokens[k], rpc(rpc_id + 1, "silk_receive", {}))
            t0 = time.perf_counter_ns()
            sent = await sender.request(send_request)
            content = tool_result(sent)
            if content is None or content["status"] != "queued":
                raise RuntimeError(f"roundtrip send failed: {sent.body[:300]!r}")
            message_id = content["message_id"]
            t1 = time.perf_counter_ns()
            received = await receiver.request(receive_request)
            inbox = tool_result(received)
            if inbox is None or not any(m["message_id"] == message_id for m in inbox["messages"]):
                raise RuntimeError(f"recipient did not observe the message: {received.body[:300]!r}")
            t2 = time.perf_counter_ns()
            ack_request = mcp_request(recipient_tokens[k], rpc(rpc_id + 2, "silk_ack", {"message_id": message_id, "idempotency_key": f"ack-rt-{j:06d}", "outcome": "received"}))
            acked = await receiver.request(ack_request)
            receipt = tool_result(acked)
            if receipt is None or receipt.get("outcome") != "received":
                raise RuntimeError(f"ack failed: {acked.body[:300]!r}")
            t3 = time.perf_counter_ns()
            if j >= RT_WARMUP:
                samples.append(t3 - t0)
                parts.append((t1 - t0, t2 - t1, t3 - t2))
                if wire is None:
                    wire = {"send": len(send_request) + sent.wire_bytes,
                            "receive": len(receive_request) + received.wire_bytes,
                            "ack": len(ack_request) + acked.wire_bytes}
        sender.close()
        receiver.close()
    finally:
        C.stop(proc)
    return {"samples": samples, "parts": parts, "wire": wire}


# ----------------------------------------------------------------------------- main

async def main():
    if not C.port_is_free(PORT):
        raise SystemExit(f"port {PORT} is already in use; stop that server or set BENCH_MAILBOX_PORT")
    workdir = Path(tempfile.mkdtemp(prefix="silk-bench-mailbox-"))
    loadavg = os.getloadavg()
    timestamp = C.now_iso()
    try:
        keys = Keys(workdir)
        C.log(f"mailbox: cold start x{COLD_RUNS}")
        cold = cold_start(workdir, keys)
        levels = []
        for concurrency in LEVELS:
            C.log(f"mailbox: throughput c={concurrency} (warmup {WARMUP}, timed {N})")
            level = await throughput_level(concurrency, workdir, keys)
            C.log(f"  {level['msgs_per_sec']} msg/s p50={level['p50_ms']}ms p99={level['p99_ms']}ms errors={level['errors']} {level['_errors']}")
            levels.append(level)
        C.log(f"mailbox: roundtrip x{RT_SAMPLES} (+{RT_WARMUP} warmup)")
        rt = await roundtrip(workdir, keys)
        with open(workdir / f"mailbox-c{LEVELS[0]}.log", "rb") as handle:
            per_request_log = [line.decode(errors="replace").strip() for line in handle if b"Processing request" in line]
    finally:
        C.stop_all()
        if not os.environ.get("BENCH_KEEP"):
            shutil.rmtree(workdir, ignore_errors=True)

    rt_stats = C.percentiles_ms(rt["samples"])
    part_stats = [C.percentiles_ms([p[i] for p in rt["parts"]]) for i in range(3)]
    c16 = next((lv for lv in levels if lv["concurrency"] == 16), None)
    footprint, footprint_note = C.footprint_mb("mailbox")
    probe = sqlite3.connect(":memory:")
    sync_default = probe.execute("PRAGMA synchronous").fetchone()[0]
    import uvicorn  # version only
    wire = rt["wire"]
    log_note = (f"The SDK's default INFO logging stays on (stderr redirected to a log file): {len(per_request_log)} 'Processing request of type ...' lines for the {WARMUP + N} sends of the c={LEVELS[0]} level."
                if per_request_log else "No per-request SDK log lines were observed.")
    notes = [
        f"Server: unmodified silk_live.create_app(settings, SQLiteFixtureStore, JWTAccessTokenVerifier, testing=True) served by uvicorn {uvicorn.__version__} (h11, asyncio loop, 1 worker, access log off, as services/mailbox/README.md runs it) via bench/v1/launch_mailbox.py. FastMCP stateless_http + json_response, MCP protocol {F.PROTOCOL_VERSION}. {log_note}",
        f"Auth: the real JWTAccessTokenVerifier verifies an RS256 (2048-bit) access token on every request (header/claim allowlists, signature, iss/aud/client_id/iat/exp). Its JWKS fetcher is the injected trusted dependency the tests use (returns the local public JWKS bytes; cached 300 s) because the verifier only accepts pinned https:// DNS URLs with TLS verification, which 127.0.0.1 cannot serve without altering trust stores. Settings mirror the tests: issuer {F.ISSUER}, resource {F.RESOURCE}; clients connect to 127.0.0.1:{PORT} with Host: {F.HOST} so the Host/Origin boundary and the SDK DNS-rebinding check pass. Token is {levels[0]['_token_bytes']} bytes and travels on every request.",
        f"Storage: SQLiteFixtureStore (WAL, new sqlite3 connection per transaction, BEGIN IMMEDIATE for writes, busy_timeout 10 s, synchronous={sync_default} i.e. FULL compile default; SQLite {sqlite3.sqlite_version}), DB in $TMPDIR on the internal APFS SSD. Store calls run in anyio's worker thread pool, as the app does.",
        f"Send = one MCP tools/call silk_send JSON-RPC POST /mcp ({levels[0]['_request_bytes']} request bytes), no initialize per call (stateless server; a real SDK client initializes once per session). Requests are pre-built before timing ({N + WARMUP} in ~{statistics.median(lv['_build_ms'] for lv in levels):.0f} ms). Text is the test suite's 57-character sample.",
        f"Throughput: each concurrency level runs on a fresh server + freshly provisioned DB ({levels[0]['_pairs']} pairs, ~{statistics.median(lv['_provision_s'] for lv in levels):.1f} s untimed provisioning): {WARMUP} untimed warmup sends, then {N} timed sends, closed loop over persistent HTTP/1.1 keep-alive connections (one per worker, opened before timing). Latency = request write to full response read. Percentiles are over accepted sends; errors are counted and never retried.",
        "Throughput errors by kind per concurrency: " + "; ".join(f"c={lv['concurrency']}: {lv['_errors'] or 'none'}" for lv in levels) + ". Rows stored after each level (warmup + timed): " + ", ".join(f"c={lv['concurrency']}: {lv['_stored']}" for lv in levels) + ".",
        "Tail latency at higher concurrency: every store call opens its own SQLite connection in anyio's worker pool (up to 40 threads) and takes the write lock with BEGIN IMMEDIATE and busy_timeout=10 s; SQLite's default busy handler then sleeps in growing steps (1 ms up to 100 ms) while it waits. That is the likely source of the large p90/p99 gaps at c>=16; it was not separately instrumented.",
        "Load generator: one Python 3.12 asyncio process using raw sockets and pre-built request bytes (no httpx, no MCP SDK client), separate from the server process. Client CPU per timed run: " + "; ".join(f"c={lv['concurrency']}: {lv['_client_cpu']:.2f}s CPU / {lv['seconds']:.2f}s wall ({100 * lv['_client_cpu'] / lv['seconds']:.0f}% of one core, {1e6 * lv['_client_cpu'] / N:.0f} us/request)" for lv in levels),
        f"Roundtrip: fresh server; per sample t0 -> silk_send (sender token) -> silk_receive (recipient token) must contain that message_id -> silk_ack outcome=received -> t3, all sequential over two keep-alive connections (sender, recipient); the ack request is built after the receive returns (inside the timed region). Breakdown p50 send/receive/ack = {part_stats[0]['p50']}/{part_stats[1]['p50']}/{part_stats[2]['p50']} ms (means {part_stats[0]['mean']}/{part_stats[1]['mean']}/{part_stats[2]['mean']} ms). The message is observable as soon as silk_send returns (no background dispatcher); pair k = sample // 6 to stay under the per-pair rate limit.",
        f"wire_bytes: HTTP bytes only (request line + headers + body, status line + headers + body), no TCP/IP framing. Client sends only the headers MCP Streamable HTTP needs (Host, Authorization: Bearer <JWT>, Accept, Content-Type, MCP-Protocol-Version, Content-Length). send = {wire['send']} (silk_send request+response); roundtrip = send + silk_receive ({wire['receive']}) + silk_ack ({wire['ack']}). Values are from the first timed roundtrip sample; JSON-RPC ids/keys vary by a few bytes.",
        "rss_mb: idle = median over the fresh throughput servers of RSS 1 s after the first healthy /health (" + ", ".join(f"{lv['_idle_mb']:.1f}" for lv in levels) + " MB); peak = max RSS sampled every 20 ms from startup through warmup and timed run (per level: " + ", ".join(f"c={lv['concurrency']} {lv['_peak_mb']:.1f}" for lv in levels) + " MB).",
        (f"cpu_ms_per_msg: server user+sys CPU over the c=16 timed run ({c16['_server_cpu_run']:.3f} s / {c16['_accepted']} accepted). No background work exists, so nothing is deferred past the run." if c16 else "cpu_ms_per_msg: c=16 not run"),
        f"cold_start_ms: median of {COLD_RUNS} spawns of bench/v1/launch_mailbox.py (the repo has no configured fixture entrypoint; silk_live.asgi without Postgres config serves only the fail-closed app) with a new DB file until the first HTTP 200 from GET /health (probe every 2 ms); includes interpreter start, imports (mcp, starlette, pydantic, uvicorn, jwt), schema creation and app construction. The JWKS is not fetched until the first authenticated request. Runs: " + ", ".join(f"{t:.0f}" for t in cold) + " ms (run_all.sh recreates the venv, so the first spawn may also write .pyc caches; hence the median).",
        f"install_mb: {footprint_note}",
        f"Machine load average at start: {loadavg[0]:.2f}/{loadavg[1]:.2f}/{loadavg[2]:.2f}; other processes were not stopped, so absolute numbers carry normal desktop noise.",
    ]
    result = {
        "system": "v1-mailbox",
        "language": C.python_label(),
        "machine": C.machine_info(),
        "timestamp": timestamp,
        "limits_overridden": LIMITS_OVERRIDDEN,
        "send_throughput": [{k: v for k, v in lv.items() if not k.startswith("_")} for lv in levels],
        "roundtrip_ms": {"samples": len(rt["samples"]), "p50": rt_stats["p50"], "p90": rt_stats["p90"], "p99": rt_stats["p99"], "mean": rt_stats["mean"]},
        "wire_bytes": {"send": wire["send"], "roundtrip": wire["send"] + wire["receive"] + wire["ack"]},
        "rss_mb": {"idle": round(statistics.median(lv["_idle_mb"] for lv in levels), 1), "peak": round(max(lv["_peak_mb"] for lv in levels), 1)},
        "cpu_ms_per_msg": round(1000 * c16["_server_cpu_run"] / c16["_accepted"], 3) if c16 and c16["_accepted"] else None,
        "cold_start_ms": round(statistics.median(cold), 1),
        "install_mb": footprint,
        "notes": notes,
    }
    C.write_result("v1-mailbox", result)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        C.stop_all()
