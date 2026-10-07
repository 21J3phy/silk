"""v1 local broker benchmark (silk/server.py + silk/service.py over real HTTP).

Writes bench/results/v1-broker.json. Run via bench/v1/run_all.sh.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import random
import secrets
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
from uuid import uuid4

import common as C

sys.path.insert(0, str(C.REPO))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from silk.protocol import SCOPE, canonical, sign_record  # noqa: E402

PY = sys.executable
PORT = int(os.environ.get("BENCH_BROKER_PORT", "8765"))
HOST = f"127.0.0.1:{PORT}"
LEVELS = [int(x) for x in os.environ.get("BENCH_LEVELS", "1,4,16,64").split(",")]
N = int(os.environ.get("BENCH_REQUESTS", "2000"))
WARMUP = int(os.environ.get("BENCH_WARMUP", "100"))
RT_SAMPLES = int(os.environ.get("BENCH_RT_SAMPLES", "300"))
RT_WARMUP = 5
POLL_GAP_S = 0.005
DISPATCH_PERIOD_S = 0.5  # silk/server.py: stop_dispatch.wait(0.5)
RT_SEED = 20261007
COLD_RUNS = 5
TITLE = "Benchmark meeting proposal"

LIMITS_OVERRIDDEN = [
    "silk.service.RATE_PER_MINUTE 6 -> 1000000 (module global rebound by bench/v1/launch_broker.py before the server is built; per sender->recipient rolling-minute admission limit in Service._receive)",
    "silk.service.MAX_TURNS 8 -> 1000000 (upper bound for an invitation's max_turns; the benchmark grant is then created through the real HTTP invite + accept flow with max_turns=1000000)",
    "silk.service.MAX_MESSAGES 1000 -> 1000000 (local message storage cap checked in Service._receive)",
]


# ----------------------------------------------------------------------------- helpers

async def call(method, path, body=None, cookie=None, csrf=None) -> C.Response:
    headers = []
    if body is not None:
        headers.append(("Content-Type", "application/json"))
    if cookie:
        headers.append(("Cookie", cookie))
    if csrf:
        headers.append(("X-CSRF-Token", csrf))
    raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    return await C.oneshot(PORT, C.build_request(method, path, HOST, headers, raw))


def expect(response: C.Response, status: int, label: str):
    if response.status != status:
        raise RuntimeError(f"{label}: HTTP {response.status} {response.body[:300]!r}")
    return response.json()


async def setup_grant(max_turns=1_000_000):
    """Create an atlas->nova grant through the real fixture UI API (alice invites,
    bob accepts). Returns grant id, the fixture meeting options, and bob's cookie."""
    response = await call("GET", "/api/session")
    session = expect(response, 200, "session")
    cookie = response.header("set-cookie").split(";", 1)[0]
    invitation = expect(await call("POST", "/api/invitations", {
        "from_agent": "atlas", "to_agent": "nova", "purpose": "Benchmark coordination permission",
        "max_turns": max_turns, "expires_in": 86400}, cookie, session["csrf_token"]), 201, "invite")
    session = expect(await call("POST", "/api/session", {"owner_id": "bob"}, cookie, session["csrf_token"]), 200, "switch")
    accepted = expect(await call("POST", f"/api/invitations/{invitation['id']}/accept", {}, cookie, session["csrf_token"]), 200, "accept")
    if accepted["status"] != "accepted":
        raise RuntimeError("invitation not accepted")
    state = expect(await call("GET", "/api/state", cookie=cookie), 200, "state")
    grant = next(g for g in state["grants"] if g["invitation_id"] == invitation["id"])
    if grant["max_turns"] != max_turns:
        raise RuntimeError("override not effective")
    return grant["id"], state["suggested_options"], cookie


def sender_key(db: Path) -> Ed25519PrivateKey:
    """The broker stores fixture seeds in its own SQLite DB (as tests/test_ingress.py
    uses via Service.keys). Read atlas's seed read-only to sign client-side."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try:
        seed = con.execute("SELECT seed FROM fixture_keys WHERE id='atlas'").fetchone()[0]
    finally:
        con.close()
    return Ed25519PrivateKey.from_private_bytes(seed)


def envelope_request(key, grant_id, options, tag, index):
    now = int(time.time())
    envelope = sign_record({
        "version": 1, "id": f"msg_{uuid4().hex}", "sender": "atlas", "recipient": "nova",
        "grant_id": grant_id, "scope": SCOPE, "created_at": now, "expires_at": now + 300,
        "nonce": secrets.token_hex(16), "idempotency_key": f"bench-{tag}-{index:06d}-{uuid4().hex[:8]}",
        "payload": {"kind": "meeting.proposal", "title": TITLE, "options": options},
    }, key)
    request = C.build_request("POST", "/api/envelopes", HOST, [("Content-Type", "application/json")], canonical(envelope))
    return envelope["id"], request


async def send(_conn, request):
    return await C.oneshot(PORT, request)


def accepted(result) -> bool:
    if not isinstance(result, C.Response) or result.status != 201:
        return False
    body = result.json()
    return body["duplicate"] is False and body["message"]["status"] == "queued"


def error_kinds(results) -> dict:
    kinds = Counter()
    for result in results:
        if accepted(result):
            continue
        if isinstance(result, C.Response):
            try:
                kinds[f"HTTP {result.status} {result.json()['error']['code']}"] += 1
            except Exception:
                kinds[f"HTTP {result.status}"] += 1
        else:
            kinds[type(result).__name__] += 1
    return dict(kinds)


def status_counts(db: Path) -> dict:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try:
        return dict(con.execute("SELECT status, COUNT(*) FROM messages GROUP BY status").fetchall())
    finally:
        con.close()


def launch(db: Path, log: Path):
    return C.spawn([PY, str(C.HERE / "launch_broker.py"), "--port", str(PORT), "--db", str(db)], log)


# ----------------------------------------------------------------------------- phases

def cold_start(workdir: Path):
    """Real entrypoint, unpatched: python -m silk --port P --db <fresh file>."""
    times = []
    for run in range(COLD_RUNS):
        db = workdir / f"cold-{run}.sqlite3"
        started = time.perf_counter()
        proc = C.spawn([PY, "-m", "silk", "--port", str(PORT), "--db", str(db)], workdir / "cold.log")
        try:
            healthy = C.wait_health(proc, PORT, HOST)
        finally:
            C.stop(proc)
        times.append((healthy - started) * 1000)
    return times


async def throughput_level(concurrency: int, workdir: Path) -> dict:
    db = workdir / f"broker-c{concurrency}.sqlite3"
    proc = launch(db, workdir / f"broker-c{concurrency}.log")
    monitor = None
    try:
        C.wait_health(proc, PORT, HOST)
        monitor = C.Monitor(proc.pid)
        await asyncio.sleep(1.0)
        idle_mb = monitor.rss_mb()
        grant_id, options, _ = await setup_grant()
        key = sender_key(db)
        warm = [envelope_request(key, grant_id, options, f"w{concurrency}", i)[1] for i in range(WARMUP)]
        t_sign = time.perf_counter()
        timed = [envelope_request(key, grant_id, options, f"c{concurrency}", i)[1] for i in range(N)]
        sign_ms = (time.perf_counter() - t_sign) * 1000
        _, warm_results, _, _ = await C.closed_loop(concurrency, warm, send)
        warm_ok = sum(map(accepted, warm_results))
        cpu0 = monitor.cpu_seconds()
        latency, results, wall, client_cpu = await C.closed_loop(concurrency, timed, send)
        cpu1 = monitor.cpu_seconds()
        ok = [accepted(r) for r in results]
        good_latency = [lat for lat, flag in zip(latency, ok) if flag]
        # Let the 500 ms dispatcher move everything queued -> awaiting_approval.
        deadline = time.perf_counter() + 10
        counts = status_counts(db)
        while counts.get("queued", 0) and time.perf_counter() < deadline:
            await asyncio.sleep(0.1)
            counts = status_counts(db)
        cpu2 = monitor.cpu_seconds()
        peak_mb = monitor.peak_mb()
    finally:
        if monitor:
            monitor.close()
        C.stop(proc)
    accepted_n = sum(ok)
    stats = C.percentiles_ms(good_latency)
    return {
        "concurrency": concurrency, "requests": N, "seconds": round(wall, 3),
        "msgs_per_sec": round(accepted_n / wall, 1), "p50_ms": stats["p50"], "p90_ms": stats["p90"],
        "p99_ms": stats["p99"], "errors": N - accepted_n,
        "_accepted": accepted_n, "_warm_ok": warm_ok, "_errors": error_kinds(results),
        "_idle_mb": idle_mb, "_peak_mb": peak_mb, "_server_cpu_run": cpu1 - cpu0, "_server_cpu_drain": cpu2 - cpu0,
        "_client_cpu": client_cpu, "_sign_ms": sign_ms, "_status_counts": counts, "_mean_ms": stats["mean"],
    }


async def backlog_probe(concurrency: int, per_worker=50) -> dict:
    """GET /health from N concurrent workers, recording where failures happen.
    Isolates the accept-queue behaviour from any application work."""
    request = C.build_request("GET", "/health", HOST)
    outcome = Counter()

    async def worker():
        for _ in range(per_worker):
            try:
                reader, writer = await asyncio.open_connection(C.LOOPBACK, PORT)
            except OSError as error:
                outcome[f"connect {type(error).__name__}"] += 1
                continue
            try:
                writer.write(request)
                outcome["ok" if await reader.read() else "empty"] += 1
            except OSError as error:
                outcome[f"read {type(error).__name__}"] += 1
            finally:
                writer.close()

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return dict(outcome)


async def roundtrip(workdir: Path) -> dict:
    db = workdir / "broker-rt.sqlite3"
    proc = launch(db, workdir / "broker-rt.log")
    try:
        C.wait_health(proc, PORT, HOST)
        probes = {c: await backlog_probe(c) for c in (4, 8, 16)}
        await asyncio.sleep(0.5)
        grant_id, options, bob_cookie = await setup_grant()
        key = sender_key(db)
        state_request = C.build_request("GET", "/api/state", HOST, [("Cookie", bob_cookie)])
        samples, polls, poll_ms, poll_bytes = [], [], [], []
        wire = None
        rng = random.Random(RT_SEED)
        for j in range(RT_WARMUP + RT_SAMPLES):
            # Untimed pause so each send lands at a uniformly random phase of the
            # dispatcher's 500 ms cycle (otherwise a sequential client phase-locks:
            # it always sends right after a dispatch and waits a full cycle).
            await asyncio.sleep(rng.uniform(0, DISPATCH_PERIOD_S))
            message_id, request = envelope_request(key, grant_id, options, "rt", j)  # signed before t0
            t0 = time.perf_counter_ns()
            sent = await C.oneshot(PORT, request)
            if sent.status != 201:
                raise RuntimeError(f"roundtrip send failed: HTTP {sent.status} {sent.body[:200]!r}")
            count = 0
            while True:
                p0 = time.perf_counter_ns()
                observed = await C.oneshot(PORT, state_request)
                count += 1
                if j >= RT_WARMUP:
                    poll_ms.append((time.perf_counter_ns() - p0) / 1e6)
                    poll_bytes.append(len(state_request) + observed.wire_bytes)
                state = observed.json()
                message = next((m for m in state["messages"] if m["id"] == message_id), None)
                if message is not None and message["status"] == "awaiting_approval":
                    break
                if message is None or message["status"] != "queued":
                    raise RuntimeError(f"unexpected message state: {message and message['status']}")
                await asyncio.sleep(POLL_GAP_S)
            elapsed = time.perf_counter_ns() - t0
            if j == 0:  # fresh DB: the state document holds exactly this one message
                wire = {"send": len(request) + sent.wire_bytes, "observe": len(state_request) + observed.wire_bytes}
            if j >= RT_WARMUP:
                samples.append(elapsed)
                polls.append(count)
        last_state_bytes = observed.wire_bytes
    finally:
        C.stop(proc)
    return {"samples": samples, "polls": polls, "poll_ms": poll_ms, "poll_bytes": poll_bytes,
            "wire": wire, "last_state_bytes": last_state_bytes, "probes": probes}


# ----------------------------------------------------------------------------- main

async def main():
    if not C.port_is_free(PORT):
        raise SystemExit(f"port {PORT} is already in use; stop that server or set BENCH_BROKER_PORT")
    workdir = Path(tempfile.mkdtemp(prefix="silk-bench-broker-"))
    loadavg = os.getloadavg()
    timestamp = C.now_iso()
    try:
        C.log(f"broker: cold start x{COLD_RUNS}")
        cold = cold_start(workdir)
        levels = []
        for concurrency in LEVELS:
            C.log(f"broker: throughput c={concurrency} (warmup {WARMUP}, timed {N})")
            level = await throughput_level(concurrency, workdir)
            C.log(f"  {level['msgs_per_sec']} msg/s p50={level['p50_ms']}ms p99={level['p99_ms']}ms errors={level['errors']} {level['_errors']}")
            levels.append(level)
        C.log(f"broker: roundtrip x{RT_SAMPLES} (+{RT_WARMUP} warmup)")
        rt = await roundtrip(workdir)
    finally:
        C.stop_all()
        if not os.environ.get("BENCH_KEEP"):
            shutil.rmtree(workdir, ignore_errors=True)

    rt_stats = C.percentiles_ms(rt["samples"])
    c16 = next((lv for lv in levels if lv["concurrency"] == 16), None)
    footprint, footprint_note = C.footprint_mb("broker")
    sync_default = sqlite3.connect(":memory:").execute("PRAGMA synchronous").fetchone()[0]
    first, last = rt["samples"][:50], rt["samples"][-50:]
    notes = [
        "Server: unmodified silk/server.py ThreadingHTTPServer (HTTP/1.0, one TCP connection per request, listen backlog 5) + silk/service.py, started via bench/v1/launch_broker.py which only rebinds the three limit globals listed in limits_overridden. Background dispatcher (500 ms poll) runs as in production.",
        f"Storage: SQLite {sqlite3.sqlite_version} via the code's own settings (rollback journal_mode=delete default, synchronous={sync_default} i.e. FULL compile default, BEGIN IMMEDIATE per admission). DB file in $TMPDIR on the internal APFS SSD.",
        f"Send = POST /api/envelopes with a client-side Ed25519-signed envelope (signing key read read-only from the broker's fixture_keys table, as tests do via Service.keys). Envelopes are signed and request bytes pre-built before timing ({N} envelopes in ~{statistics.median(lv['_sign_ms'] for lv in levels):.0f} ms). Server still canonicalizes, validates and verifies every signature.",
        f"Throughput: each concurrency level runs on a fresh server + empty DB: {WARMUP} untimed warmup sends, then {N} timed sends, closed loop (each worker sends its next request when the previous response arrives). Latency = connect + request + full response (connection-per-request is forced by the HTTP/1.0 server). Percentiles are over accepted sends; errors are counted and never retried.",
        "Throughput errors by kind per concurrency: " + "; ".join(f"c={lv['concurrency']}: {lv['_errors'] or 'none'}" for lv in levels),
        "Cause of ConnectionResetError: the broker listens with socketserver's default backlog (TCPServer.request_queue_size = 5; silk/server.py does not change it) and macOS resets connection attempts that overflow the accept queue. The request is never sent, so no message is admitted. Accept-queue probe in this run (GET /health, 50 connections per worker, no app work): " + "; ".join(f"{c} concurrent: {o}" for c, o in rt["probes"].items()) + ". A client could safely retry these (envelope retries are idempotent), but this benchmark does not retry.",
        "Post-run dispatcher check (message status counts in DB per level): " + "; ".join(f"c={lv['concurrency']}: {lv['_status_counts']}" for lv in levels),
        "With limits lifted, per-request work grows with table size: the rate-limit COUNT over the (sender,recipient,accepted_at) index covers every message of the last minute, SELECT COUNT(*) FROM messages runs per admission, and _expire() scans queued/awaiting_approval rows on every admission and every /api/state. The unpatched system never exceeds 6 messages/minute/pair or 1000 rows, so it never pays this at scale.",
        "Load generator: one Python 3.12 asyncio process using raw sockets and pre-built request bytes (no httpx), separate from the server process. Client CPU per timed run: " + "; ".join(f"c={lv['concurrency']}: {lv['_client_cpu']:.2f}s CPU / {lv['seconds']:.2f}s wall ({100 * lv['_client_cpu'] / lv['seconds']:.0f}% of one core, {1e6 * lv['_client_cpu'] / N:.0f} us/request)" for lv in levels),
        f"Roundtrip: fresh server; per sample, sign envelope (untimed) -> t0 -> POST /api/envelopes (201) -> poll GET /api/state as bob (the same endpoint the web UI polls every 2000 ms; here polled with a {POLL_GAP_S * 1000:.0f} ms gap after each response) until that message's status is awaiting_approval -> t1. Dominated by the dispatcher's 500 ms wake-up interval. Before each sample an untimed pause drawn from U(0, 500 ms) (seed {RT_SEED}) puts the send at a random phase of the dispatcher cycle; without it a sequential client phase-locks (sends right after a dispatch) and every sample measures ~505 ms (seen in a trial run). Mean polls/sample {statistics.fmean(rt['polls']):.1f}; mean /api/state call {statistics.fmean(rt['poll_ms']):.2f} ms.",
        f"/api/state returns the recipient's full history, so it grows with message count: {rt['wire']['observe']} bytes with 1 message, {rt['last_state_bytes']} bytes response after {RT_WARMUP + RT_SAMPLES} messages. Roundtrip mean over first 50 samples {statistics.fmean(first) / 1e6:.1f} ms vs last 50 {statistics.fmean(last) / 1e6:.1f} ms.",
        f"wire_bytes: HTTP bytes only (request line + headers + body, status line + headers + body), no TCP/IP framing. Client sends a minimal header set (Host, Content-Type, Content-Length; Cookie for /api/state). send = {rt['wire']['send']} (POST /api/envelopes request+response). roundtrip = send + the single GET /api/state request+response that observed the message on a fresh DB with 1 message ({rt['wire']['observe']}); the {statistics.fmean(rt['polls']) - 1:.1f} extra empty polls per roundtrip (mean {statistics.fmean(rt['poll_bytes']):.0f} bytes each over the run) are excluded.",
        "rss_mb: idle = median over the fresh throughput servers of RSS 1 s after the first healthy /health (" + ", ".join(f"{lv['_idle_mb']:.1f}" for lv in levels) + " MB); peak = max RSS sampled every 20 ms from startup through warmup, timed run and dispatcher drain (per level: " + ", ".join(f"c={lv['concurrency']} {lv['_peak_mb']:.1f}" for lv in levels) + " MB).",
        (f"cpu_ms_per_msg: server user+sys CPU over the c=16 timed run only ({c16['_server_cpu_run']:.3f} s / {c16['_accepted']} accepted). Including the dispatcher draining the remaining queue after the run: {1000 * c16['_server_cpu_drain'] / c16['_accepted']:.3f} ms/msg." if c16 else "cpu_ms_per_msg: c=16 not run"),
        f"cold_start_ms: median of {COLD_RUNS} spawns of the real unpatched entrypoint `python -m silk --port {PORT} --db <new file>` until the first HTTP 200 from GET /health (probe every 2 ms); includes interpreter start, imports, schema creation and fixture key generation. Runs: " + ", ".join(f"{t:.0f}" for t in cold) + " ms (run_all.sh recreates the venv, so the first spawn may also write .pyc caches; hence the median).",
        f"install_mb: {footprint_note}",
        f"Machine load average at start: {loadavg[0]:.2f}/{loadavg[1]:.2f}/{loadavg[2]:.2f}; other processes were not stopped, so absolute numbers carry normal desktop noise.",
    ]
    result = {
        "system": "v1-broker",
        "language": C.python_label(),
        "machine": C.machine_info(),
        "timestamp": timestamp,
        "limits_overridden": LIMITS_OVERRIDDEN,
        "send_throughput": [{k: v for k, v in lv.items() if not k.startswith("_")} for lv in levels],
        "roundtrip_ms": {"samples": len(rt["samples"]), "p50": rt_stats["p50"], "p90": rt_stats["p90"], "p99": rt_stats["p99"], "mean": rt_stats["mean"]},
        "wire_bytes": {"send": rt["wire"]["send"], "roundtrip": rt["wire"]["send"] + rt["wire"]["observe"]},
        "rss_mb": {"idle": round(statistics.median(lv["_idle_mb"] for lv in levels), 1), "peak": round(max(lv["_peak_mb"] for lv in levels), 1)},
        "cpu_ms_per_msg": round(1000 * c16["_server_cpu_run"] / c16["_accepted"], 3) if c16 and c16["_accepted"] else None,
        "cold_start_ms": round(statistics.median(cold), 1),
        "install_mb": footprint,
        "notes": notes,
    }
    C.write_result("v1-broker", result)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        C.stop_all()
