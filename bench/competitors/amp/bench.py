"""AMP (fg-amp, Fareground agent-messaging) relay benchmark driver.

Drives the real library end to end against a running relay. A full AMP
exchange cannot be expressed as fixed HTTP request templates: every envelope is
Ed25519-signed over canonical JSON, session bodies are double-ratchet
ChaCha20-Poly1305 ciphertext keyed by an X25519 + ML-KEM-768 handshake, and
every pull/ack carries a fresh single-use signature. So the load comes from
``fg_amp`` itself.

Topology: endpoint X (sender) runs in this process; endpoint Y (receiver) runs
in a spawned child process so the two endpoints' client-side crypto do not
share one core. Each endpoint has its own transport, so nothing short-circuits
in-process: every frame crosses the relay.

* Y uses an open ContactPolicy whose per-peer initiation rate limit is raised
  to admit C sessions (the stock limit is 10 initiations/min/peer).
* X opens C sessions to Y (full handshake through the relay). ``Session.send``
  holds a per-session lock across delivery (seq order is a protocol
  requirement), so concurrency C means C sessions, one closed-loop worker each.
* Throughput: ``--warmup`` untimed sends, then ``--n`` timed sends, closed loop.
  ``send_ms`` = ``await session.send_text(TEXT)``: ratchet step, AEAD encrypt,
  sign, relay POST (relay verifies + stores) until the relay answers.
  Y drains concurrently (it must, or mailboxes fill).
* Roundtrip: ``--rt-samples`` sequential messages on one session after the
  throughput phase has fully drained. For each: t0, send, then
    - ``receive``: Y's ``session.receive()`` returned the message,
    - ``relay_ack``: Y's signed relay ack (mailbox lease release) completed
      (HTTP: response 200 received; WS: ack frame written to the socket),
    - ``sender_receipt``: X processed Y's E2E receipt (cumulative session ack).
  ``roundtrip_ms`` is send -> receive -> relay_ack, the analogue of
  send / fetch / acknowledge.

Instrumentation only observes: the relay transport subclass wraps
``_call_failover`` to see ack outcomes, and X sessions' ``_handle_receipt`` is
wrapped to timestamp receipts after the original handler runs.

Output: one JSON object on stdout. Progress goes to stderr.

Usage (AMP venv, isolated mode):

    /tmp/silk-competitors/amp/.venv/bin/python -I bench/competitors/amp/bench.py \
        --relay http://127.0.0.1:8404 --n 2000 --concurrency 16
"""
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import multiprocessing as mp
import platform
import sys
import threading
import time

TEXT = "Can we coordinate a time? This is untrusted message data."
DEFAULT_AUDIENCE = "amp-bench"


def log(*parts: object) -> None:
    print("[amp-bench]", *parts, file=sys.stderr, flush=True)


def now_ns() -> int:
    # CLOCK_MONOTONIC / mach_absolute_time: system-wide, so stamps taken in the
    # receiver process are comparable with the sender's.
    return time.monotonic_ns()


def summarize(values_ns: list[int]) -> dict:
    if not values_ns:
        return {"count": 0}
    xs = sorted(v / 1e6 for v in values_ns)

    def pct(p: float) -> float:
        k = (len(xs) - 1) * p / 100.0
        lo = int(k)
        hi = min(lo + 1, len(xs) - 1)
        return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

    return {
        "count": len(xs),
        "p50": round(pct(50), 3),
        "p90": round(pct(90), 3),
        "p99": round(pct(99), 3),
        "mean": round(sum(xs) / len(xs), 3),
        "min": round(xs[0], 3),
        "max": round(xs[-1], 3),
    }


def run_loop(coro, use_uvloop: bool):
    if use_uvloop:
        try:
            import uvloop

            return asyncio.run(coro, loop_factory=uvloop.new_event_loop)
        except ImportError:
            pass
    return asyncio.run(coro)


def make_transport(url: str, audience: str, on_ack=None):
    """Relay transport for ``url`` (http(s):// long-poll, ws(s):// push), with an
    optional observer called as ``on_ack(ids, ok)`` after each relay ack."""
    from fg_amp import RelayTransport, WsRelayTransport
    from fg_amp.transport.relay import ACK_PATH

    async def _observed_call(parent, method, path, json_body, body_fn):
        if path != ACK_PATH or on_ack is None or body_fn is None:
            return await parent(method, path, json_body, body_fn)
        seen: dict = {}

        def capture(base_url, aud):
            body = body_fn(base_url, aud)
            seen["ids"] = list(body.get("ids", []))
            return body

        try:
            status, data = await parent(method, path, json_body, capture)
        except Exception:
            on_ack(seen.get("ids", []), False)
            raise
        on_ack(seen.get("ids", []), status == 200)
        return status, data

    if url.startswith(("ws://", "wss://")):
        base = url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)

        class ObservedWs(WsRelayTransport):
            async def _handle_delivery(self, node, ws, envelopes):
                await super()._handle_delivery(node, ws, envelopes)
                if on_ack is not None:
                    on_ack([w.get("id") for w in envelopes if isinstance(w, dict)], True)

            async def _call_failover(self, method, path, json_body=None, body_fn=None):
                return await _observed_call(super()._call_failover, method, path, json_body, body_fn)

        return ObservedWs(base, audience=audience), "websocket"

    class ObservedHttp(RelayTransport):
        async def _call_failover(self, method, path, json_body=None, body_fn=None):
            return await _observed_call(super()._call_failover, method, path, json_body, body_fn)

    return ObservedHttp(url, audience=audience), "http-longpoll"


# --------------------------------------------------------------------------
# Receiver (Y) — child process
# --------------------------------------------------------------------------


def receiver_main(url: str, audience: str, sessions_allowed: int, use_uvloop: bool, conn, events):
    run_loop(_receiver(url, audience, sessions_allowed, conn, events), use_uvloop)


async def _receiver(url, audience, sessions_allowed, conn, events):
    from fg_amp import AgentIdentity, AmpNode, ContactPolicy, PolicyMode

    loop = asyncio.get_running_loop()
    sessions = []
    bad_payloads = 0

    async def on_session(session):  # runs as its own task; receiving here is safe
        nonlocal bad_payloads
        sessions.append(session)
        while True:
            message = await session.receive()
            if message.payload.content != TEXT:
                bad_payloads += 1
            events.put(("recv", message.session_id, message.seq, now_ns()))

    def on_ack(ids, ok):
        events.put(("ack", list(ids), ok, now_ns()))

    policy = ContactPolicy(
        mode=PolicyMode.OPEN,
        rate_limit_per_peer=max(10, sessions_allowed),
        max_sessions=max(256, sessions_allowed),
    )
    node = AmpNode(identity=AgentIdentity.generate("bench-y"), policy=policy, on_session=on_session)
    transport, _kind = make_transport(url, audience, on_ack)
    try:
        await transport.connect(node, poll_interval=1.0)
    except Exception as exc:  # noqa: BLE001
        await loop.run_in_executor(None, conn.send, ("error", repr(exc)))
        return
    await loop.run_in_executor(None, conn.send, ("ready", node.address))
    while True:
        cmd = await loop.run_in_executor(None, conn.recv)
        if cmd == "cpu":
            await loop.run_in_executor(None, conn.send, time.process_time())
        elif cmd == "stop":
            stats = {}
            for s in sessions:
                for k, v in s.stats.model_dump().items():
                    stats[k] = stats.get(k, 0) + v
            reply = {
                "cpu_s": time.process_time(),
                "sessions": len(sessions),
                "bad_payloads": bad_payloads,
                "session_stats": stats,
            }
            await loop.run_in_executor(None, conn.send, reply)
            try:
                await asyncio.wait_for(node.aclose(), 10)
            except Exception:  # noqa: BLE001 — shutdown is best-effort
                pass
            return


# --------------------------------------------------------------------------
# Sender (X) — this process
# --------------------------------------------------------------------------


class Events:
    """Timestamps of receiver-side and receipt events, awaitable by key."""

    def __init__(self, loop):
        self.loop = loop
        self.times: dict[tuple, int] = {}
        self.ack_failures = 0
        self.waiters: dict[tuple, asyncio.Future] = {}
        self.recv_count = 0
        self.recv_by_session: dict[str, int] = {}

    def record(self, key: tuple, t: int) -> None:
        if key in self.times:
            return
        self.times[key] = t
        fut = self.waiters.pop(key, None)
        if fut is not None and not fut.done():
            fut.set_result(t)

    def handle(self, ev) -> None:
        kind = ev[0]
        if kind == "recv":
            _, sid, seq, t = ev
            if ("recv", sid, seq) not in self.times:
                self.recv_count += 1
                self.recv_by_session[sid] = self.recv_by_session.get(sid, 0) + 1
            self.record(("recv", sid, seq), t)
        elif kind == "ack":
            _, ids, ok, t = ev
            if not ok:
                self.ack_failures += 1
                return
            for mid in ids:
                self.record(("ack", mid), t)

    async def wait(self, key: tuple, timeout: float) -> int:
        if key in self.times:
            return self.times[key]
        fut = self.waiters.get(key)
        if fut is None:
            fut = self.waiters[key] = self.loop.create_future()
        return await asyncio.wait_for(asyncio.shield(fut), timeout)


async def wait_until(pred, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > deadline:
            raise TimeoutError(f"timed out waiting for {what}")
        await asyncio.sleep(0.002)


async def run(args) -> dict:
    from fg_amp import AgentIdentity, AmpNode, ContactPolicy, PolicyMode, __version__

    loop = asyncio.get_running_loop()
    ctx = mp.get_context("spawn")
    events_q = ctx.Queue()
    parent_conn, child_conn = ctx.Pipe()
    proc = ctx.Process(
        target=receiver_main,
        args=(args.relay, args.audience, args.concurrency, not args.no_uvloop, child_conn, events_q),
        daemon=True,
    )
    proc.start()
    status, payload = await loop.run_in_executor(None, parent_conn.recv)
    if status != "ready":
        raise RuntimeError(f"receiver failed to start: {payload}")
    y_address = payload

    ev = Events(loop)

    def pump():
        while True:
            item = events_q.get()
            if item is None:
                return
            loop.call_soon_threadsafe(ev.handle, item)

    threading.Thread(target=pump, daemon=True).start()

    x = AmpNode(identity=AgentIdentity.generate("bench-x"), policy=ContactPolicy(mode=PolicyMode.CLOSED))
    tx, transport_kind = make_transport(args.relay, args.audience)
    await tx.connect(x, poll_interval=1.0)
    y_card = await tx.resolve_card(y_address)  # discovery through the relay directory
    log(f"transport={transport_kind} x={x.address[:20]}… y={y_address[:20]}…")

    # ---- sessions (handshakes) -------------------------------------------
    receipt_hw: dict[str, int] = {}
    sessions = []
    handshake_ns = []

    def hook_receipts(session) -> None:
        original = session._handle_receipt
        sid = session.session_id

        async def observed(envelope):
            await original(envelope)
            try:
                acked = int(json.loads(envelope.body_bytes).get("ack", 0))
            except Exception:  # noqa: BLE001
                return
            t = now_ns()
            last = receipt_hw.get(sid, 0)
            for seq in range(last + 1, acked + 1):
                ev.record(("receipt", sid, seq), t)
            receipt_hw[sid] = max(last, acked)

        session._handle_receipt = observed

    for i in range(args.concurrency):
        t0 = time.perf_counter_ns()
        s = await x.initiate(y_card, purpose=f"bench-{i}", timeout=args.timeout)
        handshake_ns.append(time.perf_counter_ns() - t0)
        hook_receipts(s)
        sessions.append(s)
    pq = "amp.kem.ml-kem-768-x25519" in sessions[0].capabilities
    log(f"{len(sessions)} sessions established (pq_hybrid={pq})")

    sent_by_session: dict[str, int] = {s.session_id: 0 for s in sessions}

    async def closed_loop(total: int, lat: list[int] | None, errors: list[str]) -> None:
        counter = itertools.count()

        async def worker(s):
            while next(counter) < total:
                t0 = time.perf_counter_ns()
                try:
                    await s.send_text(TEXT)
                except Exception as exc:  # noqa: BLE001 — counted, never retried
                    errors.append(f"{type(exc).__name__}: {exc}"[:200])
                    continue
                if lat is not None:
                    lat.append(time.perf_counter_ns() - t0)
                sent_by_session[s.session_id] += 1

        await asyncio.gather(*(worker(s) for s in sessions))

    def all_received() -> bool:
        return all(ev.recv_by_session.get(sid, 0) >= n for sid, n in sent_by_session.items())

    def all_receipted() -> bool:
        return all(receipt_hw.get(sid, 0) >= n for sid, n in sent_by_session.items())

    # ---- warmup ---------------------------------------------------------
    warm_errors: list[str] = []
    if args.warmup:
        await closed_loop(args.warmup, None, warm_errors)
        await wait_until(lambda: all_received() and all_receipted(), args.timeout, "warmup drain")
    log(f"warmup done ({args.warmup}, errors={len(warm_errors)})")

    # ---- timed throughput -------------------------------------------------
    lat: list[int] = []
    errors: list[str] = []
    recv_before = ev.recv_count
    cpu_x0 = time.process_time()
    parent_conn.send("cpu")
    cpu_y0 = await loop.run_in_executor(None, parent_conn.recv)
    t_start = now_ns()
    await closed_loop(args.n, lat, errors)
    t_end = now_ns()
    cpu_x1 = time.process_time()
    parent_conn.send("cpu")
    cpu_y1 = await loop.run_in_executor(None, parent_conn.recv)
    await wait_until(all_received, args.timeout, "timed-phase delivery")
    t_delivered = max(v for k, v in ev.times.items() if k[0] == "recv")
    await wait_until(all_receipted, args.timeout, "timed-phase receipts")
    delivered = ev.recv_count - recv_before
    wall = (t_end - t_start) / 1e9
    log(f"timed: {len(lat)} sent in {wall:.3f}s, errors={len(errors)}")

    # ---- roundtrip --------------------------------------------------------
    rt_send, rt_recv, rt_ack, rt_receipt = [], [], [], []
    rt_errors: list[str] = []
    s = sessions[0]
    body_bytes = None
    for i in range(args.rt_warmup + args.rt_samples):
        t0 = now_ns()
        try:
            env = await s.send_text(TEXT)
            t1 = now_ns()
            sent_by_session[s.session_id] += 1
            t_recv = await ev.wait(("recv", s.session_id, env.seq), args.timeout)
            t_ack = await ev.wait(("ack", env.id), args.timeout)
            t_rcpt = await ev.wait(("receipt", s.session_id, env.seq), args.timeout)
        except Exception as exc:  # noqa: BLE001
            rt_errors.append(f"{type(exc).__name__}: {exc}"[:200])
            continue
        if i < args.rt_warmup:
            continue
        if body_bytes is None:
            # aiohttp json= serializes with json.dumps defaults: this is the POST body.
            body_bytes = len(json.dumps(env.to_wire()).encode())
        rt_send.append(t1 - t0)
        rt_recv.append(t_recv - t0)
        rt_ack.append(t_ack - t0)
        rt_receipt.append(t_rcpt - t0)
    log(f"roundtrip: {len(rt_ack)} samples, errors={len(rt_errors)}")

    # ---- teardown -----------------------------------------------------------
    x_stats: dict = {}
    for sess in sessions:
        for k, v in sess.stats.model_dump().items():
            x_stats[k] = x_stats.get(k, 0) + v
    try:
        await asyncio.wait_for(x.aclose(), 10)
    except Exception:  # noqa: BLE001
        pass
    parent_conn.send("stop")
    y_report = await loop.run_in_executor(None, parent_conn.recv)
    proc.join(10)
    events_q.put(None)

    def uniq(errs):
        out: dict[str, int] = {}
        for e in errs:
            out[e] = out.get(e, 0) + 1
        return out

    send_pct = summarize(lat)
    rt_pct = summarize(rt_ack)
    return {
        "system": "AMP (fg-amp, Fareground agent-messaging)",
        "fg_amp_version": __version__,
        # Same keys and percentile method as silk-bench's throughputLevel / pct.
        "level": {
            "concurrency": args.concurrency,
            "requests": args.n,
            "seconds": round(wall, 3),
            "msgs_per_sec": round(len(lat) / wall, 1) if wall > 0 else None,
            "p50_ms": send_pct.get("p50"),
            "p90_ms": send_pct.get("p90"),
            "p99_ms": send_pct.get("p99"),
            "errors": len(errors),
        },
        "roundtrip_pct": {
            "samples": rt_pct.get("count", 0),
            "p50": rt_pct.get("p50"),
            "p90": rt_pct.get("p90"),
            "p99": rt_pct.get("p99"),
            "mean": rt_pct.get("mean"),
        },
        "relay": args.relay,
        "transport": transport_kind,
        "audience": args.audience,
        "text": TEXT,
        "text_bytes": len(TEXT.encode()),
        "send_post_body_bytes": body_bytes,
        "pq_hybrid_handshake": pq,
        "concurrency": args.concurrency,
        "sessions": len(sessions),
        "handshake_ms": summarize(handshake_ns),
        "send_throughput": {
            "warmup": args.warmup,
            "warmup_errors": len(warm_errors),
            "n": args.n,
            "accepted": len(lat),
            "errors": len(errors),
            "error_kinds": uniq(errors),
            "wall_s": round(wall, 4),
            "msgs_per_sec": round(len(lat) / wall, 2) if wall > 0 else None,
            "send_ms": send_pct,
            "delivered": delivered,
            "delivered_msgs_per_sec": round(delivered / ((t_delivered - t_start) / 1e9), 2)
            if t_delivered > t_start
            else None,
        },
        "roundtrip_ms": rt_pct,
        "roundtrip_detail_ms": {
            "samples_requested": args.rt_samples,
            "untimed_warmup_samples": args.rt_warmup,
            "errors": len(rt_errors),
            "error_kinds": uniq(rt_errors),
            "send": summarize(rt_send),
            "send_to_receive": summarize(rt_recv),
            "send_to_relay_ack": summarize(rt_ack),
            "send_to_sender_receipt": summarize(rt_receipt),
        },
        "client": {
            "event_loop": type(loop).__module__.split(".")[0],
            "sender_cpu_s_timed": round(cpu_x1 - cpu_x0, 4),
            "sender_cpu_util_timed": round((cpu_x1 - cpu_x0) / wall, 3) if wall > 0 else None,
            "receiver_cpu_s_timed": round(cpu_y1 - cpu_y0, 4),
            "receiver_cpu_util_timed": round((cpu_y1 - cpu_y0) / wall, 3) if wall > 0 else None,
            "python": platform.python_version(),
        },
        "relay_ack_failures": ev.ack_failures,
        "receiver": y_report,
        "sender_session_stats": x_stats,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--relay", required=True, help="relay base URL: http(s)://host:port or ws(s)://host:port")
    p.add_argument("--n", type=int, required=True, help="timed sends")
    p.add_argument("--concurrency", type=int, required=True, help="closed-loop workers = sessions")
    p.add_argument("--warmup", type=int, default=100, help="untimed warmup sends (default 100)")
    p.add_argument("--rt-samples", type=int, default=300, help="sequential roundtrip samples (default 300)")
    p.add_argument("--rt-warmup", type=int, default=10, help="untimed roundtrip samples first (default 10, as silk-bench)")
    p.add_argument("--audience", default=DEFAULT_AUDIENCE, help="must equal the relay's --audience")
    p.add_argument("--timeout", type=float, default=120.0, help="per-wait timeout seconds")
    p.add_argument("--no-uvloop", action="store_true", help="use the stock asyncio loop for the clients")
    args = p.parse_args()
    if args.concurrency < 1 or args.concurrency > 256:
        raise SystemExit("--concurrency must be 1..256 (AMP max_sessions / reorder window)")
    result = run_loop(run(args), not args.no_uvloop)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
