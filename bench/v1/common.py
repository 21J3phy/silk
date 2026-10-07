"""Shared benchmark helpers: raw HTTP/1.1 client, closed-loop load runner,
server process lifecycle, RSS/CPU monitoring, statistics, machine info.

The load generator writes pre-built request bytes on asyncio streams and parses
responses minimally, so client overhead stays small and wire bytes are exact
(the request bytes are exactly what was written; response bytes are exactly
what was read from the socket, headers included). TCP/IP framing is excluded.
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RESULTS = REPO / "bench" / "results"
LOOPBACK = "127.0.0.1"


# --------------------------------------------------------------------------- HTTP

def build_request(method: str, path: str, host: str, headers=(), body: bytes | None = None) -> bytes:
    """HTTP/1.1 request with an explicit, minimal header set (no User-Agent,
    Accept-Encoding, or Connection headers unless passed in ``headers``)."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    lines += [f"{name}: {value}" for name, value in headers]
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b"")


class HTTPError(Exception):
    pass


def parse_head(head: bytes):
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise HTTPError("bad status line")
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(b":")
        headers.setdefault(name.strip().lower().decode("latin-1"), []).append(value.strip().decode("latin-1"))
    return int(parts[1]), headers


class Response:
    __slots__ = ("status", "headers", "body", "wire_bytes")

    def __init__(self, status, headers, body, wire_bytes):
        self.status, self.headers, self.body, self.wire_bytes = status, headers, body, wire_bytes

    def header(self, name):
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def json(self):
        return json.loads(self.body)


async def oneshot(port: int, request: bytes) -> Response:
    """One request on a fresh TCP connection, response read to EOF (HTTP/1.0 style server)."""
    reader, writer = await asyncio.open_connection(LOOPBACK, port)
    try:
        writer.write(request)
        data = await reader.read()
    finally:
        writer.close()
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        raise HTTPError("connection closed before a complete response head")
    status, headers = parse_head(head)
    length = headers.get("content-length")
    if length is not None and int(length[0]) != len(body):
        raise HTTPError("truncated response body")
    return Response(status, headers, body, len(data))


class KeepAlive:
    """One persistent HTTP/1.1 connection (pooled-client style)."""

    def __init__(self, port: int):
        self.port = port
        self.reader = self.writer = None

    async def open(self):
        self.reader, self.writer = await asyncio.open_connection(LOOPBACK, self.port, limit=1 << 22)
        return self

    def close(self):
        if self.writer is not None:
            self.writer.close()
            self.writer = None

    async def request(self, request: bytes) -> Response:
        if self.writer is None:
            await self.open()
        try:
            self.writer.write(request)
            head = await self.reader.readuntil(b"\r\n\r\n")
            status, headers = parse_head(head[:-4])
            wire = len(head)
            if "content-length" in headers:
                body = await self.reader.readexactly(int(headers["content-length"][0]))
                wire += len(body)
            elif "chunked" in ",".join(headers.get("transfer-encoding", [])).lower():
                chunks = []
                while True:
                    size_line = await self.reader.readuntil(b"\r\n")
                    wire += len(size_line)
                    size = int(size_line.split(b";")[0], 16)
                    data = await self.reader.readexactly(size + 2)
                    wire += len(data)
                    if size == 0:
                        break
                    chunks.append(data[:-2])
                body = b"".join(chunks)
            else:
                body = await self.reader.read()
                wire += len(body)
                self.close()
            if "close" in ",".join(headers.get("connection", [])).lower():
                self.close()
            return Response(status, headers, body, wire)
        except BaseException:
            self.close()
            raise


def sync_get(port: int, path: str, host: str, timeout=2.0) -> Response:
    """Blocking GET with Connection: close (used for health probes)."""
    request = build_request("GET", path, host, [("Connection", "close")])
    with socket.create_connection((LOOPBACK, port), timeout=timeout) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    data = b"".join(chunks)
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        raise HTTPError("incomplete response")
    status, headers = parse_head(head)
    return Response(status, headers, body, len(data))


# --------------------------------------------------------------------------- load

async def closed_loop(concurrency: int, requests: list, send, *, keepalive_port: int | None = None):
    """Run ``requests`` through ``concurrency`` workers, each issuing its next
    request as soon as the previous one completes (closed loop).

    ``send(conn, request) -> Response``; ``conn`` is a KeepAlive if
    ``keepalive_port`` is given (connections opened before timing), else None.
    Returns per-request latency (ns), results (Response or Exception), wall
    seconds and client-process CPU seconds for the timed region.
    """
    n = len(requests)
    latency = [0] * n
    results = [None] * n
    conns = [None] * concurrency
    if keepalive_port is not None:
        conns = [await KeepAlive(keepalive_port).open() for _ in range(concurrency)]
    cursor = 0

    async def worker(index):
        nonlocal cursor
        conn = conns[index]
        while cursor < n:
            i = cursor
            cursor += 1
            started = time.perf_counter_ns()
            try:
                result = await send(conn, requests[i])
            except Exception as error:  # counted as an error, never retried
                result = error
            latency[i] = time.perf_counter_ns() - started
            results[i] = result

    cpu0, t0 = time.process_time(), time.perf_counter()
    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    wall, cpu = time.perf_counter() - t0, time.process_time() - cpu0
    for conn in conns:
        if conn is not None:
            conn.close()
    return latency, results, wall, cpu


# --------------------------------------------------------------------------- stats

def percentiles_ms(latency_ns: list[int]) -> dict:
    values = sorted(v / 1e6 for v in latency_ns)
    if not values:
        return {"p50": None, "p90": None, "p99": None, "mean": None}
    if len(values) == 1:
        v = round(values[0], 3)
        return {"p50": v, "p90": v, "p99": v, "mean": v}
    q = statistics.quantiles(values, n=100, method="inclusive")
    return {"p50": round(q[49], 3), "p90": round(q[89], 3), "p99": round(q[98], 3), "mean": round(statistics.fmean(values), 3)}


# --------------------------------------------------------------------------- processes

_children: list[subprocess.Popen] = []


def spawn(cmd: list[str], log_path: Path, cwd: Path = REPO, env: dict | None = None) -> subprocess.Popen:
    log = open(log_path, "ab")
    proc = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    log.close()
    _children.append(proc)
    return proc


def wait_health(proc: subprocess.Popen, port: int, host: str, timeout=30.0, interval=0.002) -> float:
    """Poll GET /health until 200. Returns perf_counter() at first success."""
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with code {proc.returncode}")
        try:
            if sync_get(port, "/health", host, timeout=1.0).status == 200:
                return time.perf_counter()
        except (OSError, HTTPError):
            pass
        time.sleep(interval)
    raise RuntimeError("server did not become healthy in time")


def stop(proc: subprocess.Popen, timeout=10.0):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if proc in _children:
        _children.remove(proc)


def stop_all():
    for proc in list(_children):
        try:
            stop(proc, timeout=5)
        except Exception:
            proc.kill()


def port_is_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.connect((LOOPBACK, port))
        except OSError:
            return True
    return False


class Monitor:
    """Samples a server process's RSS every ``interval`` seconds in a thread."""

    def __init__(self, pid: int, interval=0.02):
        self.proc = psutil.Process(pid)
        self.interval = interval
        self.peak = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.peak = max(self.peak, self.proc.memory_info().rss)
            except psutil.Error:
                return
            self._stop.wait(self.interval)

    def rss_mb(self) -> float:
        return self.proc.memory_info().rss / (1024 * 1024)

    def reset_peak(self):
        self.peak = self.proc.memory_info().rss

    def peak_mb(self) -> float:
        return self.peak / (1024 * 1024)

    def cpu_seconds(self) -> float:
        times = self.proc.cpu_times()
        return times.user + times.system

    def close(self):
        self._stop.set()
        self._thread.join(timeout=1)


# --------------------------------------------------------------------------- metadata

def machine_info() -> dict:
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        try:
            cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            pass
        try:
            build = subprocess.check_output(["sw_vers", "-buildVersion"], text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            build = "?"
        os_name = f"macOS {platform.mac_ver()[0]} ({build}), Darwin {platform.release()}, {platform.machine()}"
    else:
        os_name = platform.platform()
    return {"cpu": cpu, "cores": os.cpu_count(), "os": os_name}


def python_label() -> str:
    return "python " + platform.python_version()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def footprint_mb(system: str):
    path = HERE / ".footprint" / "footprint.json"
    if not path.exists():
        return None, f"install footprint not measured ({path.name} missing; run bench/v1/run_all.sh)"
    data = json.loads(path.read_text())
    entry = data.get(system)
    if not entry:
        return None, "install footprint entry missing"
    return entry["site_packages_mb"], entry["note"]


def write_result(name: str, result: dict):
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {path.relative_to(REPO)}")


def log(message: str):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)
