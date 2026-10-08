"""Smoke-verify spec.json for MCP Agent Mail by executing it literally.

Mirrors the template semantics of cmd/silk-bench/foreign.go: launch argv and
env (merged over the parent environment) with {PORT}/{DATADIR}, cwd={DATADIR},
wait for the health path, then per worker: run per_worker_setup, then
send -> receive -> ack. Bodies are substituted as raw text ({ID} is a fresh
32-hex id per request, {W} the worker index, {TEXT} the 57-byte message),
captures are [{from: header|json, name, var}], and "as": "recipient" picks the
recipient connection. Unlike the Go driver it also checks that each fetch
returns exactly the message just sent and that the final unread fetch is empty.

Standard library only. Not a benchmark: keep --n small (<= 20 messages total).

    python3 -I smoke.py --port 18767 --datadir /tmp/silk-competitors/mcp-agent-mail/runs/smoke3 --workers 2 --n 3
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEXT = "Can we coordinate a time? This is untrusted message data."


def subst(s: str, values: dict) -> str:
    for k, v in values.items():
        s = s.replace("{" + k + "}", str(v))
    return s


def jpath(doc, path: str):
    for part in path.split("."):
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


class Worker:
    def __init__(self, idx: int, port: int):
        self.idx = idx
        self.vars = {"W": str(idx), "TEXT": TEXT}
        self.n = 0
        self.conns = {
            "sender": http.client.HTTPConnection("127.0.0.1", port, timeout=30),
            "recipient": http.client.HTTPConnection("127.0.0.1", port, timeout=30),
        }

    def do(self, label: str, t: dict):
        self.n += 1
        self.vars["ID"], self.vars["N"] = secrets.token_hex(16), str(self.n)
        conn = self.conns["recipient" if t.get("as") == "recipient" else "sender"]
        body = subst(json.dumps(t["body"]), self.vars).encode() if "body" in t else None
        headers = {k: subst(v, self.vars) for k, v in t.get("headers", {}).items()}
        t0 = time.perf_counter()
        conn.request(t["method"], subst(t["path"], self.vars), body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        ms = (time.perf_counter() - t0) * 1000
        doc = json.loads(raw) if raw else None
        for c in t.get("capture", []):
            if c["from"] == "header":
                self.vars[c["var"]] = resp.getheader(c["name"]) or ""
            else:
                v = jpath(doc, c["name"])
                self.vars[c["var"]] = v if isinstance(v, str) else json.dumps(v)
        text = raw.decode(errors="replace")
        rpc_error = '"error":{' in text or '"error": {' in text or '"isError":true' in text or '"isError": true' in text
        print(f"  [w{self.idx} {t.get('as', 'sender'):9}] {label:<34} {resp.status} {ms:7.1f} ms  {text[:110]}")
        if resp.status >= 300 or rpc_error:
            raise SystemExit(f"FAILED {label}: {resp.status} {text[:600]}")
        return doc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default=str(HERE / "spec.json"))
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--n", type=int, default=3, help="send/receive/ack rounds per worker")
    args = ap.parse_args()
    if args.workers * args.n > 20:
        raise SystemExit("smoke only: workers * n <= 20")
    spec = json.loads(Path(args.spec).read_text())
    datadir = Path(args.datadir)
    datadir.mkdir(parents=True, exist_ok=False)
    base = {"PORT": args.port, "DATADIR": str(datadir)}

    argv = [subst(a, base) for a in spec["launch"]]
    env = {**os.environ, **{k: subst(v, base) for k, v in spec["env"].items()}}
    print("launch:", " ".join(argv), f"(cwd={datadir})")
    log = open(datadir / "server.log", "wb")
    t_launch = time.perf_counter()
    proc = subprocess.Popen(argv, cwd=datadir, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        health = f"http://127.0.0.1:{args.port}{spec['health']}"
        while True:
            if proc.poll() is not None:
                raise SystemExit(f"server exited early: {proc.returncode}")
            try:
                with urllib.request.urlopen(health, timeout=1) as r:
                    if r.status < 400:
                        break
            except Exception:
                time.sleep(0.05)
            if time.perf_counter() - t_launch > 90:
                raise SystemExit("health timeout")
        print(f"health {spec['health']} -> 200 after {(time.perf_counter() - t_launch) * 1000:.0f} ms (pid {proc.pid})")

        workers = [Worker(i, args.port) for i in range(args.workers)]
        for w in workers:
            print(f"per_worker_setup w{w.idx}:")
            for i, step in enumerate(spec["per_worker_setup"]):
                label = step["body"].get("params", {}).get("name") or step["body"]["method"]
                w.do(f"setup[{i}] {label}", step)
        for w in workers:
            print(f"send / receive / ack x {args.n} (w{w.idx}):")
            for _ in range(args.n):
                w.do("send send_message", spec["send"])
                msg_id, subject = int(w.vars["MSG_ID"]), None
                doc = w.do("receive fetch_inbox", spec["receive"])
                inbox = doc["result"]["structuredContent"]["result"]
                assert [m["id"] for m in inbox] == [msg_id], f"expected only {msg_id}, got {[m['id'] for m in inbox]}"
                m = inbox[0]
                assert m["body_md"] == TEXT and m["from"] == f"agent-x-{w.idx}" and m["subject"].startswith("bench-"), m
                doc = w.do("ack acknowledge_message", spec["ack"])
                assert doc["result"]["structuredContent"]["acknowledged"] is True
            doc = w.do("receive (final, expect empty)", spec["receive"])
            assert doc["result"]["structuredContent"]["result"] == [], "unread inbox not empty after acks"
            for step in spec.get("per_worker_teardown", []):
                w.do("teardown DELETE session", step)
        print("checks passed: each fetch returned exactly the new message; final unread fetch empty")
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    archive = datadir / "archive"
    commits = subprocess.run(["git", "-C", str(archive), "log", "--oneline"], capture_output=True, text=True).stdout.splitlines()
    md = list(archive.rglob("*.md"))
    print(f"archive: {len(commits)} git commits, {len(md)} markdown files; newest: {commits[0] if commits else None}")
    print("datadir:", sorted(p.name for p in datadir.iterdir()))


if __name__ == "__main__":
    main()
