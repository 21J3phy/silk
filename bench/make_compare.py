#!/usr/bin/env python3
"""Build bench/compare.html: Silk against other agent-messaging systems.

Inputs are bench/results/competitors/*.json (stdlib only). Local systems were
all driven by `silk-bench foreign` / `silk-bench compare` on one machine with
one method; the live section pairs Silk's hosted relay with XMTP's dev network
measured from the same connection in the same session.
"""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent
res = root / "results" / "competitors"


def load(name):
    p = res / name
    return json.loads(p.read_text()) if p.exists() else None


def level(d, c, key):
    for t in d["send_throughput"]:
        if t["concurrency"] == c:
            return t[key]
    return None


# What each system does for every message it accepts (shown with the charts).
LOCAL = [
    ("silk", "Silk 2.1", "silk-local.json", "Go",
     "Verifies an Ed25519 signature, checks budget and sequence, stores post-quantum end-to-end ciphertext durably (fsync), appends to a Merkle ledger"),
    ("a2a-go", "A2A Go SDK", "a2a-go.json", "Go",
     "Parses JSON-RPC and replies from memory; nothing stored, no signature, no encryption beyond optional TLS"),
    ("a2a-python", "A2A Python SDK", "a2a-python.json", "Python",
     "Parses JSON-RPC and replies from memory; nothing stored, no signature, no encryption beyond optional TLS"),
    ("mcp-agent-mail", "MCP Agent Mail", "mcp-agent-mail.json", "Python",
     "Stores the message in SQLite and as a Markdown file committed to Git; no signature, no encryption"),
    ("amp", "AMP (Fareground)", "amp.json", "Python",
     "Checks the sender's signature and stores the end-to-end encrypted envelope in SQLite (fsync); the receiver's pull, receipt and acknowledgments are further writes. Encryption runs in its Python client"),
]

data = {"local": [], "live": {}, "protections": None}
for key, name, f, lang, work in LOCAL:
    # Each system ran in two back-to-back rounds; keep its faster run (by throughput at 16 clients).
    runs = [r for r in (load(f), load(f.replace(".json", "-run2.json"))) if r]
    if not runs:
        continue
    d = max(runs, key=lambda r: level(r, 16, "msgs_per_sec") or 0)
    data["local"].append({
        "key": key, "name": name, "lang": lang, "work": work,
        "version": (d.get("extra", {}).get("version") or d.get("version", "")).split(" (")[0].split(";")[0],
        "thr16": level(d, 16, "msgs_per_sec"), "thr64": level(d, 64, "msgs_per_sec"),
        "p50_16": level(d, 16, "p50_ms"), "p99_64": level(d, 64, "p99_ms"),
        "err64": level(d, 64, "errors"), "err16": level(d, 16, "errors"),
        "bytes": d["wire_bytes"].get("send"), "cpu": d.get("cpu_ms_per_msg"),
        "idle": d["rss_mb"].get("idle"), "peak": d["rss_mb"].get("peak"),
        "cold": d.get("cold_start_ms"), "install": d.get("install_mb"),
        "rt": d.get("roundtrip_ms", {}).get("p50"),
        "rtbytes": d["wire_bytes"].get("roundtrip"),
        "runs": len(runs),
    })

def num(v, *path):
    """Read a number that may be nested (XMTP's file nests medians and per-process values)."""
    for p in path:
        if isinstance(v, dict):
            v = v.get(p)
    return v


# The primary live pair was measured back to back; every run is listed in the table.
LIVE = {"silk": ("silk-live-agents-run3.json", ["silk-live-agents.json", "silk-live-agents-run3.json"]),
        "xmtp": ("xmtp-dev-run2.json", ["xmtp-dev.json", "xmtp-dev-run2.json"])}
for key, (f, runs) in LIVE.items():
    d = load(f)
    if not d:
        continue
    rss = d.get("rss_mb", {})
    sender = rss.get("sender") if isinstance(rss.get("sender"), dict) else {"idle": rss.get("sender_idle"), "peak": rss.get("sender_peak")}
    inst = d.get("install_mb")
    reg, reo, byt = d.get("register_ms"), d.get("reopen_ms"), d.get("bytes_per_msg")
    data["live"][key] = {
        "send": d["send_ms"]["p50"], "send90": d["send_ms"]["p90"],
        "deliver": d["deliver_ms"]["p50"], "deliver90": d["deliver_ms"]["p90"],
        "rt": d["roundtrip_ms"]["p50"], "rt90": d["roundtrip_ms"]["p90"],
        # XMTP: timed after the SDK is loaded (the more favorable of its two figures).
        "register": reg["median"] if isinstance(reg, dict) else reg,
        "reopen": reo["median"] if isinstance(reo, dict) else reo,
        "rss_idle": sender.get("idle"), "rss_peak": sender.get("peak"),
        "cpu": d.get("cpu_ms_per_msg"),
        "bytes": num(byt, "sender", "total_per_msg") if isinstance(byt, dict) else byt,
        # XMTP: node_modules without other platforms' binaries; the Node.js runtime is extra.
        "install": inst.get("node_modules_without_other_platform_binaries") if isinstance(inst, dict) else inst,
        "install_runtime": num(inst, "node_runtime", "total_mb") if isinstance(inst, dict) else 0,
        "runs": [{"at": r.get("timestamp"), "send": r["send_ms"]["p50"], "deliver": r["deliver_ms"]["p50"], "rt": r["roundtrip_ms"]["p50"]}
                 for r in (load(x) for x in runs) if r],
    }

# Protections, from each project's own documentation (see docs/v2/COMPARISON.md).
# 2 = yes, 1 = partial or optional, 0 = no.
data["protections"] = {
    "systems": ["Silk", "XMTP", "A2A", "AMP", "MCP Agent Mail"],
    "rows": [
        ["End-to-end encryption", [2, 2, 0, 2, 0]],
        ["Post-quantum key exchange", [2, 2, 0, 2, 0]],
        ["Recovers after a key theft", [2, 2, 0, 2, 0]],
        ["Approval for new contacts that the agent cannot give itself", [2, 0, 0, 1, 0]],
        ["Unsolicited contact costs the sender, priced by recipient load", [2, 1, 0, 0, 0]],
        ["Public tamper-evident log of every event", [2, 0, 0, 0, 0]],
        ["Software updates checked against a public log", [2, 0, 0, 0, 0]],
        ["Message budgets and expiry per conversation", [2, 0, 0, 0, 0]],
        ["Delivers while the recipient is offline", [2, 2, 0, 2, 2]],
        ["Built-in MCP tools for agents", [2, 0, 0, 0, 2]],
    ],
}

html = (root / "compare_template.html").read_text().replace("__DATA__", json.dumps(data, separators=(",", ":")))
(root / "compare.html").write_text(html)
print(f"wrote bench/compare.html ({len(html)//1024} KB, {len(data['local'])} local systems, live: {sorted(data['live'])})")


# Results tables for docs/v2/COMPARISON.md (between the results markers).
def f0(v, d=0, unit=""):
    if v is None:
        return "–"
    if d == 0 and 0 < v < 10:
        d = 1
    return f"{v:,.{d}f}{unit}"


lines = ["**Same machine, same load** (each system's faster of two back-to-back runs):", "",
         "| | " + " | ".join(x["name"] for x in data["local"]) + " |",
         "|---|" + "---|" * len(data["local"])]
for label, key, d, unit in (("Throughput, 16 clients (msg/s)", "thr16", 0, ""), ("Throughput, 64 clients (msg/s)", "thr64", 0, ""),
                            ("p99 latency, 64 clients", "p99_64", 1, " ms"), ("Deliver + acknowledge, p50", "rt", 2, " ms"),
                            ("Bytes to send", "bytes", 0, " B"), ("Bytes to deliver + acknowledge", "rtbytes", 0, " B"),
                            ("Server CPU per message", "cpu", 3, " ms"), ("Server memory idle / peak", None, 0, ""),
                            ("Cold start", "cold", 0, " ms"), ("Install", "install", 1, " MB")):
    if key is None:
        cells = [f0(x["idle"], 1) + " / " + f0(x["peak"], 1, " MB") for x in data["local"]]
    else:
        cells = [f0(x[key], d, unit) for x in data["local"]]
    lines.append(f"| {label} | " + " | ".join(cells) + " |")
L, X = data["live"].get("silk"), data["live"].get("xmtp")
if L and X:
    lines += ["", "**Over the internet** (medians, the back-to-back pair):", "", "| | Silk (hosted relay) | XMTP (dev network) |", "|---|---|---|"]
    for label, key, d, unit in (("Send", "send", 0, " ms"), ("Delivery to a waiting recipient", "deliver", 0, " ms"), ("Ask and get a reply", "rt", 0, " ms"),
                                ("New identity ready", "register", 0, " ms"), ("Agent ready from existing identity", "reopen", 1, " ms"),
                                ("Client memory, peak", "rss_peak", 0, " MB"), ("Client CPU per message", "cpu", 1, " ms"),
                                ("Network bytes per message sent", "bytes", 0, " B"), ("Client install", "install", 1, " MB")):
        lines.append(f"| {label} | {f0(L[key], d, unit)} | {f0(X[key], d, unit)} |")
doc = root.parent / "docs" / "v2" / "COMPARISON.md"
text = doc.read_text()
a, b = text.index("<!-- results:start -->"), text.index("<!-- results:end -->")
doc.write_text(text[:a] + "<!-- results:start -->\n" + "\n".join(lines) + "\n" + text[b:])
