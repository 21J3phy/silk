#!/usr/bin/env python3
"""Local preview of the deployable public surface, without the fixture broker."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import argparse
import json
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from production.http import CSP, route_response


class PreviewHandler(BaseHTTPRequestHandler):
    def respond(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            status, body, _ = route_response(path.removeprefix("/api/"), self.command)
            content, mime = json.dumps(body).encode(), "application/json"
        elif self.command in {"GET", "HEAD"} and path in {"/", "/index.html", "/styles.css", "/app.js", "/model.js", "/favicon.svg", "/robots.txt"}:
            filename = "index.html" if path == "/" else path[1:]
            target = ROOT / "public" / filename
            if not target.is_file():
                status, content, mime = 404, b"Not found", "text/plain"
            else:
                status, content = 200, target.read_bytes()
                mime = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".txt": "text/plain"}[target.suffix]
        else:
            status, content, mime = 404, b"Not found", "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    do_GET = respond
    do_HEAD = respond
    do_POST = respond
    do_PUT = respond
    do_DELETE = respond

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), PreviewHandler)
    print(f"Silk public preview: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
