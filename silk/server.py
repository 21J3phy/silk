"""Loopback-only HTTP transport for the local fixture broker.

Python's development HTTP server is intentionally not an internet deployment.
No reverse proxy, public bind, TLS, or production login is offered here.
"""
from __future__ import annotations

import argparse
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from .protocol import DomainError, OWNERS, canonical, exact_object, fail
from .service import Service

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate_json_key", "Duplicate JSON object keys are not accepted.")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: fail("invalid_json", "JSON numbers must be finite."))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        fail("invalid_json", "Request body must be valid UTF-8 JSON.")


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, service, host="127.0.0.1", port=8765, dispatch=True):
        if host != "127.0.0.1":
            raise ValueError("This fixture server binds only to 127.0.0.1.")
        self.service = service
        self.sessions = {}
        self.session_lock = threading.RLock()
        self.stop_dispatch = threading.Event()
        self.dispatcher = None
        super().__init__((host, port), Handler)
        if dispatch:
            self.dispatcher = threading.Thread(target=self._dispatch_loop, daemon=True)
            self.dispatcher.start()

    def _dispatch_loop(self):
        while not self.stop_dispatch.wait(0.5):
            try:
                self.service.dispatch_pending()
            except Exception:
                # Avoid exposing untrusted request bodies in logs. The app is a demo;
                # a durable supervised worker and operational alarms are future work.
                print("Local dispatcher error; pending requests remain subject to their deadlines.", flush=True)

    def server_close(self):
        self.stop_dispatch.set()
        if self.dispatcher:
            self.dispatcher.join(timeout=5)
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "SilkLocal/0.1"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, fmt, *args):
        # Do not log URLs, request text, owner data, tokens, or signatures.
        pass

    def _write(self, status, body, content_type="application/json; charset=utf-8", cookie=None):
        if type(body) is not bytes:
            body = canonical(body)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, error):
        self._write(error.status, {"error": {"code": error.code, "message": error.message}})

    def _host(self):
        port = self.server.server_address[1]
        hosts = self.headers.get_all("Host", [])
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if len(hosts) != 1 or hosts[0] not in allowed:
            fail("invalid_host", "Use the loopback address printed at startup.", 403)
        return hosts[0]

    def _origin(self):
        host = self._host()
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1 or (origins and origins[0] != f"http://{host}"):
            fail("cross_origin", "Cross-origin requests are not accepted.", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            fail("cross_origin", "Cross-site requests are not accepted.", 403)

    def _session(self, create=False):
        token = None
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            if "silk_session" in cookies:
                token = cookies["silk_session"].value
        except CookieError:
            pass
        with self.server.session_lock:
            now = time.time()
            for stale in [k for k, v in self.server.sessions.items() if now - v["created"] > 3600]:
                del self.server.sessions[stale]
            session = self.server.sessions.get(token)
            cookie = None
            if session is None and create:
                if len(self.server.sessions) >= 128:
                    fail("session_capacity", "The local demo has too many open sessions; restart it to clear sessions.", 429)
                token = secrets.token_urlsafe(32)
                session = {"owner_id": "alice", "csrf_token": secrets.token_urlsafe(32), "created": now}
                self.server.sessions[token] = session
                cookie = f"silk_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"
            if session is None:
                fail("session_required", "Reload the demo to create a fixture session.", 401)
            return session, cookie

    def _session_body(self, session):
        return {"csrf_token": session["csrf_token"], "current_owner": session["owner_id"], "owners": OWNERS, "demo": True}

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            fail("unsupported_encoding", "Chunked requests are not supported.")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
            fail("length_required", "Supply one valid Content-Length header.", 411)
        length = int(lengths[0])
        if not 1 <= length <= 8192:
            fail("payload_too_large", "JSON requests must be between 1 and 8192 bytes.", 413)
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
            fail("json_required", "Use application/json requests.", 415)
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            fail("request_timeout", "The request body was incomplete.", 408)
        if len(raw) != length:
            fail("incomplete_body", "The request body was incomplete.")
        return strict_json(raw)

    def do_GET(self):
        try:
            self._origin()
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                fail("invalid_path", "This route does not accept an absolute URL or query string.")
            path = parsed.path
            if path == "/health":
                return self._write(200, {"status": "ok", "mode": "local-fixture"})
            if path == "/api/session":
                session, cookie = self._session(create=True)
                return self._write(200, self._session_body(session), cookie=cookie)
            if path == "/api/state":
                session, _ = self._session()
                return self._write(200, self.server.service.state(session["owner_id"]))
            static = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/styles.css": ("styles.css", "text/css; charset=utf-8")}
            if path in static:
                filename, mime = static[path]
                try:
                    content = (WEB_ROOT / filename).read_bytes()
                except FileNotFoundError:
                    fail("ui_not_ready", "The local interface has not been built yet.", 503)
                return self._write(200, content, mime)
            fail("not_found", "Route not found.", 404)
        except DomainError as error:
            self._error(error)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._error(DomainError("internal_error", "An internal local-demo error occurred.", 500))

    def do_POST(self):
        try:
            self._origin()
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                fail("invalid_path", "This route does not accept an absolute URL or query string.")
            path = parsed.path
            data = self._body()
            if path == "/api/envelopes":
                result = self.server.service.receive(data)
                return self._write(200 if result["duplicate"] else 201, result)
            session, _ = self._session()
            token = self.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(token, session["csrf_token"]):
                fail("csrf_failed", "The action token is missing or stale. Reload the demo and try again.", 403)
            owner = session["owner_id"]
            if path == "/api/session":
                exact_object(data, {"owner_id"}, "Owner switch")
                self.server.service._owner(data["owner_id"])
                with self.server.session_lock:
                    session["owner_id"] = data["owner_id"]
                    session["csrf_token"] = secrets.token_urlsafe(32)
                return self._write(200, self._session_body(session))
            if path == "/api/invitations":
                return self._write(201, self.server.service.create_invitation(owner, data))
            if path == "/api/messages":
                result = self.server.service.send_fixture(owner, data)
                return self._write(200 if result["duplicate"] else 201, result)
            match = re.fullmatch(r"/api/(invitations|grants|messages)/([A-Za-z0-9._:-]{8,100})/(accept|decline|revoke|approve)", path)
            if match:
                kind, identifier, action = match.groups()
                exact_object(data, set(), "Action")
                if kind == "invitations" and action in {"accept", "decline"}:
                    return self._write(200, self.server.service.respond_invitation(owner, identifier, action == "accept"))
                if kind == "grants" and action == "revoke":
                    return self._write(200, self.server.service.revoke_grant(owner, identifier))
                if kind == "messages" and action in {"approve", "decline"}:
                    return self._write(200, self.server.service.decide(owner, identifier, "approved" if action == "approve" else "declined"))
            fail("not_found", "Route not found.", 404)
        except DomainError as error:
            self._error(error)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._error(DomainError("internal_error", "An internal local-demo error occurred.", 500))


def make_server(db_path, host="127.0.0.1", port=0, dispatch=True, clock=time.time):
    return AppServer(Service(db_path, clock=clock), host=host, port=port, dispatch=dispatch)


def main():
    parser = argparse.ArgumentParser(description="Run Silk's local consent demo. No live providers or public deployment.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="var/silk.sqlite3")
    args = parser.parse_args()
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if str(db_path.parent) not in {".", "/"}:
        # Only the dedicated default data directory is permission-managed.
        if db_path.parent.resolve() == (Path.cwd() / "var").resolve():
            db_path.parent.chmod(0o700)
    server = make_server(db_path, port=args.port)
    print(f"Silk local fixture demo: http://127.0.0.1:{server.server_address[1]}", flush=True)
    print("Owner switching is demo-only. No providers, calendars, accounts, or payments are connected.", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.service.close()


if __name__ == "__main__":
    main()
