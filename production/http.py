"""Minimal public handlers. No local demo import, writes, keys, or background work."""
from http.server import BaseHTTPRequestHandler
import json

from .readiness import status_document

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"


def route_response(route, method):
    if route == "status" and method in {"GET", "HEAD"}:
        return 200, status_document(), "GET, HEAD"
    if route in {"messages", "connections"} and method == "POST":
        return 503, {"error": {
            "code": "live_messaging_unavailable", "message": "Live messaging is disabled until verified owner authentication, durable storage, and supported agent adapters are configured.",
        }, "live_messaging": False}, "POST"
    if route in {"status", "messages", "connections"}:
        return 405, {"error": {"code": "method_not_allowed", "message": "This HTTP method is not supported."}}, "GET, HEAD" if route == "status" else "POST"
    return 404, {"error": {"code": "not_found", "message": "Route not found."}}, None


class PublicHandler(BaseHTTPRequestHandler):
    route = ""

    def _respond(self):
        status, document, allowed = route_response(self.route, self.command)
        body = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if status == 405 and allowed:
            self.send_header("Allow", allowed)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond
    do_POST = _respond
    do_PUT = _respond
    do_PATCH = _respond
    do_DELETE = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond
    do_CONNECT = _respond

    def log_message(self, format, *args):
        # Never persist untrusted request paths, bodies, headers, or tokens here.
        pass
