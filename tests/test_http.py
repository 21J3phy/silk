"""Real loopback HTTP checks with synthetic sessions and temporary SQLite."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from silk.server import make_server
from tests.support import Clock


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="silk-http-")
        self.clock = Clock()
        self.server = make_server(Path(self.temp.name)/"http.sqlite3", port=0, dispatch=False, clock=self.clock)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.cookie = None
        self.csrf = None
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.server.service.close()
        self.temp.cleanup()

    def request(self, method, path, data=None, headers=None, session=True, csrf=True, raw=None):
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        req_headers = {"Origin": self.origin}
        if body is not None:
            req_headers["Content-Type"] = "application/json"
        if session and self.cookie:
            req_headers["Cookie"] = self.cookie
        if csrf and self.csrf:
            req_headers["X-CSRF-Token"] = self.csrf
        if headers:
            req_headers.update(headers)
        req_headers = {k: v for k, v in req_headers.items() if v is not None}
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            connection.request(method, path, body=body, headers=req_headers)
            response = connection.getresponse()
            content = response.read()
            result_headers = dict(response.getheaders())
            try:
                decoded = json.loads(content)
            except (ValueError, UnicodeDecodeError):
                decoded = content
            return response.status, result_headers, decoded
        finally:
            connection.close()

    def session(self):
        status, headers, body = self.request("GET", "/api/session")
        self.assertEqual(status, 200)
        if "Set-Cookie" in headers:
            self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = body["csrf_token"]
        return headers, body

    def switch(self, owner):
        status, _, body = self.request("POST", "/api/session", {"owner_id": owner})
        self.assertEqual(status, 200, body)
        self.csrf = body["csrf_token"]
        return body

    def assertError(self, response, status=None, code=None):
        actual, _, body = response
        self.assertGreaterEqual(actual, 400, body)
        self.assertLess(actual, 500, body)
        self.assertIn("error", body)
        if status:
            self.assertEqual(actual, status)
        if code:
            self.assertEqual(body["error"]["code"], code)
        return body

    def invitation(self):
        status, _, body = self.request("POST", "/api/invitations", {"from_agent": "atlas", "to_agent": "nova", "purpose": "HTTP test invitation", "max_turns": 4, "expires_in": 3600})
        self.assertEqual(status, 201, body)
        return body

    def test_health_is_local_and_does_not_require_session(self):
        status, _, body = self.request("GET", "/health", session=False)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok", "mode": "local-fixture"})

    def test_session_cookie_is_http_only_strict_and_bounded(self):
        headers, body = self.session()
        self.assertEqual(body["current_owner"], "alice")
        self.assertTrue(body["demo"])
        self.assertGreaterEqual(len(body["csrf_token"]), 32)
        cookie = headers["Set-Cookie"]
        for required in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=3600"):
            self.assertIn(required, cookie)
        _, repeat = self.session()
        self.assertEqual(repeat, body)

    def test_state_requires_valid_session(self):
        self.assertError(self.request("GET", "/api/state", session=False), 401, "session_required")
        self.assertError(self.request("GET", "/api/state", headers={"Cookie": "silk_session=unknown"}), 401)

    def test_browser_mutations_require_matching_csrf(self):
        self.session()
        self.assertError(self.request("POST", "/api/session", {"owner_id": "bob"}, csrf=False), 403, "csrf_failed")
        self.assertError(self.request("POST", "/api/session", {"owner_id": "bob"}, headers={"X-CSRF-Token": "wrong"}), 403, "csrf_failed")
        self.assertEqual(self.request("GET", "/api/state")[2]["current_owner"]["id"], "alice")

    def test_owner_switch_rotates_csrf_and_invalidates_old_token(self):
        self.session()
        old = self.csrf
        self.switch("bob")
        self.assertNotEqual(self.csrf, old)
        self.assertError(self.request("POST", "/api/session", {"owner_id": "alice"}, headers={"X-CSRF-Token": old}), 403, "csrf_failed")
        self.assertEqual(self.request("GET", "/api/state")[2]["current_owner"]["id"], "bob")

    def test_independent_browser_sessions_keep_distinct_owners(self):
        self.session()
        first_cookie = self.cookie
        self.switch("bob")
        self.cookie, self.csrf = None, None
        self.session()
        self.assertNotEqual(self.cookie, first_cookie)
        self.assertEqual(self.request("GET", "/api/state")[2]["current_owner"]["id"], "alice")
        self.assertEqual(self.request("GET", "/api/state", headers={"Cookie": first_cookie})[2]["current_owner"]["id"], "bob")

    def test_cross_origin_and_null_origin_rejected_even_with_csrf(self):
        self.session()
        for origin in ("https://attacker.invalid", "null", "http://127.0.0.1:1", self.origin+"/", "http://localhost:"+str(self.port)):
            with self.subTest(origin=origin):
                self.assertError(self.request("POST", "/api/session", {"owner_id": "bob"}, headers={"Origin": origin}), 403, "cross_origin")

    def test_cross_site_fetch_metadata_rejected(self):
        self.session()
        self.assertError(self.request("POST", "/api/session", {"owner_id": "bob"}, headers={"Sec-Fetch-Site": "cross-site", "Origin": None}), 403, "cross_origin")

    def test_untrusted_host_and_forwarded_origin_cannot_bypass_loopback(self):
        for host in ("attacker.invalid", "localhost", "127.0.0.1.evil.invalid:"+str(self.port), "0.0.0.0:"+str(self.port)):
            with self.subTest(host=host):
                self.assertError(self.request("GET", "/health", headers={"Host": host, "X-Forwarded-Host": "127.0.0.1:"+str(self.port), "Origin": None}), 403, "invalid_host")

    def test_json_content_type_and_size_are_bounded(self):
        self.session()
        self.assertError(self.request("POST", "/api/session", {"owner_id": "bob"}, headers={"Content-Type": "text/plain"}), 415, "json_required")
        self.assertError(self.request("POST", "/api/session", raw=b" "*8193), 413, "payload_too_large")
        self.assertError(self.request("POST", "/api/session", raw=b""), 413, "payload_too_large")

    def test_malformed_utf8_json_duplicates_and_nonfinite_are_rejected(self):
        self.session()
        cases = [b'{"owner_id":"alice","owner_id":"bob"}', b'{"owner_id": NaN}', b'{"owner_id": Infinity}', b'\xff', b'{"owner_id":', b'['*1500+b']'*1500]
        for raw in cases:
            with self.subTest(raw=raw[:50]):
                self.assertError(self.request("POST", "/api/session", raw=raw))
        self.assertEqual(self.request("GET", "/api/state")[2]["current_owner"]["id"], "alice")

    def test_unknown_fields_and_types_cannot_switch_owner(self):
        self.session()
        for data in (None, [], "bob", {"owner_id": "bob", "admin": True}, {"owner_id": []}, {"owner_id": "mallory"}):
            with self.subTest(data=data):
                self.assertError(self.request("POST", "/api/session", raw=json.dumps(data).encode()))
        self.assertEqual(self.request("GET", "/api/state")[2]["current_owner"]["id"], "alice")

    def test_security_headers_on_json_errors_and_state(self):
        for path in ("/health", "/api/state", "/not-found"):
            with self.subTest(path=path):
                _, headers, _ = self.request("GET", path)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertEqual(headers["Referrer-Policy"], "no-referrer")
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
                self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
                self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_static_paths_do_not_expose_database_source_or_parent_files(self):
        for path in ("/../silk/service.py", "/%2e%2e/silk/service.py", "/var/silk.sqlite3", "/docs/CONTRACT.md", "/.git/config", "/api/state?owner=bob", "http://attacker.invalid/health"):
            with self.subTest(path=path):
                self.assertError(self.request("GET", path))

    def test_signed_ingress_does_not_need_browser_session(self):
        service = self.server.service
        invitation = service.create_invitation("alice", {"from_agent": "atlas", "to_agent": "nova", "purpose": "Signed ingress", "max_turns": 4, "expires_in": 3600})
        service.respond_invitation("bob", invitation["id"], True)
        grant = service.state("alice")["grants"][0]
        wire = service.fixture_envelope("alice", {"grant_id": grant["id"], "title": "Signed local request", "options": service.state("alice")["suggested_options"], "idempotency_key": "http-wire-request"})
        status, _, body = self.request("POST", "/api/envelopes", wire, session=False, csrf=False, headers={"Origin": None})
        self.assertEqual(status, 201, body)
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["message"]["status"], "queued")
        self.assertEqual(self.request("POST", "/api/envelopes", wire, session=False, csrf=False)[0], 200)
        self.assertError(self.request("POST", "/api/envelopes", wire, session=False, csrf=False, headers={"Origin": "https://attacker.invalid"}), 403)

    def test_http_two_owner_happy_path_and_decision_retries(self):
        self.session()
        invitation = self.invitation()
        self.assertError(self.request("POST", f'/api/invitations/{invitation["id"]}/accept', {}), 403)
        self.switch("bob")
        self.assertEqual(self.request("POST", f'/api/invitations/{invitation["id"]}/accept', {})[0], 200)
        self.switch("alice")
        state = self.request("GET", "/api/state")[2]
        data = {"grant_id": state["grants"][0]["id"], "title": "Complete HTTP fixture", "options": state["suggested_options"], "idempotency_key": "http-happy-request"}
        status, _, result = self.request("POST", "/api/messages", data)
        self.assertEqual(status, 201, result)
        message_id = result["message"]["id"]
        self.assertEqual(self.request("POST", "/api/messages", data)[0], 200)
        self.server.service.dispatch_pending()
        self.assertError(self.request("POST", f"/api/messages/{message_id}/approve", {}), 403)
        self.switch("bob")
        status, _, result = self.request("POST", f"/api/messages/{message_id}/approve", {})
        self.assertEqual(status, 200, result)
        receipt = result["receipt"]
        self.assertEqual(receipt["execution"], "simulation_only_no_calendar_write")
        self.assertEqual(self.request("POST", f"/api/messages/{message_id}/approve", {})[2]["receipt"], receipt)
        self.assertError(self.request("POST", f"/api/messages/{message_id}/decline", {}), 409)

    def test_http_owner_gate_and_csrf_apply_to_invitation(self):
        self.session()
        self.switch("bob")
        data = {"from_agent": "atlas", "to_agent": "nova", "purpose": "Wrong owner", "max_turns": 4, "expires_in": 3600}
        self.assertError(self.request("POST", "/api/invitations", data), 403, "not_owner")
        self.assertError(self.request("POST", "/api/invitations", data, csrf=False), 403, "csrf_failed")
        self.assertEqual(self.server.service.state("alice")["invitations"], [])

    def test_duplicate_host_origin_and_content_length_are_rejected(self):
        self.session()
        cases = [
            [("Host", f"127.0.0.1:{self.port}"), ("Host", f"127.0.0.1:{self.port}")],
            [("Origin", self.origin), ("Origin", self.origin)],
            [("Content-Length", "2"), ("Content-Length", "2")],
            [("Content-Type", "application/json"), ("Content-Type", "application/json")],
            [("Transfer-Encoding", "chunked")],
        ]
        for extra in cases:
            with self.subTest(headers=extra):
                replaced = {key.lower() for key, _ in extra}
                base = [("Host", f"127.0.0.1:{self.port}"), ("Origin", self.origin), ("Content-Length", "2"), ("Content-Type", "application/json"), ("Cookie", self.cookie), ("X-CSRF-Token", self.csrf)]
                headers = [(key, value) for key, value in base if key.lower() not in replaced] + extra
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                try:
                    connection.putrequest("POST", "/api/session", skip_host=True, skip_accept_encoding=True)
                    for key, value in headers:
                        connection.putheader(key, value)
                    connection.endheaders(b"{}")
                    response = connection.getresponse()
                    body = json.loads(response.read())
                    self.assertGreaterEqual(response.status, 400, body)
                    self.assertLess(response.status, 500, body)
                    self.assertIn("error", body)
                finally:
                    connection.close()

    def test_no_public_bind_supported(self):
        with self.assertRaises(ValueError):
            from silk.server import AppServer
            AppServer(self.server.service, host="0.0.0.0", port=0)
