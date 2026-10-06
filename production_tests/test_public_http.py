"""Readiness/HTTP checks against actual Python handlers on loopback only."""

import http.client
from http.server import HTTPServer
import importlib
import json
import os
import threading
import unittest
from unittest.mock import patch

from production.http import route_response
from production.readiness import status_document


class ReadinessTests(unittest.TestCase):
    def test_status_truthfully_reports_every_missing_live_dependency(self):
        document = status_document()
        self.assertEqual(document["product"], "Silk")
        self.assertEqual(document["stage"], "development_preview")
        self.assertIs(document["live_messaging"], False)
        self.assertEqual(document["owner_authentication"]["state"], "not_configured")
        self.assertEqual(document["durable_storage"]["state"], "not_configured")
        self.assertGreaterEqual(len(document["missing_requirements"]), 4)
        self.assertEqual({entry["id"] for entry in document["connections"]}, {"grok", "dot"})
        for entry in document["connections"]:
            self.assertIs(entry["connected"], False)
            self.assertEqual(entry["state"], "not_connected")
            self.assertEqual(entry["inbound"], "unverified")
            self.assertEqual(entry["outbound"], "unverified")
        self.assertEqual(document["walkthrough"], {
            "mode": "browser_simulation", "sends_messages": False, "creates_accounts": False,
        })

    def test_environment_flags_cannot_fabricate_connections_or_leak_secrets(self):
        synthetic = {
            "SILK_LIVE_MESSAGING": "true", "SILK_CONNECTED": "true",
            "SILK_AUTH_SECRET": "test-sentinel-never-a-real-secret",
            "DATABASE_URL": "test-sentinel-never-a-real-database",
            "XAI_API_KEY": "test-sentinel-never-a-real-key",
        }
        baseline = status_document()
        with patch.dict(os.environ, synthetic):
            self.assertEqual(status_document(), baseline)
            status, response, _ = route_response("messages", "POST")
        self.assertEqual(status, 503)
        self.assertNotIn("test-sentinel", json.dumps(response))

    def test_status_returns_fresh_independent_documents(self):
        first = status_document()
        first["connections"][0]["connected"] = True
        first["missing_requirements"].clear()
        self.assertIs(status_document()["connections"][0]["connected"], False)
        self.assertGreaterEqual(len(status_document()["missing_requirements"]), 4)

    def test_status_and_rejections_perform_no_file_or_network_io(self):
        with patch("builtins.open", side_effect=AssertionError("Unexpected filesystem access")), \
             patch("socket.socket", side_effect=AssertionError("Unexpected network access")):
            status_document()
            for route in ("status", "messages", "connections", "session"):
                for method in ("GET", "POST", "DELETE"):
                    route_response(route, method)

    def test_routes_reject_unknown_paths_and_unsupported_methods(self):
        for route in ("session", "state", "invitations", "../silk", ""):
            for method in ("GET", "POST"):
                self.assertEqual(route_response(route, method)[0], 404)
        for route in ("status", "messages", "connections"):
            for method in ("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"):
                status, body, allow = route_response(route, method)
                self.assertEqual(status, 405)
                self.assertEqual(body["error"]["code"], "method_not_allowed")
                self.assertTrue(allow)


class PublicHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = {}
        for route in ("status", "messages", "connections"):
            handler = importlib.import_module("api." + route).handler
            server = HTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            cls.servers[route] = (server, thread)

    @classmethod
    def tearDownClass(cls):
        for server, thread in cls.servers.values():
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def request(self, route, method="GET", body=None, headers=None):
        server, _ = self.servers[route]
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        try:
            connection.request(method, "/api/" + route, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            return response.status, dict(response.getheaders()), payload
        finally:
            connection.close()

    def assert_security_headers(self, headers):
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("form-action 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_get_status_has_truthful_json_and_security_headers(self):
        status, headers, body = self.request("status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), status_document())
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assert_security_headers(headers)

    def test_head_status_has_same_metadata_without_response_body(self):
        _, get_headers, _ = self.request("status")
        status, headers, body = self.request("status", "HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], get_headers["Content-Length"])
        self.assert_security_headers(headers)

    def test_public_mutations_fail_closed_for_untrusted_and_forged_input(self):
        payloads = (None, b"{}", b'{"owner_id":"alice","connected":true}', b"not-json",
                    b'\xff', b'{"body":"synthetic-private-content-must-not-be-echoed"}', b" " * 16384)
        for route in ("messages", "connections"):
            for payload in payloads:
                with self.subTest(route=route, payload=repr(payload)[:80]):
                    status, headers, body = self.request(route, "POST", payload, {
                        "Authorization": "Bearer forged", "Cookie": "silk_session=forged",
                        "X-Owner-ID": "alice", "X-CSRF-Token": "forged",
                        "Origin": "https://attacker.invalid", "Content-Type": "application/json",
                    })
                    self.assertEqual(status, 503)
                    document = json.loads(body)
                    self.assertEqual(document["error"]["code"], "live_messaging_unavailable")
                    self.assertIs(document["live_messaging"], False)
                    self.assertNotIn(b"synthetic-private-content", body)
                    self.assert_security_headers(headers)

    def test_wrong_methods_return_json_405_and_correct_allow_header(self):
        for route, methods, allowed in (
            ("status", ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"), "GET, HEAD"),
            ("messages", ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"), "POST"),
            ("connections", ("GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"), "POST"),
        ):
            for method in methods:
                with self.subTest(route=route, method=method):
                    status, headers, body = self.request(route, method)
                    self.assertEqual(status, 405)
                    self.assertEqual(headers["Allow"], allowed)
                    if method == "HEAD":
                        self.assertEqual(body, b"")
                    else:
                        self.assertEqual(json.loads(body)["error"]["code"], "method_not_allowed")
                    self.assert_security_headers(headers)

    def test_attempted_mutations_do_not_change_subsequent_readiness(self):
        before = self.request("status")[2]
        for route in ("connections", "messages"):
            self.request(route, "POST", b'{"connected":true,"enabled":true}')
        self.assertEqual(self.request("status")[2], before)


if __name__ == "__main__":
    unittest.main()
