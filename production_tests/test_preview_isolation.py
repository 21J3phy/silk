"""Source-serving restrictions in the local public preview, not a hosted smoke test."""

import http.client
from http.server import HTTPServer
import json
import threading
import unittest

from scripts.serve_public import PreviewHandler


class PublicPreviewIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), PreviewHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, method, path, body=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_fixture_source_database_and_configuration_paths_are_not_served(self):
        for path in ("/web/index.html", "/web/app.js", "/silk/server.py", "/silk/service.py",
                     "/var/silk.sqlite3", "/requirements-dev.txt", "/vercel.json", "/.env",
                     "/production/interfaces.py", "/api/status.py", "/README.md"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)

    def test_traversal_and_encoded_private_paths_are_not_served(self):
        for path in ("/../web/index.html", "/%2e%2e/web/index.html", "/public/../web/index.html",
                     "/%2eenv", "/%2fweb%2findex.html", "/index.html/../silk/server.py"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)

    def test_fixture_session_and_state_routes_are_absent(self):
        for route in ("session", "state", "invitations", "grants", "envelopes"):
            for method in ("GET", "POST"):
                with self.subTest(route=route, method=method):
                    self.assertEqual(self.request(method, "/api/" + route)[0], 404)

    def test_readiness_and_closed_mutations_are_available(self):
        status, _, body = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertIs(json.loads(body)["live_messaging"], False)
        for route in ("messages", "connections"):
            status, _, body = self.request("POST", "/api/" + route, b"{}")
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body)["error"]["code"], "live_messaging_unavailable")

    def test_public_index_and_local_dependencies_are_served(self):
        for path, content_type in (("/", "text/html"), ("/styles.css", "text/css"),
                                   ("/app.js", "text/javascript")):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["Content-Type"].startswith(content_type))
                self.assertTrue(body)
                self.assertEqual(headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
