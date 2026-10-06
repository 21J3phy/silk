"""Focused adversarial regressions found during the final boundary review.

These exercise the real SDK-wrapped ASGI app, using explicitly synthetic
identity/store fixtures. They establish no live OAuth or PostgreSQL behavior.
"""
import logging
import unittest
from unittest.mock import patch

import anyio

from starlette.testclient import TestClient

from silk_live.app import BoundaryMiddleware, create_app
from tests.test_mcp_transport import HEADERS, SETTINGS, FixtureStore, FixtureVerifier


class SecurityBoundaryRegressionTests(unittest.TestCase):
    def setUp(self):
        self.store = FixtureStore()
        self.client = TestClient(
            create_app(SETTINGS, self.store, FixtureVerifier(), testing=True),
            base_url="https://silk.example",
        )
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def call_tool(self, name, arguments=None, *, authenticated=True):
        headers = HEADERS if authenticated else {
            key: value for key, value in HEADERS.items() if key != "Authorization"
        }
        return self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            },
            headers=headers,
        )

    def assert_bounded_failure(self, response):
        # JSON-RPC invalid-params responses may correctly use HTTP 200.
        if response.status_code == 200:
            self.assertIn("error", response.json(), response.text)
        else:
            self.assertGreaterEqual(response.status_code, 400, response.text)
            self.assertLess(response.status_code, 500, response.text)

    def test_unhashable_tool_names_fail_without_exception_or_store_access(self):
        for name in ([], {}, ["silk_identity"], {"name": "silk_identity"}):
            for authenticated in (False, True):
                with self.subTest(name=name, authenticated=authenticated):
                    response = self.call_tool(name, authenticated=authenticated)
                    self.assert_bounded_failure(response)
        self.assertEqual(self.store.calls, [])

    def test_other_non_string_tool_names_are_bounded_errors(self):
        for name in (None, False, 1, 1.5):
            with self.subTest(name=name):
                response = self.call_tool(name)
                self.assert_bounded_failure(response)
        self.assertEqual(self.store.calls, [])

    def test_absurd_content_length_does_not_reach_integer_conversion(self):
        # Python limits integer conversion to 4,300 digits by default. Leading
        # zeros also require a bound, independent of the numeric value.
        for length in ("9" * 4500, "0" * 4500, "0" * 4500 + "2"):
            with self.subTest(prefix=length[:1], length=len(length)):
                response = self.client.post(
                    "/mcp", content=b"{}",
                    headers={**HEADERS, "Content-Length": length},
                )
                self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(self.store.calls, [])

    def test_nullable_reply_id_string_is_not_silently_coerced_to_null(self):
        response = self.call_tool("silk_send", {
            "grant_id": "grant-fixture-01", "recipient_agent_id": "agent-fixture-b",
            "text": "Synthetic bounded message", "idempotency_key": "idem-fixture-01",
            "reply_to": "null",
        })
        if response.status_code == 200:
            self.assertTrue(response.json()["result"].get("isError"), response.text)
        else:
            self.assertGreaterEqual(response.status_code, 400, response.text)
            self.assertLess(response.status_code, 500, response.text)
        self.assertEqual(self.store.calls, [])

    def test_malformed_notification_does_not_log_request_body(self):
        marker = "PRIVATE-MESSAGE-SENTINEL"
        captured = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())

        handler = Capture()
        logging.getLogger().addHandler(handler)
        try:
            response = self.client.post("/mcp", json={
                "jsonrpc": "2.0", "method": "notifications/initialized",
                "params": {"x": marker, "_meta": []},
            }, headers=HEADERS)
            self.assertLess(response.status_code, 500, response.text)
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertNotIn(marker, "\n".join(captured))
        self.assertEqual(self.store.calls, [])

    def test_lone_surrogate_request_id_is_rejected_before_response_encoding(self):
        for method in ("unknown", "tools/list"):
            with self.subTest(method=method):
                # Escaped lone surrogates are accepted by Python json.loads but
                # cannot be safely serialized into the ASGI JSON response.
                raw = ('{"jsonrpc":"2.0","id":"\\ud800","method":"' + method + '"}').encode("ascii")
                response = self.client.post("/mcp", content=raw, headers=HEADERS)
                self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(self.store.calls, [])

    def test_stalled_body_has_total_read_deadline(self):
        messages = []
        called = []

        async def inner(*args):
            called.append(True)

        async def receive():
            await anyio.sleep_forever()

        async def send(message):
            messages.append(message)

        async def exercise():
            await BoundaryMiddleware(inner, None)(
                {"type": "http", "method": "POST", "path": "/mcp",
                 "query_string": b"", "headers": []}, receive, send,
            )

        # Shorten only the test deadline; production retains its five seconds.
        fail_after = anyio.fail_after
        with patch("silk_live.app.anyio.fail_after", side_effect=lambda _: fail_after(0.01)):
            anyio.run(exercise)
        self.assertEqual(called, [])
        self.assertEqual(messages[0]["status"], 408)
        self.assertIn(b"request_timeout", messages[1]["body"])

    def test_explicit_null_and_valid_reply_id_reach_store_unchanged(self):
        for reply_to in (None, "msg_fixture_parent_01"):
            with self.subTest(reply_to=reply_to):
                response = self.call_tool("silk_send", {
                    "grant_id": "grant-fixture-01", "recipient_agent_id": "agent-fixture-b",
                    "text": "Synthetic bounded message", "idempotency_key": "idem-fixture-01",
                    "reply_to": reply_to,
                })
                self.assertEqual(response.status_code, 200, response.text)
                self.assertFalse(response.json()["result"].get("isError"), response.text)
                self.assertEqual(self.store.calls[-1][2][0]["reply_to"], reply_to)


if __name__ == "__main__":
    unittest.main()
