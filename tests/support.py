"""Deterministic test fixtures; never connect to external services."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from silk.service import DomainError, Service


class Clock:
    def __init__(self):
        self.now = int(datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc).timestamp())

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="silk-test-")
        self.addCleanup(self.temp.cleanup)
        self.db_path = str(Path(self.temp.name) / "fixture.sqlite3")
        self.clock = Clock()
        self.service = Service(self.db_path, clock=self.clock)
        self.addCleanup(lambda: self.service.close())

    def invite(self, owner="alice", **changes):
        data = dict(from_agent="atlas", to_agent="nova", purpose="Find one mutually useful study meeting", max_turns=4, expires_in=3600)
        data.update(changes)
        return self.service.create_invitation(owner, data)

    def grant(self, **changes):
        invitation = self.invite(**changes)
        self.service.respond_invitation("bob", invitation["id"], True)
        return next(g for g in self.service.state("alice")["grants"] if g["invitation_id"] == invitation["id"])

    def request(self, grant_id, key="request-one", **changes):
        data = dict(grant_id=grant_id, title="Coordinate a mock study meeting", options=self.service.state("alice")["suggested_options"][:3], idempotency_key=key)
        data.update(changes)
        return data

    def send(self, grant_id, key="request-one", owner="alice", **changes):
        return self.service.send_fixture(owner, self.request(grant_id, key, **changes))

    def message(self, message_id, owner="alice"):
        return next(m for m in self.service.state(owner)["messages"] if m["id"] == message_id)

    def current_grant(self, grant_id):
        return next(g for g in self.service.state("alice")["grants"] if g["id"] == grant_id)

    def assertDomainError(self, function, *args, code=None, **kwargs):
        with self.assertRaises(DomainError) as caught:
            function(*args, **kwargs)
        self.assertTrue(caught.exception.code)
        self.assertTrue(caught.exception.message)
        self.assertGreaterEqual(caught.exception.status, 400)
        self.assertLess(caught.exception.status, 500)
        if code:
            self.assertEqual(caught.exception.code, code)
        return caught.exception
