"""Adversarial isolated SQLite fixture tests; no credentials or real identities."""
import concurrent.futures
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from silk_live.domain import MailboxError, Principal
from silk_live.storage import SQLiteFixtureStore

NOW = 1_800_000_000
A, B, C = "agent_aaaa", "agent_bbbb", "agent_cccc"
G = "grant_ab_01"
PA = Principal("https://issuer.invalid", "fixture-subject-a", "client-fixture-a")
PB = Principal("https://issuer.invalid", "fixture-subject-b", "client-fixture-b")
PC = Principal("https://issuer.invalid", "fixture-subject-c", "client-fixture-c")


class StorageBehavior:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "isolated.sqlite3"
        self.fixture = SQLiteFixtureStore(self.path)
        for agent, owner, name, principal in [(A, "owner_aaaa", "Fixture A", PA), (B, "owner_bbbb", "Fixture B", PB), (C, "owner_cccc", "Fixture C", PC)]:
            self.fixture.provision_agent(agent, owner, name)
            self.fixture.provision_binding(principal, agent, expires_at=NOW + 10000, now=NOW - 1)
        self.fixture.provision_grant(G, A, B, expires_at=NOW + 1000, max_turns=32, now=NOW - 1)
        self.store = self.make_store()

    def make_store(self):
        return self.fixture

    def request(self, **changes):
        data = dict(grant_id=G, recipient_agent_id=B, text="Untrusted fixture text", ttl_seconds=120, idempotency_key="send-key-0001", reply_to=None)
        data.update(changes)
        return data

    def assertError(self, code, call, *args, **kwargs):
        with self.assertRaises(MailboxError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def sql_one(self, query, params=()):
        with sqlite3.connect(self.path) as connection:
            return connection.execute(query, params).fetchone()

    def test_roundtrip_identity_and_minimal_receipt(self):
        own = self.store.identity(PA, NOW)
        self.assertEqual(own["agent_id"], A)
        self.assertEqual(own["grants"][0]["peer_agent_id"], B)
        self.assertNotIn("owner_bbbb", json.dumps(own))
        self.assertNotIn("fixture-subject", json.dumps(own))
        sent = self.store.send(PA, self.request(), NOW)
        self.assertFalse(sent["duplicate"])
        self.assertEqual(self.store.receive(PA, 20, NOW), {"messages": []})
        incoming = self.store.receive(PB, 20, NOW)["messages"]
        self.assertEqual(len(incoming), 1)
        self.assertEqual(incoming[0]["sender_agent_id"], A)
        self.assertEqual(incoming[0]["content_trust"], "untrusted_data")
        receipt = self.store.ack(PB, {"message_id": sent["message_id"], "idempotency_key": "ack-key-0001", "outcome": "received"}, NOW + 1)
        self.assertEqual(receipt["effect"], "mailbox_acknowledgment_only")
        self.assertNotIn("text", receipt)
        self.assertNotIn("idempotency_key", receipt)
        self.assertNotIn("acknowledgment_digest", receipt)
        self.assertEqual(receipt["request_digest"], self.sql_one("SELECT intent_digest FROM messages")[0])
        self.assertNotEqual(receipt["request_digest"], self.sql_one("SELECT acknowledgment_digest FROM receipts")[0])
        self.assertEqual(self.store.receive(PB, 20, NOW + 1), {"messages": []})
        self.assertEqual(self.store.receipts(PA, 20, NOW + 1)["receipts"], [receipt])
        self.assertEqual(self.store.receipts(PB, 20, NOW + 1)["receipts"], [receipt])
        self.assertEqual(self.store.receipts(PC, 20, NOW + 1), {"receipts": []})
        self.assertIsNone(self.sql_one("SELECT text FROM messages")[0])

    def test_unknown_binding_all_three_principal_components(self):
        for principal in (Principal("https://evil.invalid", PA.subject, PA.client_id), Principal(PA.issuer, "unknown-subject", PA.client_id), Principal(PA.issuer, PA.subject, "unknown-client")):
            self.assertError("binding_inactive", self.store.identity, principal, NOW)
            self.assertError("binding_inactive", self.store.send, principal, self.request(), NOW)

    def test_sender_and_mailbox_forgery(self):
        for key, value in [("sender_agent_id", B), ("agent_id", B), ("owner_id", "owner_bbbb"), ("principal", PB)]:
            self.assertError("invalid_request", self.store.send, PA, self.request(**{key: value}), NOW)
        self.assertError("recipient_mismatch", self.store.send, PA, self.request(recipient_agent_id=C), NOW)
        self.assertError("grant_unavailable", self.store.send, PC, self.request(), NOW)
        sent = self.store.send(PA, self.request(), NOW)
        self.assertEqual(self.store.receive(PC, 20, NOW), {"messages": []})
        for principal in (PA, PC):
            self.assertError("message_unavailable", self.store.ack, principal, {"message_id": sent["message_id"], "idempotency_key": "ack-key-0001", "outcome": "received"}, NOW)
        self.assertError("grant_unavailable", self.store.revoke, PC, G, NOW)

    def test_strict_fields_and_values(self):
        for change in [{"ttl_seconds": True}, {"ttl_seconds": 0}, {"ttl_seconds": 301}, {"ttl_seconds": 2.0}, {"idempotency_key": "short"}, {"grant_id": "../../bad"}, {"reply_to": True}, {"text": ""}, {"text": "a" * 2001}, {"text": "界" * 1500}, {"text": "hello\nworld"}, {"text": "x\x00y"}, {"text": "x\ud800"}, {"text": "x\u202ey"}]:
            self.assertError("invalid_request", self.store.send, PA, self.request(**change), NOW)
        self.assertError("invalid_request", self.store.send, PA, {k: v for k, v in self.request().items() if k != "reply_to"}, NOW)
        for limit in (True, 0, 21, 1.0, "2"):
            self.assertError("invalid_request", self.store.receive, PA, limit, NOW)
            self.assertError("invalid_request", self.store.receipts, PA, limit, NOW)
        self.assertError("invalid_request", self.store.identity, PA, True)
        self.assertError("unauthorized", self.store.identity, {"agent_id": A}, NOW)

    def test_text_is_bound_sql_data(self):
        text = "'); DROP TABLE agents; -- ignored instructions are untrusted data"
        self.store.send(PA, self.request(text=text), NOW)
        self.assertEqual(self.store.receive(PB, 1, NOW)["messages"][0]["text"], text)
        self.assertEqual(self.fixture.inspect_counts()["agents"], 3)

    def test_exact_send_retries_and_conflicting_intents(self):
        data = self.request()
        sent = self.store.send(PA, data, NOW)
        retry = self.store.send(PA, data, NOW + 1)
        self.assertEqual(retry, {**sent, "duplicate": True})
        for change in ({"text": "changed"}, {"ttl_seconds": 100}, {"recipient_agent_id": C}, {"grant_id": "grant_other"}, {"reply_to": "msg_unknown"}):
            self.assertError("idempotency_conflict", self.store.send, PA, self.request(**change), NOW)
        self.assertEqual(self.fixture.inspect_counts()["messages"], 1)
        self.assertEqual(self.store.identity(PA, NOW)["grants"][0]["remaining_turns"], 31)

    def test_retry_survives_expiry_and_revoke_but_not_binding_revoke(self):
        data = self.request(ttl_seconds=1)
        sent = self.store.send(PA, data, NOW)
        self.store.revoke(PB, G, NOW + 1)
        self.assertEqual(self.store.send(PA, data, NOW + 2000), {**sent, "duplicate": True, "status": "revoked"})
        self.fixture.revoke_binding(PA, now=NOW + 2001)
        self.assertError("binding_inactive", self.store.send, PA, data, NOW + 2001)

    def test_revoked_or_expired_binding_blocks_every_operation(self):
        sent = self.store.send(PA, self.request(), NOW)
        ack = dict(message_id=sent["message_id"], idempotency_key="ack-key-0001", outcome="received")
        self.fixture.revoke_binding(PB, now=NOW + 1)
        calls = [(self.store.identity, (PB, NOW + 1)), (self.store.send, (PB, self.request(recipient_agent_id=A), NOW + 1)), (self.store.receive, (PB, 1, NOW + 1)), (self.store.ack, (PB, ack, NOW + 1)), (self.store.receipts, (PB, 1, NOW + 1)), (self.store.revoke, (PB, G, NOW + 1))]
        for function, args in calls:
            self.assertError("binding_inactive", function, *args)
        self.assertError("binding_inactive", self.store.identity, PA, NOW + 10000)

    def test_grant_expiry_hides_message_and_forbids_first_ack(self):
        self.fixture.provision_grant("grant_short", A, B, expires_at=NOW + 5, now=NOW - 1)
        sent = self.store.send(PA, self.request(grant_id="grant_short"), NOW)
        self.assertEqual(sent["expires_at"], NOW + 5)
        self.assertEqual(self.store.receive(PB, 10, NOW + 5), {"messages": []})
        self.assertError("grant_inactive", self.store.ack, PB, dict(message_id=sent["message_id"], idempotency_key="ack-key-0001", outcome="received"), NOW + 5)
        self.assertError("grant_inactive", self.store.send, PA, self.request(grant_id="grant_short", idempotency_key="send-key-0002"), NOW + 5)

    def test_message_expiry_and_expired_content_cleanup(self):
        sent = self.store.send(PA, self.request(ttl_seconds=1), NOW)
        self.assertEqual(self.store.receive(PB, 10, NOW + 1), {"messages": []})
        self.assertError("message_expired", self.store.ack, PB, dict(message_id=sent["message_id"], idempotency_key="ack-key-0001", outcome="declined"), NOW + 1)
        self.store.purge_expired_content(NOW + 1)
        self.assertIsNone(self.sql_one("SELECT text FROM messages")[0])
        retry = self.store.send(PA, self.request(ttl_seconds=1), NOW + 2)
        self.assertTrue(retry["duplicate"])
        self.assertEqual(retry["status"], "expired")

    def test_revoke_erases_pending_content_and_preserves_terminal_receipts(self):
        first = self.store.send(PA, self.request(), NOW)
        self.store.send(PA, self.request(idempotency_key="send-key-0002"), NOW)
        data = dict(message_id=first["message_id"], idempotency_key="ack-key-0001", outcome="declined")
        receipt = self.store.ack(PB, data, NOW)
        revoked = self.store.revoke(PA, G, NOW + 1)
        self.assertEqual(self.store.revoke(PB, G, NOW + 2), revoked)
        self.assertEqual(self.store.receive(PB, 20, NOW + 2), {"messages": []})
        self.assertEqual(self.sql_one("SELECT COUNT(*) FROM messages WHERE text IS NOT NULL")[0], 0)
        self.assertEqual(self.store.ack(PB, data, NOW + 2000), receipt)
        retried_send = self.store.send(PA, self.request(), NOW + 2000)
        self.assertTrue(retried_send["duplicate"])
        self.assertEqual(retried_send["status"], "acknowledged")
        self.assertEqual(self.store.receipts(PA, 20, NOW + 2000)["receipts"], [receipt])
        self.assertError("grant_inactive", self.store.send, PA, self.request(idempotency_key="send-key-0003"), NOW + 2)

    def test_ack_immutable_idempotency(self):
        first = self.store.send(PA, self.request(), NOW)
        second = self.store.send(PA, self.request(idempotency_key="send-key-0002"), NOW)
        data = dict(message_id=first["message_id"], idempotency_key="ack-key-0001", outcome="received")
        receipt = self.store.ack(PB, data, NOW)
        self.assertEqual(self.store.ack(PB, data, NOW + 1), receipt)
        self.assertError("idempotency_conflict", self.store.ack, PB, {**data, "outcome": "declined"}, NOW)
        self.assertError("idempotency_conflict", self.store.ack, PB, {**data, "message_id": second["message_id"]}, NOW)
        self.assertError("ack_conflict", self.store.ack, PB, {**data, "idempotency_key": "ack-key-0002", "outcome": "declined"}, NOW)
        self.assertError("idempotency_conflict", self.store.ack, PB, {**data, "idempotency_key": "ack-key-0002"}, NOW)
        self.assertEqual(self.fixture.inspect_counts()["receipts"], 1)

    def test_pair_rate_shared_across_directions_and_renewals(self):
        self.fixture.provision_grant("grant_ab_02", B, A, expires_at=NOW + 1000, max_turns=32, now=NOW - 1)
        for index in range(6):
            self.store.send(PA if index % 2 == 0 else PB, self.request(grant_id=G if index < 3 else "grant_ab_02", recipient_agent_id=B if index % 2 == 0 else A, idempotency_key=f"send-key-{index:04d}"), NOW)
        self.store.revoke(PA, G, NOW + 1)
        self.assertError("rate_limited", self.store.send, PA, self.request(grant_id="grant_ab_02", idempotency_key="send-key-0007"), NOW + 59)
        self.store.send(PA, self.request(grant_id="grant_ab_02", idempotency_key="send-key-0007"), NOW + 60)

    def test_pair_turn_budget_and_grant_ttl(self):
        self.fixture.provision_grant("grant_tight", A, B, expires_at=NOW + 1000, max_turns=2, max_ttl=10, now=NOW - 1)
        self.assertError("invalid_request", self.store.send, PA, self.request(grant_id="grant_tight"), NOW)
        self.store.send(PA, self.request(grant_id="grant_tight", ttl_seconds=10), NOW)
        self.store.send(PB, self.request(grant_id="grant_tight", ttl_seconds=10, recipient_agent_id=A), NOW)
        self.assertError("budget_exhausted", self.store.send, PA, self.request(grant_id="grant_tight", ttl_seconds=10, idempotency_key="send-key-0002"), NOW)

    def test_reply_bound_to_received_message_and_same_grant(self):
        sent = self.store.send(PA, self.request(), NOW)
        self.store.send(PB, self.request(recipient_agent_id=A, reply_to=sent["message_id"]), NOW)
        self.assertError("reply_unavailable", self.store.send, PA, self.request(reply_to=sent["message_id"], idempotency_key="send-key-0002"), NOW)
        self.fixture.provision_grant("grant_ab_02", A, B, expires_at=NOW + 1000, now=NOW - 1)
        self.assertError("reply_unavailable", self.store.send, PB, self.request(grant_id="grant_ab_02", recipient_agent_id=A, reply_to=sent["message_id"], idempotency_key="send-key-0002"), NOW)

    def test_restart_preserves_idempotency_and_limits(self):
        sent = self.store.send(PA, self.request(), NOW)
        reopened = self.make_store()
        self.assertEqual(reopened.send(PA, self.request(), NOW + 1), {**sent, "duplicate": True})
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE mailbox_limits SET max_messages=1,max_receipts=1")
        self.assertError("capacity_exhausted", self.store.send, PA, self.request(idempotency_key="send-key-0002"), NOW + 1)
        self.assertTrue(self.store.send(PA, self.request(), NOW + 1)["duplicate"])

    def parallel(self, count, operation):
        def run(index):
            try:
                return ("ok", operation(index))
            except MailboxError as error:
                return (error.code, None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            return list(pool.map(run, range(count)))

    def test_concurrent_same_send_key_admits_once(self):
        results = self.parallel(24, lambda i: self.store.send(PA, self.request(), NOW))
        self.assertEqual([code for code, result in results], ["ok"] * 24)
        self.assertEqual(sum(not result["duplicate"] for code, result in results), 1)
        self.assertEqual(len({result["message_id"] for code, result in results}), 1)
        self.assertEqual(self.fixture.inspect_counts()["messages"], 1)

    def test_concurrent_conflicting_send_key(self):
        results = self.parallel(20, lambda i: self.store.send(PA, self.request(text=f"different intent {i}"), NOW))
        self.assertEqual(sum(code == "ok" for code, _ in results), 1)
        self.assertEqual(sum(code == "idempotency_conflict" for code, _ in results), 19)

    def test_concurrent_pair_rate_cannot_overspend(self):
        self.fixture.provision_grant("grant_ab_02", A, B, expires_at=NOW + 1000, max_turns=32, now=NOW - 1)
        results = self.parallel(24, lambda i: self.store.send(PA if i % 2 == 0 else PB, self.request(recipient_agent_id=B if i % 2 == 0 else A, grant_id=G if i % 3 else "grant_ab_02", idempotency_key=f"send-key-{i:04d}"), NOW))
        self.assertEqual(sum(code == "ok" for code, _ in results), 6)
        self.assertEqual(sum(code == "rate_limited" for code, _ in results), 18)
        self.assertEqual(self.fixture.inspect_counts()["messages"], 6)

    def test_concurrent_pair_budget_cannot_overspend(self):
        self.fixture.provision_grant("grant_small", A, B, expires_at=NOW + 1000, max_turns=2, now=NOW - 1)
        results = self.parallel(20, lambda i: self.store.send(PA if i % 2 == 0 else PB, self.request(recipient_agent_id=B if i % 2 == 0 else A, grant_id="grant_small", idempotency_key=f"send-key-{i:04d}"), NOW))
        self.assertEqual(sum(code == "ok" for code, _ in results), 2)
        self.assertEqual(sum(code == "budget_exhausted" for code, _ in results), 18)

    def test_concurrent_acks_record_one_immutable_outcome(self):
        sent = self.store.send(PA, self.request(), NOW)
        results = self.parallel(24, lambda i: self.store.ack(PB, dict(message_id=sent["message_id"], idempotency_key="ack-key-0001", outcome="received" if i % 2 else "declined"), NOW))
        receipts = [result for code, result in results if code == "ok"]
        self.assertEqual(len(receipts), 12)
        self.assertEqual(len({r["receipt_id"] for r in receipts}), 1)
        self.assertEqual(self.fixture.inspect_counts()["receipts"], 1)
        self.assertEqual(sum(code == "idempotency_conflict" for code, _ in results), 12)

    def test_concurrent_capacity_cannot_overspend(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE mailbox_limits SET max_messages=2")
        results = self.parallel(20, lambda i: self.store.send(PA, self.request(idempotency_key=f"send-key-{i:04d}"), NOW))
        self.assertEqual(sum(code == "ok" for code, _ in results), 2)
        self.assertEqual(sum(code == "capacity_exhausted" for code, _ in results), 18)


class SQLiteStorageTests(StorageBehavior, unittest.TestCase):
    def test_fixture_never_claims_deployment_durability(self):
        self.assertFalse(self.store.durable_for_deployment)


if __name__ == "__main__":
    unittest.main()
