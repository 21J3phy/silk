"""Operator administration through the PostgreSQL DB-API path.

Uses the same SQLite-backed connection double as test_storage_postgres, so it
checks SQL order and invariants, not real PostgreSQL privileges or locking.
"""
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from silk_live import admin as admin_cli
from silk_live.admin import MailboxAdmin
from silk_live.domain import MailboxError, Principal
from silk_live.storage import PostgresStore, SQLiteFixtureStore
from tests.test_storage_postgres import DBAPIConnectionDouble

NOW = 1_800_000_000
A, B, C = "agent_aaaa", "agent_bbbb", "agent_cccc"
PA = Principal("https://issuer.invalid/", "subject-a", "client-a")
PB = Principal("https://issuer.invalid/", "subject-b", "client-b")


class AdminTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "isolated.sqlite3"
        SQLiteFixtureStore(self.path)  # schema and capacity row only
        self.connections = []
        def factory():
            connection = DBAPIConnectionDouble(self.path)
            self.connections.append(connection)
            return connection
        self.admin = MailboxAdmin(factory)
        self.runtime = PostgresStore(factory)

    def assertError(self, code, call, *args, **kwargs):
        with self.assertRaises(MailboxError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def provision_pair(self):
        self.admin.register_agent(A, "owner_aaaa", "Agent A")
        self.admin.register_agent(B, "owner_bbbb", "Agent B")
        self.admin.bind(PA, A, expires_at=NOW + 1000, now=NOW - 1)
        self.admin.bind(PB, B, expires_at=NOW + 1000, now=NOW - 1)
        return self.admin.grant("grant_ab_01", B, A, consent_a="ticket:B-1", consent_b="ticket:A-1", expires_at=NOW + 500, now=NOW - 1)

    def send(self, key="send-key-0001"):
        return self.runtime.send(PA, dict(grant_id="grant_ab_01", recipient_agent_id=B, text="Hello", ttl_seconds=120, idempotency_key=key, reply_to=None), NOW)

    def test_provisioned_pair_completes_a_runtime_roundtrip(self):
        grant = self.provision_pair()
        self.assertEqual((grant["agent_a"], grant["agent_b"]), (A, B))
        with sqlite3.connect(self.path) as connection:
            refs = connection.execute("SELECT consent_a_reference,consent_b_reference FROM pair_grants").fetchone()
        self.assertEqual(refs, ("ticket:A-1", "ticket:B-1"))  # follow sorted agents
        self.assertEqual(self.runtime.identity(PA, NOW)["grants"][0]["peer_agent_id"], B)
        sent = self.send()
        self.assertEqual([m["message_id"] for m in self.runtime.receive(PB, 20, NOW)["messages"]], [sent["message_id"]])
        status = self.admin.status()
        self.assertEqual(status["counts"]["messages"], 1)
        self.assertEqual(status["counts"]["agents"], 2)

    def test_every_mutation_locks_capacity_first(self):
        self.provision_pair()
        self.admin.revoke_grant("grant_ab_01", now=NOW)
        self.admin.revoke_binding(PA, now=NOW)
        self.admin.disable_agent(B, now=NOW)
        writes = [c for c in self.connections if any(q.startswith(("INSERT", "UPDATE")) for q, _ in c.statements)]
        self.assertEqual(len(writes), 8)
        for connection in writes:
            sql = [q for q, _ in connection.statements if not q.startswith("SET")]
            self.assertTrue(sql[0].startswith("SELECT * FROM silk_mailbox.mailbox_limits"), sql[0])
            self.assertTrue(sql[0].endswith(" FOR UPDATE"))
            self.assertTrue(all("%s" in q or "?" not in q for q in sql))

    def test_bindings_are_never_reassigned_or_resurrected(self):
        self.provision_pair()
        self.assertError("conflict", self.admin.bind, PA, B, expires_at=NOW + 1000, now=NOW)
        self.admin.revoke_binding(PA, now=NOW)
        self.assertError("binding_inactive", self.runtime.identity, PA, NOW)
        self.assertError("conflict", self.admin.bind, PA, A, expires_at=NOW + 2000, now=NOW + 1)
        self.assertEqual(self.admin.revoke_binding(PA, now=NOW + 5)["revoked_at"], NOW)
        self.assertError("not_found", self.admin.revoke_binding, Principal("https://issuer.invalid/", "nobody", "client-a"), now=NOW)

    def test_grants_require_real_consent_references_and_active_agents(self):
        self.admin.register_agent(A, "owner_aaaa", "Agent A")
        self.admin.register_agent(B, "owner_bbbb", "Agent B")
        for consent in ("", "fixture-only:x", "line\nbreak"):
            self.assertError("invalid_request", self.admin.grant, "grant_ab_01", A, B, consent_a=consent, consent_b="ticket:B-1", expires_at=NOW + 500, now=NOW)
        self.assertError("invalid_request", self.admin.grant, "grant_aa_01", A, A, consent_a="x", consent_b="y", expires_at=NOW + 500, now=NOW)
        self.assertError("not_found", self.admin.grant, "grant_ac_01", A, C, consent_a="x", consent_b="y", expires_at=NOW + 500, now=NOW)
        self.admin.disable_agent(B, now=NOW)
        self.assertError("not_found", self.admin.grant, "grant_ab_01", A, B, consent_a="x", consent_b="y", expires_at=NOW + 500, now=NOW)
        self.assertError("not_found", self.admin.bind, PB, B, expires_at=NOW + 500, now=NOW)

    def test_renewal_requires_a_new_grant_id_and_keeps_pair_history(self):
        self.provision_pair()
        self.assertError("conflict", self.admin.grant, "grant_ab_01", A, B, consent_a="x", consent_b="y", expires_at=NOW + 900, now=NOW)
        self.admin.grant("grant_ab_02", A, B, consent_a="ticket:A-2", consent_b="ticket:B-2", expires_at=NOW + 900, now=NOW)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM pair_quotas").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM pair_grants").fetchone()[0], 2)

    def test_revoke_grant_clears_pending_text_and_is_idempotent(self):
        self.provision_pair()
        self.send()
        first = self.admin.revoke_grant("grant_ab_01", now=NOW + 1)
        self.assertEqual(self.admin.revoke_grant("grant_ab_01", now=NOW + 9)["revoked_at"], first["revoked_at"])
        self.assertEqual(self.runtime.receive(PB, 20, NOW + 2), {"messages": []})
        with sqlite3.connect(self.path) as connection:
            self.assertIsNone(connection.execute("SELECT text FROM messages").fetchone()[0])
        self.assertError("grant_unavailable", self.admin.revoke_grant, "grant_none_01", now=NOW)

    def test_disabled_agent_loses_access(self):
        self.provision_pair()
        self.admin.disable_agent(A, now=NOW)
        self.assertError("binding_inactive", self.runtime.identity, PA, NOW)
        self.assertError("conflict", self.admin.register_agent, A, "owner_other", "Again")

    def test_capacity_is_enforced(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE mailbox_limits SET max_agents=1")
        self.admin.register_agent(A, "owner_aaaa", "Agent A")
        self.assertError("capacity_exhausted", self.admin.register_agent, B, "owner_bbbb", "Agent B")


class CommandLineTests(unittest.TestCase):
    def run_cli(self, argv, environ, connector=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = admin_cli.main(argv, environ, connector or admin_cli._connector)
        return code, out.getvalue(), err.getvalue()

    def test_unconfigured_names_the_variable_only(self):
        code, out, err = self.run_cli(["status"], {"SILK_ADMIN_POSTGRES_DSN": "postgresql://admin:secret@db"})
        self.assertEqual(code, 2)
        self.assertIn("SILK_POSTGRES_DSN", err)
        self.assertNotIn("secret", out + err)
        code, _, err = self.run_cli(["register-agent", "--agent-id", A, "--owner-id", "owner_aaaa", "--display-name", "A"], {"SILK_POSTGRES_DSN": "postgresql://runtime:secret@db"})
        self.assertEqual(code, 2)
        self.assertIn("SILK_ADMIN_POSTGRES_DSN", err)

    def test_connection_failure_never_prints_secrets(self):
        def connector(dsn, root_cert):
            def connect(autocommit=False):
                raise RuntimeError(f"could not connect to {dsn}")
            return connect
        env = {"SILK_ADMIN_POSTGRES_DSN": "postgresql://admin:secret@db"}
        for argv in (["migrate"], ["register-agent", "--agent-id", A, "--owner-id", "owner_aaaa", "--display-name", "A"]):
            code, out, err = self.run_cli(argv, env, connector)
            self.assertEqual(code, 1)
            self.assertNotIn("secret", out + err)
            self.assertEqual(json.loads(err)["error"]["code"], "storage_unavailable")

    def test_commands_provision_through_the_admin_role(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "isolated.sqlite3"
        SQLiteFixtureStore(path)
        used = []
        def connector(dsn, root_cert):
            used.append((dsn, root_cert))
            return lambda autocommit=False: DBAPIConnectionDouble(path)
        env = {"SILK_ADMIN_POSTGRES_DSN": "admin-dsn", "SILK_POSTGRES_DSN": "runtime-dsn"}
        for agent in (A, B):
            self.assertEqual(self.run_cli(["register-agent", "--agent-id", agent, "--owner-id", "owner_" + agent[-4:], "--display-name", agent], env, connector)[0], 0)
        self.assertEqual(self.run_cli(["bind", "--issuer", PA.issuer, "--subject", PA.subject, "--client-id", PA.client_id, "--agent-id", A, "--days", "7"], env, connector)[0], 0)
        code, out, _ = self.run_cli(["grant", "--grant-id", "grant_ab_01", "--agent-a", A, "--consent-a", "ticket:1", "--agent-b", B, "--consent-b", "ticket:2", "--max-turns", "4"], env, connector)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["max_turns"], 4)
        code, out, _ = self.run_cli(["status"], env, connector)
        self.assertEqual(json.loads(out)["counts"]["pair_grants"], 1)
        self.assertEqual(self.run_cli(["purge-expired"], env, connector)[0], 0)
        self.assertEqual([dsn for dsn, _ in used], ["admin-dsn"] * 4 + ["runtime-dsn"] * 2)
        self.assertEqual({cert for _, cert in used}, {"system"})
        code, _, err = self.run_cli(["bind", "--issuer", PA.issuer, "--subject", PA.subject, "--client-id", PA.client_id, "--agent-id", A, "--days", "0"], env, connector)
        self.assertEqual((code, json.loads(err)["error"]["code"]), (1, "invalid_request"))


if __name__ == "__main__":
    unittest.main()
