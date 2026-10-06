"""DB-API SQL-path contract tests, explicitly NOT PostgreSQL integration.

The double translates PostgreSQL placeholders/row-lock clauses to SQLite and
uses its whole-write-transaction lock. It catches DB-API wiring and validates
SQL order/parameterization, but cannot establish PostgreSQL syntax, privileges,
MVCC/lock behavior, crash durability, or managed-provider behavior.
"""
import re
import sqlite3
import unittest
from pathlib import Path

from silk_live.domain import MailboxError
from silk_live.storage import PostgresStore
from tests.test_storage import StorageBehavior, PA, PB, NOW, G


class DBAPICursorDouble:
    def __init__(self, owner):
        self.owner = owner
        self.cursor = owner.connection.cursor()
        self.description = None

    def execute(self, sql, params=()):
        self.owner.statements.append((sql, tuple(params)))
        if self.owner.fail_on and self.owner.fail_on in sql:
            raise RuntimeError("secret DSN and token that must never be exposed")
        if sql.startswith("SET TRANSACTION"):
            assert self.owner.autocommit is False
            assert sql == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
            self.cursor.execute("BEGIN IMMEDIATE")
            return
        if sql.startswith("SET LOCAL"):
            return
        if "?" in sql:
            raise AssertionError("PostgreSQL must use DB-API %s placeholders")
        translated = sql.replace("silk_mailbox.", "").replace("%s", "?")
        translated = re.sub(r" FOR (?:SHARE|UPDATE)$", "", translated)
        self.cursor.execute(translated, params)
        self.description = self.cursor.description

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        self.cursor.close()


class DBAPIConnectionDouble:
    def __init__(self, path, *, fail_on=None, ambiguous_commit=False, fail_close=False):
        self.connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.autocommit = True
        self.statements = []
        self.committed = self.rolled_back = self.closed = False
        self.fail_on, self.ambiguous_commit, self.fail_close = fail_on, ambiguous_commit, fail_close

    def cursor(self):
        return DBAPICursorDouble(self)

    def commit(self):
        self.connection.commit()
        self.committed = True
        if self.ambiguous_commit:
            raise RuntimeError("connection lost after COMMIT with secret details")

    def rollback(self):
        self.connection.rollback()
        self.rolled_back = True

    def close(self):
        self.connection.close()
        self.closed = True
        if self.fail_close:
            raise RuntimeError("private close error")


class PostgresDBAPIContractTests(StorageBehavior, unittest.TestCase):
    def make_store(self):
        self.connections = []
        def factory():
            connection = DBAPIConnectionDouble(self.path)
            self.connections.append(connection)
            return connection
        return PostgresStore(factory)

    def test_constructor_does_not_connect_or_migrate(self):
        calls = []
        store = PostgresStore(lambda: calls.append(True))
        self.assertEqual(calls, [])
        self.assertTrue(store.durable_for_deployment)
        for helper in ("provision_agent", "provision_binding", "provision_grant", "revoke_binding"):
            self.assertFalse(hasattr(store, helper))
        with self.assertRaises(TypeError):
            PostgresStore(None)

    def test_real_sql_path_uses_parameters_and_lock_order(self):
        text = "Private contents must remain bound parameters"
        self.store.send(PA, self.request(text=text), NOW)
        connection = self.connections[-1]
        self.assertTrue(connection.committed)
        self.assertTrue(connection.closed)
        statements = connection.statements
        sql = [q for q, _ in statements]
        self.assertTrue(sql[0].startswith("SET TRANSACTION"))
        capacity = next(i for i, q in enumerate(sql) if "FROM silk_mailbox.mailbox_limits" in q)
        binding = next(i for i, q in enumerate(sql) if "FROM silk_mailbox.agent_bindings" in q)
        pair_lock = next(i for i, q in enumerate(sql) if "FROM silk_mailbox.pair_quotas" in q)
        grant_lock = next(i for i, q in enumerate(sql) if "SELECT * FROM silk_mailbox.pair_grants" in q)
        rate = next(i for i, q in enumerate(sql) if "pair_id=%s AND created_at>" in q)
        insert = next(i for i, q in enumerate(sql) if "INSERT INTO silk_mailbox.messages" in q)
        self.assertLess(capacity, binding)
        self.assertLess(binding, pair_lock)
        self.assertLess(pair_lock, grant_lock)
        self.assertLess(grant_lock, rate)
        self.assertLess(rate, insert)
        self.assertTrue(sql[capacity].endswith(" FOR UPDATE"))
        self.assertTrue(sql[binding].endswith(" FOR SHARE"))
        self.assertTrue(sql[pair_lock].endswith(" FOR UPDATE"))
        self.assertTrue(sql[grant_lock].endswith(" FOR UPDATE"))
        self.assertTrue(all(text not in q for q in sql))
        self.assertIn(text, statements[insert][1])
        self.assertFalse(any(re.search(r"\b(CREATE|ALTER|DROP|GRANT)\b", q) for q in sql))

    def test_readiness_is_read_only_and_does_not_provision(self):
        result = self.store.check_readiness()
        self.assertEqual(result, {"ready": True, "backend": "postgresql", "check": "schema_and_capacity_read_only"})
        self.assertTrue(all(q.startswith(("SELECT", "SET")) for q, _ in self.connections[-1].statements))

    def test_missing_schema_fails_closed(self):
        connection = DBAPIConnectionDouble(self.path, fail_on="FROM silk_mailbox.agents")
        store = PostgresStore(lambda: connection)
        error = self.assertError("storage_unavailable", store.check_readiness)
        self.assertNotIn("secret", str(error))
        self.assertTrue(connection.rolled_back)
        self.assertTrue(connection.closed)

    def test_write_failure_rolls_back_admission_and_hides_database_details(self):
        connection = DBAPIConnectionDouble(self.path, fail_on="UPDATE silk_mailbox.pair_grants SET used_turns", fail_close=True)
        store = PostgresStore(lambda: connection)
        error = self.assertError("storage_unavailable", store.send, PA, self.request(), NOW)
        self.assertNotIn("secret", str(error))
        self.assertTrue(connection.rolled_back)
        self.assertTrue(connection.closed)
        self.assertEqual(self.fixture.inspect_counts()["messages"], 0)
        self.assertEqual(self.store.identity(PA, NOW)["grants"][0]["remaining_turns"], 32)

    def test_ambiguous_commit_recovered_by_same_key(self):
        connection = DBAPIConnectionDouble(self.path, ambiguous_commit=True)
        store = PostgresStore(lambda: connection)
        self.assertError("storage_unavailable", store.send, PA, self.request(), NOW)
        self.assertTrue(connection.committed)
        retried = self.store.send(PA, self.request(), NOW + 1)
        self.assertTrue(retried["duplicate"])
        self.assertEqual(self.fixture.inspect_counts()["messages"], 1)

    def test_connection_factory_failure_is_bounded(self):
        def broken():
            raise RuntimeError("sensitive connection URL")
        error = self.assertError("storage_unavailable", PostgresStore(broken).identity, PA, NOW)
        self.assertNotIn("sensitive", str(error))

    def test_revoke_writes_and_ack_retries_share_transaction(self):
        sent = self.store.send(PA, self.request(), NOW)
        self.store.ack(PB, dict(message_id=sent["message_id"], idempotency_key="ack-key-0001", outcome="received"), NOW)
        self.store.revoke(PA, G, NOW)
        connection = self.connections[-1]
        self.assertTrue(connection.committed)
        self.assertTrue(any("UPDATE silk_mailbox.pair_grants SET revoked_at" in q for q, _ in connection.statements))
        self.assertTrue(any("UPDATE silk_mailbox.messages SET text=NULL WHERE grant_id" in q for q, _ in connection.statements))

    def test_schema_and_privilege_templates_have_critical_constraints(self):
        root = Path(__file__).resolve().parents[1]
        schema = (root / "migrations/001_mailbox.sql").read_text()
        privileges = (root / "migrations/002_runtime_permissions.sql.example").read_text()
        for text in ("UNIQUE(sender_agent_id,idempotency_key)", "UNIQUE(recipient_agent_id,idempotency_key)", "max_turns BETWEEN 1 AND 32", "max_ttl BETWEEN 1 AND 300", "consent_a_reference", "consent_b_reference", "NOT LIKE 'fixture-only:%'", 'COLLATE "C"'):
            self.assertIn(text, schema)
        self.assertIn("GRANT UPDATE(lock_version)", privileges)
        self.assertIn("GRANT UPDATE(text)", privileges)
        executable = "\n".join(line for line in privileges.splitlines() if not line.strip().startswith("--"))
        self.assertNotRegex(executable, r"GRANT\s+(ALL|CREATE|DELETE|TRUNCATE)")


if __name__ == "__main__":
    unittest.main()
