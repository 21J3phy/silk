"""Bounded durable mailbox storage.

SQLiteFixtureStore is intentionally never a deployment backend. PostgresStore
uses ordinary DB-API connections supplied by the deployment, never provisions
identities/consent, and never falls back to SQLite. All SQL values are bound.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import re
import sqlite3
import unicodedata
import uuid
from pathlib import Path
from typing import Callable

from .domain import MailboxError, Principal

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}\Z", re.ASCII)
_MAX_TIME = 9_007_199_254_740_991
_SEND_FIELDS = {"grant_id", "recipient_agent_id", "text", "ttl_seconds", "idempotency_key", "reply_to"}
_ACK_FIELDS = {"message_id", "idempotency_key", "outcome"}
_RECEIPT_COLUMNS = "receipt_id,message_id,sender_agent_id,recipient_agent_id,outcome,recorded_at,request_digest"


def _fail(code, message):
    raise MailboxError(code, message)


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        _fail("invalid_request", f"Invalid {label}.")
    return value


def _id(value, label="identifier"):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail("invalid_request", f"Invalid {label}.")
    return value


def _plain(value, low, high, max_bytes, label):
    if not isinstance(value, str) or not low <= len(value) <= high:
        _fail("invalid_request", f"Invalid {label}.")
    # Reject controls, surrogates, format/bidi controls, and unassigned/private
    # characters rather than allowing hidden instructions in rendered text.
    if any(unicodedata.category(c).startswith("C") for c in value):
        _fail("invalid_request", f"Invalid {label}.")
    if len(value.encode("utf-8")) > max_bytes:
        _fail("invalid_request", f"Invalid {label}.")
    return value


def _data(data, keys):
    if type(data) is not dict or set(data) != keys:
        _fail("invalid_request", "Unexpected or missing request fields.")


def _digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _pair(a, b):
    return _digest(sorted([a, b]))


def _new_id(prefix):
    return prefix + uuid.uuid4().hex


def _receipt(row):
    return {**{k: row[k] for k in _RECEIPT_COLUMNS.split(",")}, "effect": "mailbox_acknowledgment_only"}


class _Session:
    def __init__(self, connection, postgres):
        self.connection, self.postgres = connection, postgres

    def execute(self, sql, params=()):
        if self.postgres:
            # SQL is static application text. Never interpolate values here.
            sql = sql.replace("?", "%s")
            for table in _TABLES:
                sql = re.sub(r"\b" + table + r"\b", "silk_mailbox." + table, sql)
        cur = self.connection.cursor()
        try:
            cur.execute(sql, params)
            if cur.description:
                names = [c[0] for c in cur.description]
                return [dict(zip(names, r)) for r in cur.fetchall()]
            return []
        finally:
            cur.close()

    def one(self, sql, params=()):
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def lock(self, mode="UPDATE"):
        return " FOR " + mode if self.postgres else ""


_TABLES = ("agent_bindings", "pair_quotas", "mailbox_limits", "pair_grants", "agents", "messages", "receipts")


class _MailboxStore:
    """Shared transactional logic; SQLite's write lock substitutes row locks in fixtures."""
    _postgres = False

    @contextmanager
    def _transaction(self, write=False):
        connection = None
        try:
            connection = self._connection_factory()
            if self._postgres:
                # A fresh, idle connection is required; override driver autocommit
                # so row locks and admission updates always share one transaction.
                connection.autocommit = False
                session = _Session(connection, True)
                session.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                session.execute("SET LOCAL lock_timeout = '5s'")
                session.execute("SET LOCAL statement_timeout = '10s'")
            else:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                session = _Session(connection, False)
            yield session
            connection.commit()
        except MailboxError:
            if connection is not None:
                try:
                    connection.rollback()
                except Exception:
                    pass
            raise
        except Exception:
            if connection is not None:
                try:
                    connection.rollback()
                except Exception:
                    pass
            # SQL errors can include request data. Never return or chain them.
            raise MailboxError("storage_unavailable", "Mailbox storage is unavailable; retry with the same idempotency key.") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    @staticmethod
    def _now(now):
        return _integer(now, 0, _MAX_TIME - 300, "time")

    def _binding(self, tx, principal, now):
        if not isinstance(principal, Principal):
            _fail("unauthorized", "An authenticated principal is required.")
        for value in (principal.issuer, principal.subject, principal.client_id):
            if not isinstance(value, str) or not value or len(value) > 2048 or any(unicodedata.category(c).startswith("C") for c in value):
                _fail("unauthorized", "An authenticated principal is required.")
        row = tx.one("SELECT agent_id,expires_at,revoked_at,created_at FROM agent_bindings WHERE issuer=? AND subject=? AND client_id=?" + tx.lock("SHARE"), (principal.issuer, principal.subject, principal.client_id))
        if row is None or row["revoked_at"] is not None or row["created_at"] > now or row["expires_at"] <= now:
            _fail("binding_inactive", "No active agent binding exists for this principal.")
        agent = tx.one("SELECT agent_id,owner_id,display_name,disabled_at FROM agents WHERE agent_id=?" + tx.lock("SHARE"), (row["agent_id"],))
        if agent is None or agent["disabled_at"] is not None:
            _fail("binding_inactive", "No active agent binding exists for this principal.")
        return agent

    def _capacity(self, tx):
        limits = tx.one("SELECT * FROM mailbox_limits WHERE singleton=1" + tx.lock())
        if limits is None:
            _fail("storage_unavailable", "Mailbox capacity has not been configured.")
        return limits

    @staticmethod
    def _available(tx, table, limit):
        # table is an internal constant, never caller input.
        count = tx.one(f"SELECT COUNT(*) AS count FROM {table}")["count"]
        if count >= limit:
            _fail("capacity_exhausted", "Mailbox capacity is exhausted.")

    def _grant(self, tx, grant_id, agent_id, now, *, active=True):
        grant = tx.one("SELECT * FROM pair_grants WHERE grant_id=?" + tx.lock(), (grant_id,))
        if grant is None or agent_id not in (grant["agent_a"], grant["agent_b"]):
            _fail("grant_unavailable", "The pair grant is unavailable.")
        if active and (grant["revoked_at"] is not None or grant["created_at"] > now or grant["expires_at"] <= now or grant["scope"] != "message.coordinate"):
            _fail("grant_inactive", "The pair grant is inactive.")
        return grant

    def _lock_pair(self, tx, grant_id):
        # Metadata is used only to find the shared quota lock, then the grant is
        # re-read under lock. All runtime mutations first hold mailbox_limits.
        row = tx.one("SELECT pair_id FROM pair_grants WHERE grant_id=?", (grant_id,))
        if row is None:
            _fail("grant_unavailable", "The pair grant is unavailable.")
        pair = tx.one("SELECT pair_id FROM pair_quotas WHERE pair_id=?" + tx.lock(), (row["pair_id"],))
        if pair is None:
            _fail("grant_unavailable", "The pair grant is unavailable.")

    @staticmethod
    def _clean_expired(tx, now):
        tx.execute("UPDATE messages SET text=NULL WHERE text IS NOT NULL AND expires_at<=?", (now,))

    def identity(self, principal, now):
        now = self._now(now)
        with self._transaction() as tx:
            agent = self._binding(tx, principal, now)
            grants = tx.execute("SELECT grant_id,agent_a,agent_b,scope,expires_at,max_turns,used_turns,max_ttl FROM pair_grants WHERE (agent_a=? OR agent_b=?) AND revoked_at IS NULL AND created_at<=? AND expires_at>? ORDER BY grant_id" + tx.lock("SHARE"), (agent["agent_id"], agent["agent_id"], now, now))
            return {"agent_id": agent["agent_id"], "owner_id": agent["owner_id"], "display_name": agent["display_name"], "grants": [{"grant_id": g["grant_id"], "peer_agent_id": g["agent_b"] if g["agent_a"] == agent["agent_id"] else g["agent_a"], "scope": g["scope"], "expires_at": g["expires_at"], "max_turns": g["max_turns"], "remaining_turns": g["max_turns"] - g["used_turns"], "max_ttl": g["max_ttl"], "rate_per_minute": 6} for g in grants]}

    def send(self, principal, data, now):
        now = self._now(now)
        _data(data, _SEND_FIELDS)
        for name in ("grant_id", "recipient_agent_id", "idempotency_key"):
            _id(data[name], name)
        _plain(data["text"], 1, 2000, 4096, "message text")
        _integer(data["ttl_seconds"], 1, 300, "message TTL")
        if data["reply_to"] is not None:
            _id(data["reply_to"], "reply_to")
        digest = _digest({k: v for k, v in data.items() if k != "idempotency_key"})
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            agent = self._binding(tx, principal, now)
            sender = agent["agent_id"]
            previous = tx.one("SELECT message_id,grant_id,intent_digest,expires_at FROM messages WHERE sender_agent_id=? AND idempotency_key=?", (sender, data["idempotency_key"]))
            if previous:
                if previous["intent_digest"] != digest:
                    _fail("idempotency_conflict", "Idempotency key is already bound to a different request.")
                terminal = tx.one("SELECT receipt_id FROM receipts WHERE message_id=?", (previous["message_id"],))
                historical_grant = tx.one("SELECT revoked_at FROM pair_grants WHERE grant_id=?", (previous["grant_id"],))
                if terminal:
                    status = "acknowledged"
                elif historical_grant is None or historical_grant["revoked_at"] is not None:
                    status = "revoked"
                elif previous["expires_at"] <= now:
                    status = "expired"
                else:
                    status = "queued"
                return {"message_id": previous["message_id"], "status": status, "duplicate": True, "expires_at": previous["expires_at"]}
            self._lock_pair(tx, data["grant_id"])
            grant = self._grant(tx, data["grant_id"], sender, now)
            recipient = grant["agent_b"] if sender == grant["agent_a"] else grant["agent_a"]
            if data["recipient_agent_id"] != recipient:
                _fail("recipient_mismatch", "Recipient is not the named peer in this grant.")
            peer = tx.one("SELECT disabled_at FROM agents WHERE agent_id=?" + tx.lock("SHARE"), (recipient,))
            if peer is None or peer["disabled_at"] is not None:
                _fail("grant_inactive", "The pair grant is inactive.")
            if data["ttl_seconds"] > grant["max_ttl"]:
                _fail("invalid_request", "Message TTL exceeds the grant limit.")
            if grant["used_turns"] >= grant["max_turns"]:
                _fail("budget_exhausted", "The pair grant has no remaining turns.")
            rate = tx.one("SELECT COUNT(*) AS count FROM messages WHERE pair_id=? AND created_at>?", (grant["pair_id"], now - 60))["count"]
            if rate >= 6:
                _fail("rate_limited", "The named pair has reached its rolling minute limit.")
            if data["reply_to"] is not None:
                parent = tx.one("SELECT message_id FROM messages WHERE message_id=? AND grant_id=? AND sender_agent_id=? AND recipient_agent_id=?", (data["reply_to"], data["grant_id"], recipient, sender))
                if parent is None:
                    _fail("reply_unavailable", "Reply target is unavailable in this conversation.")
            self._available(tx, "messages", limits["max_messages"])
            self._clean_expired(tx, now)
            message_id = _new_id("msg_")
            expires = min(now + data["ttl_seconds"], grant["expires_at"])
            tx.execute("INSERT INTO messages(message_id,grant_id,pair_id,sender_agent_id,recipient_agent_id,text,created_at,expires_at,idempotency_key,intent_digest,reply_to) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (message_id, data["grant_id"], grant["pair_id"], sender, recipient, data["text"], now, expires, data["idempotency_key"], digest, data["reply_to"]))
            tx.execute("UPDATE pair_grants SET used_turns=used_turns+1 WHERE grant_id=?", (data["grant_id"],))
            return {"message_id": message_id, "status": "queued", "duplicate": False, "expires_at": expires}

    def receive(self, principal, limit, now):
        now = self._now(now)
        _integer(limit, 1, 20, "receive limit")
        with self._transaction() as tx:
            agent = self._binding(tx, principal, now)
            # Lock eligible grants before the second statement reads content. A
            # concurrent revocation either linearizes before this read or waits.
            grants = tx.execute("SELECT grant_id FROM pair_grants WHERE (agent_a=? OR agent_b=?) AND revoked_at IS NULL AND created_at<=? AND expires_at>? ORDER BY grant_id" + tx.lock("SHARE"), (agent["agent_id"], agent["agent_id"], now, now))
            if not grants:
                return {"messages": []}
            rows = tx.execute("SELECT m.message_id,m.sender_agent_id,m.recipient_agent_id,m.grant_id,m.text,m.created_at,m.expires_at,m.reply_to FROM messages m JOIN pair_grants g ON g.grant_id=m.grant_id WHERE m.recipient_agent_id=? AND m.text IS NOT NULL AND m.expires_at>? AND g.revoked_at IS NULL AND g.created_at<=? AND g.expires_at>? AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.message_id=m.message_id) ORDER BY m.created_at,m.message_id LIMIT ?", (agent["agent_id"], now, now, now, limit))
            return {"messages": [{**row, "content_trust": "untrusted_data"} for row in rows]}

    def ack(self, principal, data, now):
        now = self._now(now)
        _data(data, _ACK_FIELDS)
        _id(data["message_id"], "message_id")
        _id(data["idempotency_key"], "idempotency_key")
        if data["outcome"] not in ("received", "declined"):
            _fail("invalid_request", "Invalid acknowledgment outcome.")
        digest = _digest({"message_id": data["message_id"], "outcome": data["outcome"]})
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            agent = self._binding(tx, principal, now)
            recipient = agent["agent_id"]
            previous = tx.one("SELECT * FROM receipts WHERE recipient_agent_id=? AND idempotency_key=?", (recipient, data["idempotency_key"]))
            if previous:
                if previous["acknowledgment_digest"] != digest:
                    _fail("idempotency_conflict", "Idempotency key is already bound to a different request.")
                return _receipt(previous)
            message = tx.one("SELECT * FROM messages WHERE message_id=? AND recipient_agent_id=?", (data["message_id"], recipient))
            if message is None:
                _fail("message_unavailable", "The message is unavailable.")
            recorded = tx.one("SELECT * FROM receipts WHERE message_id=?", (data["message_id"],))
            if recorded:
                if recorded["outcome"] != data["outcome"]:
                    _fail("ack_conflict", "The message already has a different acknowledgment.")
                # A terminal receipt is immutable. Require the original key so
                # every accepted idempotency key remains durably reserved.
                _fail("idempotency_conflict", "Retry this acknowledgment with its original idempotency key.")
            self._lock_pair(tx, message["grant_id"])
            self._grant(tx, message["grant_id"], recipient, now)
            if message["expires_at"] <= now or message["text"] is None:
                _fail("message_expired", "The message is no longer pending.")
            self._available(tx, "receipts", limits["max_receipts"])
            receipt = {"receipt_id": _new_id("rcpt_"), "message_id": message["message_id"], "sender_agent_id": message["sender_agent_id"], "recipient_agent_id": recipient, "outcome": data["outcome"], "recorded_at": now, "request_digest": message["intent_digest"]}
            tx.execute("INSERT INTO receipts(receipt_id,message_id,sender_agent_id,recipient_agent_id,outcome,recorded_at,request_digest,acknowledgment_digest,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?)", (*[receipt[k] for k in _RECEIPT_COLUMNS.split(",")], digest, data["idempotency_key"]))
            tx.execute("UPDATE messages SET text=NULL WHERE message_id=?", (message["message_id"],))
            self._clean_expired(tx, now)
            return _receipt(receipt)

    def receipts(self, principal, limit, now):
        now = self._now(now)
        _integer(limit, 1, 20, "receipt limit")
        with self._transaction() as tx:
            agent = self._binding(tx, principal, now)
            rows = tx.execute(f"SELECT {_RECEIPT_COLUMNS} FROM receipts WHERE sender_agent_id=? OR recipient_agent_id=? ORDER BY recorded_at DESC,receipt_id DESC LIMIT ?", (agent["agent_id"], agent["agent_id"], limit))
            return {"receipts": [_receipt(row) for row in rows]}

    def revoke(self, principal, grant_id, now):
        now = self._now(now)
        _id(grant_id, "grant_id")
        with self._transaction(True) as tx:
            self._capacity(tx)
            agent = self._binding(tx, principal, now)
            self._lock_pair(tx, grant_id)
            grant = self._grant(tx, grant_id, agent["agent_id"], now, active=False)
            revoked = grant["revoked_at"]
            if revoked is None:
                revoked = now
                tx.execute("UPDATE pair_grants SET revoked_at=? WHERE grant_id=?", (now, grant_id))
            tx.execute("UPDATE messages SET text=NULL WHERE grant_id=? AND text IS NOT NULL", (grant_id,))
            return {"grant_id": grant_id, "status": "revoked", "revoked_at": revoked}

    def purge_expired_content(self, now):
        """Operator maintenance only. MUST NOT be registered as a public MCP tool."""
        now = self._now(now)
        with self._transaction(True) as tx:
            self._capacity(tx)
            self._clean_expired(tx, now)


class PostgresStore(_MailboxStore):
    """Production adapter; factory returns a fresh/idle DB-API connection.

    Uses PostgreSQL %s parameters and tuple-row cursors. A pool adapter may
    implement close() as return-to-pool after commit/rollback. Migrations and
    consent provisioning MUST be performed separately by an approved operator.
    """
    durable_for_deployment = True
    _postgres = True

    def __init__(self, connection_factory: Callable):
        if not callable(connection_factory):
            raise TypeError("A PostgreSQL DB-API connection factory is required")
        self._connection_factory = connection_factory

    def check_readiness(self):
        """Read-only schema/query check. Does not provision, migrate, or write.

        This checks required columns and configured capacity, not real grants,
        identity verification, failover, all privileges, or delivery end to end.
        """
        projections = {
            "agents": "agent_id,owner_id,display_name,disabled_at,lock_version",
            "agent_bindings": "issuer,subject,client_id,agent_id,created_at,expires_at,revoked_at,lock_version",
            "pair_quotas": "pair_id,agent_a,agent_b,lock_version",
            "pair_grants": "grant_id,pair_id,agent_a,agent_b,scope,created_at,expires_at,revoked_at,max_turns,used_turns,max_ttl,consent_a_reference,consent_b_reference",
            "messages": "message_id,grant_id,pair_id,sender_agent_id,recipient_agent_id,text,created_at,expires_at,idempotency_key,intent_digest,reply_to",
            "receipts": "receipt_id,message_id,sender_agent_id,recipient_agent_id,outcome,recorded_at,request_digest,acknowledgment_digest,idempotency_key",
            "mailbox_limits": "singleton,max_messages,max_receipts,max_agents,max_bindings,max_grants,lock_version",
        }
        with self._transaction() as tx:
            for table, columns in projections.items():
                tx.execute(f"SELECT {columns} FROM {table} WHERE 1=0")
            configured = tx.one("SELECT singleton FROM mailbox_limits WHERE singleton=1")
            if configured is None:
                _fail("storage_unavailable", "Mailbox capacity has not been configured.")
        return {"ready": True, "backend": "postgresql", "check": "schema_and_capacity_read_only"}


_SQLITE_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS agents (
 agent_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, display_name TEXT NOT NULL,
 disabled_at INTEGER, lock_version INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS agent_bindings (
 issuer TEXT NOT NULL, subject TEXT NOT NULL, client_id TEXT NOT NULL,
 agent_id TEXT NOT NULL REFERENCES agents(agent_id), created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, revoked_at INTEGER, lock_version INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(issuer,subject,client_id), CHECK(expires_at>created_at));
CREATE TABLE IF NOT EXISTS pair_quotas (
 pair_id TEXT PRIMARY KEY, agent_a TEXT NOT NULL REFERENCES agents(agent_id),
 agent_b TEXT NOT NULL REFERENCES agents(agent_id), lock_version INTEGER NOT NULL DEFAULT 0,
 UNIQUE(agent_a,agent_b), CHECK(agent_a<agent_b));
CREATE TABLE IF NOT EXISTS pair_grants (
 grant_id TEXT PRIMARY KEY, pair_id TEXT NOT NULL REFERENCES pair_quotas(pair_id),
 agent_a TEXT NOT NULL REFERENCES agents(agent_id), agent_b TEXT NOT NULL REFERENCES agents(agent_id),
 scope TEXT NOT NULL CHECK(scope='message.coordinate'), created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, revoked_at INTEGER,
 max_turns INTEGER NOT NULL CHECK(max_turns BETWEEN 1 AND 32),
 used_turns INTEGER NOT NULL DEFAULT 0 CHECK(used_turns>=0 AND used_turns<=max_turns),
 max_ttl INTEGER NOT NULL CHECK(max_ttl BETWEEN 1 AND 300),
 consent_a_reference TEXT NOT NULL, consent_b_reference TEXT NOT NULL,
 CHECK(agent_a<agent_b), CHECK(expires_at>created_at));
CREATE TABLE IF NOT EXISTS messages (
 message_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES pair_grants(grant_id),
 pair_id TEXT NOT NULL REFERENCES pair_quotas(pair_id),
 sender_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
 recipient_agent_id TEXT NOT NULL REFERENCES agents(agent_id), text TEXT,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 idempotency_key TEXT NOT NULL, intent_digest TEXT NOT NULL,
 reply_to TEXT REFERENCES messages(message_id), UNIQUE(sender_agent_id,idempotency_key),
 CHECK(sender_agent_id<>recipient_agent_id), CHECK(expires_at>created_at));
CREATE TABLE IF NOT EXISTS receipts (
 receipt_id TEXT PRIMARY KEY, message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id),
 sender_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
 recipient_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
 outcome TEXT NOT NULL CHECK(outcome IN ('received','declined')), recorded_at INTEGER NOT NULL,
 request_digest TEXT NOT NULL, acknowledgment_digest TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 UNIQUE(recipient_agent_id,idempotency_key));
CREATE TABLE IF NOT EXISTS mailbox_limits (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), max_messages INTEGER NOT NULL CHECK(max_messages>0),
 max_receipts INTEGER NOT NULL CHECK(max_receipts>0), max_agents INTEGER NOT NULL CHECK(max_agents>0),
 max_bindings INTEGER NOT NULL CHECK(max_bindings>0), max_grants INTEGER NOT NULL CHECK(max_grants>0),
 lock_version INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS messages_pair_rate ON messages(pair_id,created_at);
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_agent_id,expires_at);
CREATE INDEX IF NOT EXISTS receipts_sender ON receipts(sender_agent_id,recorded_at);
CREATE INDEX IF NOT EXISTS receipts_recipient ON receipts(recipient_agent_id,recorded_at);
"""


class SQLiteFixtureStore(_MailboxStore):
    """Isolated test/dev fixture ONLY. Not a production/deployment fallback.

    Provisioning helpers below are test-only and do not establish real consent.
    """
    durable_for_deployment = False

    def __init__(self, path, *, max_messages=1024, max_receipts=1024, max_agents=128, max_bindings=256, max_grants=1024):
        if str(path) == ":memory:":
            raise ValueError("Use an isolated fixture file, not connection-local :memory:")
        self.path = str(Path(path))
        values = [max_messages, max_receipts, max_agents, max_bindings, max_grants]
        for v in values:
            _integer(v, 1, 1_000_000, "fixture capacity")
        def connect():
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")
            return connection
        self._connection_factory = connect
        connection = connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(_SQLITE_SCHEMA)
            connection.execute("INSERT OR IGNORE INTO mailbox_limits(singleton,max_messages,max_receipts,max_agents,max_bindings,max_grants) VALUES(1,?,?,?,?,?)", values)
        finally:
            connection.close()

    def provision_agent(self, agent_id, owner_id, display_name):
        _id(agent_id, "agent_id")
        _id(owner_id, "owner_id")
        _plain(display_name, 1, 100, 400, "display_name")
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            self._available(tx, "agents", limits["max_agents"])
            tx.execute("INSERT INTO agents(agent_id,owner_id,display_name) VALUES(?,?,?)", (agent_id, owner_id, display_name))

    def provision_binding(self, principal, agent_id, *, expires_at, now=0):
        now = self._now(now)
        _integer(expires_at, now + 1, _MAX_TIME, "binding expiry")
        _id(agent_id, "agent_id")
        if not isinstance(principal, Principal):
            raise TypeError("principal must be Principal")
        for value in (principal.issuer, principal.subject, principal.client_id):
            _plain(value, 1, 2048, 8192, "principal field")
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            self._available(tx, "agent_bindings", limits["max_bindings"])
            tx.execute("INSERT INTO agent_bindings(issuer,subject,client_id,agent_id,created_at,expires_at) VALUES(?,?,?,?,?,?)", (principal.issuer, principal.subject, principal.client_id, agent_id, now, expires_at))

    def provision_grant(self, grant_id, agent_a, agent_b, *, expires_at, max_turns=8, max_ttl=300, now=0):
        now = self._now(now)
        _id(grant_id, "grant_id")
        _id(agent_a, "agent_a")
        _id(agent_b, "agent_b")
        if agent_a == agent_b:
            _fail("invalid_request", "A pair requires two distinct agents.")
        _integer(expires_at, now + 1, _MAX_TIME, "grant expiry")
        _integer(max_turns, 1, 32, "turn budget")
        _integer(max_ttl, 1, 300, "grant TTL")
        a, b = sorted([agent_a, agent_b])
        pair_id = _pair(a, b)
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            self._available(tx, "pair_grants", limits["max_grants"])
            tx.execute("INSERT INTO pair_quotas(pair_id,agent_a,agent_b) VALUES(?,?,?) ON CONFLICT(pair_id) DO NOTHING", (pair_id, a, b))
            tx.execute("INSERT INTO pair_grants(grant_id,pair_id,agent_a,agent_b,scope,created_at,expires_at,max_turns,max_ttl,consent_a_reference,consent_b_reference) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (grant_id, pair_id, a, b, "message.coordinate", now, expires_at, max_turns, max_ttl, "fixture-only:" + a, "fixture-only:" + b))

    def revoke_binding(self, principal, *, now=0):
        now = self._now(now)
        with self._transaction(True) as tx:
            self._capacity(tx)
            tx.execute("UPDATE agent_bindings SET revoked_at=? WHERE issuer=? AND subject=? AND client_id=?", (now, principal.issuer, principal.subject, principal.client_id))

    def inspect_counts(self):
        with self._transaction() as tx:
            return {table: tx.one(f"SELECT COUNT(*) AS count FROM {table}")["count"] for table in _TABLES}
