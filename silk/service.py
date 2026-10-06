"""Persistent local broker and owner-consent state machine.

One trusted demo process owns all fixture keys. This is deliberately not a
multi-tenant production identity system. SQLite serializes admission, replay
checks, budgets, decisions, and audit writes in one transaction.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from .adapters import LocalCoordinationAdapter
from .protocol import (
    AGENTS, OWNERS, SCOPE, MAX_TTL, MAX_TURNS, MAX_MESSAGES, RATE_PER_MINUTE,
    DomainError, canonical, digest, exact_object, fail, integer, opaque_id,
    option_timestamp, public_key_text, sign_record, text_value, validate_payload,
    validate_wire, verify_record,
)


def new_id(prefix):
    return f"{prefix}_{uuid4().hex}"


class Service:
    def __init__(self, db_path, clock=time.time, adapter=None):
        self.clock = clock
        self.lock = threading.RLock()
        self.adapter = adapter or LocalCoordinationAdapter()
        path = Path(db_path)
        if str(db_path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS fixture_keys (id TEXT PRIMARY KEY, seed BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS invitations (
              id TEXT PRIMARY KEY, from_agent TEXT NOT NULL, to_agent TEXT NOT NULL,
              purpose TEXT NOT NULL, scope TEXT NOT NULL, status TEXT NOT NULL,
              created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, max_turns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
              id TEXT PRIMARY KEY, invitation_id TEXT UNIQUE NOT NULL REFERENCES invitations(id),
              from_agent TEXT NOT NULL, to_agent TEXT NOT NULL, scope TEXT NOT NULL,
              status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              max_turns INTEGER NOT NULL, turns_used INTEGER NOT NULL DEFAULT 0,
              rate_per_minute INTEGER NOT NULL, ttl_seconds INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
              sender TEXT NOT NULL, recipient TEXT NOT NULL,
              nonce TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              envelope TEXT NOT NULL, wire_hash TEXT NOT NULL, intent_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, accepted_at INTEGER NOT NULL,
              status TEXT NOT NULL, proposal TEXT, receipt TEXT, failure_code TEXT,
              UNIQUE(sender, nonce), UNIQUE(sender, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS message_rate ON messages(sender, recipient, accepted_at);
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL,
              event TEXT NOT NULL, entity_id TEXT NOT NULL, actor_id TEXT NOT NULL,
              owner_ids TEXT NOT NULL
            );
        """)
        with self._transaction():
            for agent_id in [*AGENTS, "broker"]:
                if not self.db.execute("SELECT 1 FROM fixture_keys WHERE id=?", (agent_id,)).fetchone():
                    key = Ed25519PrivateKey.generate()
                    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                    self.db.execute("INSERT INTO fixture_keys VALUES (?,?)", (agent_id, seed))
            if not self.db.execute("SELECT 1 FROM metadata WHERE key='fixture_options'").fetchone():
                tomorrow = (datetime.fromtimestamp(self.now(), timezone.utc) + timedelta(days=1)).replace(hour=14, minute=0, second=0, microsecond=0)
                options = [{"start": (tomorrow + timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ"), "duration_minutes": 30} for i in range(3)]
                self.db.execute("INSERT INTO metadata VALUES ('fixture_options',?)", (json.dumps(options),))
                self.db.execute("INSERT INTO metadata VALUES ('schema_version','1')")
        if str(db_path) != ":memory:":
            os.chmod(path, 0o600)
        self.keys = {r["id"]: Ed25519PrivateKey.from_private_bytes(r["seed"]) for r in self.db.execute("SELECT * FROM fixture_keys")}
        self.fixture_options = json.loads(self.db.execute("SELECT value FROM metadata WHERE key='fixture_options'").fetchone()["value"])

    @contextmanager
    def _transaction(self):
        # Reserve the SQLite write lock BEFORE reading quota/consent state. This
        # prevents separate Service instances from racing admission checks.
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.db.rollback()
                raise
            else:
                self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()

    def now(self):
        return int(self.clock())

    def _owner(self, owner_id):
        if type(owner_id) is not str or owner_id not in {o["id"] for o in OWNERS}:
            fail("unknown_owner", "Choose a fixture owner.", 403)
        return owner_id

    def _owns(self, owner_id, agent_id):
        self._owner(owner_id)
        if type(agent_id) is not str or agent_id not in AGENTS or AGENTS[agent_id]["owner_id"] != owner_id:
            fail("not_owner", "This action belongs to the other fixture owner.", 403)

    def _owners_for(self, sender, recipient):
        return sorted({AGENTS[sender]["owner_id"], AGENTS[recipient]["owner_id"]})

    def _audit(self, event, entity_id, actor_id, owners):
        self.db.execute("INSERT INTO audit (occurred_at,event,entity_id,actor_id,owner_ids) VALUES (?,?,?,?,?)", (self.now(), event, entity_id, actor_id, json.dumps(owners)))

    def _get(self, table, identifier):
        if table not in {"invitations", "grants", "messages"}:
            raise ValueError("Unsupported resource table")
        opaque_id(identifier, "Resource ID")
        row = self.db.execute(f"SELECT * FROM {table} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            fail("not_found", "That resource does not exist.", 404)
        return dict(row)

    def _active_grant(self, grant_id):
        grant = self._get("grants", grant_id)
        if grant["status"] != "active" or grant["expires_at"] <= self.now():
            fail("grant_inactive", "This permission has expired or been revoked.", 403)
        return grant

    def _expire(self):
        now = self.now()
        for row in self.db.execute("SELECT * FROM invitations WHERE status='pending' AND expires_at<=?", (now,)).fetchall():
            self.db.execute("UPDATE invitations SET status='expired' WHERE id=?", (row["id"],))
            self._audit("invitation.expired", row["id"], "broker", self._owners_for(row["from_agent"], row["to_agent"]))
        for row in self.db.execute("SELECT * FROM grants WHERE status='active' AND expires_at<=?", (now,)).fetchall():
            self.db.execute("UPDATE grants SET status='expired' WHERE id=?", (row["id"],))
            self._audit("grant.expired", row["id"], "broker", self._owners_for(row["from_agent"], row["to_agent"]))
        for row in self.db.execute("SELECT m.*,g.status AS grant_status FROM messages m JOIN grants g ON g.id=m.grant_id WHERE m.status IN ('queued','awaiting_approval') AND (m.expires_at<=? OR g.status!='active')", (now,)).fetchall():
            status = "expired" if row["expires_at"] <= now or row["grant_status"] == "expired" else "cancelled"
            self.db.execute("UPDATE messages SET status=?,failure_code=? WHERE id=?", (status, "message_expired" if status == "expired" else "grant_revoked", row["id"]))
            self._audit(f"message.{status}", row["id"], "broker", self._owners_for(row["sender"], row["recipient"]))

    def _message(self, row):
        envelope = json.loads(row["envelope"])
        return {
            "id": row["id"], "grant_id": row["grant_id"], "sender": row["sender"], "recipient": row["recipient"],
            "created_at": row["created_at"], "expires_at": row["expires_at"], "status": row["status"],
            "payload": envelope["payload"], "proposal": json.loads(row["proposal"]) if row["proposal"] else None,
            "receipt": json.loads(row["receipt"]) if row["receipt"] else None, "failure_code": row["failure_code"],
            "envelope_signature": envelope["signature"],
        }

    def availability(self, owner_id):
        self._owner(owner_id)
        options = self.fixture_options[:2] if owner_id == "alice" else self.fixture_options[1:]
        return json.loads(json.dumps(options))

    def state(self, owner_id):
        self._owner(owner_id)
        with self._transaction():
            self._expire()
            mine = next(a for a in AGENTS if AGENTS[a]["owner_id"] == owner_id)
            agents = []
            for agent_id, agent in AGENTS.items():
                public = public_key_text(self.keys[agent_id].public_key())
                agents.append({**agent, "public_key": public, "fingerprint": digest(public)[:16]})
            return {
                "demo": True, "current_owner": next(o.copy() for o in OWNERS if o["id"] == owner_id),
                "owners": [o.copy() for o in OWNERS], "agents": agents,
                "invitations": [dict(r) for r in self.db.execute("SELECT * FROM invitations WHERE from_agent=? OR to_agent=? ORDER BY created_at DESC,rowid DESC", (mine, mine))],
                "grants": [dict(r) for r in self.db.execute("SELECT * FROM grants WHERE from_agent=? OR to_agent=? ORDER BY created_at DESC,rowid DESC", (mine, mine))],
                "messages": [self._message(dict(r)) for r in self.db.execute("SELECT * FROM messages WHERE sender=? OR recipient=? ORDER BY accepted_at DESC,rowid DESC", (mine, mine))],
                "audit": [{k: r[k] for k in ("id", "occurred_at", "event", "entity_id", "actor_id")} for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC") if owner_id in json.loads(r["owner_ids"])][:80],
                "suggested_options": json.loads(json.dumps(self.fixture_options)),
                "private_availability": self.availability(owner_id), "server_time": self.now(),
                "broker_public_key": public_key_text(self.keys["broker"].public_key()),
                "limits": {"max_payload_bytes": 4096, "max_options": 3, "rate_per_minute": RATE_PER_MINUTE, "max_ttl_seconds": MAX_TTL},
            }

    def create_invitation(self, owner_id, data):
        exact_object(data, {"from_agent", "to_agent", "purpose", "max_turns", "expires_in"}, "Invitation")
        self._owns(owner_id, data["from_agent"])
        if type(data["to_agent"]) is not str or data["to_agent"] not in AGENTS or data["to_agent"] == data["from_agent"]:
            fail("invalid_recipient", "Choose the other fixture agent.")
        text_value(data["purpose"], "Invitation purpose", 1, 280)
        integer(data["max_turns"], "Request budget", 1, MAX_TURNS)
        integer(data["expires_in"], "Permission lifetime", 60, 86400)
        with self._transaction():
            self._expire()
            if self.db.execute("SELECT COUNT(*) FROM invitations").fetchone()[0] >= 200:
                fail("demo_capacity", "This local demo has reached its invitation storage limit.", 429)
            if self.db.execute("SELECT 1 FROM invitations WHERE from_agent=? AND to_agent=? AND status='pending'", (data["from_agent"], data["to_agent"])).fetchone():
                fail("invitation_pending", "An invitation to this agent is already waiting for consent.", 409)
            recent = self.db.execute("SELECT COUNT(*) FROM invitations WHERE from_agent=? AND created_at>?", (data["from_agent"], self.now() - 60)).fetchone()[0]
            if recent >= 5:
                fail("invitation_rate_limited", "Wait a minute before inviting again.", 429)
            identifier = new_id("inv")
            self.db.execute("INSERT INTO invitations VALUES (?,?,?,?,?,?,?,?,?)", (identifier, data["from_agent"], data["to_agent"], data["purpose"], SCOPE, "pending", self.now(), self.now() + data["expires_in"], data["max_turns"]))
            self._audit("invitation.created", identifier, owner_id, self._owners_for(data["from_agent"], data["to_agent"]))
            return self._get("invitations", identifier)

    def respond_invitation(self, owner_id, invitation_id, accept):
        if type(accept) is not bool:
            fail("invalid_decision", "Invitation decision must be a boolean.")
        with self._transaction():
            self._expire()
            invitation = self._get("invitations", invitation_id)
            self._owns(owner_id, invitation["to_agent"])
            wanted = "accepted" if accept else "declined"
            if invitation["status"] == wanted:
                return invitation
            if invitation["status"] != "pending":
                fail("invitation_closed", "This invitation has already been answered or expired.", 409)
            self.db.execute("UPDATE invitations SET status=? WHERE id=?", (wanted, invitation_id))
            owners = self._owners_for(invitation["from_agent"], invitation["to_agent"])
            self._audit(f"invitation.{wanted}", invitation_id, owner_id, owners)
            if accept:
                identifier = new_id("grant")
                self.db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (identifier, invitation_id, invitation["from_agent"], invitation["to_agent"], SCOPE, "active", self.now(), invitation["expires_at"], invitation["max_turns"], 0, RATE_PER_MINUTE, MAX_TTL))
                self._audit("grant.created", identifier, owner_id, owners)
            return self._get("invitations", invitation_id)

    def revoke_grant(self, owner_id, grant_id):
        self._owner(owner_id)
        with self._transaction():
            self._expire()
            grant = self._get("grants", grant_id)
            owners = self._owners_for(grant["from_agent"], grant["to_agent"])
            if owner_id not in owners:
                fail("not_owner", "This permission belongs to a different owner.", 403)
            if grant["status"] == "revoked":
                return grant
            if grant["status"] != "active":
                fail("grant_inactive", "This permission is no longer active.", 409)
            self.db.execute("UPDATE grants SET status='revoked' WHERE id=?", (grant_id,))
            self._audit("grant.revoked", grant_id, owner_id, owners)
            self._expire()
            return self._get("grants", grant_id)

    def fixture_envelope(self, owner_id, data, **overrides):
        """Test/local adapter helper. HTTP exposes only send_fixture, never raw keys."""
        exact_object(data, {"grant_id", "title", "options", "idempotency_key"}, "Message request")
        with self.lock:
            grant = self._get("grants", data["grant_id"])
            self._owns(owner_id, grant["from_agent"])
            record = {
                "version": 1, "id": new_id("msg"), "sender": grant["from_agent"], "recipient": grant["to_agent"],
                "grant_id": grant["id"], "scope": SCOPE, "created_at": self.now(),
                "expires_at": min(self.now() + MAX_TTL, grant["expires_at"]), "nonce": secrets.token_hex(16),
                "idempotency_key": data["idempotency_key"],
                "payload": {"kind": "meeting.proposal", "title": data["title"], "options": data["options"]},
            }
            record.update(overrides)
            return sign_record(record, self.keys[grant["from_agent"]])

    def _intent(self, envelope):
        return digest({k: envelope[k] for k in ("sender", "recipient", "grant_id", "scope", "payload")})

    def send_fixture(self, owner_id, data):
        exact_object(data, {"grant_id", "title", "options", "idempotency_key"}, "Message request")
        opaque_id(data["idempotency_key"], "Idempotency key")
        validate_payload({"kind": "meeting.proposal", "title": data["title"], "options": data["options"]})
        with self._transaction():
            grant = self._get("grants", data["grant_id"])
            self._owns(owner_id, grant["from_agent"])
            intent = self._intent({"sender": grant["from_agent"], "recipient": grant["to_agent"], "grant_id": grant["id"], "scope": SCOPE, "payload": {"kind": "meeting.proposal", "title": data["title"], "options": data["options"]}})
            old = self.db.execute("SELECT * FROM messages WHERE sender=? AND idempotency_key=?", (grant["from_agent"], data["idempotency_key"])).fetchone()
            if old:
                if old["intent_hash"] != intent:
                    fail("idempotency_conflict", "This retry key was already used for a different request.", 409)
                self._expire()
                return {"message": self._message(self._get("messages", old["id"])), "duplicate": True}
            envelope = self.fixture_envelope(owner_id, data)
            return self._receive(envelope)

    def receive(self, envelope):
        with self._transaction():
            return self._receive(envelope)

    def _receive(self, envelope):
        validate_wire(envelope)
        if not verify_record(envelope, self.keys[envelope["sender"]].public_key()):
            fail("invalid_signature", "The signature does not authenticate this envelope.", 401)
        self._expire()
        wire_hash, intent_hash = digest(envelope), self._intent(envelope)
        old = self.db.execute("SELECT * FROM messages WHERE id=?", (envelope["id"],)).fetchone()
        if old:
            if old["wire_hash"] != wire_hash:
                fail("message_id_conflict", "That message ID is already bound to different data.", 409)
            return {"message": self._message(dict(old)), "duplicate": True}
        old = self.db.execute("SELECT * FROM messages WHERE sender=? AND idempotency_key=?", (envelope["sender"], envelope["idempotency_key"])).fetchone()
        if old:
            if old["intent_hash"] != intent_hash:
                fail("idempotency_conflict", "This retry key was already used for a different request.", 409)
            return {"message": self._message(dict(old)), "duplicate": True}
        if self.db.execute("SELECT 1 FROM messages WHERE sender=? AND nonce=?", (envelope["sender"], envelope["nonce"])).fetchone():
            fail("replay_detected", "That sender nonce has already been consumed.", 409)
        now = self.now()
        if envelope["created_at"] > now + 5:
            fail("future_message", "Message creation is too far ahead of the broker clock.")
        if envelope["expires_at"] <= now:
            fail("message_expired", "The message deadline has passed.", 410)
        grant = self._active_grant(envelope["grant_id"])
        if envelope["sender"] != grant["from_agent"] or envelope["recipient"] != grant["to_agent"] or envelope["scope"] != grant["scope"]:
            fail("grant_mismatch", "The permission does not cover this sender, recipient, and scope.", 403)
        if envelope["expires_at"] > grant["expires_at"]:
            fail("grant_deadline", "The message deadline cannot outlive the permission.")
        if any(not now < option_timestamp(option) <= now + 30 * 86400 for option in envelope["payload"]["options"]):
            fail("invalid_meeting_date", "Candidate meetings must be in the next 30 days.")
        if grant["turns_used"] >= grant["max_turns"]:
            fail("turn_budget_exhausted", "This permission's request budget is exhausted.", 429)
        recent = self.db.execute("SELECT COUNT(*) FROM messages WHERE sender=? AND recipient=? AND accepted_at>?", (envelope["sender"], envelope["recipient"], now - 60)).fetchone()[0]
        if recent >= RATE_PER_MINUTE:
            fail("rate_limited", "This sender has reached six requests per minute to this recipient.", 429)
        if self.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0] >= MAX_MESSAGES:
            fail("demo_capacity", "This demo has reached its local message storage limit.", 429)
        self.db.execute("INSERT INTO messages (id,grant_id,sender,recipient,nonce,idempotency_key,envelope,wire_hash,intent_hash,created_at,expires_at,accepted_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (envelope["id"], envelope["grant_id"], envelope["sender"], envelope["recipient"], envelope["nonce"], envelope["idempotency_key"], canonical(envelope).decode(), wire_hash, intent_hash, envelope["created_at"], envelope["expires_at"], now, "queued"))
        self.db.execute("UPDATE grants SET turns_used=turns_used+1 WHERE id=?", (grant["id"],))
        self._audit("message.queued", envelope["id"], envelope["sender"], self._owners_for(envelope["sender"], envelope["recipient"]))
        return {"message": self._message(self._get("messages", envelope["id"])), "duplicate": False}

    def dispatch_pending(self):
        """One local adapter attempt per message; no background external effects.

        Adapter runs under the broker transaction lock. A future slow/network
        adapter needs a durable claimed job, fencing, and revalidation at commit.
        """
        with self._transaction():
            self._expire()
            rows = self.db.execute("SELECT * FROM messages WHERE status='queued' ORDER BY accepted_at,rowid").fetchall()
            for row in rows:
                owners = self._owners_for(row["sender"], row["recipient"])
                try:
                    envelope = json.loads(row["envelope"])
                    validate_wire(envelope)
                    if not verify_record(envelope, self.keys[envelope["sender"]].public_key()):
                        fail("invalid_signature", "Stored message authentication failed.")
                    grant = self._active_grant(row["grant_id"])
                    if envelope["sender"] != grant["from_agent"] or envelope["recipient"] != grant["to_agent"] or envelope["scope"] != grant["scope"]:
                        fail("grant_mismatch", "Stored permission does not match the message.")
                    if envelope["expires_at"] <= self.now() or envelope["expires_at"] > grant["expires_at"]:
                        fail("message_expired", "Message deadline is no longer valid.")
                    self._audit("message.delivered", row["id"], "broker", owners)
                    proposal = self.adapter.propose(recipient=row["recipient"], payload=json.loads(json.dumps(envelope["payload"])), availability=self.availability(AGENTS[row["recipient"]]["owner_id"]))
                    if proposal is None:
                        fail("no_matching_option", "No offered option matches the private sample availability.")
                    exact_object(proposal, {"selected_option", "explanation"}, "Adapter proposal")
                    if proposal["selected_option"] not in envelope["payload"]["options"]:
                        fail("invalid_adapter_result", "Adapter returned an option outside the request.")
                    text_value(proposal["explanation"], "Adapter explanation", 1, 300)
                    if option_timestamp(proposal["selected_option"]) <= self.now():
                        fail("meeting_time_passed", "The proposed meeting time has passed.")
                    if envelope["expires_at"] <= self.now():
                        fail("message_expired", "The message expired during dispatch.")
                    self.db.execute("UPDATE messages SET status='awaiting_approval',proposal=? WHERE id=?", (canonical(proposal).decode(), row["id"]))
                    self._audit("message.awaiting_approval", row["id"], row["recipient"], owners)
                except DomainError as error:
                    self.db.execute("UPDATE messages SET status='rejected',failure_code=? WHERE id=?", (error.code, row["id"]))
                    self._audit("message.rejected", row["id"], "broker", owners)
                except Exception:
                    # Do not persist exception text or untrusted payloads in the audit.
                    self.db.execute("UPDATE messages SET status='rejected',failure_code='adapter_failure' WHERE id=?", (row["id"],))
                    self._audit("message.rejected", row["id"], "broker", owners)
            return len(rows)

    def decide(self, owner_id, message_id, decision):
        if type(decision) is not str or decision not in {"approved", "declined"}:
            fail("invalid_decision", "Choose approved or declined.")
        with self._transaction():
            self._expire()
            row = self._get("messages", message_id)
            self._owns(owner_id, row["recipient"])
            if row["status"] == decision:
                return self._message(row)
            if row["status"] != "awaiting_approval":
                fail("message_not_approvable", "This request is not waiting for an owner decision.", 409)
            self._active_grant(row["grant_id"])
            proposal = json.loads(row["proposal"])
            if option_timestamp(proposal["selected_option"]) <= self.now():
                fail("meeting_time_passed", "The proposed meeting time has passed.", 409)
            receipt = sign_record({
                "version": 1, "id": new_id("receipt"), "message_id": message_id,
                "grant_id": row["grant_id"], "request_digest": row["wire_hash"],
                "decision": decision, "decided_by": owner_id, "decided_at": self.now(),
                "selected_option": proposal["selected_option"] if decision == "approved" else None,
                "execution": "simulation_only_no_calendar_write",
            }, self.keys["broker"])
            self.db.execute("UPDATE messages SET status=?,receipt=? WHERE id=?", (decision, canonical(receipt).decode(), message_id))
            self._audit(f"message.{decision}", message_id, owner_id, self._owners_for(row["sender"], row["recipient"]))
            return self._message(self._get("messages", message_id))
