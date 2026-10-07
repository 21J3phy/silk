"""Operator administration for a self-hosted mailbox.

Run by the operating business with its own credentials, never through MCP:

    python -m silk_live.admin <command> [options]

Provisioning and migration use SILK_ADMIN_POSTGRES_DSN, a separate migration/
admin authority. `status` and `purge-expired` need only the restricted runtime
role in SILK_POSTGRES_DSN. Owner consent is recorded only as opaque references
to evidence the operator retains elsewhere; this module cannot verify it.
Never prints DSNs, tokens, or underlying driver errors.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

from .domain import MailboxError, Principal
from .storage import PostgresStore, _MAX_TIME, _fail, _id, _integer, _pair, _plain, _TABLES

MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "001_mailbox.sql"
_DAY = 86_400


def _principal(principal):
    if not isinstance(principal, Principal):
        raise TypeError("principal must be Principal")
    for value in (principal.issuer, principal.subject, principal.client_id):
        _plain(value, 1, 2048, 8192, "principal field")
    return principal


def _consent(value, label):
    _plain(value, 1, 200, 800, label)
    if value.startswith("fixture-only:"):
        _fail("invalid_request", f"Invalid {label}.")
    return value


class MailboxAdmin(PostgresStore):
    """Provisioning for an operator-owned deployment.

    Every mutation locks the mailbox_limits singleton first, then agents,
    bindings and pair rows, matching the runtime lock order. Bindings are never
    reassigned or resurrected; grants are never renewed in place.
    """

    def register_agent(self, agent_id, owner_id, display_name):
        _id(agent_id, "agent_id")
        _id(owner_id, "owner_id")
        _plain(display_name, 1, 100, 400, "display_name")
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            if tx.one("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)):
                _fail("conflict", "That agent is already registered.")
            self._available(tx, "agents", limits["max_agents"])
            tx.execute("INSERT INTO agents(agent_id,owner_id,display_name) VALUES(?,?,?)", (agent_id, owner_id, display_name))
        return {"agent_id": agent_id, "owner_id": owner_id, "display_name": display_name}

    def bind(self, principal, agent_id, *, expires_at, now):
        now = self._now(now)
        _principal(principal)
        _id(agent_id, "agent_id")
        _integer(expires_at, now + 1, _MAX_TIME, "binding expiry")
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            self._active_agent(tx, agent_id)
            if tx.one("SELECT agent_id FROM agent_bindings WHERE issuer=? AND subject=? AND client_id=?" + tx.lock(), (principal.issuer, principal.subject, principal.client_id)):
                # Covers revoked and expired tuples too: a retired identity is
                # never silently reassigned or brought back.
                _fail("conflict", "A binding already exists for this issuer, subject and client.")
            self._available(tx, "agent_bindings", limits["max_bindings"])
            tx.execute("INSERT INTO agent_bindings(issuer,subject,client_id,agent_id,created_at,expires_at) VALUES(?,?,?,?,?,?)", (principal.issuer, principal.subject, principal.client_id, agent_id, now, expires_at))
        return {"agent_id": agent_id, "created_at": now, "expires_at": expires_at}

    def revoke_binding(self, principal, *, now):
        now = self._now(now)
        _principal(principal)
        with self._transaction(True) as tx:
            self._capacity(tx)
            row = tx.one("SELECT agent_id,revoked_at FROM agent_bindings WHERE issuer=? AND subject=? AND client_id=?" + tx.lock(), (principal.issuer, principal.subject, principal.client_id))
            if row is None:
                _fail("not_found", "No binding exists for this issuer, subject and client.")
            revoked = row["revoked_at"]
            if revoked is None:
                revoked = now
                tx.execute("UPDATE agent_bindings SET revoked_at=? WHERE issuer=? AND subject=? AND client_id=?", (now, principal.issuer, principal.subject, principal.client_id))
        return {"agent_id": row["agent_id"], "status": "revoked", "revoked_at": revoked}

    def grant(self, grant_id, agent_a, agent_b, *, consent_a, consent_b, expires_at, now, max_turns=8, max_ttl=300):
        now = self._now(now)
        _id(grant_id, "grant_id")
        _id(agent_a, "agent_a")
        _id(agent_b, "agent_b")
        if agent_a == agent_b:
            _fail("invalid_request", "A pair requires two distinct agents.")
        consent = {agent_a: _consent(consent_a, "consent_a"), agent_b: _consent(consent_b, "consent_b")}
        _integer(expires_at, now + 1, _MAX_TIME, "grant expiry")
        _integer(max_turns, 1, 32, "turn budget")
        _integer(max_ttl, 1, 300, "grant TTL")
        a, b = sorted([agent_a, agent_b])
        pair_id = _pair(a, b)
        with self._transaction(True) as tx:
            limits = self._capacity(tx)
            self._active_agent(tx, a)
            self._active_agent(tx, b)
            if tx.one("SELECT grant_id FROM pair_grants WHERE grant_id=?", (grant_id,)):
                _fail("conflict", "That grant ID already exists; renew consent with a new grant ID.")
            self._available(tx, "pair_grants", limits["max_grants"])
            tx.execute("INSERT INTO pair_quotas(pair_id,agent_a,agent_b) VALUES(?,?,?) ON CONFLICT(pair_id) DO NOTHING", (pair_id, a, b))
            tx.one("SELECT pair_id FROM pair_quotas WHERE pair_id=?" + tx.lock(), (pair_id,))
            tx.execute("INSERT INTO pair_grants(grant_id,pair_id,agent_a,agent_b,scope,created_at,expires_at,max_turns,max_ttl,consent_a_reference,consent_b_reference) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (grant_id, pair_id, a, b, "message.coordinate", now, expires_at, max_turns, max_ttl, consent[a], consent[b]))
        return {"grant_id": grant_id, "agent_a": a, "agent_b": b, "scope": "message.coordinate", "created_at": now, "expires_at": expires_at, "max_turns": max_turns, "max_ttl": max_ttl}

    def revoke_grant(self, grant_id, *, now):
        now = self._now(now)
        _id(grant_id, "grant_id")
        with self._transaction(True) as tx:
            self._capacity(tx)
            self._lock_pair(tx, grant_id)
            grant = tx.one("SELECT revoked_at FROM pair_grants WHERE grant_id=?" + tx.lock(), (grant_id,))
            revoked = grant["revoked_at"]
            if revoked is None:
                revoked = now
                tx.execute("UPDATE pair_grants SET revoked_at=? WHERE grant_id=?", (now, grant_id))
            tx.execute("UPDATE messages SET text=NULL WHERE grant_id=? AND text IS NOT NULL", (grant_id,))
        return {"grant_id": grant_id, "status": "revoked", "revoked_at": revoked}

    def disable_agent(self, agent_id, *, now):
        now = self._now(now)
        _id(agent_id, "agent_id")
        with self._transaction(True) as tx:
            self._capacity(tx)
            row = tx.one("SELECT disabled_at FROM agents WHERE agent_id=?" + tx.lock(), (agent_id,))
            if row is None:
                _fail("not_found", "That agent is not registered.")
            disabled = row["disabled_at"]
            if disabled is None:
                disabled = now
                tx.execute("UPDATE agents SET disabled_at=? WHERE agent_id=?", (now, agent_id))
        return {"agent_id": agent_id, "status": "disabled", "disabled_at": disabled}

    def status(self):
        with self._transaction() as tx:
            limits = tx.one("SELECT max_messages,max_receipts,max_agents,max_bindings,max_grants FROM mailbox_limits WHERE singleton=1")
            if limits is None:
                _fail("storage_unavailable", "Mailbox capacity has not been configured.")
            counts = {table: tx.one(f"SELECT COUNT(*) AS count FROM {table}")["count"] for table in _TABLES}
        return {"counts": counts, "limits": limits}

    @staticmethod
    def _active_agent(tx, agent_id):
        agent = tx.one("SELECT disabled_at FROM agents WHERE agent_id=?" + tx.lock("SHARE"), (agent_id,))
        if agent is None or agent["disabled_at"] is not None:
            _fail("not_found", "No active agent is registered with that ID.")


def apply_migration(connect):
    """Apply the reviewed schema once. Requires the migration authority."""
    connection = connect(autocommit=True)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT 1 FROM information_schema.schemata WHERE schema_name='silk_mailbox'")
        if cursor.fetchall():
            return {"migration": MIGRATION.name, "status": "already_applied"}
        # Static reviewed file with its own BEGIN/COMMIT; no parameters.
        cursor.execute(MIGRATION.read_text())
        return {"migration": MIGRATION.name, "status": "applied"}
    finally:
        connection.close()


def _connector(dsn, root_cert):
    def connect(autocommit=False):
        import psycopg
        return psycopg.connect(dsn, sslmode="verify-full", sslrootcert=root_cert, connect_timeout=5, autocommit=autocommit)
    return connect


def _parser():
    parser = argparse.ArgumentParser(prog="python -m silk_live.admin", description="Operator administration for a self-hosted Silk mailbox. Not exposed through MCP.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="Apply the reviewed schema (admin authority)")
    commands.add_parser("status", help="Show row counts and capacity limits (runtime role)")
    commands.add_parser("purge-expired", help="Clear expired message text (runtime role)")
    agent = commands.add_parser("register-agent", help="Register an agent and its accountable owner")
    agent.add_argument("--agent-id", required=True)
    agent.add_argument("--owner-id", required=True)
    agent.add_argument("--display-name", required=True)
    disable = commands.add_parser("disable-agent", help="Disable an agent; its bindings stop working")
    disable.add_argument("--agent-id", required=True)
    for name, text in (("bind", "Bind a verified OAuth issuer/subject/client to an agent"), ("revoke-binding", "Revoke an issuer/subject/client binding")):
        command = commands.add_parser(name, help=text)
        command.add_argument("--issuer", required=True)
        command.add_argument("--subject", required=True)
        command.add_argument("--client-id", required=True)
        if name == "bind":
            command.add_argument("--agent-id", required=True)
            command.add_argument("--days", type=int, default=90, help="Binding lifetime in days (default 90)")
    grant = commands.add_parser("grant", help="Record both owners' consent for a named pair")
    grant.add_argument("--grant-id", required=True)
    grant.add_argument("--agent-a", required=True)
    grant.add_argument("--consent-a", required=True, help="Opaque reference to agent A's owner consent evidence")
    grant.add_argument("--agent-b", required=True)
    grant.add_argument("--consent-b", required=True, help="Opaque reference to agent B's owner consent evidence")
    grant.add_argument("--days", type=int, default=30, help="Grant lifetime in days (default 30)")
    grant.add_argument("--max-turns", type=int, default=8, help="Send budget, 1-32 (default 8)")
    grant.add_argument("--max-ttl", type=int, default=300, help="Message TTL ceiling in seconds, 1-300 (default 300)")
    revoke = commands.add_parser("revoke-grant", help="Revoke a pair grant and clear its pending text")
    revoke.add_argument("--grant-id", required=True)
    return parser


def _lifetime(days, now):
    return now + _integer(days, 1, 3650, "lifetime in days") * _DAY


def main(argv=None, environ=None, connector=_connector):
    args = _parser().parse_args(argv)
    env = os.environ if environ is None else environ
    variable = "SILK_POSTGRES_DSN" if args.command in ("status", "purge-expired") else "SILK_ADMIN_POSTGRES_DSN"
    if not env.get(variable):
        print(f"Not configured. Set {variable}; its value is never printed.", file=sys.stderr)
        return 2
    connect = connector(env[variable], env.get("SILK_POSTGRES_CA", "system"))
    admin, now = MailboxAdmin(connect), int(time.time())
    try:
        if args.command == "migrate":
            try:
                result = apply_migration(connect)
            except Exception:
                raise MailboxError("storage_unavailable", "Migration did not complete.") from None
        elif args.command == "status":
            result = admin.status()
        elif args.command == "purge-expired":
            admin.purge_expired_content(now)
            result = {"status": "purged", "at": now}
        elif args.command == "register-agent":
            result = admin.register_agent(args.agent_id, args.owner_id, args.display_name)
        elif args.command == "disable-agent":
            result = admin.disable_agent(args.agent_id, now=now)
        elif args.command == "bind":
            result = admin.bind(Principal(args.issuer, args.subject, args.client_id), args.agent_id, expires_at=_lifetime(args.days, now), now=now)
        elif args.command == "revoke-binding":
            result = admin.revoke_binding(Principal(args.issuer, args.subject, args.client_id), now=now)
        elif args.command == "grant":
            result = admin.grant(args.grant_id, args.agent_a, args.agent_b, consent_a=args.consent_a, consent_b=args.consent_b, expires_at=_lifetime(args.days, now), now=now, max_turns=args.max_turns, max_ttl=args.max_ttl)
        else:
            result = admin.revoke_grant(args.grant_id, now=now)
    except MailboxError as error:
        print(json.dumps({"error": {"code": error.code, "message": error.message}}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
