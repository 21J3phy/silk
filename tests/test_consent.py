"""Owner consent, revocation, expiry, budgets, and durable local state."""
import json

from silk.service import Service
from tests.support import ServiceCase


class ConsentTests(ServiceCase):
    def test_fresh_state_has_no_grants_messages_or_receipts(self):
        for owner in ("alice", "bob"):
            state = self.service.state(owner)
            self.assertTrue(state["demo"])
            self.assertEqual(state["current_owner"]["id"], owner)
            self.assertEqual(state["grants"], [])
            self.assertEqual(state["messages"], [])

    def test_invitation_does_not_authorize_a_message(self):
        invitation = self.invite()
        self.assertEqual(invitation["status"], "pending")
        self.assertEqual(self.service.state("alice")["grants"], [])
        self.assertDomainError(self.send, invitation["id"])
        self.service.dispatch_pending()
        self.assertEqual(self.service.state("bob")["messages"], [])

    def test_invitation_sender_must_belong_to_owner(self):
        self.assertDomainError(self.invite, owner="bob")
        self.assertEqual(self.service.state("alice")["invitations"], [])

    def test_only_recipient_owner_can_accept_or_decline(self):
        invitation = self.invite()
        for accepted in (True, False):
            self.assertDomainError(self.service.respond_invitation, "alice", invitation["id"], accepted)
        self.assertEqual(self.service.state("alice")["grants"], [])

    def test_accepted_invitation_produces_one_directional_grant(self):
        invitation = self.invite()
        self.service.respond_invitation("bob", invitation["id"], True)
        self.service.respond_invitation("bob", invitation["id"], True)
        grants = self.service.state("alice")["grants"]
        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertEqual((grant["from_agent"], grant["to_agent"], grant["scope"]), ("atlas", "nova", "meeting.coordinate"))
        self.assertDomainError(self.send, grant["id"], owner="bob")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_declined_invitation_never_creates_grant(self):
        invitation = self.invite()
        self.service.respond_invitation("bob", invitation["id"], False)
        self.service.respond_invitation("bob", invitation["id"], False)
        self.assertDomainError(self.service.respond_invitation, "bob", invitation["id"], True)
        self.assertEqual(self.service.state("alice")["grants"], [])

    def test_expired_invitation_cannot_be_accepted(self):
        invitation = self.invite()
        self.clock.advance(3600)
        self.assertDomainError(self.service.respond_invitation, "bob", invitation["id"], True)
        self.assertEqual(self.service.state("alice")["grants"], [])
        self.assertEqual(self.service.state("alice")["invitations"][0]["status"], "expired")

    def test_dispatch_requires_separate_recipient_decision(self):
        grant = self.grant()
        result = self.send(grant["id"])
        message_id = result["message"]["id"]
        self.assertFalse(result["duplicate"])
        self.assertEqual(self.message(message_id)["status"], "queued")
        self.assertIsNone(self.message(message_id)["receipt"])
        self.service.dispatch_pending()
        pending = self.message(message_id)
        self.assertEqual(pending["status"], "awaiting_approval")
        self.assertIsNotNone(pending["proposal"])
        self.assertIsNone(pending["receipt"])
        self.assertDomainError(self.service.decide, "alice", message_id, "approved")
        self.assertEqual(self.message(message_id)["status"], "awaiting_approval")

    def test_cannot_approve_before_dispatch(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_approval_is_durable_idempotent_and_conflicts_fail(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.service.decide("bob", message_id, "approved")
        approved = self.message(message_id)
        receipt = approved["receipt"]
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(receipt["decision"], "approved")
        self.assertEqual(receipt["message_id"], message_id)
        self.assertEqual(receipt["selected_option"], approved["proposal"]["selected_option"])
        self.assertTrue(receipt["signature"])
        self.service.decide("bob", message_id, "approved")
        self.assertEqual(self.message(message_id)["receipt"], receipt)
        self.assertDomainError(self.service.decide, "bob", message_id, "declined")
        self.service.close()
        self.service = Service(self.db_path, clock=self.clock)
        self.assertEqual(self.message(message_id)["receipt"], receipt)
        self.service.decide("bob", message_id, "approved")
        self.assertEqual(self.message(message_id)["receipt"], receipt)

    def test_decline_has_immutable_receipt_and_no_selected_option(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.service.decide("bob", message_id, "declined")
        declined = self.message(message_id)
        self.assertEqual(declined["status"], "declined")
        self.assertEqual(declined["receipt"]["decision"], "declined")
        self.assertIsNone(declined["receipt"]["selected_option"])
        self.service.decide("bob", message_id, "declined")
        self.assertEqual(self.message(message_id)["receipt"], declined["receipt"])
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")

    def test_revoke_before_dispatch_cancels_work(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.revoke_grant("alice", grant["id"])
        self.service.dispatch_pending()
        self.assertEqual(self.message(message_id)["status"], "cancelled")
        self.assertIsNone(self.message(message_id)["proposal"])
        self.assertIsNone(self.message(message_id)["receipt"])
        self.assertDomainError(self.send, grant["id"], key="after-revoke")

    def test_recipient_can_revoke_before_approval(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.service.revoke_grant("bob", grant["id"])
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")
        self.assertEqual(self.message(message_id)["status"], "cancelled")
        self.assertIsNone(self.message(message_id)["receipt"])
        self.service.revoke_grant("bob", grant["id"])
        self.assertEqual(self.current_grant(grant["id"])["status"], "revoked")

    def test_revoke_does_not_rewrite_completed_receipt(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.service.decide("bob", message_id, "approved")
        receipt = self.message(message_id)["receipt"]
        self.service.revoke_grant("alice", grant["id"])
        self.assertEqual(self.message(message_id)["receipt"], receipt)
        self.assertEqual(self.message(message_id)["status"], "approved")

    def test_message_ttl_prevents_late_dispatch(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.clock.advance(grant["ttl_seconds"])
        self.service.dispatch_pending()
        self.assertEqual(self.message(message_id)["status"], "expired")
        self.assertIsNone(self.message(message_id)["proposal"])
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_message_ttl_prevents_late_approval(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.clock.advance(grant["ttl_seconds"])
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")
        self.assertEqual(self.message(message_id)["status"], "expired")
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_turn_budget_counts_unique_messages_not_retries(self):
        grant = self.grant(max_turns=2)
        first = self.send(grant["id"], key="request-one")
        duplicate = self.send(grant["id"], key="request-one")
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(first["message"]["id"], duplicate["message"]["id"])
        self.send(grant["id"], key="request-two")
        self.assertDomainError(self.send, grant["id"], key="request-three")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 2)
        self.assertEqual(len(self.service.state("alice")["messages"]), 2)

    def test_changed_idempotent_request_is_rejected(self):
        grant = self.grant()
        self.send(grant["id"], key="retry-same")
        self.assertDomainError(self.send, grant["id"], key="retry-same", title="A different meeting")
        self.assertEqual(len(self.service.state("alice")["messages"]), 1)
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_restart_retains_queued_work_keys_and_idempotency(self):
        grant = self.grant()
        message_id = self.send(grant["id"], key="retry-durable")["message"]["id"]
        agents = self.service.state("alice")["agents"]
        self.service.close()
        self.service = Service(self.db_path, clock=self.clock)
        self.assertEqual(self.service.state("alice")["agents"], agents)
        retry = self.send(grant["id"], key="retry-durable")
        self.assertTrue(retry["duplicate"])
        self.assertEqual(retry["message"]["id"], message_id)
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)
        self.service.dispatch_pending()
        self.assertEqual(self.message(message_id)["status"], "awaiting_approval")
        self.service.dispatch_pending()
        self.assertEqual(self.message(message_id)["status"], "awaiting_approval")
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_owner_state_contains_only_own_private_availability(self):
        alice = self.service.state("alice")
        bob = self.service.state("bob")
        self.assertNotEqual(alice["private_availability"], bob["private_availability"])
        self.assertEqual(alice["suggested_options"], bob["suggested_options"])
        for state in (alice, bob):
            rendered = json.dumps(state).lower()
            self.assertNotIn("private_key", rendered)
            self.assertNotIn("secret_key", rendered)
            self.assertNotIn("pkcs8", rendered)
            self.assertNotIn("nonce", rendered)
            self.assertNotIn("idempotency_key", rendered)
        self.assertDomainError(self.service.state, "mallory")

    def test_grant_expiry_prevents_pending_dispatch_and_fresh_work(self):
        grant = self.grant(expires_in=60)
        message_id = self.send(grant["id"])["message"]["id"]
        self.clock.advance(60)
        self.service.dispatch_pending()
        self.assertEqual(self.current_grant(grant["id"])["status"], "expired")
        self.assertEqual(self.message(message_id)["status"], "expired")
        self.assertIsNone(self.message(message_id)["proposal"])
        self.assertDomainError(self.send, grant["id"], key="after-expiry")
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")

    def test_grant_expiry_prevents_pending_approval(self):
        grant = self.grant(expires_in=60)
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.clock.advance(60)
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")
        self.assertIsNone(self.message(message_id)["receipt"])
        self.assertEqual(self.message(message_id)["status"], "expired")

    def test_invitation_bounds_and_unknown_fields_fail_closed(self):
        changes = [{"max_turns": 0}, {"max_turns": 9}, {"max_turns": True}, {"expires_in": 59}, {"expires_in": 86401}, {"purpose": ""}, {"purpose": "x"*281}, {"scope": "calendar.write"}, {"to_agent": "atlas"}, {"to_agent": []}]
        for change in changes:
            with self.subTest(change=change):
                self.assertDomainError(self.invite, **change)
        self.assertEqual(self.service.state("alice")["invitations"], [])

    def test_only_one_pending_invitation_and_bounded_invitation_rate(self):
        invitation = self.invite()
        self.assertDomainError(self.invite, code="invitation_pending")
        self.service.respond_invitation("bob", invitation["id"], False)
        for _ in range(4):
            invitation = self.invite()
            self.service.respond_invitation("bob", invitation["id"], False)
        self.assertDomainError(self.invite, code="invitation_rate_limited")
        self.clock.advance(60)
        self.assertEqual(self.invite()["status"], "pending")

    def test_mutating_a_snapshot_does_not_mutate_persisted_state(self):
        grant = self.grant()
        snapshot = self.service.state("alice")
        snapshot["grants"][0]["status"] = "revoked"
        snapshot["private_availability"].clear()
        self.assertEqual(self.current_grant(grant["id"])["status"], "active")
        self.assertTrue(self.service.state("alice")["private_availability"])
