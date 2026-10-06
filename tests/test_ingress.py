"""Signed wire ingress, replay isolation, budgets, receipts, and adapter safety."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from silk.adapters import LocalCoordinationAdapter
from silk.protocol import DomainError, sign_record, verify_record
from silk.service import Service
from tests.support import ServiceCase


class CountingAdapter(LocalCoordinationAdapter):
    def __init__(self):
        self.calls = 0

    def propose(self, **kwargs):
        self.calls += 1
        return super().propose(**kwargs)


class IngressTests(ServiceCase):
    def wire(self, grant_id, key="wire-request-one", **changes):
        return self.service.fixture_envelope("alice", self.request(grant_id, key), **changes)

    def test_valid_wire_admission_and_exact_retry_only_count_once(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        first = self.service.receive(wire)
        retry = self.service.receive(copy.deepcopy(wire))
        self.assertFalse(first["duplicate"])
        self.assertTrue(retry["duplicate"])
        self.assertEqual(first["message"]["id"], retry["message"]["id"])
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_signature_tampering_never_uses_budget(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        wire["payload"]["title"] = "Tampered after signing"
        self.assertDomainError(self.service.receive, wire, code="invalid_signature")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)
        self.assertEqual(self.service.state("bob")["messages"], [])

    def test_unregistered_private_key_cannot_impersonate_sender(self):
        grant = self.grant()
        wire = sign_record(self.wire(grant["id"]), Ed25519PrivateKey.generate())
        self.assertDomainError(self.service.receive, wire, code="invalid_signature")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_authenticated_reverse_sender_cannot_use_forward_grant(self):
        grant = self.grant()
        wire = self.wire(grant["id"], sender="nova", recipient="atlas")
        wire = sign_record(wire, self.service.keys["nova"])
        self.assertDomainError(self.service.receive, wire, code="grant_mismatch")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_nonce_replay_with_new_message_and_retry_key_is_rejected(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.service.receive(wire)
        replay = self.wire(grant["id"], key="new-retry-key", nonce=wire["nonce"])
        self.assertDomainError(self.service.receive, replay, code="replay_detected")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_same_id_bound_to_different_signed_content_is_rejected(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.service.receive(wire)
        changed = self.wire(grant["id"], key="other-retry-key", id=wire["id"])
        self.assertDomainError(self.service.receive, changed, code="message_id_conflict")

    def test_semantic_retry_with_new_nonce_still_returns_original(self):
        grant = self.grant()
        first = self.service.receive(self.wire(grant["id"]))
        retry = self.service.receive(self.wire(grant["id"]))
        self.assertTrue(retry["duplicate"])
        self.assertEqual(first["message"]["id"], retry["message"]["id"])
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_replay_remains_rejected_after_restart_and_regrant(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.service.receive(wire)
        self.service.revoke_grant("bob", grant["id"])
        self.service.close()
        self.service = Service(self.db_path, clock=self.clock)
        new_grant = self.grant()
        replay = self.wire(new_grant["id"], key="new-grant-request", nonce=wire["nonce"])
        self.assertDomainError(self.service.receive, replay, code="replay_detected")
        self.assertEqual(self.current_grant(new_grant["id"])["turns_used"], 0)

    def test_exact_duplicate_after_revoke_never_wakes_again(self):
        adapter = CountingAdapter()
        self.service.adapter = adapter
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.service.receive(wire)
        self.service.dispatch_pending()
        self.assertEqual(adapter.calls, 1)
        self.service.revoke_grant("bob", grant["id"])
        duplicate = self.service.receive(wire)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["message"]["status"], "cancelled")
        self.service.dispatch_pending()
        self.assertEqual(adapter.calls, 1)

    def test_future_timestamp_beyond_skew_is_rejected(self):
        grant = self.grant()
        wire = self.wire(grant["id"], created_at=self.clock()+6, expires_at=self.clock()+306)
        self.assertDomainError(self.service.receive, wire, code="future_message")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_expired_wire_is_rejected_before_admission(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.clock.advance(300)
        self.assertDomainError(self.service.receive, wire, code="message_expired")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_message_cannot_outlive_short_grant(self):
        grant = self.grant(expires_in=60)
        wire = self.wire(grant["id"], expires_at=self.clock()+61)
        self.assertDomainError(self.service.receive, wire, code="grant_deadline")

    def test_inactive_grant_rejects_fresh_valid_wire(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        self.service.revoke_grant("bob", grant["id"])
        self.assertDomainError(self.service.receive, wire, code="grant_inactive")

    def test_meeting_must_be_in_next_thirty_days(self):
        grant = self.grant()
        for offset in (-1, 0, 30*86400+1):
            start = datetime.fromtimestamp(self.clock()+offset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            request = self.request(grant["id"], f"invalid-date-{offset}", options=[{"start": start, "duration_minutes": 30}])
            wire = self.service.fixture_envelope("alice", request)
            with self.subTest(offset=offset):
                self.assertDomainError(self.service.receive, wire, code="invalid_meeting_date")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 0)

    def test_rate_limit_is_rolling_and_persists_across_restart(self):
        grant = self.grant(max_turns=8)
        for i in range(6):
            self.send(grant["id"], key=f"rate-request-{i}")
        self.assertDomainError(self.send, grant["id"], key="rate-request-6", code="rate_limited")
        self.service.close()
        self.service = Service(self.db_path, clock=self.clock)
        self.assertDomainError(self.send, grant["id"], key="rate-request-6", code="rate_limited")
        self.clock.advance(59)
        self.assertDomainError(self.send, grant["id"], key="rate-request-6", code="rate_limited")
        self.clock.advance(1)
        self.send(grant["id"], key="rate-request-6")
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 7)

    def test_new_grant_does_not_reset_sender_recipient_rate(self):
        first = self.grant(max_turns=8)
        for i in range(6):
            self.send(first["id"], key=f"first-rate-{i}")
        second = self.grant(max_turns=8)
        self.assertDomainError(self.send, second["id"], key="second-grant-request", code="rate_limited")
        self.assertEqual(self.current_grant(second["id"])["turns_used"], 0)

    def test_simultaneous_unique_requests_do_not_overrun_turn_budget(self):
        grant = self.grant(max_turns=2)
        wires = [self.wire(grant["id"], key=f"parallel-request-{i}") for i in range(12)]
        def admit(wire):
            try:
                return self.service.receive(wire)
            except DomainError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(admit, wires))
        self.assertEqual(sum(isinstance(result, dict) for result in results), 2)
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 2)
        self.assertEqual(len(self.service.state("alice")["messages"]), 2)

    def test_two_service_instances_share_atomic_turn_budget(self):
        grant = self.grant(max_turns=1)
        other = Service(self.db_path, clock=self.clock)
        self.addCleanup(other.close)
        barrier = threading.Barrier(2)
        wires = [self.wire(grant["id"], key=f"two-services-{i}") for i in range(2)]
        def admit(index):
            barrier.wait(timeout=5)
            try:
                return (self.service if index == 0 else other).receive(wires[index])
            except DomainError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(admit, range(2)))
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertIn("turn_budget_exhausted", results)
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_simultaneous_retries_create_only_one_message(self):
        grant = self.grant()
        wire = self.wire(grant["id"])
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(self.service.receive, [wire]*12))
        self.assertEqual(sum(not result["duplicate"] for result in results), 1)
        self.assertEqual(len({result["message"]["id"] for result in results}), 1)
        self.assertEqual(self.current_grant(grant["id"])["turns_used"], 1)

    def test_receipt_is_verifiable_with_public_broker_key(self):
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.service.decide("bob", message_id, "approved")
        state = self.service.state("alice")
        receipt = self.message(message_id)["receipt"]
        public_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(state["broker_public_key"]+"="))
        self.assertTrue(verify_record(receipt, public_key))
        self.assertEqual(receipt["decided_by"], "bob")
        self.assertEqual(receipt["execution"], "simulation_only_no_calendar_write")
        self.assertFalse(verify_record({**receipt, "decision": "declined"}, public_key))

    def test_adapter_is_called_once_and_never_approves(self):
        adapter = CountingAdapter()
        self.service.adapter = adapter
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        for _ in range(5):
            self.service.dispatch_pending()
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(self.message(message_id)["status"], "awaiting_approval")
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_no_private_match_fails_closed(self):
        grant = self.grant()
        alice_only = self.service.state("alice")["suggested_options"][:1]
        message_id = self.send(grant["id"], options=alice_only)["message"]["id"]
        self.service.dispatch_pending()
        message = self.message(message_id)
        self.assertEqual(message["status"], "rejected")
        self.assertEqual(message["failure_code"], "no_matching_option")
        self.assertIsNone(message["receipt"])
        self.assertDomainError(self.service.decide, "bob", message_id, "approved")

    def test_faulty_adapter_cannot_choose_option_outside_payload(self):
        class BadAdapter:
            def propose(self, **kwargs):
                return {"selected_option": {"start": "2026-10-20T14:00:00Z", "duration_minutes": 30}, "explanation": "Unexpected option"}
        self.service.adapter = BadAdapter()
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        self.assertEqual(self.message(message_id)["failure_code"], "invalid_adapter_result")
        self.assertIsNone(self.message(message_id)["receipt"])

    def test_adapter_exception_is_redacted_and_terminal(self):
        class BrokenAdapter:
            def propose(self, **kwargs):
                raise RuntimeError("secret fixture diagnostic that must not escape")
        self.service.adapter = BrokenAdapter()
        grant = self.grant()
        message_id = self.send(grant["id"])["message"]["id"]
        self.service.dispatch_pending()
        message = self.message(message_id)
        self.assertEqual(message["status"], "rejected")
        self.assertEqual(message["failure_code"], "adapter_failure")
        self.assertNotIn("secret fixture diagnostic", str(self.service.state("alice")))
        self.assertEqual(self.service.dispatch_pending(), 0)
