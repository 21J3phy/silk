"""Fail-closed provider contracts; stub success is not live integration proof."""

from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from production.interfaces import (
    AdapterCapabilities, AdmittedDelivery, LiveUnavailable, TransportAcknowledgment,
    UnconfiguredAgentAdapter, VerifiedOwner, require_live_dependencies,
)


def full_capabilities(provider="grok"):
    return AdapterCapabilities(
        provider_id=provider, authenticated_inbound=True, inbound_wake=True,
        outbound_delivery=True, idempotency=True, real_agent_identity=True,
        evidence_url="https://example.invalid/test-evidence-only",
    )


def structural_dependencies():
    """Callable-only doubles, intentionally never real credentials or delivery."""
    auth = SimpleNamespace(authenticate=Mock())
    store = SimpleNamespace(durable=True, admit_atomically=Mock(),
                            claim_and_revalidate=Mock(), record_transport_result=Mock())
    inbound = SimpleNamespace(capabilities=full_capabilities(), authenticate_event=Mock())
    outbound = SimpleNamespace(capabilities=full_capabilities("dot"), deliver=Mock(), wake=Mock())
    return auth, store, inbound, outbound


class InterfaceTests(unittest.TestCase):
    def test_unconfigured_providers_never_advertise_live_capabilities(self):
        for provider in ("grok", "dot"):
            capabilities = UnconfiguredAgentAdapter(provider).capabilities
            self.assertEqual(capabilities.provider_id, provider)
            self.assertFalse(capabilities.round_trip_supported)
            self.assertFalse(capabilities.authenticated_inbound)
            self.assertFalse(capabilities.inbound_wake)
            self.assertFalse(capabilities.outbound_delivery)
            self.assertFalse(capabilities.idempotency)
            self.assertFalse(capabilities.real_agent_identity)
            self.assertIsNone(capabilities.evidence_url)

    def test_unconfigured_adapters_reject_every_operation_without_inspecting_input(self):
        class Poison:
            def __getattribute__(self, name):
                raise AssertionError("An unavailable adapter must not inspect a delivery")

        for provider in ("grok", "dot"):
            adapter = UnconfiguredAgentAdapter(provider)
            operations = ((adapter.authenticate_event, ({"Authorization": "synthetic-token"}, b"{}")),
                          (adapter.deliver, (Poison(),)), (adapter.wake, (Poison(),)))
            for operation, args in operations:
                with self.subTest(provider=provider, operation=operation.__name__):
                    with self.assertRaises(LiveUnavailable) as caught:
                        operation(*args)
                    self.assertEqual(caught.exception.code, "adapter_unverified")

    def test_unknown_provider_cannot_silently_become_a_live_adapter(self):
        for provider in ("openai", "xai", "Grok", "", "fixture", None):
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                UnconfiguredAgentAdapter(provider)

    def test_all_capabilities_and_evidence_are_required(self):
        complete = full_capabilities()
        self.assertTrue(complete.round_trip_supported)
        for field in ("authenticated_inbound", "inbound_wake", "outbound_delivery",
                      "idempotency", "real_agent_identity"):
            with self.subTest(field=field):
                self.assertFalse(replace(complete, **{field: False}).round_trip_supported)
        for evidence in (None, ""):
            self.assertFalse(replace(complete, evidence_url=evidence).round_trip_supported)

    def test_capabilities_and_identity_cannot_be_modified_in_place(self):
        owner = VerifiedOwner("synthetic-owner", "synthetic-tenant", 1)
        with self.assertRaises(FrozenInstanceError):
            owner.subject = "forged-owner"
        capabilities = UnconfiguredAgentAdapter("grok").capabilities
        with self.assertRaises(FrozenInstanceError):
            capabilities.real_agent_identity = True

    def test_missing_authentication_always_fails_first(self):
        for auth in (None, object(), SimpleNamespace(authenticate=None)):
            with self.subTest(auth=auth), self.assertRaises(LiveUnavailable) as caught:
                require_live_dependencies(auth, None, None, None)
            self.assertEqual(caught.exception.code, "owner_authentication_required")

    def test_missing_or_merely_truthy_storage_is_rejected(self):
        auth, _, inbound, outbound = structural_dependencies()
        for store in (None, object(), SimpleNamespace(durable=False),
                      SimpleNamespace(durable=1), SimpleNamespace(durable="true")):
            with self.subTest(store=store), self.assertRaises(LiveUnavailable) as caught:
                require_live_dependencies(auth, store, inbound, outbound)
            self.assertEqual(caught.exception.code, "durable_storage_required")

    def test_durable_flag_without_atomic_storage_methods_is_rejected(self):
        auth, _, inbound, outbound = structural_dependencies()
        with self.assertRaises(LiveUnavailable):
            require_live_dependencies(auth, SimpleNamespace(durable=True), inbound, outbound)

    def test_each_atomic_storage_method_is_required(self):
        for method in ("admit_atomically", "claim_and_revalidate", "record_transport_result"):
            auth, store, inbound, outbound = structural_dependencies()
            setattr(store, method, None)
            with self.subTest(method=method), self.assertRaises(LiveUnavailable):
                require_live_dependencies(auth, store, inbound, outbound)

    def test_missing_or_unverified_adapter_is_rejected(self):
        for adapter in (None, object(), UnconfiguredAgentAdapter("grok"),
                        SimpleNamespace(capabilities={"round_trip_supported": True})):
            for position in (2, 3):
                dependencies = list(structural_dependencies())
                dependencies[position] = adapter
                with self.subTest(adapter=adapter, position=position), self.assertRaises(LiveUnavailable) as caught:
                    require_live_dependencies(*dependencies)
                self.assertEqual(caught.exception.code, "adapter_unverified")

    def test_claimed_adapter_capabilities_without_operations_are_rejected(self):
        for position in (2, 3):
            dependencies = list(structural_dependencies())
            dependencies[position] = SimpleNamespace(capabilities=full_capabilities())
            with self.subTest(position=position), self.assertRaises(LiveUnavailable):
                require_live_dependencies(*dependencies)

    def test_structural_check_does_not_call_auth_storage_or_providers(self):
        dependencies = structural_dependencies()
        require_live_dependencies(*dependencies)
        for dependency in dependencies:
            for value in vars(dependency).values():
                if isinstance(value, Mock):
                    value.assert_not_called()

    def test_transport_acceptance_is_not_execution_or_owner_approval(self):
        acknowledgement = TransportAcknowledgment("synthetic-message", 1)
        self.assertEqual(acknowledgement.status, "transport_accepted")
        job = AdmittedDelivery("job", "tenant", "sender", "recipient", "message.send", 123,
                               "synthetic-digest", 1, "synthetic-idempotency-key")
        with self.assertRaises(FrozenInstanceError):
            job.recipient_agent_id = "other-recipient"


if __name__ == "__main__":
    unittest.main()
