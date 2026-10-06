"""Provider-neutral contracts for a future authenticated, durable live service.

These are deliberately separate from the runnable local fixture broker. No
production identity, persistence, or consumer-agent API is fabricated here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Mapping


class LiveUnavailable(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class VerifiedOwner:
    """Produced by a real, verified owner-auth implementation, never browser input."""
    subject: str
    tenant_id: str
    authentication_time: int


@dataclass(frozen=True)
class AdapterCapabilities:
    provider_id: str
    authenticated_inbound: bool = False
    inbound_wake: bool = False
    outbound_delivery: bool = False
    idempotency: bool = False
    real_agent_identity: bool = False
    evidence_url: str | None = None

    @property
    def round_trip_supported(self) -> bool:
        return all((self.authenticated_inbound, self.inbound_wake, self.outbound_delivery, self.idempotency, self.real_agent_identity)) and bool(self.evidence_url)


@dataclass(frozen=True)
class AdmittedDelivery:
    """Opaque durable job after atomic consent/replay/budget admission.

    The real store must bind job_id, tenant, sender, recipient, scope, deadline,
    message digest, grant version, and idempotency key in one transaction.
    """
    job_id: str
    tenant_id: str
    sender_agent_id: str
    recipient_agent_id: str
    scope: str
    deadline: int
    request_digest: str
    grant_version: int
    idempotency_key: str


@dataclass(frozen=True)
class TransportAcknowledgment:
    provider_message_id: str
    accepted_at: int
    # Transport acceptance is never treated as owner approval or task execution.
    status: str = "transport_accepted"


class OwnerAuthenticator(Protocol):
    def authenticate(self, headers: Mapping[str, str]) -> VerifiedOwner:
        """Validate real issuer/audience/signature/session/revocation and tenant binding."""
        ...


class DurableBrokerStore(Protocol):
    @property
    def durable(self) -> bool:
        ...

    def admit_atomically(self, owner: VerifiedOwner, envelope: dict) -> AdmittedDelivery:
        """Verify owner-agent binding, consent, signature, replay, idempotency and quotas atomically.

        Implementations must use a shared durable transaction, not process memory
        or an ephemeral function-local SQLite file. Enqueue outbox in the same commit.
        """
        ...

    def claim_and_revalidate(self, job_id: str) -> AdmittedDelivery:
        """Fence a job and recheck current consent/deadline before external effects."""
        ...

    def record_transport_result(self, job: AdmittedDelivery, result: TransportAcknowledgment) -> None:
        """Durably reconcile provider idempotency and outcome; never infer completion."""
        ...


class InboundAgentAdapter(Protocol):
    @property
    def capabilities(self) -> AdapterCapabilities:
        ...

    def authenticate_event(self, headers: Mapping[str, str], raw_body: bytes) -> dict:
        """Authenticate source event, reject replays, bind target and return untrusted data."""
        ...


class OutboundAgentAdapter(Protocol):
    @property
    def capabilities(self) -> AdapterCapabilities:
        ...

    def deliver(self, job: AdmittedDelivery) -> TransportAcknowledgment:
        """Bounded delivery to one registered destination using the durable idempotency key."""
        ...

    def wake(self, job: AdmittedDelivery) -> TransportAcknowledgment:
        """Wake a supported persistent agent. Model inference alone does not implement this."""
        ...


class UnconfiguredAgentAdapter:
    """Fail-closed adapter used until an actual supported integration is verified."""
    def __init__(self, provider_id: str):
        if provider_id not in {"grok", "dot"}:
            raise ValueError("Unknown requested provider")
        self._capabilities = AdapterCapabilities(provider_id=provider_id)

    @property
    def capabilities(self):
        return self._capabilities

    def _blocked(self):
        raise LiveUnavailable("adapter_unverified", f"{self.capabilities.provider_id} inbound wake and outbound delivery have not been verified or configured.")

    def authenticate_event(self, headers, raw_body):
        self._blocked()

    def deliver(self, job):
        self._blocked()

    def wake(self, job):
        self._blocked()


def require_live_dependencies(authenticator, store, inbound, outbound) -> None:
    """Fail closed before a request can reach a provider.

    Passing this structural gate is necessary, not a security certification. The
    configured implementations and actual round trip still require verification.
    """
    if authenticator is None or not callable(getattr(authenticator, "authenticate", None)):
        raise LiveUnavailable("owner_authentication_required", "Verified owner authentication is not configured.")
    if store is None or getattr(store, "durable", False) is not True or not all(callable(getattr(store, method, None)) for method in ("admit_atomically", "claim_and_revalidate", "record_transport_result")):
        raise LiveUnavailable("durable_storage_required", "A shared durable broker store is not configured.")
    for adapter, methods in ((inbound, ("authenticate_event",)), (outbound, ("deliver", "wake"))):
        capabilities = getattr(adapter, "capabilities", None)
        if not isinstance(capabilities, AdapterCapabilities) or not capabilities.round_trip_supported or not all(callable(getattr(adapter, method, None)) for method in methods):
            raise LiveUnavailable("adapter_unverified", "Supported authenticated inbound wake and outbound delivery are required.")
