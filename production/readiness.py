"""Truthful public capability status; no environment flag pretends to connect APIs."""
from .interfaces import UnconfiguredAgentAdapter


def status_document():
    connections = []
    for identifier, name in (("grok", "Grok"), ("dot", "dot")):
        adapter = UnconfiguredAgentAdapter(identifier)
        assert not adapter.capabilities.round_trip_supported
        connections.append({
            "id": identifier, "name": name, "inbound": "unverified", "outbound": "unverified",
            "connected": False, "state": "not_connected",
            "explanation": "A supported persistent-agent inbox, authenticated wake, and outbound route have not been verified or configured.",
        })
    return {
        "product": "Silk", "stage": "development_preview", "live_messaging": False,
        "owner_authentication": {"state": "not_configured"},
        "durable_storage": {"state": "not_configured"},
        "connections": connections,
        "missing_requirements": [
            "Verified owner authentication and owner-to-agent binding",
            "Shared durable permissions, replay protection, quotas, and inbox/outbox storage",
            "Supported authenticated inbound wake and outbound messaging for both agents",
            "A verified end-to-end round trip with permission and revocation checks",
        ],
        "walkthrough": {"mode": "browser_simulation", "sends_messages": False, "creates_accounts": False},
    }
