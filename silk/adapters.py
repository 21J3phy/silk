"""Agent adapters. Network adapters are intentionally not implemented.

Inbound titles are untrusted display data, never instructions. The local adapter
can only choose a supplied candidate matching a fixture's sample availability.
"""
from __future__ import annotations
from typing import Protocol


class AgentAdapter(Protocol):
    def propose(self, *, recipient: str, payload: dict, availability: list[dict]) -> dict | None:
        """Return a bounded proposed option, or None. Must not approve or act externally."""
        ...


class LocalCoordinationAdapter:
    def propose(self, *, recipient: str, payload: dict, availability: list[dict]) -> dict | None:
        for candidate in payload["options"]:
            if candidate in availability:
                return {
                    "selected_option": dict(candidate),
                    "explanation": "This candidate matches the recipient's private sample availability. Owner approval is still required.",
                }
        return None
