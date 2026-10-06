#!/usr/bin/env python3
"""Run the fixture coordination flow without a browser or external effects."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from silk.service import Service
from silk.protocol import verify_record


def main():
    with tempfile.TemporaryDirectory(prefix="silk-demo-") as directory:
        service = Service(Path(directory) / "demo.sqlite3")
        try:
            invitation = service.create_invitation("alice", {
                "from_agent": "atlas", "to_agent": "nova", "purpose": "Coordinate one design catch-up.",
                "max_turns": 2, "expires_in": 3600,
            })
            print("1. Alice invited Bob's fixture agent. No message permission yet.")
            service.respond_invitation("bob", invitation["id"], True)
            grant = service.state("alice")["grants"][0]
            print("2. Bob accepted a scoped Atlas → Nova permission.")
            request = {"grant_id": grant["id"], "title": "Design catch-up", "options": service.state("alice")["suggested_options"], "idempotency_key": "cli-demo-request-001"}
            result = service.send_fixture("alice", request)
            message_id = result["message"]["id"]
            print("3. Signed request accepted:", result["message"]["status"])
            service.dispatch_pending()
            print("4. Local mock selected a candidate:", service.state("bob")["messages"][0]["status"])
            message = service.decide("bob", message_id, "approved")
            assert verify_record(message["receipt"], service.keys["broker"].public_key())
            print("5. Bob approved. Broker receipt signature verified.")
            retry = service.send_fixture("alice", request)
            assert retry["duplicate"] and retry["message"]["id"] == message_id
            print("6. Retrying returned the same result without another request.")
            service.revoke_grant("bob", grant["id"])
            print("7. Bob revoked the permission. The completed receipt remains.")
            print("Simulation only: no accounts, providers, calendars, or payments contacted.")
        finally:
            service.close()


if __name__ == "__main__":
    main()
