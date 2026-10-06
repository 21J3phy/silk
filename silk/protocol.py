"""Strict wire validation and fixture Ed25519 signing, independent of transport."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCOPE = "meeting.coordinate"
MAX_WIRE_BYTES = 4096
MAX_TTL = 300
RATE_PER_MINUTE = 6
MAX_TURNS = 8
MAX_MESSAGES = 1000
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,100}$")
AGENTS = {
    "atlas": {"id": "atlas", "owner_id": "alice", "name": "Atlas", "provider": "Local fixture", "description": "Alice's coordination assistant"},
    "nova": {"id": "nova", "owner_id": "bob", "name": "Nova", "provider": "Local fixture", "description": "Bob's coordination assistant"},
}
OWNERS = [{"id": "alice", "name": "Alice Chen"}, {"id": "bob", "name": "Bob Rivera"}]


class DomainError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def fail(code: str, message: str, status: int = 400):
    raise DomainError(code, message, status)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        fail("invalid_json", "A finite, valid UTF-8 JSON value is required.")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def exact_object(value: Any, keys: set[str], label: str):
    if type(value) is not dict or set(value) != keys:
        fail("invalid_fields", f"{label} has missing or unsupported fields.")


def text_value(value: Any, label: str, minimum: int, maximum: int) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum or value != value.strip():
        fail("invalid_text", f"{label} must be {minimum}–{maximum} characters without leading or trailing spaces.")
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        fail("invalid_text", f"{label} contains unsupported control characters.")
    return value


def integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        fail("invalid_number", f"{label} must be an integer from {minimum} to {maximum}.")
    return value


def opaque_id(value: Any, label: str) -> str:
    if type(value) is not str or not ID_RE.fullmatch(value):
        fail("invalid_id", f"{label} is not a valid opaque identifier.")
    return value


def validate_payload(payload: Any) -> None:
    exact_object(payload, {"kind", "title", "options"}, "Payload")
    if payload["kind"] != "meeting.proposal":
        fail("unsupported_kind", "Only structured meeting proposals are supported.")
    text_value(payload["title"], "Meeting title", 1, 120)
    options = payload["options"]
    if type(options) is not list or not 1 <= len(options) <= 3:
        fail("invalid_options", "Provide one to three candidate meeting times.")
    seen = set()
    for option in options:
        exact_object(option, {"start", "duration_minutes"}, "Meeting option")
        start = option["start"]
        if type(start) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", start):
            fail("invalid_time", "Meeting times must be UTC ISO timestamps ending in Z.")
        try:
            datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            fail("invalid_time", "The proposed date or time is invalid.")
        if type(option["duration_minutes"]) is not int or option["duration_minutes"] not in {15, 30, 45, 60}:
            fail("invalid_duration", "Meeting duration must be 15, 30, 45, or 60 minutes.")
        key = (start, option["duration_minutes"])
        if key in seen:
            fail("duplicate_option", "Candidate meeting times must be distinct.")
        seen.add(key)


def validate_wire(envelope: Any) -> None:
    exact_object(envelope, {"version", "id", "sender", "recipient", "grant_id", "scope", "created_at", "expires_at", "nonce", "idempotency_key", "payload", "signature"}, "Envelope")
    if len(canonical(envelope)) > MAX_WIRE_BYTES:
        fail("payload_too_large", "The signed envelope exceeds 4096 bytes.", 413)
    if type(envelope["version"]) is not int or envelope["version"] != 1:
        fail("unsupported_version", "Only protocol version 1 is supported.")
    for field in ("id", "grant_id", "nonce", "idempotency_key"):
        opaque_id(envelope[field], field)
    if type(envelope["sender"]) is not str or envelope["sender"] not in AGENTS:
        fail("unknown_sender", "The sender is not a registered fixture agent.", 401)
    if type(envelope["recipient"]) is not str or envelope["recipient"] not in AGENTS:
        fail("unknown_recipient", "The recipient is not a registered fixture agent.")
    if envelope["sender"] == envelope["recipient"]:
        fail("same_agent", "Send to a different agent.")
    if envelope["scope"] != SCOPE:
        fail("unsupported_scope", "Only meeting.coordinate is implemented.", 403)
    integer(envelope["created_at"], "created_at", 0, 2**53 - 1)
    integer(envelope["expires_at"], "expires_at", 0, 2**53 - 1)
    if not 1 <= envelope["expires_at"] - envelope["created_at"] <= MAX_TTL:
        fail("invalid_ttl", "The message lifetime must be 1–300 seconds.")
    validate_payload(envelope["payload"])
    sig = envelope["signature"]
    if type(sig) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{86}", sig):
        fail("invalid_signature", "An Ed25519 signature is required.", 401)


def sign_record(record: dict, private_key: Ed25519PrivateKey) -> dict:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    sig = private_key.sign(canonical(unsigned))
    return {**unsigned, "signature": base64.urlsafe_b64encode(sig).decode().rstrip("=")}


def verify_record(record: dict, public_key: Ed25519PublicKey) -> bool:
    try:
        signature = base64.urlsafe_b64decode(record["signature"] + "==")
        if base64.urlsafe_b64encode(signature).decode().rstrip("=") != record["signature"]:
            return False
        public_key.verify(signature, canonical({k: v for k, v in record.items() if k != "signature"}))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def public_key_text(key: Ed25519PublicKey) -> str:
    return base64.urlsafe_b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip("=")


def option_timestamp(option: dict) -> int:
    return int(datetime.strptime(option["start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
