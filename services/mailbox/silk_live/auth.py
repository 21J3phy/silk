"""Pinned OAuth JWT resource-server verification; never issues access tokens.

Only configuration supplies the issuer, audience, and JWKS URL. The signed
``client_id`` claim is the sole OAuth client binding; ``azp`` is not a fallback.
See docs/AUTH_SETUP.md for the intentionally narrow interoperability profile.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import math
import re
import time
from collections.abc import Awaitable, Callable, Collection
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from mcp.server.auth.provider import AccessToken

MAILBOX_SCOPE = "silk:mailbox"
MAX_TOKEN_BYTES = 16_384
MAX_JWKS_BYTES = 65_536
MAX_JWKS_KEYS = 16
MAX_CACHE_TTL_SECONDS = 300
FETCH_TIMEOUT_SECONDS = 5.0
_ALLOWED_ALGORITHMS = frozenset({"RS256", "ES256"})
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+\Z", re.ASCII)
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
JWKSFetcher = Callable[[str], Awaitable[bytes]]


def _text(value: Any, maximum: int = 256) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and all(0x20 <= ord(c) < 0xD800 or 0xDFFF < ord(c) <= 0x10FFFF for c in value)
        and not any(0x7F <= ord(c) <= 0x9F for c in value)
    )


def _https_url(value: str) -> str:
    """Validate trusted operator configuration, without normalizing identifiers."""
    if not _text(value, 2048) or not value.isascii() or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("Expected a pinned HTTPS URL")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https" or not value.startswith("https://")
            or not host or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or "?" in value or "#" in value
            or port is not None and not 1 <= port <= 65535
            or len(host) > 253 or "." not in host or host.endswith((".", ".localhost", ".local"))
            or not any(c.isalpha() for c in host.rsplit(".", 1)[-1])
            or not all(_DNS_LABEL.fullmatch(label) for label in host.split("."))
        ):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Expected a pinned HTTPS DNS URL without credentials, query, or fragment") from None
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(_: str) -> Any:
    raise ValueError("Non-finite JSON value")


def _json_object(data: bytes, maximum: int) -> dict[str, Any]:
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise ValueError("Invalid bounded JSON data")
    result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(result, dict):
        raise ValueError("Expected JSON object")
    return result


def _b64_decode(segment: str) -> bytes:
    if not _BASE64URL.fullmatch(segment):
        raise ValueError("Invalid base64url")
    decoded = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    # Reject noncanonical base64 encodings rather than letting different token
    # representations disagree between this parser and the JWT implementation.
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise ValueError("Noncanonical base64url")
    return decoded


async def fetch_public_jwks(url: str) -> bytes:
    """Fetch only the configured public JWKS, with TLS and hostname verification.

    No redirects, environment proxies, credentials, cookies, or token headers.
    An outer deadline bounds the whole download, including slow streaming.
    """
    _https_url(url)

    async def fetch() -> bytes:
        async with httpx.AsyncClient(
            verify=True, follow_redirects=False, trust_env=False,
            timeout=httpx.Timeout(FETCH_TIMEOUT_SECONDS),
        ) as client:
            async with client.stream("GET", url, headers={"Accept": "application/jwk-set+json, application/json", "Accept-Encoding": "identity"}) as response:
                if response.status_code != 200:
                    raise ValueError("JWKS response unavailable")
                if response.headers.get("content-encoding", "identity").lower().strip() != "identity":
                    raise ValueError("Compressed JWKS responses are not supported")
                media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if media_type not in {"application/json", "application/jwk-set+json"}:
                    raise ValueError("Unexpected JWKS response type")
                length = response.headers.get("content-length")
                if length is not None and (not length.isdigit() or not 0 < int(length) <= MAX_JWKS_BYTES):
                    raise ValueError("JWKS response too large")
                body = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    if len(body) + len(chunk) > MAX_JWKS_BYTES:
                        raise ValueError("JWKS response too large")
                    body.extend(chunk)
                if not body:
                    raise ValueError("Empty JWKS response")
                return bytes(body)

    return await asyncio.wait_for(fetch(), timeout=FETCH_TIMEOUT_SECONDS)


def _parse_jwks(data: bytes) -> dict[str, tuple[str, Any]]:
    document = _json_object(data, MAX_JWKS_BYTES)
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
        raise ValueError("Invalid JWKS key count")
    result: dict[str, tuple[str, Any]] = {}
    seen: set[str] = set()
    for item in keys:
        if not isinstance(item, dict) or not _text(item.get("kid"), 128):
            raise ValueError("Invalid JWKS key")
        kid = item["kid"]
        if kid in seen or _PRIVATE_JWK_FIELDS.intersection(item):
            raise ValueError("Ambiguous or private JWKS key")
        seen.add(kid)
        # A provider may also publish encryption or other-algorithm keys. Those
        # cannot be selected here, even if a token names their kid.
        if "use" in item and item["use"] != "sig":
            continue
        if "key_ops" in item and item["key_ops"] != ["verify"]:
            continue
        kty = item.get("kty")
        algorithm = "RS256" if kty == "RSA" else "ES256" if kty == "EC" else None
        if algorithm is None or item.get("alg", algorithm) != algorithm:
            continue
        # Pass a new public-only mapping to PyJWT. In particular neither x5u
        # nor any certificate/URL metadata can trigger a second network fetch.
        public: dict[str, Any] = {"kty": kty, "kid": kid, "alg": algorithm}
        if algorithm == "RS256":
            n, e = item.get("n"), item.get("e")
            if not isinstance(n, str) or not 1 <= len(n) <= 684 or not isinstance(e, str) or not 1 <= len(e) <= 8:
                raise ValueError("Invalid RSA public parameters")
            modulus, exponent = int.from_bytes(_b64_decode(n)), int.from_bytes(_b64_decode(e))
            if not 2048 <= modulus.bit_length() <= 4096 or exponent != 65537:
                raise ValueError("Unsupported RSA public parameters")
            public.update(n=n, e=e)
        else:
            x, y = item.get("x"), item.get("y")
            if item.get("crv") != "P-256" or not isinstance(x, str) or not isinstance(y, str) or len(x) != 43 or len(y) != 43:
                raise ValueError("Unsupported EC public parameters")
            if len(_b64_decode(x)) != 32 or len(_b64_decode(y)) != 32:
                raise ValueError("Invalid EC public parameters")
            public.update(crv="P-256", x=x, y=y)
        key = jwt.PyJWK.from_dict(public, algorithm=algorithm).key
        if algorithm == "RS256" and not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Invalid RSA public key")
        if algorithm == "ES256" and not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("Invalid EC public key")
        result[kid] = (algorithm, key)
    if not result:
        raise ValueError("No supported signing keys")
    return result


class JWTAccessTokenVerifier:
    """Implements the SDK TokenVerifier protocol using public asymmetric keys.

    ``jwks_fetcher`` is an optional trusted test dependency: async (URL) -> bytes.
    ``clock`` supplies Unix seconds; ``monotonic_clock`` controls cache expiry.
    A fresh cached key remains usable during provider outage. Expired keys are
    NEVER usable; unknown-kid refreshes and failures share a bounded cooldown.
    """

    def __init__(
        self, *, issuer: str, resource: str, jwks_url: str,
        allowed_client_ids: Collection[str], jwks_fetcher: JWKSFetcher | None = None,
        clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        cache_ttl_seconds: int = MAX_CACHE_TTL_SECONDS,
        refresh_interval_seconds: int = 30,
    ) -> None:
        self.issuer = _https_url(issuer)
        self.resource = _https_url(resource)
        self.jwks_url = _https_url(jwks_url)
        if (
            isinstance(allowed_client_ids, (str, bytes))
            or not isinstance(allowed_client_ids, Collection)
            or not 1 <= len(allowed_client_ids) <= 64
            or any(not _text(value) for value in allowed_client_ids)
        ):
            raise ValueError("A bounded nonempty OAuth client ID allowlist is required")
        self.allowed_client_ids = frozenset(allowed_client_ids)
        if type(cache_ttl_seconds) is not int or not 1 <= cache_ttl_seconds <= MAX_CACHE_TTL_SECONDS:
            raise ValueError("JWKS cache TTL must be 1 through 300 seconds")
        if type(refresh_interval_seconds) is not int or not 1 <= refresh_interval_seconds <= cache_ttl_seconds:
            raise ValueError("JWKS refresh interval must be 1 through the cache TTL seconds")
        self._fetcher = jwks_fetcher or fetch_public_jwks
        self._clock = clock
        self._monotonic = monotonic_clock
        self._ttl = cache_ttl_seconds
        self._refresh_interval = refresh_interval_seconds
        self._keys: dict[str, tuple[str, Any]] = {}
        self._expires_at = float("-inf")
        self._last_fetch = float("-inf")
        self._lock = asyncio.Lock()

    def _claims_valid(self, claims: dict[str, Any]) -> bool:
        if claims.get("iss") != self.issuer:
            return False
        audience = claims.get("aud")
        if audience != self.resource and audience != [self.resource]:
            return False
        if not _text(claims.get("sub")) or not _text(claims.get("client_id")):
            return False
        if claims["client_id"] not in self.allowed_client_ids:
            return False
        # azp never grants an identity. Reject contradictory provider mappings.
        if "azp" in claims and claims["azp"] != claims["client_id"]:
            return False
        for field in ("iat", "exp"):
            if type(claims.get(field)) is not int or not 0 <= claims[field] <= 253_402_300_799:
                return False
        if "nbf" in claims and (type(claims["nbf"]) is not int or not 0 <= claims["nbf"] <= 253_402_300_799):
            return False
        now = self._clock()
        if not math.isfinite(now) or not claims["iat"] <= now < claims["exp"] or claims["iat"] >= claims["exp"]:
            return False
        if "nbf" in claims and (claims["nbf"] > now or claims["nbf"] >= claims["exp"]):
            return False
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str) or len(scopes) > 1024:
            return False
        if scopes and (len(scopes.split(" ")) > 32 or any(not _SCOPE.fullmatch(s) for s in scopes.split(" "))):
            return False
        return True

    async def _key(self, kid: str, algorithm: str) -> Any | None:
        async with self._lock:
            now = self._monotonic()
            if not math.isfinite(now):
                return None
            entry = self._keys.get(kid) if now < self._expires_at else None
            if entry is not None:
                return entry[1] if entry[0] == algorithm else None
            if now - self._last_fetch < self._refresh_interval:
                return None
            self._last_fetch = now
            try:
                data = await asyncio.wait_for(self._fetcher(self.jwks_url), timeout=FETCH_TIMEOUT_SECONDS)
                keys = _parse_jwks(data)
                refreshed = self._monotonic()
                if not math.isfinite(refreshed):
                    return None
                self._keys = keys
                self._expires_at = refreshed + self._ttl
            except Exception:
                # Do not log exceptions: providers/test dependencies can include
                # credentials or token text in exception messages. Do not extend
                # the old expiry or authorize this request on refresh failure.
                return None
            entry = self._keys.get(kid)
            return entry[1] if entry is not None and entry[0] == algorithm else None

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return a minimally populated SDK token, or a generic failure."""
        try:
            if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_BYTES or not token.isascii():
                return None
            segments = token.split(".")
            if len(segments) != 3 or len(segments[0]) > 2048:
                return None
            header = _json_object(_b64_decode(segments[0]), 1536)
            claims = _json_object(_b64_decode(segments[1]), 12_288)
            _b64_decode(segments[2])
            # Explicit header allowlist rejects remote-key metadata, critical
            # extensions, detached payloads, compression, and embedded keys.
            if set(header) != {"alg", "kid", "typ"}:
                return None
            if header["alg"] not in _ALLOWED_ALGORITHMS or header["typ"] not in {"at+jwt", "application/at+jwt"}:
                return None
            if not _text(header["kid"], 128) or not self._claims_valid(claims):
                return None
            key = await self._key(header["kid"], header["alg"])
            if key is None:
                return None
            verified = jwt.decode(
                token, key=key, algorithms=[header["alg"]], issuer=self.issuer, audience=self.resource,
                options={
                    "require": ["iss", "sub", "aud", "client_id", "exp", "iat"],
                    # Time is checked explicitly before AND after verification,
                    # using the injected clock with strict integer types.
                    "verify_exp": False, "verify_iat": False, "verify_nbf": False,
                },
            )
            if verified != claims or not self._claims_valid(verified):
                return None
            # Never expose arbitrary profile/role claims to application code.
            return AccessToken(
                token=token,  # Required by SDK; do not serialize or log it.
                client_id=verified["client_id"], subject=verified["sub"],
                scopes=[MAILBOX_SCOPE] if MAILBOX_SCOPE in verified.get("scope", "").split(" ") else [],
                expires_at=verified["exp"], resource=self.resource,
                claims={"iss": self.issuer, "sub": verified["sub"], "client_id": verified["client_id"]},
            )
        except Exception:
            # SDK middleware receives no diagnostic or unverified claim values.
            # Cancellation (BaseException) still propagates normally.
            return None
