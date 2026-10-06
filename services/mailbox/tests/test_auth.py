"""Isolated authentication tests: disposable keys, no accounts or network."""
from __future__ import annotations

import asyncio
import base64
import copy
import json
import unittest
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from silk_live.auth import (
    JWTAccessTokenVerifier, MAILBOX_SCOPE, MAX_JWKS_BYTES, MAX_TOKEN_BYTES,
    fetch_public_jwks,
)

ISSUER = "https://auth.example.test/tenant"
RESOURCE = "https://mailbox.example.test/mcp"
JWKS_URL = "https://auth.example.test/tenant/jwks"
CLIENT = "registered-client-1"
NOW = 1_800_000_000


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def public_jwk(key, kid, algorithm="RS256"):
    codec = jwt.algorithms.RSAAlgorithm if algorithm == "RS256" else jwt.algorithms.ECAlgorithm
    item = json.loads(codec.to_jwk(key.public_key()))
    item.update(kid=kid, alg=algorithm, use="sig", key_ops=["verify"])
    return item


class Time:
    def __init__(self):
        self.unix = float(NOW)
        self.monotonic = 100.0

    def advance(self, seconds):
        self.unix += seconds
        self.monotonic += seconds


class AuthTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.rsa_second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.rsa_jwk = public_jwk(cls.rsa, "key-1")
        cls.second_jwk = public_jwk(cls.rsa_second, "key-2")
        cls.ec_jwk = public_jwk(cls.ec, "ec-1", "ES256")

    def setUp(self):
        self.time = Time()
        self.calls = []
        self.jwks = encoded({"keys": [self.rsa_jwk]})
        self.fetch_error = None

        async def fetcher(url):
            self.calls.append(url)
            if self.fetch_error:
                raise self.fetch_error
            return self.jwks

        self.verifier = JWTAccessTokenVerifier(
            issuer=ISSUER, resource=RESOURCE, jwks_url=JWKS_URL,
            allowed_client_ids={CLIENT}, jwks_fetcher=fetcher,
            clock=lambda: self.time.unix, monotonic_clock=lambda: self.time.monotonic,
            cache_ttl_seconds=60, refresh_interval_seconds=5,
        )

    def claims(self, **changes):
        claims = {
            "iss": ISSUER, "aud": RESOURCE, "sub": "subject-1", "client_id": CLIENT,
            "iat": NOW - 10, "exp": NOW + 3600, "scope": MAILBOX_SCOPE, "jti": "disposable-token-id",
        }
        claims.update(changes)
        return claims

    def token(self, claims=None, headers=None, key=None, algorithm="RS256"):
        return jwt.encode(
            self.claims() if claims is None else claims, key=key or self.rsa,
            algorithm=algorithm, headers={"kid": "key-1", "typ": "at+jwt", **(headers or {})},
        )

    async def test_valid_rsa_returns_minimal_validated_identity(self):
        token = self.token(self.claims(email="private@example.test", roles=["admin"], owner_id="spoofed"))
        access = await self.verifier.verify_token(token)
        self.assertIsNotNone(access)
        self.assertEqual(access.token, token)
        self.assertEqual(access.client_id, CLIENT)
        self.assertEqual(access.subject, "subject-1")
        self.assertEqual(access.claims, {"iss": ISSUER, "sub": "subject-1", "client_id": CLIENT})
        self.assertEqual(access.resource, RESOURCE)
        self.assertEqual(access.expires_at, NOW + 3600)
        self.assertEqual(access.scopes, [MAILBOX_SCOPE])
        self.assertEqual(self.calls, [JWKS_URL])

    async def test_valid_es256(self):
        self.jwks = encoded({"keys": [self.ec_jwk]})
        access = await self.verifier.verify_token(self.token(key=self.ec, algorithm="ES256", headers={"kid": "ec-1"}))
        self.assertIsNotNone(access)

    async def test_application_typ_and_singleton_audience(self):
        access = await self.verifier.verify_token(self.token(self.claims(aud=[RESOURCE]), headers={"typ": "application/at+jwt"}))
        self.assertIsNotNone(access)

    async def test_missing_scope_is_verified_but_sdk_can_deny_it(self):
        claims = self.claims()
        del claims["scope"]
        access = await self.verifier.verify_token(self.token(claims))
        self.assertIsNotNone(access)
        self.assertEqual(access.scopes, [])

    async def test_only_mailbox_scope_is_forwarded(self):
        access = await self.verifier.verify_token(self.token(self.claims(scope="profile silk:mailbox email")))
        self.assertEqual(access.scopes, [MAILBOX_SCOPE])

    async def test_signature_tampering_and_untrusted_key(self):
        self.assertIsNone(await self.verifier.verify_token(self.token(key=self.rsa_second)))
        parts = self.token().split(".")
        parts[1] = b64(encoded(self.claims(sub="spoofed")))
        self.assertIsNone(await self.verifier.verify_token(".".join(parts)))

    async def test_required_claims(self):
        for claim in ("iss", "sub", "aud", "client_id", "iat", "exp"):
            with self.subTest(claim=claim):
                claims = self.claims()
                del claims[claim]
                self.assertIsNone(await self.verifier.verify_token(self.token(claims)))
        self.assertEqual(self.calls, [])

    async def test_exact_issuer_resource_and_client_binding(self):
        cases = [
            {"iss": ISSUER + "/"}, {"iss": "https://evil.example.test"},
            {"aud": RESOURCE + "/"}, {"aud": [RESOURCE, "https://other.example.test"]},
            {"aud": []}, {"client_id": "other-client"}, {"azp": "other-client"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertIsNone(await self.verifier.verify_token(self.token(self.claims(**changes))))
        self.assertEqual(self.calls, [])

    async def test_azp_cannot_replace_client_id(self):
        claims = self.claims(azp=CLIENT)
        del claims["client_id"]
        self.assertIsNone(await self.verifier.verify_token(self.token(claims)))
        self.assertIsNotNone(await self.verifier.verify_token(self.token(self.claims(azp=CLIENT))))

    async def test_invalid_subject_and_client_types(self):
        for field in ("sub", "client_id"):
            for value in (None, True, 42, [], {}, "", "x" * 257, "x\ny", "x\ud800y", "x\x7fy"):
                with self.subTest(field=field, value=repr(value)):
                    self.assertIsNone(await self.verifier.verify_token(self.token(self.claims(**{field: value}))))

    async def test_numeric_dates_strict_and_time_boundaries(self):
        for changes in (
            {"exp": NOW}, {"exp": NOW - 1}, {"iat": NOW + 1}, {"nbf": NOW + 1},
            {"iat": NOW + 10, "exp": NOW + 5}, {"nbf": NOW + 3600},
            *({name: value} for name in ("exp", "iat", "nbf") for value in (True, None, "1800000000", 1.5, -1, 253402300800)),
        ):
            with self.subTest(changes=changes):
                self.assertIsNone(await self.verifier.verify_token(self.token(self.claims(**changes))))
        self.assertIsNotNone(await self.verifier.verify_token(self.token(self.claims(iat=NOW, nbf=NOW))))

    async def test_expiration_rechecked_after_fetch(self):
        async def fetcher(url):
            self.time.advance(2)
            return self.jwks
        self.verifier._fetcher = fetcher
        self.assertIsNone(await self.verifier.verify_token(self.token(self.claims(exp=NOW + 1))))

    async def test_invalid_scope_syntax(self):
        for scope in ([], None, "silk:mailbox\nadmin", "silk:mailbox  admin", "silk:mailbox ", " silk:mailbox", '"', "x" * 1025, " ".join(["s"] * 33)):
            with self.subTest(scope=scope):
                self.assertIsNone(await self.verifier.verify_token(self.token(self.claims(scope=scope))))

    async def test_none_and_hmac_algorithms_are_rejected_without_fetch(self):
        unsigned = jwt.encode(self.claims(), key=None, algorithm="none", headers={"kid": "key-1", "typ": "at+jwt"})
        hmac = jwt.encode(self.claims(), key=b"fixture-test-only-hmac-key-32-bytes", algorithm="HS256", headers={"kid": "key-1", "typ": "at+jwt"})
        self.assertIsNone(await self.verifier.verify_token(unsigned))
        self.assertIsNone(await self.verifier.verify_token(hmac))
        self.assertEqual(self.calls, [])

    async def test_key_type_algorithm_mismatch_is_rejected(self):
        self.assertIsNone(await self.verifier.verify_token(self.token(key=self.ec, algorithm="ES256")))

    async def test_token_header_never_controls_url_or_embedded_key(self):
        for addition in ({"jku": "https://evil.example.test/keys"}, {"x5u": "https://evil.example.test/cert"}, {"jwk": self.rsa_jwk}, {"crit": []}, {"b64": False}, {"zip": "DEF"}):
            with self.subTest(addition=list(addition)):
                self.assertIsNone(await self.verifier.verify_token(self.token(headers=addition)))
        self.assertEqual(self.calls, [])

    async def test_id_token_and_missing_header_fields_are_rejected(self):
        for headers in ({"typ": "JWT"}, {"typ": None}, {"kid": ""}, {"kid": None}, {"kid": ["key-1"]}, {"kid": "k" * 129}):
            with self.subTest(headers=headers):
                parts = self.token().split(".")
                parts[0] = b64(encoded({"alg": "RS256", "kid": "key-1", "typ": "at+jwt", **headers}))
                self.assertIsNone(await self.verifier.verify_token(".".join(parts)))
        self.assertEqual(self.calls, [])

    async def test_malformed_tokens_are_bounded(self):
        for token in (None, 123, b"token", "", "x" * (MAX_TOKEN_BYTES + 1), "a.b.c", "a.b.c.d", "a.é.c", "e30=.e30=.AA", ".."):
            with self.subTest(token_type=type(token).__name__):
                self.assertIsNone(await self.verifier.verify_token(token))
        self.assertEqual(self.calls, [])

    async def test_duplicate_json_members_are_rejected(self):
        good = self.token().split(".")
        for index, payload in (
            (0, b'{"alg":"RS256","alg":"RS256","kid":"key-1","typ":"at+jwt"}'),
            (1, b'{"iss":"one","iss":"two"}'),
        ):
            parts = good.copy()
            parts[index] = b64(payload)
            self.assertIsNone(await self.verifier.verify_token(".".join(parts)))
        self.assertEqual(self.calls, [])

    async def test_nonfinite_and_deep_json_rejected(self):
        good = self.token().split(".")
        for data in (b'{"exp":NaN}', b'{"a":' + b'[' * 1200 + b'0' + b']' * 1200 + b'}'):
            parts = good.copy()
            parts[1] = b64(data)
            self.assertIsNone(await self.verifier.verify_token(".".join(parts)))

    async def test_cache_reused_until_ttl(self):
        token = self.token()
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.time.advance(59)
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.assertEqual(len(self.calls), 1)
        self.time.advance(1)
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.assertEqual(len(self.calls), 2)

    async def test_key_rotation_unknown_kid_is_rate_limited(self):
        self.assertIsNotNone(await self.verifier.verify_token(self.token()))
        rotated = self.token(key=self.rsa_second, headers={"kid": "key-2"})
        self.jwks = encoded({"keys": [self.second_jwk]})
        self.assertIsNone(await self.verifier.verify_token(rotated))
        self.assertEqual(len(self.calls), 1)
        self.time.advance(5)
        self.assertIsNotNone(await self.verifier.verify_token(rotated))
        self.assertEqual(len(self.calls), 2)
        self.assertIsNone(await self.verifier.verify_token(self.token()))

    async def test_unknown_kid_does_not_create_negative_cache_growth(self):
        self.assertIsNotNone(await self.verifier.verify_token(self.token()))
        for i in range(30):
            self.assertIsNone(await self.verifier.verify_token(self.token(headers={"kid": f"unknown-{i}"})))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.verifier._keys), 1)

    async def test_expired_cache_and_provider_outage_fail_closed(self):
        token = self.token()
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.fetch_error = RuntimeError("secret material must not be echoed")
        self.time.advance(60)
        self.assertIsNone(await self.verifier.verify_token(token))
        self.assertIsNone(await self.verifier.verify_token(token))
        self.assertEqual(len(self.calls), 2)
        self.time.advance(5)
        self.fetch_error = None
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.assertEqual(len(self.calls), 3)

    async def test_unexpired_cache_survives_unknown_key_refresh_outage(self):
        token = self.token()
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.fetch_error = RuntimeError("offline")
        self.time.advance(5)
        self.assertIsNone(await self.verifier.verify_token(self.token(headers={"kid": "unknown"})))
        self.assertIsNotNone(await self.verifier.verify_token(token))
        self.time.advance(55)
        self.assertIsNone(await self.verifier.verify_token(token))

    async def test_concurrent_initial_requests_fetch_once(self):
        accesses = await asyncio.gather(*(self.verifier.verify_token(self.token()) for _ in range(20)))
        self.assertTrue(all(access is not None for access in accesses))
        self.assertEqual(len(self.calls), 1)

    async def test_fetch_timeout_is_fail_closed(self):
        async def stuck(url):
            await asyncio.sleep(10)
            return self.jwks
        self.verifier._fetcher = stuck
        with patch("silk_live.auth.FETCH_TIMEOUT_SECONDS", 0.01):
            self.assertIsNone(await self.verifier.verify_token(self.token()))

    async def test_cancellation_propagates(self):
        async def cancelled(url):
            raise asyncio.CancelledError
        self.verifier._fetcher = cancelled
        with self.assertRaises(asyncio.CancelledError):
            await self.verifier.verify_token(self.token())

    async def test_malformed_jwks_is_rejected(self):
        variants = (
            b"", b"x" * (MAX_JWKS_BYTES + 1), b"not json", b"[]", b'{"keys":[],"keys":[]}',
            encoded({}), encoded({"keys": []}), encoded({"keys": "key"}),
            encoded({"keys": [self.rsa_jwk] * 17}), encoded({"keys": [self.rsa_jwk, self.rsa_jwk]}),
            encoded({"keys": [None]}), {"keys": [self.rsa_jwk]},
        )
        for data in variants:
            with self.subTest(data_type=type(data).__name__):
                self.jwks = data
                self.assertIsNone(await self.verifier.verify_token(self.token()))
                self.time.advance(5)

    async def test_invalid_or_private_jwks_key_rejected(self):
        variants = [
            {"d": "private-material"}, {"kid": ""}, {"use": "enc"}, {"key_ops": ["sign"]},
            {"key_ops": ["verify", "sign"]}, {"kty": "oct"}, {"alg": "HS256"},
            {"n": "AQAB"}, {"n": "a" * 685}, {"e": "Aw"}, {"n": "invalid="},
        ]
        for changes in variants:
            with self.subTest(changes=list(changes)):
                self.jwks = encoded({"keys": [{**self.rsa_jwk, **changes}]})
                self.assertIsNone(await self.verifier.verify_token(self.token()))
                self.time.advance(5)

    async def test_jwks_optional_algorithm_and_usage_metadata(self):
        item = copy.deepcopy(self.rsa_jwk)
        for field in ("alg", "use", "key_ops"):
            del item[field]
        item["x5u"] = "https://never-fetch.example.test/certificate"
        self.jwks = encoded({"keys": [item]})
        self.assertIsNotNone(await self.verifier.verify_token(self.token()))
        self.assertEqual(self.calls, [JWKS_URL])

    async def test_nonfinite_clocks_fail_closed(self):
        for attribute in ("unix", "monotonic"):
            with self.subTest(attribute=attribute):
                previous = getattr(self.time, attribute)
                setattr(self.time, attribute, float("nan"))
                self.assertIsNone(await self.verifier.verify_token(self.token()))
                setattr(self.time, attribute, previous)


class ConfigurationTests(unittest.TestCase):
    def config(self, **changes):
        return dict(issuer=ISSUER, resource=RESOURCE, jwks_url=JWKS_URL, allowed_client_ids={CLIENT}, **changes)

    def test_nonempty_bounded_client_allowlist_required(self):
        for clients in ([], "client", None, [""], [True], ["x\ny"], ["c"] * 65):
            with self.subTest(clients=clients):
                config = self.config()
                config["allowed_client_ids"] = clients
                with self.assertRaises(ValueError):
                    JWTAccessTokenVerifier(**config)

    def test_url_configuration_is_https_pinned_and_not_local(self):
        for url in ("http://auth.example.test/jwks", "https://localhost/jwks", "https://127.0.0.1/jwks", "https://127.1/jwks", "https://0177.0.0.1/jwks", "https://0x7f.0.0.1/jwks", "https://[::1]/jwks", "https://u:p@auth.example.test/jwks", "https://auth.example.test/jwks?token=x", "https://auth.example.test/jwks#x", "https://auth.example.test\\evil", "https://auth.example.test/\n", "https://auth.example.test:99999/jwks"):
            for field in ("issuer", "resource", "jwks_url"):
                with self.subTest(field=field, url=url):
                    config = self.config()
                    config[field] = url
                    with self.assertRaises(ValueError):
                        JWTAccessTokenVerifier(**config)

    def test_cache_settings_bounded(self):
        for changes in ({"cache_ttl_seconds": 0}, {"cache_ttl_seconds": 301}, {"cache_ttl_seconds": True}, {"refresh_interval_seconds": 0}, {"refresh_interval_seconds": 301}, {"refresh_interval_seconds": True}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    JWTAccessTokenVerifier(**self.config(**changes))


class PublicFetchTests(unittest.IsolatedAsyncioTestCase):
    async def request(self, handler):
        original = httpx.AsyncClient
        options = []
        def client(**kwargs):
            options.append(kwargs)
            return original(**kwargs, transport=httpx.MockTransport(handler))
        with patch("silk_live.auth.httpx.AsyncClient", client):
            result = await fetch_public_jwks(JWKS_URL)
        return result, options

    async def test_fetch_tls_hostname_checks_no_redirects_no_proxy_no_bearer(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, content=b'{"keys":[]}', headers={"content-type": "application/jwk-set+json"})
        body, options = await self.request(handler)
        self.assertEqual(body, b'{"keys":[]}')
        self.assertTrue(options[0]["verify"])
        self.assertFalse(options[0]["follow_redirects"])
        self.assertFalse(options[0]["trust_env"])
        self.assertNotIn("authorization", requests[0].headers)
        self.assertEqual(requests[0].headers["accept-encoding"], "identity")
        self.assertEqual(str(requests[0].url), JWKS_URL)

    async def test_redirect_is_not_followed(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(302, headers={"location": "https://evil.example.test/jwks"})
        with self.assertRaises(ValueError):
            await self.request(handler)
        self.assertEqual(len(requests), 1)

    async def test_bad_status_content_type_and_oversize_rejected(self):
        responses = [
            httpx.Response(503),
            httpx.Response(200, content=b"{}", headers={"content-type": "application/json", "content-encoding": "identity, identity"}),
            httpx.Response(200, content=b"<html></html>", headers={"content-type": "text/html"}),
            httpx.Response(200, content=b"{}", headers={"content-type": "application/json", "content-length": str(MAX_JWKS_BYTES + 1)}),
            httpx.Response(200, content=b"x" * (MAX_JWKS_BYTES + 1), headers={"content-type": "application/json"}),
            httpx.Response(200, content=b"", headers={"content-type": "application/json"}),
        ]
        for response in responses:
            with self.subTest(status=response.status_code, size=len(response.content)):
                with self.assertRaises(ValueError):
                    await self.request(lambda request: response)


if __name__ == "__main__":
    unittest.main()
