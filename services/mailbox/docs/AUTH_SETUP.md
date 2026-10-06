# OAuth resource-server setup and verification boundary

## Current status

This project implements public-key access-token verification. It does not run an authorization server, issue tokens, perform browser sign-in, create OAuth grants, register clients, or establish anyone's real identity merely because a subject claim exists. No live provider, account, OAuth grant, domain, paid service, or production credentials were created or tested.

The adapter targets the installed official Python MCP SDK 1.29.0 and its **2025-11-25** Streamable HTTP/authorization facilities. This is not a claim of compatibility with a later protocol revision. PyJWT 2.13.0 and cryptography 50.0.0 perform signature/key operations. No additional installation was needed.

## Provider selection and approval gate

An authorization provider remains **unselected**. Before any real setup, the owner must approve the specific provider, account/tenant, exact MCP resource, client registrations and redirect destinations, requested permissions, data being disclosed, and any costs or agreements. Do not create an account, consent grant, persistent credential, or public deployment as a side effect of running tests or reading this document.

Select a provider that can issue the narrow JWT access-token profile below, publish a stable public HTTPS JWKS, provide OAuth or OIDC discovery, and support authorization-code PKCE with S256 for the intended pre-registered client. Verify actual client compatibility rather than assuming a consumer chat subscription can operate as an arbitrary MCP OAuth client. Provider-specific claim mapping or an incompatible `typ`/audience/client claim is a setup blocker; do not disable checks to make it work.

Costs are unknown until a provider and usage plan are selected. Check the price and limits for custom API/resource registration, custom scopes/claims, active users, machine-to-machine tokens if applicable, retained logs, tenant administration, and any required paid tier. Hosting, domain/TLS, database, and network charges are separate. A free tier or zero-cost deployment is not promised.

## Approved administrator setup checklist

Only after the relevant approvals:

1. Register one dedicated protected resource using the exact deployed HTTPS MCP URL, including its `/mcp` path. Use it as the token audience and OAuth `resource` parameter. Do not reuse another API's audience or request a token covering multiple resources.
2. Define only the mailbox API scope `silk:mailbox` for this resource. Do not request mail, contacts, files, calendar, administrative, offline, or other unrelated scopes. This scope permits entry to the mailbox API; it does not register an agent, create a pair permission, or authorize message execution.
3. Pre-register the exact intended OAuth client or small reviewed set of clients. Configure exact authorized redirect URIs, authorization-code flow, and S256 PKCE. Public clients must not be issued an embedded client secret. Do not enable broad dynamic registration or accept arbitrary client metadata URLs to avoid selecting an allowlist.
4. Configure provider-issued access tokens with the required claims and headers below. The `client_id` claim must identify the OAuth client that received the token; never copy it from an untrusted user-editable profile field. Use a provider-controlled, stable, non-reassignable subject in the reviewed issuer/tenant. Prefer short-lived access tokens. Do not request refresh/offline access without a separately approved need.
5. Verify the provider's authoritative discovery document manually as part of approved setup. Pin its exact issuer identifier and exact public JWKS URL in operator configuration. The verifier deliberately does not follow arbitrary discovery URLs during requests. Trailing slashes matter. Ensure SDK-published metadata uses the same canonical forms; URL libraries may add `/` to bare origins.
6. Set the exact accepted client ID allowlist. The application currently allows one through eight reviewed IDs; the verifier itself caps the input at 64. No wildcard, empty allowlist, implicit `azp` fallback, or auto-accept-on-first-use is supported.
7. Through separately approved owner/admin provisioning, bind the exact `(issuer, subject, client_id)` to a registered agent, then establish an explicitly approved named pair and its limits. Runtime mailbox operations recheck current bindings and permissions. Possessing a valid JWT alone does not establish ownership of a user, assistant, or other agent.
8. After approved deployment, perform the live interoperability checks below before allowing real mailbox messages.

The resource server needs **no authorization-server client secret** for public JWT verification. It uses the public JWKS only. If a confidential OAuth client later needs its own secret, that is client-side provider setup with separate authorization, not an excuse to add a secret to this verifier. Never paste tokens or secrets into support messages, source, test fixtures, logs, or this document.

## Exact accepted token profile

The client identity rule follows RFC 9068's signed `client_id` convention. `azp` alone is rejected; if present alongside `client_id`, it must have the same value. This intentionally narrow implementation is not a declaration that every RFC 9068 token from every provider is supported.

- Compact, unencrypted signed JWT: at most 16,384 ASCII bytes, canonical base64url segments, JSON objects without duplicate members or non-finite constants.
- Header contains exactly `alg`, `kid`, and `typ`. `alg` is `RS256` or `ES256`. `typ` is exactly `at+jwt` or `application/at+jwt`. ID-token-style `JWT`, HMAC, unsigned tokens, remote/embedded-key headers, critical extensions, and compressed/detached payloads are rejected.
- `kid` is a nonempty bounded string of at most 128 characters. Its only use is lookup within the pinned JWKS; it never selects a URL.
- `iss` matches the configured HTTPS issuer exactly, including path and trailing slash.
- `aud` is the exact configured resource string or a singleton array containing that string. Other/multiple audiences are rejected.
- `sub` and `client_id` are nonempty strings of at most 256 characters without controls or surrogates. `client_id` must be in the allowlist.
- `iat` and `exp` are required integer Unix seconds; booleans, numeric strings, fractions, negative values, and values beyond year 9999 are rejected. `iat <= now < exp`, and `iat < exp`. Optional `nbf` has the same integer constraints, must not be in the future, and must precede expiration. No clock-skew allowance is used; synchronize deployment clocks. Time is checked again after key retrieval/signature verification.
- Optional `scope` is an OAuth space-delimited string, up to 1,024 characters and 32 scope tokens. A valid token with no `silk:mailbox` produces no effective scopes, allowing SDK middleware to return an insufficient-scope denial. Only `silk:mailbox` is propagated to middleware; other scopes are not mailbox powers.
- A provider following full RFC 9068 should also issue `jti`; this verifier does not use it for identity, replay prevention, or token revocation. The application must not infer either one-time use or per-token revocation from JWT verification.

The verifier returns only validated `iss`, `sub`, and `client_id` in `AccessToken.claims`, plus the SDK's subject, client ID, resource, expiry, and effective scope fields. SDK `AccessToken.token` must contain the incoming bearer string for interface compatibility: **never serialize, log, return, or forward that object or its token**. Derive the application's `Principal` from the validated identity fields. Tokens are never sent to a peer agent, downstream API, or JWKS endpoint.

## Pinned JWKS and outage behavior

The operator-configured issuer, resource, and JWKS are HTTPS DNS URLs without credentials, query strings, or fragments. Numeric IP literals, localhost names, malformed DNS labels, controls, and backslashes are rejected. Configuration is trusted operator input, not request data. The HTTPS client verifies certificates and hostnames, follows no redirects, ignores environment proxies, sends no bearer token or cookies, accepts only JSON/JWK-set JSON, requests identity encoding, and rejects compressed responses. There is a five-second whole-fetch deadline and a 65,536-byte body limit.

This is **URL pinning, not certificate pinning or a general-purpose SSRF proxy**. Use only the approved provider's public hostname. Production network policy should independently restrict outbound HTTPS to approved provider destinations and deny private/link-local/metadata addresses. The adapter does not perform separate DNS-address allowlisting, DNS pinning, certificate pinning, or arbitrary issuer discovery.

JWKS limits:

- At most 16 keys; malformed, duplicate-key-ID, or private-key-containing sets fail closed.
- RSA signing keys: 2,048 through 4,096 bits with exponent 65,537. EC signing keys: P-256 only.
- Signing usage and verify-only operations are enforced when advertised. Unsupported algorithms/encryption keys cannot authorize a token. `x5u` and certificate metadata are never fetched.
- The complete successful key set replaces the prior set; a removed key is not retained indefinitely.
- Default cache TTL is 300 seconds, configurable only from 1 through 300. A monotonic clock controls TTL independently of token wall-clock validation.
- Unknown-key refresh and failed refresh attempts share a 30-second default cooldown. It is configurable from 1 through the TTL. Refresh is serialized so concurrent requests cannot trigger a fetch stampede. No unbounded per-`kid` negative cache is maintained.
- A known, unexpired cached public key remains usable during a provider outage. Unknown keys cannot authorize a request, and **expired cached keys are never used**. Failed refresh never extends the old TTL. New keys may be denied until the cooldown ends. Cache and cooldown are per process; use provider/network limits appropriate to the deployment's worker count.

JWT signature verification is offline between JWKS refreshes. Removing a provider key is observed after successful refresh/TTL, not instantaneously. Provider token revocation/introspection is not implemented. Immediate mailbox revocation relies on active binding/pair checks on every operation; those checks are separate from the OAuth token's validity. Do not promise immediate global OAuth logout or stolen-token detection.

## SDK wiring and discovery

`JWTAccessTokenVerifier` implements the SDK's async `TokenVerifier` protocol. Production construction is explicit:

```python
verifier = JWTAccessTokenVerifier(
    issuer=approved_exact_issuer,
    resource=approved_exact_resource_url,
    jwks_url=approved_exact_public_jwks_url,
    allowed_client_ids=approved_client_ids,
)
```

Pass it to `FastMCP(token_verifier=verifier, auth=AuthSettings(...))`, with `issuer_url`, `resource_server_url`, and `required_scopes=["silk:mailbox"]`. The application owns this wiring. The SDK exposes protected-resource metadata at `/.well-known/oauth-protected-resource/mcp` for the configured `/mcp` resource. Verify its `resource`, `authorization_servers`, and `scopes_supported`, and the `resource_metadata` link in unauthenticated challenges. Clients discover the external authorization server and obtain access tokens there; this service does not proxy token issuance.

MCP 2025-11-25 uses protected-resource metadata and requires clients to include the intended resource in authorization and token requests. Authorization-code clients must verify provider PKCE support before starting. For this service, use pre-registration and the dedicated mailbox scope. See the official [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

## Verification performed and still required

Local command:

```text
python -m unittest tests.test_auth -v
```

Tests generate disposable RSA and P-256 private keys only in memory. There is no fixed admin token, real credential, external network call, or public fallback. Covered cases include signature forgery; cross-issuer/audience/client confusion; `azp` fallback rejection; missing/invalid temporal claims; scope filtering; malicious JWT key-location headers; malformed/oversized tokens and JWKS; key rotation; stale-key rejection and bounded retries; concurrent fetches; cancellation; and HTTPS/no-redirect/no-proxy/no-bearer fetch configuration through mocked transport. These tests do not establish live provider interoperability or prove a live certificate chain.

After all required approvals and deployment, verify real provider discovery, exact token profile/issuer/resource/client mapping, client PKCE, redirect destinations, consent scope, fresh and rotated provider keys, outage behavior, token expiration, insufficient scope, and operator-provisioned identity binding. Test that neither access logs nor application telemetry expose bearer headers/objects. Confirm revoked bindings immediately block mailbox operations. Full deployed end-to-end OAuth and provider key rotation remain **unverified** until actually run.

## Primary references

- [RFC 9068, JWT OAuth access tokens](https://www.rfc-editor.org/rfc/rfc9068.html): signed access-token typing, issuer/audience verification, and `client_id` binding.
- [RFC 8725, JWT best current practices](https://www.rfc-editor.org/rfc/rfc8725.html): fixed algorithm policy, validation boundaries, and cross-JWT confusion defenses.
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/stable/api.html): decoding with a caller-selected allowed algorithm list. Installed 2.13.0 source was also inspected; the online stable documentation may describe a newer version.
- Installed MCP 1.29.0 source: `AccessToken`, `TokenVerifier`, `AuthSettings`, bearer middleware, and protected-resource route construction were inspected directly for this implementation.
