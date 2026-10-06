# Activation checklist

No item below has been provisioned or approved by this code. Costs remain unknown until the actual existing accounts, providers, and plans are selected. Do not create or upgrade paid services automatically.

## 1. Verify the actual clients

- Identify the specific source and destination applications/accounts. A claim about Cursor is not evidence about Grok.
- Confirm each supports remote MCP with the tested 2025-11-25 profile and the selected OAuth client-registration method.
- Confirm what runs while the user is absent. A polling mailbox does not independently wake a dormant consumer assistant.
- Agree on the specific owners, two agents, message category, and bounded consent scope before linking them.

## 2. Authorization server

Prefer an already-approved authorization server if it supports the required profile. No provider has been chosen.

Minimum setup:
- One resource audience equal to the canonical HTTPS `/mcp` URL
- One narrow scope: `silk:mailbox`; no email, calendar, files, financial, admin, or unrelated account scopes
- Only the specific reviewed client IDs; user-facing clients use authorization code + PKCE and real owner consent
- Access tokens matching the documented RS256/ES256 RFC 9068 profile, including exact issuer/audience, signed `client_id`, subject, expiry, and `at+jwt` type
- Public authorization-server metadata and a pinned HTTPS JWKS URL

The resource server only needs public issuer/JWKS/client metadata, not an OAuth client secret or signing key. Client registration, new persistent grants, or credentials require explicit approval through the appropriate secure flow. Provider interoperability, free-tier eligibility, user/client counts, and monthly costs are unverified.

## 3. PostgreSQL

Prefer an already-approved compatible database only after confirming ownership, permitted use, isolation, and cost. No database/provider has been selected.

Separate privileges:
- Migration authority applies the reviewed schema and permission template once; it is not the runtime credential.
- Runtime role gets schema usage, selected reads, message/receipt inserts, bounded message-content updates, grant revocation/budget updates, and sentinel-column privileges required for row locks.
- Runtime gets no role/account creation, DDL, schema ownership, identity/binding/grant creation, receipt modification, DELETE/TRUNCATE, superuser, or unrelated database access.
- Administrative owner provisioning records verified agent bindings and both owners' consent references separately.

TLS must verify certificate and hostname. Store the connection secret only in approved hosting settings; never paste it into chat, source, URLs, or client-visible configuration. Connection limits/pooling, backup retention, restore, expiry cleanup, data deletion, and storage ceilings require an operator plan. Costs and provider quotas are unknown.

## 4. Host and preflight

- Approved HTTPS hosting account/plan and exact domain/resource URL
- ASGI lifespan startup supported; no ephemeral SQLite fallback
- Narrow deployment secret access; only approved people/service identities may read the DB credential
- Exact Host/Origin rules, request time/concurrency/size limits, public-JWKS outbound policy, and content-safe logging
- Run configuration preflight. After explicit setup approval, use the optional read-only database preflight.
- Verify actual PostgreSQL migration syntax, role privileges, MVCC/concurrent races, TLS, and failure/restore behavior. These did not run against a real PostgreSQL server in the build environment.

## 5. Prove the real connection

Using an approved disposable pair and harmless message:
1. Authenticate each real client; confirm `silk_identity` maps to the intended agent.
2. Send one scoped request, poll the intended recipient, and record acknowledgment.
3. Send a correlated reply and confirm the original sender receives it.
4. Check receipts, duplicate retry, wrong-recipient rejection, expiry, and revocation.
5. Confirm whether the actual clients support unattended polling/wake. If not, describe the connection as interactive only.

Only after this succeeds may the specific tested client pair be called connected. A source repository, successful deploy, token validation, or local fixture round trip alone is insufficient.
