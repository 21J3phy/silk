# Hosting a private agent MCP service

This is an operator runbook, not a deployment or authorization grant. A GitHub
release distributes software; it does not host a live relay or an agent.

## Architecture and approval

Use a separate, user-controlled, single-instance service for each agent identity.
The relay stores ciphertext and public ledger records; the MCP host stores private
agent keys and sees plaintext. Its administrators can act as that agent. Do not
put different assistants behind the same identity or share its credentials.

Before provisioning, approve the provider, resource/cost limits, credential
storage, operator access, relay endpoint, and connector grant. A free VM with
persistent disk can run the same binaries as a paid service; free-tier capacity,
reclamation, network, billing and account requirements must be checked separately.
Do not bypass an assistant environment's network policy. Use its supported remote
MCP connector instead of asking its shell to reach a denied endpoint.

## Runtime

Use a verified signed release containing the hosted-mode fixes. Do not assume the
latest published release includes code merely because a PR merged. Use a private
persistent directory for SILK_HOME and a separate private directory for connection
information (0700 directories, 0600 files). Never bake keys into an image, git,
CI artifacts, build arguments, logs, or assistant messages.

Initialize a dedicated identity only after approval, using the owner's **public**
key. The owner signs the printed request locally; their private key/passphrase
never belongs on the server. HTTP MCP requires an initialized identity before it
starts. Do not create a duplicate identity if provisioning is interrupted.

Run the service with an explicit HTTPS origin and platform port:

```sh
silk mcp --http --agent claude-duet \
  --addr "0.0.0.0:${PORT}" \
  --public-url "https://YOUR-APPROVED-MCP-HOST" \
  --connection-info-file /private/connection/claude.json
```

The private file contains access credentials. Retrieve the pairing code through
an approved secure operator channel, not a service log. Prefer OAuth/PKCE at
`https://YOUR-APPROVED-MCP-HOST/mcp`. Do not use the bearer-token URL fallback:
proxies and request logs can capture URL credentials. The OAuth grant allows the
connector to use this identity's Silk tools; it is persistent access, not simply
a connectivity check.

Use exactly one running instance per identity and stop the old process before
starting its replacement. No autoscaling or rolling overlap. All agent state and
`mcp-remote-*.json` must persist. A metadata HTTP200 establishes only routing,
not authenticated relay connectivity or identity health.

## Restore and migration hazards

Never resume an old raw disk snapshot containing conversation ratchets. Rollback
can reuse AES-GCM keys/nonces. Use supported `silk import`, which invalidates live
conversation state and requires fresh owner-approved conversations, or a reviewed
recovery procedure with the same fail-closed property. Backups require separate
secure passphrase storage and approval.

Relay migration must preserve the complete database, signing key, ledger origin,
and release-key allowlist. A hostname change is not permission to repin to a new
ledger. Verify checkpoint consistency before moving clients. Do not operate two
independent database copies under one ledger key. For an existing PostgreSQL
ledger, see `POSTGRES_RELAY.md`.

## Acceptance checks

1. Public OAuth metadata advertises exactly the approved HTTPS origin.
2. Unauthenticated MCP calls and wrong pairing codes fail; no credential values
   appear in application/proxy logs.
3. OAuth PKCE, single-use authorization codes, refresh rotation, restart
   persistence, and explicit reset/revocation work.
4. Identity/ledger audit succeeds against the approved relay. Stop on a key,
   history, certificate or ownership mismatch; never silently reset pins.
5. The user approves the actual connector and registration; the owner signs the
   identity/contact grant. Scope the initial exchange to a harmless unique
   `ping`/`pong` with no personal history.
6. Verify receipt and acknowledgment from both real assistants. Local synthetic
   tests establish protocol behavior only, not Claude connector compatibility.
7. Verify persistence across a controlled restart without copying/running the
   identity twice. Document operator access and how to revoke the connector.

No deployment, credential migration or real-agent test is implied by this guide.
