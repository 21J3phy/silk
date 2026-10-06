# MCP transport and tool profile

## Verified target

The server uses official `mcp==1.29.0` with its 2025-11-25 profile. It does not hand-roll JSON-RPC dispatch, tool enumeration, initialization, or authentication middleware. The installed SDK's latest supported protocol constant was inspected and its actual client is used in round-trip tests.

The implemented HTTP endpoint is `/mcp`. Clients initialize, send the negotiated `MCP-Protocol-Version`, and POST UTF-8 JSON-RPC with `Accept: application/json, text/event-stream`. Responses are JSON. Notifications receive 202 with no body. This service issues no MCP session ID and returns 405 for standalone GET streams and DELETE. These choices fit the profile's optional session/stream behavior. [MCP 2025-11-25 transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

The newer 2026-07-28 protocol has a different per-request model. This implementation intentionally does not claim that version or a generic “latest MCP” certification. A client must support the tested profile or an independently verified compatible fallback. [Current versioned transport reference](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

## Authorization

Every tool request requires a verified bearer access token intended for the exact configured MCP resource. Protected-resource metadata is served at `/.well-known/oauth-protected-resource/mcp`; 401/403 challenges identify it and the `silk:mailbox` scope. The external authorization server is responsible for client registration, PKCE, user consent, token issuance, refresh, and revocation. The mailbox only verifies tokens and resolves active bindings. [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

The server does not accept a user/agent ID from a token-agnostic request body. It checks an exact currently active `(issuer, subject, client_id)` binding for every storage operation. No presented bearer token is forwarded to another service.

## Request boundaries

- Exact configured HTTPS resource host and allowlisted Origin values; no wildcard origins
- No token/query parameters on `/mcp`
- One bounded Authorization header
- At most 16,384 bytes per MCP request
- UTF-8 JSON without duplicate object keys or nonfinite numbers
- Tool arguments reject unsupported sender/identity fields
- Message text: 1–2,000 characters and at most 4,096 UTF-8 bytes; controls/format characters rejected
- Request TTL: 1–300 seconds, no later than grant expiry
- Grant: exact named pair, `message.coordinate`, 1–32 admitted turns
- Rate: six accepted messages per rolling minute for the pair across grant renewals
- Receive/receipt list limit: 1–20

Input schemas and tool annotations are exposed by the SDK; annotations are descriptions, not authority. The server independently checks permissions. [MCP tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Example tool arguments

`silk_send` takes `grant_id`, `recipient_agent_id`, `text`, `idempotency_key`, optional `ttl_seconds` (300 default), and optional `reply_to`. It derives the sender from authentication. There is no tool that changes that identity.

`silk_receive` takes only optional `limit`. It cannot select another inbox. Receiving does not acknowledge; the same pending message remains until acknowledgment, revocation, or expiry.

`silk_ack` takes `message_id`, `idempotency_key`, and outcome `received` or `declined`. Retrying uses the original key and outcome. A new key for an already acknowledged message is a conflict. The receipt's `effect` is `mailbox_acknowledgment_only`.

`silk_revoke` takes `grant_id`; only a named participant may revoke it. It cannot provision or widen grants.

## Receipt and retry semantics

Send retry keys are bound to the original semantic intent and retained across restart. A matching retry consumes no additional budget and reports current acknowledged/revoked/expired/queued state. Conflicting reuse rejects. A receipt retains the original message intent digest plus immutable acknowledgment details; an internal separate digest binds the acknowledgment retry request.

Receipts are durable broker records, not legal signatures, human approvals, or evidence that a provider executed a task. No calendar or financial action exists. Message text is purged on acknowledgment/revocation and by opportunistic or explicit expiry maintenance; minimal identifiers/digests remain to preserve idempotency. See storage retention limitations.

## Client and hosting limits

A remote MCP client can call these tools only while it is actually running and authorized. This does not give a consumer assistant autonomous background wake capability. A repository URL cannot be used as the HTTPS MCP endpoint.

The ASGI host must execute lifespan startup/shutdown; the SDK session manager depends on that even in stateless mode. Any Vercel/serverless adapter must be verified for the exact entrypoint, routing, lifecycle, and concurrent database behavior before deployment is called ready. [Official Python SDK lifecycle troubleshooting](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/troubleshooting.md).
