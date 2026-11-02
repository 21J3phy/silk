# Silk consumer readiness review

Reviewed November 2, 2026 against upstream ff232faf94483b0a04b3619e96ca94c29d6b4118. This is a proposal and acceptance plan, not a deployed service or release claim.

## Implemented slice in this candidate

Receive-only SDK and CLI mode eliminates an incidental-send hazard during notification monitoring. It does not provide durable hosting, a restricted MCP permission, or automatic user notifications. Existing MCP inbox behavior is unchanged. A published signed release is required before this can be advertised as available to every user.

## Reuse existing product primitives

- Local setup preserves unrelated assistant configurations (cmd/silk/setup.go).
- Owner-separated signing keeps owner private keys out of agent runtimes (cmd/silk/owner.go).
- HTTP MCP supports OAuth/PKCE and persistent connector state (cmd/silk/remote.go, pkg/mcp/http.go).
- Supported encrypted export/import invalidates restored conversation ratchets, pending approvals and queued sends (pkg/client/backup_restore.go). Never restore raw state snapshots to resume ratchets; rollback risks nonce/key reuse.

## Recommended supported product path

1. A stable supported runtime per assistant identity, with durable private storage, singleton ownership, supervised restart, fixed HTTPS endpoint and clear operator-custody disclosure. Do not turn private chat attachments or ephemeral assistant scratch storage into an ad hoc secrets service.
2. A resumable pairing workflow with understandable owner approval, exact assistant/identity display and secure one-time pairing. Interrupted setup must resume the same identity rather than silently create a duplicate. No private keys or passphrases in chat.
3. A durable notification delivery queue with explicit consumer acknowledgement, deduplication, retry/backoff and visible degraded state. Receiving encrypted events and advancing the protocol cursor is not proof a human or assistant was notified.
4. Recovery via supported export/import with a prominent impact summary: retained identity/history, invalidated conversations, canceled queued sends, required new owner approvals and possible old-relay revocation. An old backup cannot be advertised as seamless conversation continuation.
5. A signed release and provider-support matrix verified using the actual consumer flow. Main-branch fixes are not a released product. Current v2.3.0 predates the backup/hosted/distribution changes reviewed here.

These require an explicit hosting/cost/custody product choice before provisioning. No provider or paid resource has been chosen or created.

## Release gates

- A novice user installs a signed published artifact and completes owner pairing and a real approved exchange without developer intervention or undocumented terminal/file-transfer work.
- Interrupted pairing, repeated clicks and retry after uncertain outcome do not create duplicate identities or widen grants.
- Restart retains the identity, endpoint, OAuth session and inbox; two simultaneous instances cannot use the same ratchet state.
- A crash before/after notification delivery does not lose notifications; duplicate delivery is detected by event ID.
- Pending outgoing messages and contact requests remain queued during receive-only monitoring; no automatic replies or acknowledgements.
- Wrong passphrase, corrupt/stale backup, disk loss, overwrite and interrupted import fail safely with explicit recovery consequences.
- Revoking a connector/contact is effective and visible. Metadata HTTP200 is not a messaging-health check.
- Upgrade from the current published version and rollback policy are tested without restoring old live ratchets.

## Source evidence

- docs/v2/CONNECT.md:43–71: tunnel dependency, changing quick-tunnel URL, process lifetime and local OAuth persistence.
- docs/v2/CONNECT.md:83–100: manual owner signing and backup/recovery workflow.
- docs/v2/HOSTED_MCP.md:8–18,24–52: operator custody, provider approval, persistent directories and singleton hosting requirements.
- docs/v2/GITHUB_DISTRIBUTION.md:3–5: new distribution path is not supported by existing 2.3.0 binaries.
- pkg/client/backup_restore.go:11–38: restored sessions and queued sends invalidated.
- cmd/silk/backup.go:147–153: current import summary is not a complete consumer recovery-impact summary.

No deployment, real-provider connection, real credential migration, managed backup service, or user notification end-to-end test was performed.
