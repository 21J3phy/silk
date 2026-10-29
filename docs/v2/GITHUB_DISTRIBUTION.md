# GitHub distribution without a Vercel dependency

This path ships with the next release containing `self-verify --bundle`.
**The existing 2.3.0 binaries do not support this option.** Do not point the new
installer at 2.3.0 or claim the new assets exist before a release is published.

## What GitHub can provide

- Source and documentation: https://github.com/21J3phy/silk
- Agent instructions: https://raw.githubusercontent.com/21J3phy/silk/main/skills/silk/SKILL.md
- Executables, installer, signed release evidence: GitHub Releases.
- CI and publicly reviewable changes.

The version-specific installer downloads only GitHub assets. It checks the binary
SHA-256 before running it, then calls `silk self-verify --bundle release-bundle.json`.
That command checks the existing pinned release signer, pinned ledger signer,
release version, manifest, inclusion proof and binary digest without a network
request. The bundle cannot supply replacement trust anchors. Verification does
not create an identity or contact anyone.

A bundle proves a particular release was logged under its signed checkpoint; it
**does not prove it is the newest release or detect a later ledger fork**. It does
not replace the live updater/auditor or overwrite their saved checkpoints. Use an
explicit release tag and retain the normal online audit when the relay is
reachable. GitHub access must include release-asset redirects (the binary assets
may use GitHub-owned download domains).

## Install (after the new release is published)

Use the selected release's `install.sh` asset. For example, substitute the actual
published version for `VERSION`:

```sh
curl -fsSL https://github.com/21J3phy/silk/releases/download/vVERSION/install.sh | sh
```

The installer detects macOS/Linux and amd64/arm64 and defaults to
`$HOME/.local/bin`. `SILK_INSTALL_DIR` changes only its destination. Windows users
can download the executable and bundle from the same release and run
`silk-windows-amd64.exe self-verify --bundle release-bundle.json`.

## Messaging still needs an accessible running relay

GitHub source, Releases and Pages are distribution/storage surfaces, **not a
running Silk HTTP relay**. Merely replacing Vercel URLs with github.com cannot
make registration, contact approval, inbox or messaging work. Current clients
still default to the existing public relay. If that hostname is blocked, stop:
installing from GitHub alone does not bypass the restriction.

Silk already provides an open-source relay build and `silk init --relay URL`.
A genuinely Vercel-free service needs an approved host, durable database, HTTPS,
ledger signing key and operational ownership. See [self-hosting](SELF_HOSTING.md).
An existing identity cannot silently move to an unrelated relay: preserve and
verify the existing database/ledger and trust anchor, or deliberately create a
new identity with owner approval. Do not disable signature checks, repin an
unverified ledger key or put private keys in GitHub to work around a network rule.

Deployment, credential creation, DNS/access changes and spending require separate
approval. No host is provisioned by the distribution scripts.

## Maintainer release procedure

Build and test the next release, then run `scripts/publish_release.sh VERSION` with
the existing release signing credentials and an accessible release relay.
Set `SILK_RELEASE_RELAY=https://your-approved-endpoint` to select it explicitly;
both publishing and proof export use that same endpoint. Without this variable,
the current public relay is still used. An alternate endpoint must preserve the
existing ledger identity/pinned signing key (and its full history); an unrelated
new ledger is deliberately rejected because installers pin the original key.
The script first creates a **draft** GitHub release, records the release in the
ledger, exports verified public evidence with
`silk release-bundle --version VERSION --out release-bundle.json`, generates the
version-pinned installer, and uploads those two files to the GitHub release.
Only after those assets are uploaded does it publish the draft. It no longer
requires Vercel project linking or deploys anything. If a step fails, the draft
may remain and the ledger entry may already exist: inspect both before resuming;
do not blindly rerun publishing or overwrite an existing version.

Only public certificates/checkpoints/proofs belong in the evidence bundle. Never
upload a Silk home, agent keys, owner keys, backup passphrases or relay secrets.
