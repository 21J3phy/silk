package client

// Release bundles mirror public, signed evidence, not private keys. They allow
// installation behind a network policy that permits GitHub but not the relay.
import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

const ReleaseBundleFormat = "silk-release-bundle/1"

type ReleaseBundle struct {
	Format     string            `json:"format"`
	Release    relay.ReleaseInfo `json:"release"`
	Checkpoint []byte            `json:"checkpoint"`
	Proof      relay.Proof       `json:"proof"`
}

// VerifyReleaseBundle proves the requested version was signed and publicly
// logged. Trust anchors come from the caller, NEVER from the bundle. A static
// bundle does not establish freshness or consistency with a newer checkpoint.
func VerifyReleaseBundle(b *ReleaseBundle, releaseKeys []ed25519.PublicKey, ledgerKey, version string) (*UpdateCheck, error) {
	if b == nil || b.Format != ReleaseBundleFormat || version == "" || ledgerKey == "" {
		return nil, errors.New("release bundle requires a format, pinned ledger key and exact version")
	}
	r, err := wire.DecodeRelease(b.Release.Frame)
	if err != nil {
		return nil, err
	}
	trusted := false
	for _, key := range releaseKeys {
		if key.Equal(ed25519.PublicKey(r.Signer[:])) {
			trusted = true
		}
	}
	if !trusted || !r.VerifySig() {
		return nil, errors.New("release is not signed by a pinned Silk release key")
	}
	if r.Version != version {
		return nil, errors.New("release bundle version mismatch")
	}
	cp, err := ledger.OpenCheckpoint(b.Checkpoint, ledgerKey)
	if err != nil {
		return nil, err
	}
	p := b.Proof
	if p.Index != b.Release.LedgerIdx || p.Size != cp.Size || p.Index < 0 || p.Index >= cp.Size {
		return nil, errors.New("release bundle proof position mismatch")
	}
	for _, hash := range p.Hashes {
		if len(hash) != sha256.Size {
			return nil, errors.New("release bundle proof contains invalid hash length")
		}
	}
	leaf, err := ledger.ParseLeaf(p.Leaf)
	if err != nil || leaf.Kind != wire.KindRelease || leaf.Commitment != sha256.Sum256(b.Release.Frame) {
		return nil, errors.New("ledger entry does not commit to this release")
	}
	if err := ledger.VerifyInclusion(toRecordProof(p.Hashes), cp.Size, cp.Root, p.Index, p.Leaf); err != nil {
		return nil, fmt.Errorf("release is not provably in the ledger: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(r.Manifest, &m); err != nil {
		return nil, err
	}
	if m.Version != version {
		return nil, errors.New("manifest version does not match the signed release")
	}
	return &UpdateCheck{Current: version, Latest: version, LedgerIdx: p.Index, Manifest: &m}, nil
}

// FetchReleaseBundle obtains and verifies public evidence for mirroring. It
// does not change this client's checkpoint or substitute a new trust anchor.
func (c *Client) FetchReleaseBundle(ctx context.Context, releaseKeys []ed25519.PublicKey, version string) (*ReleaseBundle, error) {
	if version == "" {
		return nil, errors.New("an exact release version is required")
	}
	b := &ReleaseBundle{Format: ReleaseBundleFormat}
	if err := c.getJSON(ctx, "/v2/release?version="+url.QueryEscape(version), nil, &b.Release); err != nil {
		return nil, err
	}
	raw, _, err := c.do(ctx, "GET", "/v2/ledger/checkpoint", nil, nil)
	if err != nil {
		return nil, err
	}
	b.Checkpoint = raw
	cp, err := ledger.OpenCheckpoint(raw, c.Config.LedgerKey)
	if err != nil {
		return nil, err
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/v2/ledger/proof?index=%d&size=%d", b.Release.LedgerIdx, cp.Size), nil, &b.Proof); err != nil {
		return nil, err
	}
	if _, err := VerifyReleaseBundle(b, releaseKeys, c.Config.LedgerKey, version); err != nil {
		return nil, err
	}
	return b, nil
}
