package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

// Manifest describes the files of one release.
type Manifest struct {
	Version  string                  `json:"version"`
	Protocol string                  `json:"protocol"`
	Created  string                  `json:"created"`
	Notes    string                  `json:"notes,omitempty"`
	Files    map[string]ManifestFile `json:"files"` // "darwin-arm64" -> file
}

// ManifestFile is one downloadable binary.
type ManifestFile struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// UpdateCheck is a verified view of the latest published release.
type UpdateCheck struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`
	Newer     bool      `json:"newer"`
	LedgerIdx int64     `json:"ledger_index"`
	Manifest  *Manifest `json:"manifest"`
}

// CompareVersions compares dotted numeric versions ("2.0.10" > "2.0.9").
// Anything after a '-' is ignored.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(strings.SplitN(strings.TrimPrefix(a, "v"), "-", 2)[0], "."), strings.Split(strings.SplitN(strings.TrimPrefix(b, "v"), "-", 2)[0], ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// CheckRelease fetches the latest release and verifies that it is signed by a
// pinned release key AND recorded in the relay's ledger under a checkpoint
// signed by the pinned ledger key. An update that is not publicly logged is
// never offered.
func (c *Client) CheckRelease(ctx context.Context, releaseKeys []ed25519.PublicKey, current string) (*UpdateCheck, error) {
	return c.CheckReleaseVersion(ctx, releaseKeys, current, "")
}

// CheckReleaseVersion is CheckRelease for a specific version ("" = latest).
func (c *Client) CheckReleaseVersion(ctx context.Context, releaseKeys []ed25519.PublicKey, current, version string) (*UpdateCheck, error) {
	if c.Config.LedgerKey == "" {
		return nil, errors.New("no pinned ledger key")
	}
	path := "/v2/release"
	if version != "" {
		path += "?version=" + version
	}
	var info relay.ReleaseInfo
	if err := c.getJSON(ctx, path, nil, &info); err != nil {
		return nil, err
	}
	rel, err := wire.DecodeRelease(info.Frame)
	if err != nil {
		return nil, err
	}
	trusted := false
	for _, k := range releaseKeys {
		if k.Equal(ed25519.PublicKey(rel.Signer[:])) {
			trusted = true
		}
	}
	if !trusted || !rel.VerifySig() {
		return nil, errors.New("release is not signed by a pinned Silk release key")
	}
	raw, _, err := c.do(ctx, "GET", "/v2/ledger/checkpoint", nil, nil)
	if err != nil {
		return nil, err
	}
	cp, err := ledger.OpenCheckpoint(raw, c.Config.LedgerKey)
	if err != nil {
		return nil, err
	}
	var p relay.Proof
	if err := c.getJSON(ctx, fmt.Sprintf("/v2/ledger/proof?index=%d&size=%d", info.LedgerIdx, cp.Size), nil, &p); err != nil {
		return nil, err
	}
	leaf, err := ledger.ParseLeaf(p.Leaf)
	if err != nil || leaf.Kind != wire.KindRelease || leaf.Commitment != sha256.Sum256(info.Frame) {
		return nil, errors.New("ledger entry does not commit to this release")
	}
	if err := ledger.VerifyInclusion(toRecordProof(p.Hashes), cp.Size, cp.Root, info.LedgerIdx, p.Leaf); err != nil {
		return nil, fmt.Errorf("release is not provably in the ledger: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(rel.Manifest, &m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if m.Version != rel.Version {
		return nil, errors.New("manifest version does not match the signed release")
	}
	return &UpdateCheck{Current: current, Latest: rel.Version, Newer: CompareVersions(rel.Version, current) > 0, LedgerIdx: info.LedgerIdx, Manifest: &m}, nil
}

// Platform is this binary's manifest key.
func Platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// ApplyUpdate downloads this platform's binary, checks size and SHA-256 against
// the verified manifest, and atomically replaces exe.
func (c *Client) ApplyUpdate(ctx context.Context, chk *UpdateCheck, exe string) error {
	f, ok := chk.Manifest.Files[Platform()]
	if !ok {
		return fmt.Errorf("release %s has no build for %s", chk.Latest, Platform())
	}
	if !strings.HasPrefix(f.URL, "https://") || f.Size <= 0 || f.Size > 128<<20 {
		return errors.New("manifest entry is invalid")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".silk-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(f.SHA256) {
		tmp.Close()
		return errors.New("downloaded binary does not match the signed manifest; not installed")
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), exe)
}

// VerifyBinary checks that the file at exe is exactly this platform's build in
// a verified release manifest.
func VerifyBinary(chk *UpdateCheck, exe string) error {
	f, ok := chk.Manifest.Files[Platform()]
	if !ok {
		return fmt.Errorf("release %s has no build for %s", chk.Latest, Platform())
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != f.Size || hex.EncodeToString(sum[:]) != strings.ToLower(f.SHA256) {
		return fmt.Errorf("this binary is NOT the published silk %s build for %s", chk.Latest, Platform())
	}
	return nil
}
