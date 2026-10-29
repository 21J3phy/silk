package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

func TestReleaseBundleOfflineVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, relay.Config{ReleaseKeys: []ed25519.PublicKey{pub}})
	c := e.agent("bundle-test", "").Client()
	manifest, _ := json.Marshal(client.Manifest{Version: "9.1.0", Protocol: relay.Protocol})
	r := &wire.Release{Version: "9.1.0", Created: time.Now().UnixMilli(), Manifest: manifest}
	r.Sign(priv)
	if _, err := c.Submit(e.ctx, r.Raw); err != nil {
		t.Fatal(err)
	}
	bundle, err := c.FetchReleaseBundle(e.ctx, []ed25519.PublicKey{pub}, "9.1.0")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Close() // verify must work without any network access
	if _, err := client.VerifyReleaseBundle(bundle, []ed25519.PublicKey{pub}, c.Config.LedgerKey, "9.1.0"); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(bundle)
	tests := map[string]func(*client.ReleaseBundle){
		"format":               func(b *client.ReleaseBundle) { b.Format = "unknown" },
		"release signature":    func(b *client.ReleaseBundle) { b.Release.Frame[len(b.Release.Frame)-1] ^= 1 },
		"checkpoint signature": func(b *client.ReleaseBundle) { b.Checkpoint[len(b.Checkpoint)-5] ^= 1 },
		"proof leaf":           func(b *client.ReleaseBundle) { b.Proof.Leaf[0] ^= 1 },
		"proof index":          func(b *client.ReleaseBundle) { b.Proof.Index++ },
		"proof hash length":    func(b *client.ReleaseBundle) { b.Proof.Hashes = append(b.Proof.Hashes, []byte{1}) },
		"proof size":           func(b *client.ReleaseBundle) { b.Proof.Size++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var b client.ReleaseBundle
			json.Unmarshal(encoded, &b)
			mutate(&b)
			if _, err := client.VerifyReleaseBundle(&b, []ed25519.PublicKey{pub}, c.Config.LedgerKey, "9.1.0"); err == nil {
				t.Fatal("accepted tampered bundle")
			}
		})
	}
	for _, version := range []string{"", "9.0.0", "9.2.0"} {
		if _, err := client.VerifyReleaseBundle(bundle, []ed25519.PublicKey{pub}, c.Config.LedgerKey, version); err == nil {
			t.Fatal("accepted wrong version")
		}
	}
	if _, err := client.VerifyReleaseBundle(bundle, nil, c.Config.LedgerKey, "9.1.0"); err == nil {
		t.Fatal("accepted untrusted release signer")
	}
	if _, err := client.VerifyReleaseBundle(bundle, []ed25519.PublicKey{pub}, "", "9.1.0"); err == nil {
		t.Fatal("accepted missing ledger trust anchor")
	}
}
