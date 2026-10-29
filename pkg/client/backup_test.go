package client_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/relay"
)

const testBackupPass = "test-only backup passphrase"

// An agent whose disk is wiped comes back from an encrypted backup with the
// same identity, but can talk only after a fresh owner-approved handshake.
func TestBackupRestoresIdentityAndRequiresFreshConversation(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-backup")
	bob := e.agent("codex", "bob-backup")
	grant := e.connect(alice, bob, "Backups")
	if _, err := alice.Send(e.ctx, grant, "before the wipe", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if res, err := bob.Sync(e.ctx, 2*time.Second); err != nil || len(res.Messages) != 1 {
		t.Fatalf("first message: %+v %v", res, err)
	}

	home := alice.Client().Home
	data, err := alice.Client().Export(testBackupPass)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile(filepath.Join(home, "agents", "claude", "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kf struct {
		SignSeed []byte `json:"sign_seed"`
	}
	if err := json.Unmarshal(keys, &kf); err != nil || len(kf.SignSeed) == 0 {
		t.Fatalf("keys.json: %v", err)
	}
	seedB64, _ := json.Marshal(kf.SignSeed)
	if bytes.Contains(data, bytes.Trim(seedB64, `"`)) || bytes.Contains(data, []byte("sign_seed")) {
		t.Fatal("backup exposes agent keys")
	}
	if err := os.RemoveAll(home); err != nil {
		t.Fatal(err)
	}

	res, err := client.Import(home, data, testBackupPass, client.ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 1 || res.Agents[0] != "claude" {
		t.Fatalf("restored agents %v", res.Agents)
	}
	for _, f := range res.Files {
		if strings.HasSuffix(f, "/lock") {
			t.Fatalf("lock file %s was backed up", f)
		}
	}
	c, err := client.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := c.Agent("")
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != alice.ID {
		t.Fatalf("restored ID %s, want %s", restored.ID, alice.ID)
	}
	if _, err := restored.Send(e.ctx, grant, "unsafe old session", client.SendOptions{}); err == nil {
		t.Fatal("restored old ratchet allowed sending")
	}
	grant = e.connect(restored, bob, "Fresh handshake after restore")
	if _, err := restored.Send(e.ctx, grant, "after the wipe", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := bob.Sync(e.ctx, 2*time.Second)
	if err != nil || len(got.Messages) != 1 || got.Messages[0].Body != "after the wipe" || got.Messages[0].Error != "" {
		t.Fatalf("message from restored agent: %+v %v", got, err)
	}
	if _, err := bob.Send(e.ctx, grant, "welcome back", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err = restored.Sync(e.ctx, 2*time.Second)
	if err != nil || len(got.Messages) != 1 || got.Messages[0].Body != "welcome back" || got.Messages[0].Error != "" {
		t.Fatalf("reply to restored agent: %+v %v", got, err)
	}
}

func TestBackupRejectsWrongPassphraseAndTampering(t *testing.T) {
	e := newEnv(t, relay.Config{})
	a := e.agent("claude", "")
	data, err := a.Client().Export(testBackupPass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Import(t.TempDir(), data, "a different passphrase", client.ImportOptions{}); !errors.Is(err, client.ErrBackupPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	var f map[string]any
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	f["created_ms"] = f["created_ms"].(float64) + 1 // header is authenticated
	altered, _ := json.Marshal(f)
	if _, err := client.Import(t.TempDir(), altered, testBackupPass, client.ImportOptions{}); !errors.Is(err, client.ErrBackupPassphrase) {
		t.Fatalf("altered header: %v", err)
	}
	f["created_ms"] = f["created_ms"].(float64) - 1
	f["iter"] = 1 // too cheap to guess against: refused before any decryption
	weak, _ := json.Marshal(f)
	if _, err := client.Import(t.TempDir(), weak, testBackupPass, client.ImportOptions{}); err == nil || errors.Is(err, client.ErrBackupPassphrase) {
		t.Fatalf("weak KDF: %v", err)
	}
	if _, err := a.Client().Export("short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestBackupImportDoesNotClobber(t *testing.T) {
	e := newEnv(t, relay.Config{})
	a := e.agent("claude", "")
	data, err := a.Client().Export(testBackupPass)
	if err != nil {
		t.Fatal(err)
	}
	home := a.Client().Home
	if _, err := client.Import(home, data, testBackupPass, client.ImportOptions{}); err == nil {
		t.Fatal("import over an existing home without overwrite")
	}
	if _, err := client.Import(home, data, testBackupPass, client.ImportOptions{Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Client().Agent(""); err != nil {
		t.Fatal(err)
	}
}
