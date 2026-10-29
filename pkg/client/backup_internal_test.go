package client

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealBundle builds a backup around arbitrary contents, as a hostile file could.
func sealBundle(t *testing.T, pass string, files map[string][]byte) []byte {
	t.Helper()
	plain, _ := json.Marshal(backupBundle{Files: files})
	f := backupFile{Format: BackupFormat, KDF: "pbkdf2-sha256", Iter: backupMinIter, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	rand.Read(f.Salt)
	rand.Read(f.Nonce)
	g, err := backupAEAD(pass, &f)
	if err != nil {
		t.Fatal(err)
	}
	f.Data = g.Seal(nil, f.Nonce, plain, f.header())
	b, _ := json.Marshal(f)
	return b
}

func TestBackupImportRejectsUnsafePaths(t *testing.T) {
	const pass = "test-only backup passphrase"
	for _, rel := range []string{"../escape", "/abs/path", "agents/x/../../escape", "agents/x/lock", `agents\x\keys.json`, "agents//x", ""} {
		parent := t.TempDir()
		home := filepath.Join(parent, "home")
		_, err := Import(home, sealBundle(t, pass, map[string][]byte{rel: []byte("x")}), pass, ImportOptions{})
		if err == nil || !strings.Contains(err.Error(), "unsafe path") {
			t.Errorf("%q: %v", rel, err)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("%q: wrote %v before refusing", rel, entries)
		}
	}
}
