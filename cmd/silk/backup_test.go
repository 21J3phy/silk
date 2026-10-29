package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExportImportCommands(t *testing.T) {
	t.Setenv(backupPassEnv, "test-only backup passphrase")
	home := filepath.Join(t.TempDir(), "home")
	config := []byte(`{"relay":"https://relay.example"}`)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), "export", []string{"--home", home, filepath.Join(home, "backup.silk")}); err == nil {
		t.Fatal("export into the home it backs up")
	}
	file := filepath.Join(t.TempDir(), "backup.silk")
	if err := run(t.Context(), "export", []string{"--home", home, "--json", file}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file %v %v", fi, err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := run(t.Context(), "import", []string{"--home", restored, "--json", file}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(restored, "config.json")); err != nil || !bytes.Equal(got, config) {
		t.Fatalf("restored config %q %v", got, err)
	}
	if err := run(t.Context(), "import", []string{"--home", restored, "--json", file}); err == nil {
		t.Fatal("import over existing files without --overwrite")
	}
	if err := run(t.Context(), "import", []string{"--home", restored, "--overwrite", "--json", file}); err != nil {
		t.Fatal(err)
	}
}
