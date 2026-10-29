package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelfVerifyRejectsBundleWithoutNetwork(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundle, []byte(`{"format":"not-a-release"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), "self-verify", []string{"--home", home, "--bundle", bundle})
	if err == nil || !strings.Contains(err.Error(), "release bundle requires") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "checkpoint")); !os.IsNotExist(err) {
		t.Fatal("offline verification changed checkpoint")
	}
}
