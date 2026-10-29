//go:build !client

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/21J3phy/silk/pkg/ledger"
)

func TestRelayExistingKeyBootstrap(t *testing.T) {
	private, public, err := ledger.GenerateKey("migration-test.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_LEDGER_KEY", private)
	signer, err := loadRelaySigner("", "TEST_LEDGER_KEY", "", public, false)
	if err != nil || signer.VKey != public {
		t.Fatalf("existing key rejected: %v", err)
	}
	_, other, _ := ledger.GenerateKey("other.example")
	if _, err := loadRelaySigner("", "TEST_LEDGER_KEY", "", other, false); err == nil {
		t.Fatal("different ledger identity accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing-key")
	if _, err := loadRelaySigner(missing, "", "", public, false); err == nil {
		t.Fatal("missing existing key accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("created missing migration key")
	}
	t.Setenv("TEST_LEDGER_KEY", "")
	if _, err := loadRelaySigner("", "TEST_LEDGER_KEY", "", public, false); err == nil {
		t.Fatal("empty secret accepted")
	}
	t.Setenv("TEST_LEDGER_KEY", "SECRET-DO-NOT-LOG")
	if _, err := loadRelaySigner("", "TEST_LEDGER_KEY", "", public, false); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("invalid secret accepted or disclosed")
	}
}

func TestPostgresRelayRequiresExplicitExistingIdentity(t *testing.T) {
	for _, args := range [][]string{
		{"--store", "postgres"},
		{"--store", "postgres", "--key-env", "NO_SUCH_KEY"},
		{"--store", "postgres", "--expected-ledger-key", "public"},
	} {
		if err := runRelay(t.Context(), args); err == nil {
			t.Fatal("incomplete migration config accepted")
		}
	}
}

func TestPostgresRelayConnectionErrorRedacted(t *testing.T) {
	private, public, _ := ledger.GenerateKey("migration-test.example")
	t.Setenv("TEST_LEDGER_KEY", private)
	t.Setenv("TEST_POSTGRES_DSN", "postgres://user:DO-NOT-LOG@%invalid/database")
	err := runRelay(t.Context(), []string{"--store", "postgres", "--key-env", "TEST_LEDGER_KEY", "--expected-ledger-key", public, "--dsn-env", "TEST_POSTGRES_DSN"})
	if err == nil || strings.Contains(err.Error(), "DO-NOT-LOG") || strings.Contains(err.Error(), private) {
		t.Fatalf("error not redacted: %v", err)
	}
}
