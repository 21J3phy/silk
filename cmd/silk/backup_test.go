package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/21J3phy/silk/pkg/client"
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

func TestImportResultExplainsRecovery(t *testing.T) {
	var b bytes.Buffer
	printImportResult(&b, "/example/home", &client.ImportResult{
		Files: []string{"config.json"}, Agents: []string{"helper"}, CreatedMs: 1,
		Recovery: client.RestoreImpact{ConversationsRequiringApproval: 2, CanceledQueuedMessages: 3},
	})
	text := b.String()
	for _, want := range []string{"2 conversations", "3 queued messages canceled", "fresh contact requests and owner approval", "were not resent", "does not revoke", "never run restored copies simultaneously", "silk doctor"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
}

func TestImportJSONIncludesRecoveryGuidance(t *testing.T) {
	const pass = "test-only backup passphrase"
	t.Setenv(backupPassEnv, pass)
	home := t.TempDir()
	dir := filepath.Join(home, "agents", "helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"grants":{"old":{"status":"active"}},"sent":[{"status":"queued","frame":"dGVzdA=="}]}`)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := client.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.Export(pass)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "backup.silk")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	capture := func(args []string) ([]byte, error) {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "output")
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = f
		defer func() { os.Stdout = old; f.Close() }()
		runErr := run(t.Context(), "import", args)
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		output, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return output, runErr
	}
	restored := filepath.Join(t.TempDir(), "restored")
	output, err := capture([]string{"--home", restored, "--json", file})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		client.ImportResult
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("invalid JSON %q: %v", output, err)
	}
	if result.Recovery.ConversationsRequiringApproval != 1 || result.Recovery.CanceledQueuedMessages != 1 || len(result.NextSteps) != len(restoreNextSteps) {
		t.Fatalf("result: %+v", result)
	}
	if len(result.Agents) != 1 || len(result.Files) != 2 || result.CreatedMs == 0 {
		t.Fatalf("legacy fields lost: %+v", result)
	}
	// Failure must not emit a success/recovery report.
	t.Setenv(backupPassEnv, "wrong passphrase")
	output, err = capture([]string{"--home", filepath.Join(t.TempDir(), "failed"), "--json", file})
	if err == nil || len(output) != 0 {
		t.Fatalf("failed import output=%q error=%v", output, err)
	}
}
