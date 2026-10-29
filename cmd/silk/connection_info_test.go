package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateConnectionInfo(t *testing.T) {
	dir := privateTestDir(t)
	p := filepath.Join(dir, "connection.json")
	f, err := openConnectionInfoFile(p, "https://silk.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.publish("synthetic-token", "FIRST-CODE"); err != nil {
		t.Fatal(err)
	}
	if err := f.publish("", "NEXT-CODE"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got connectionInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.PairingCode != "NEXT-CODE" || got.BearerToken != "synthetic-token" || got.SecretURL != "https://silk.example/mcp/synthetic-token" {
		t.Fatalf("bad synthetic info: %+v", got)
	}
	if strings.Contains(string(b), "FIRST-CODE") {
		t.Fatal("old code retained")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file left")
	}
}

func TestPrivateConnectionInfoRejectsUnsafeDestinations(t *testing.T) {
	for _, kind := range []string{"relative", "missing-parent", "public-parent", "symlink-file", "directory-file", "public-file", "symlink-parent"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDir(t)
			p := filepath.Join(dir, "info")
			switch kind {
			case "relative":
				p = "relative.json"
			case "missing-parent":
				p = filepath.Join(dir, "missing", "info")
			case "public-parent":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				if err := os.Symlink(filepath.Join(dir, "target"), p); err != nil {
					t.Fatal(err)
				}
			case "directory-file":
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.WriteFile(p, []byte("original"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				p = filepath.Join(link, "info")
			}
			f, err := openConnectionInfoFile(p, "https://silk.example")
			if err == nil {
				f.root.Close()
				t.Fatal("unsafe destination accepted")
			}
		})
	}
}

func TestPrivateConnectionInfoFailsClosedAfterReplacement(t *testing.T) {
	dir := privateTestDir(t)
	p := filepath.Join(dir, "info")
	f, err := openConnectionInfoFile(p, "https://silk.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.publish("synthetic-token", "FIRST-CODE"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := f.publish("", "NEXT-CODE"); err == nil {
		t.Fatal("unsafe replacement accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "unchanged" {
		t.Fatal("symlink target changed")
	}
}

func TestPublicURLValidation(t *testing.T) {
	for _, s := range []string{"", "https://silk.example", "https://silk.example/", "https://silk.example:443"} {
		if err := validatePublicURL(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"http://silk.example", "https://user:secret@silk.example", "https://silk.example/path", "https://silk.example?x=secret", "https://silk.example?", "https://silk.example#secret", "https:///", "//silk.example"} {
		if err := validatePublicURL(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestHostedConnectionInstructionsDoNotLeakSecrets(t *testing.T) {
	var out bytes.Buffer
	printConnectionInstructions(&out, "@test", "https://silk.example", "SYNTHETIC-PAIR", "synthetic-bearer-token", true)
	for _, secret := range []string{"SYNTHETIC-PAIR", "synthetic-bearer-token", "Authorization: Bearer", "/mcp/"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("hosted output leaked %q", secret)
		}
	}
	if !strings.Contains(out.String(), "https://silk.example/mcp") {
		t.Fatal("missing public endpoint")
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPrivateConnectionInfoRejectsStateAncestorAlias(t *testing.T) {
	base := privateTestDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(real, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	// The immediate parent isn't a symlink; only an ancestor is. Detect even
	// before the shared target file exists, without creating OAuth credentials.
	destination := filepath.Join(alias, "home", "state.json")
	f, err := openConnectionInfoFile(destination, "https://silk.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.protectStatePath(filepath.Join(home, "state.json")); err == nil {
		t.Fatal("ancestor alias of OAuth state accepted")
	}
	if _, err := os.Stat(filepath.Join(home, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state created while checking")
	}
}

func TestPrivateConnectionInfoRejectsStateHardlink(t *testing.T) {
	dir := privateTestDir(t)
	state := filepath.Join(dir, "state.json")
	dest := filepath.Join(dir, "connection.json")
	if err := os.WriteFile(state, []byte("synthetic state, unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(state, dest); err != nil {
		t.Fatal(err)
	}
	f, err := openConnectionInfoFile(dest, "https://silk.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.protectStatePath(state); err == nil {
		t.Fatal("hardlinked OAuth state accepted")
	}
	b, _ := os.ReadFile(state)
	if string(b) != "synthetic state, unchanged" {
		t.Fatal("state modified")
	}
}

func TestPrivateConnectionInfoRechecksStateCollisionOnRotation(t *testing.T) {
	dir := privateTestDir(t)
	state := filepath.Join(dir, "state.json")
	dest := filepath.Join(dir, "connection.json")
	if err := os.WriteFile(state, []byte("synthetic state, unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openConnectionInfoFile(dest, "https://silk.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.protectStatePath(state); err != nil {
		t.Fatal(err)
	}
	if err := f.publish("synthetic-token", "FIRST-CODE"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(state, dest); err != nil {
		t.Fatal(err)
	}
	if err := f.publish("", "NEXT-CODE"); err == nil {
		t.Fatal("rotation accepted state hardlink")
	}
	b, _ := os.ReadFile(state)
	if string(b) != "synthetic state, unchanged" {
		t.Fatal("state modified")
	}
}
