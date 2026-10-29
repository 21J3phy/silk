package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewImportRejectsSymlinkParent(t *testing.T) {
	const pass = "review-only backup password"
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "agents")); err != nil {
		t.Fatal(err)
	}
	data := sealBundle(t, pass, map[string][]byte{"agents/test/keys.json": []byte("synthetic-test-key")})
	_, err := Import(home, data, pass, ImportOptions{})
	if b, e := os.ReadFile(filepath.Join(outside, "test/keys.json")); e == nil {
		t.Fatalf("import escaped home via symlink: outside file=%q, import error=%v", b, err)
	}
	if err == nil {
		t.Fatal("import must reject symlink parent")
	}
}

func TestBackupImportRejectsRootSymlink(t *testing.T) {
	const pass = "review-only backup password"
	base := t.TempDir()
	target := filepath.Join(base, "outside")
	home := filepath.Join(base, "home")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, home); err != nil {
		t.Fatal(err)
	}
	data := sealBundle(t, pass, map[string][]byte{"config.json": []byte("synthetic")})
	if _, err := Import(home, data, pass, ImportOptions{}); err == nil {
		t.Fatal("accepted symlink home")
	}
	if _, err := os.Stat(filepath.Join(target, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("modified outside: %v", err)
	}
}

func TestBackupImportRejectsSymlinkFileEvenOverwrite(t *testing.T) {
	const pass = "review-only backup password"
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "config.json")); err != nil {
		t.Fatal(err)
	}
	data := sealBundle(t, pass, map[string][]byte{"config.json": []byte("synthetic")})
	if _, err := Import(home, data, pass, ImportOptions{Overwrite: true}); err == nil {
		t.Fatal("accepted symlink destination")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("modified outside %q %v", got, err)
	}
}

func TestRootedBackupWriteNoClobber(t *testing.T) {
	home := t.TempDir()
	root, err := os.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("state.json", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeBackupFileRooted(root, "state.json", []byte("new"), false); err == nil {
		t.Fatal("clobbered existing target")
	}
	got, err := root.ReadFile("state.json")
	if err != nil || string(got) != "old" {
		t.Fatalf("changed file: %q %v", got, err)
	}
}
