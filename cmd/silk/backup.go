package main

// Encrypted backups of a Silk home, for agents whose disk does not last (a
// cloud container that is rebuilt, a reinstalled machine): `silk export`
// seals the home under a passphrase into one file that can be kept in shared
// or remote storage, and `silk import` restores it after the disk is wiped.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/21J3phy/silk/pkg/client"
)

const backupPassEnv = "SILK_BACKUP_PASSPHRASE"

// backupPassphrase reads the backup passphrase from $SILK_BACKUP_PASSPHRASE
// or the terminal; a new one is asked twice.
func backupPassphrase(confirm bool) (string, error) {
	if p := os.Getenv(backupPassEnv); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("the backup passphrase needs a terminal or " + backupPassEnv)
	}
	fmt.Fprint(os.Stderr, "Backup passphrase: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil || !confirm {
		return string(b), err
	}
	fmt.Fprint(os.Stderr, "Repeat it: ")
	again, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(again) != string(b) {
		return "", errors.New("the passphrases do not match")
	}
	return string(b), nil
}

// inside reports whether path p is inside dir.
func inside(p, dir string) bool {
	ap, err1 := filepath.Abs(p)
	ad, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(ad, ap)
	return err == nil && filepath.IsLocal(rel)
}

func runExport(g *globals, args []string) error {
	fs := newFlags("export", g)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: silk export <file>")
	}
	file := pos[0]
	if inside(file, g.home) {
		return fmt.Errorf("write the backup outside %s, where it survives losing the home", g.home)
	}
	c, err := client.Open(g.home)
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(true)
	if err != nil {
		return err
	}
	data, err := c.Export(pass)
	if err != nil {
		return err
	}
	if err := writeBackup(file, data); err != nil {
		return err
	}
	out(g, map[string]any{"file": file, "home": g.home, "bytes": len(data)}, func(w io.Writer) {
		fmt.Fprintf(w, "Encrypted backup of %s written to %s.\n"+
			"Restore it with `silk import %s` (same passphrase). Export again after each session:\n"+
			"conversation state changes with every message.\n", g.home, file, file)
	})
	return nil
}

// writeBackup replaces file via a temp file in the same directory.
func writeBackup(file string, data []byte) error {
	dir := filepath.Dir(file)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(file)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func runImport(g *globals, args []string) error {
	fs := newFlags("import", g)
	overwrite := fs.Bool("overwrite", false, "replace files that already exist in the home")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: silk import <file> [--overwrite]")
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(false)
	if err != nil {
		return err
	}
	res, err := client.Import(g.home, data, pass, client.ImportOptions{Overwrite: *overwrite})
	if err != nil {
		return err
	}
	out(g, res, func(w io.Writer) {
		fmt.Fprintf(w, "Restored %d files into %s from a backup made %s.\n", len(res.Files), g.home,
			time.UnixMilli(res.CreatedMs).Format(time.RFC3339))
		if len(res.Agents) > 0 {
			fmt.Fprintf(w, "  agents: %s\n", strings.Join(res.Agents, ", "))
		}
		fmt.Fprintln(w, "Run `silk doctor` to check it against the relay.")
	})
	return nil
}
