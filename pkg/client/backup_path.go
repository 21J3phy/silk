package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// restoreBackupFiles uses descriptor-rooted operations for every destination
// access, including temporary files and locks. Lexical validation alone does not
// stop an existing parent symlink from redirecting a restore outside the home.
// This is not a transaction: an I/O error can leave a partially restored home.
func restoreBackupFiles(home string, files map[string][]byte, res *ImportResult, o ImportOptions) error {
	if err := os.MkdirAll(home, 0700); err != nil {
		return err
	}
	before, err := os.Lstat(home)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return errors.New("restore home must not be a symbolic link")
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) {
		return errors.New("restore home changed while opening it")
	}
	// Reject existing symlinks even when they point within the home: aliases can
	// otherwise defeat the per-agent locking and no-overwrite guarantees.
	for _, rel := range res.Files {
		parts := strings.Split(rel, "/")
		for i := range parts {
			name := filepath.FromSlash(strings.Join(parts[:i+1], "/"))
			fi, err := root.Lstat(name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("restore %s: %w", rel, err)
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("restore path contains symbolic link: %s", name)
			}
			if i < len(parts)-1 && !fi.IsDir() {
				return fmt.Errorf("restore parent is not a directory: %s", name)
			}
			if i == len(parts)-1 && !o.Overwrite {
				return fmt.Errorf("%s already exists in %s (restore into an empty home, or overwrite)", rel, home)
			}
		}
	}
	// Hold each agent's lock across its entire restore, not one file at a time.
	// res.Agents is sorted, so concurrent restorers acquire locks consistently.
	var unlocks []func()
	defer func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}()
	for _, label := range res.Agents {
		dir := filepath.Join("agents", label)
		if err := root.MkdirAll(dir, 0700); err != nil {
			return err
		}
		m, _ := processLocks.LoadOrStore(filepath.Join(home, dir), &sync.Mutex{})
		mu := m.(*sync.Mutex)
		mu.Lock()
		f, err := root.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			mu.Unlock()
			return err
		}
		unlock, err := lockOpenedFile(f)
		if err != nil {
			mu.Unlock()
			return err
		}
		unlocks = append(unlocks, func() { unlock(); mu.Unlock() })
	}
	for _, rel := range res.Files {
		name := filepath.FromSlash(rel)
		if err := root.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return err
		}
		if err := writeBackupFileRooted(root, name, files[rel], o.Overwrite); err != nil {
			return err
		}
	}
	return nil
}

func writeBackupFileRooted(root *os.Root, name string, data []byte, overwrite bool) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(name), ".tmp-restore-"+hex.EncodeToString(nonce[:]))
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if !overwrite {
		// Link fails if name appeared after validation, preserving no-clobber.
		return root.Link(tmp, name)
	}
	return root.Rename(tmp, name)
}
