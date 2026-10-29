package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Encrypted backups: the whole home (owner key if present, agent keys,
// certificates, conversation state) sealed under a passphrase, so an agent
// whose disk is wiped (a cloud container, a reinstalled machine) can be
// restored from a copy kept somewhere shared or remote without exposing keys.

// BackupFormat identifies the backup file format.
const BackupFormat = "silk-backup/1"

// MinBackupPassphrase is the shortest passphrase Export accepts. A backup is
// meant to sit outside the machine, so it must hold up to offline guessing.
const MinBackupPassphrase = 12

const (
	backupMaxFile  = 16 << 20
	backupMaxTotal = 64 << 20
	backupMinIter  = 100_000
	backupMaxIter  = 10_000_000
)

// ErrBackupPassphrase means the backup passphrase is wrong or the file was altered.
var ErrBackupPassphrase = errors.New("backup passphrase incorrect, or the backup file was altered")

type backupFile struct {
	Format    string `json:"format"`
	KDF       string `json:"kdf"` // "pbkdf2-sha256"
	Iter      int    `json:"iter"`
	Salt      []byte `json:"salt"`
	Nonce     []byte `json:"nonce"`
	CreatedMs int64  `json:"created_ms"`
	Data      []byte `json:"data"` // AES-256-GCM ciphertext of backupBundle
}

type backupBundle struct {
	Files map[string][]byte `json:"files"` // slash-separated path in the home -> contents
}

// header is everything but the ciphertext; it is authenticated as AAD so the
// KDF parameters and timestamp cannot be swapped.
func (f *backupFile) header() []byte {
	h := *f
	h.Data = nil
	b, _ := json.Marshal(h)
	return b
}

// skipInBackup reports whether a file is process-local and never backed up.
func skipInBackup(name string) bool {
	return name == "lock" || strings.HasPrefix(name, ".tmp-")
}

// lockAgentDir takes the in-process and file lock that guards an agent's state.
func lockAgentDir(dir string) (func(), error) {
	m, _ := processLocks.LoadOrStore(dir, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	unlock, err := lockFile(filepath.Join(dir, "lock"))
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	return func() { unlock(); mu.Unlock() }, nil
}

// agentOf returns the agent directory a home-relative path belongs to, or "".
func agentOf(rel string) string {
	parts := strings.Split(rel, "/")
	if len(parts) >= 3 && parts[0] == "agents" {
		return parts[0] + "/" + parts[1]
	}
	return ""
}

// Export seals the home directory into an encrypted backup. Each agent's
// files are read under its lock, so a running agent is copied consistently.
func (c *Client) Export(passphrase string) ([]byte, error) {
	if len([]rune(passphrase)) < MinBackupPassphrase {
		return nil, fmt.Errorf("backup passphrase must be at least %d characters", MinBackupPassphrase)
	}
	var rels []string
	err := filepath.WalkDir(c.Home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() || skipInBackup(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(c.Home, p)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rels) == 0 {
		return nil, fmt.Errorf("nothing to back up in %s", c.Home)
	}
	sort.Strings(rels)
	bundle := backupBundle{Files: map[string][]byte{}}
	total := 0
	read := func(rel string) error {
		b, err := os.ReadFile(filepath.Join(c.Home, filepath.FromSlash(rel)))
		if errors.Is(err, os.ErrNotExist) {
			return nil // removed meanwhile (e.g. a finished rotation)
		}
		if err != nil {
			return err
		}
		if total += len(b); len(b) > backupMaxFile || total > backupMaxTotal {
			return fmt.Errorf("%s: home is too large to back up", rel)
		}
		bundle.Files[rel] = b
		return nil
	}
	for i := 0; i < len(rels); {
		dir := agentOf(rels[i])
		j := i + 1
		for j < len(rels) && dir != "" && agentOf(rels[j]) == dir {
			j++
		}
		unlock := func() {}
		if dir != "" {
			if unlock, err = lockAgentDir(filepath.Join(c.Home, filepath.FromSlash(dir))); err != nil {
				return nil, err
			}
		}
		for _, rel := range rels[i:j] {
			if err = read(rel); err != nil {
				break
			}
		}
		unlock()
		if err != nil {
			return nil, err
		}
		i = j
	}
	plain, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	f := backupFile{Format: BackupFormat, KDF: "pbkdf2-sha256", Iter: ownerIter, Salt: make([]byte, 16), Nonce: make([]byte, 12), CreatedMs: c.Now().UnixMilli()}
	rand.Read(f.Salt)
	rand.Read(f.Nonce)
	g, err := backupAEAD(passphrase, &f)
	if err != nil {
		return nil, err
	}
	f.Data = g.Seal(nil, f.Nonce, plain, f.header())
	return json.MarshalIndent(f, "", " ")
}

func backupAEAD(passphrase string, f *backupFile) (cipher.AEAD, error) {
	block, err := aes.NewCipher(passKey(passphrase, f.Salt, f.Iter))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ImportOptions controls Import.
type ImportOptions struct {
	// Overwrite replaces files that already exist in the home. Without it,
	// Import refuses to touch a home that holds any file in the backup.
	Overwrite bool
}

// ImportResult describes a restored backup.
type ImportResult struct {
	Files     []string `json:"files"`
	Agents    []string `json:"agents"`
	CreatedMs int64    `json:"created_ms"`
}

// Import restores an encrypted backup made by Export into home. The backup
// is decrypted and checked in full before anything is written.
func Import(home string, data []byte, passphrase string, o ImportOptions) (*ImportResult, error) {
	var f backupFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a Silk backup: %w", err)
	}
	if f.Format != BackupFormat {
		return nil, fmt.Errorf("unsupported backup format %q", f.Format)
	}
	if f.KDF != "pbkdf2-sha256" || f.Iter < backupMinIter || f.Iter > backupMaxIter || len(f.Salt) != 16 || len(f.Nonce) != 12 {
		return nil, errors.New("backup file is corrupt")
	}
	if passphrase == "" {
		return nil, ErrBackupPassphrase
	}
	g, err := backupAEAD(passphrase, &f)
	if err != nil {
		return nil, err
	}
	plain, err := g.Open(nil, f.Nonce, f.Data, f.header())
	if err != nil {
		return nil, ErrBackupPassphrase
	}
	var b backupBundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, errors.New("backup file is corrupt")
	}
	res := &ImportResult{CreatedMs: f.CreatedMs}
	agents := map[string]bool{}
	for rel := range b.Files {
		if !filepath.IsLocal(filepath.FromSlash(rel)) || path.Clean(rel) != rel || strings.Contains(rel, `\`) || skipInBackup(path.Base(rel)) {
			return nil, fmt.Errorf("backup contains an unsafe path %q", rel)
		}
		if !o.Overwrite {
			if _, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel))); err == nil {
				return nil, fmt.Errorf("%s already exists in %s (restore into an empty home, or overwrite)", rel, home)
			}
		}
		res.Files = append(res.Files, rel)
		if dir := agentOf(rel); dir != "" {
			agents[dir] = true
		}
	}
	sort.Strings(res.Files)
	for dir := range agents {
		res.Agents = append(res.Agents, strings.TrimPrefix(dir, "agents/"))
	}
	sort.Strings(res.Agents)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	for _, rel := range res.Files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if dir := agentOf(rel); dir != "" {
			d := filepath.Join(home, filepath.FromSlash(dir))
			if err := os.MkdirAll(d, 0o700); err != nil {
				return nil, err
			}
			unlock, err := lockAgentDir(d)
			if err != nil {
				return nil, err
			}
			err = writeFileAtomic(p, b.Files[rel], 0o600)
			unlock()
			if err != nil {
				return nil, err
			}
			continue
		}
		if err := writeFileAtomic(p, b.Files[rel], 0o600); err != nil {
			return nil, err
		}
	}
	return res, nil
}
