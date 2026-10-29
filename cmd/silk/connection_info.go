package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type connectionInfo struct {
	Endpoint    string `json:"endpoint"`
	PairingCode string `json:"pairing_code"`
	BearerToken string `json:"bearer_token"`
	SecretURL   string `json:"secret_url"`
}

type connectionInfoFile struct {
	mu        sync.Mutex
	root      *os.Root
	name      string
	info      connectionInfo
	statePath string
}

func openConnectionInfoFile(path, publicURL string) (*connectionInfoFile, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("--connection-info-file requires an absolute path")
	}
	if publicURL == "" {
		return nil, errors.New("--connection-info-file requires --public-url")
	}
	if err := validatePublicURL(publicURL); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("private connection-info directory: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("connection-info parent must be an existing private directory (0700), not a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(fi, opened) {
		root.Close()
		return nil, errors.New("connection-info directory changed while opening")
	}
	f := &connectionInfoFile{root: root, name: filepath.Base(path)}
	if err := f.checkDestination(); err != nil {
		root.Close()
		return nil, err
	}
	f.info.Endpoint = strings.TrimRight(publicURL, "/") + "/mcp"
	return f, nil
}

func (f *connectionInfoFile) checkDestination() error {
	fi, err := f.root.Lstat(f.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("connection-info destination must be a private regular file (0600), not a symlink")
	}
	return nil
}

func (f *connectionInfoFile) publish(token, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkDestination(); err != nil {
		return err
	}
	if f.statePath != "" {
		if err := f.checkStateCollision(); err != nil {
			return err
		}
	}
	info := f.info
	if token != "" {
		info.BearerToken = token
		info.SecretURL = info.Endpoint + "/" + token
	}
	info.PairingCode = code
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	tmp := ".tmp-connection-" + hex.EncodeToString(b[:])
	out, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.root.Remove(tmp)
	if _, err = out.Write(append(data, '\n')); err != nil {
		out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = f.root.Rename(tmp, f.name); err != nil {
		return err
	}
	f.info = info
	return nil
}

// validatePublicURL accepts an HTTPS origin, never credentials or URL suffixes
// that could leak to logs or change the OAuth issuer/endpoints.
func validatePublicURL(value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return errors.New("--public-url must be an HTTPS origin with no credentials, path, query, or fragment")
	}
	return nil
}

func printConnectionInstructions(out io.Writer, name, base, pair, token string, private bool) {
	if private {
		fmt.Fprintf(out, "Silk MCP over HTTP for %s\n  Endpoint: %s/mcp\n  Connection credentials are in the configured private file, not service logs.\n", name, base)
	} else {
		fmt.Fprintf(out, `Silk MCP over HTTP for %s
  Endpoint:      %s/mcp
  Pairing code:  %s

Connect a cloud agent (grok.com, Grok Bot, Meta Muse, OpenAI Dots, ChatGPT, claude.ai):
  add %s/mcp as a custom MCP connector. When its sign-in page opens, enter the pairing code.
Agents that take a header (Muse Code, Grok Build, the xAI and OpenAI APIs):
  Authorization: Bearer %s
Agents that only take a URL, with no sign-in:
  %s/mcp/%s

Anyone with the token or that URL can read this agent's inbox and send in approved
conversations; keep them secret. Contact requests still need you: silk accept <id>.
`, name, base, pair, base, token, base, token)
	}
}

// protectStatePath prevents aliases of the same directory entry or existing
// hard links from turning a credential publication into an OAuth-state overwrite.
// Keep checking on rotations as well as before HTTP.Load creates any state.
func (f *connectionInfoFile) protectStatePath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	f.statePath = abs
	return f.checkStateCollision()
}

func (f *connectionInfoFile) checkStateCollision() error {
	collision := errors.New("connection-info file must differ from MCP state file")
	parent, err := os.Stat(filepath.Dir(f.statePath))
	if err != nil {
		return err
	}
	ownParent, err := f.root.Stat(".")
	if err != nil {
		return err
	}
	sameName := f.name == filepath.Base(f.statePath)
	if runtime.GOOS == "windows" {
		sameName = strings.EqualFold(f.name, filepath.Base(f.statePath))
	}
	if sameName && os.SameFile(parent, ownParent) {
		return collision
	}
	state, err := os.Stat(f.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	own, err := f.root.Stat(f.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if os.SameFile(state, own) {
		return collision
	}
	return nil
}
