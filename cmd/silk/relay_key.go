//go:build !client

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/21J3phy/silk/pkg/ledger"
)

// Existing deployments may attach to a new host, never silently acquire a new
// ledger identity. Errors intentionally contain no secret material.
func loadRelaySigner(keyFile, keyEnv, origin, expected string, allowCreate bool) (*ledger.Signer, error) {
	if keyFile != "" && keyEnv != "" {
		return nil, errors.New("choose --key or --key-env, not both")
	}
	var raw []byte
	if keyEnv != "" {
		raw = []byte(strings.TrimSpace(os.Getenv(keyEnv)))
		if len(raw) == 0 {
			return nil, errors.New("ledger key environment variable is missing or empty")
		}
	} else {
		var err error
		raw, err = os.ReadFile(keyFile)
		if errors.Is(err, os.ErrNotExist) && allowCreate {
			if origin == "" {
				host, _ := os.Hostname()
				origin = strings.ToLower(strings.Split(host, ".")[0]) + ".silk.relay"
			}
			private, _, e := ledger.GenerateKey(origin)
			if e != nil {
				return nil, errors.New("could not generate ledger key")
			}
			if e = os.MkdirAll(filepath.Dir(keyFile), 0o700); e != nil {
				return nil, e
			}
			// Exclusive creation refuses a concurrently created key rather than replacing it.
			f, e := os.OpenFile(keyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if e != nil {
				return nil, errors.New("could not create ledger key file")
			}
			_, e = f.WriteString(private)
			closeErr := f.Close()
			if e != nil || closeErr != nil {
				return nil, errors.New("could not persist ledger key")
			}
			raw = []byte(private)
		} else if err != nil {
			return nil, errors.New("existing ledger key file is unavailable; no new key was created")
		}
	}
	signer, err := ledger.NewSigner(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("ledger signing key is invalid")
	}
	if expected != "" && signer.VKey != expected {
		return nil, errors.New("ledger signing key does not match expected public verifier; refusing identity change")
	}
	return signer, nil
}
