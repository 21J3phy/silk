package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/21J3phy/silk/pkg/client"
	"net/http"
	"os"
	"time"
)

func runReleaseBundle(ctx context.Context, g *globals, args []string) error {
	fs := newFlags("release-bundle", g)
	version := fs.String("version", "", "exact published version")
	output := fs.String("out", "", "public evidence JSON output")
	relayURL := fs.String("relay", DefaultRelay, "relay endpoint serving the pinned release ledger")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *version == "" || *output == "" {
		return errors.New("release-bundle requires --version and --out")
	}
	// Distribution installers pin this ledger; a replacement endpoint must
	// preserve its identity. Never accept a home-configured replacement key.
	c := &client.Client{Config: client.Config{Relay: *relayURL, LedgerKey: defaultLedgerKey}, HTTP: &http.Client{Timeout: time.Minute}}
	b, err := c.FetchReleaseBundle(ctx, pinnedReleaseKeys(), *version)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*output, append(data, '\n'), 0o644)
}
