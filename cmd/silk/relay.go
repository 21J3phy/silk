//go:build !client

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof" // only served when --debug-addr is set
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
)

// The full build updates itself to full (relay) builds.
func init() { client.Flavor = "relay-" }

func runRelay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8790", "listen address")
	db := fs.String("db", "silk-relay.db", "SQLite database file")
	keyFile := fs.String("key", "", "ledger signing key file (default: <db>.ledger-key, created if missing)")
	origin := fs.String("origin", "", "ledger origin name for a new key (default: hostname/silk)")
	regBits := fs.Uint("register-bits", 24, "proof-of-work bits for new identities")
	introBits := fs.Uint("intro-bits", 20, "base proof-of-work bits for contact requests")
	syncMode := fs.String("sync", "FULL", "SQLite synchronous mode: FULL or NORMAL")
	backend := fs.String("store", "sqlite", "storage engine: sqlite (default) or bolt")
	cacheMB := fs.Int("cache-mb", 4, "SQLite writer page cache in MB")
	relKeys := fs.String("release-keys", "", "comma-separated base64 Ed25519 keys allowed to publish releases to this relay's ledger")
	trustProxy := fs.Bool("trust-proxy", false, "rate-limit by X-Forwarded-For")
	noLimits := fs.Bool("no-ip-limits", false, "disable per-IP request limits (benchmarks)")
	benchRate := fs.Bool("bench-unlimited-rate", false, "ignore per-conversation rate windows (benchmarks only)")
	maxBatch := fs.Int("max-batch", 512, "max writes per group commit (1 disables grouping)")
	debugAddr := fs.String("debug-addr", "", "serve Go pprof on this loopback address (diagnostics only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		*keyFile = *db + ".ledger-key"
	}
	if os.Getenv("GOMAXPROCS") == "" {
		// One writer goroutine owns the database; a few procs for TLS/HTTP/signature work
		// measured both faster and lighter than one per core.
		runtime.GOMAXPROCS(min(4, runtime.NumCPU()))
	}
	skey, err := os.ReadFile(*keyFile)
	if errors.Is(err, os.ErrNotExist) {
		if *origin == "" {
			host, _ := os.Hostname()
			*origin = strings.ToLower(strings.Split(host, ".")[0]) + ".silk.relay"
		}
		s, _, err := ledger.GenerateKey(*origin)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*keyFile), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(*keyFile, []byte(s), 0o600); err != nil {
			return err
		}
		skey = []byte(s)
	} else if err != nil {
		return err
	}
	signer, err := ledger.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		return err
	}
	var store kv.Store
	switch *backend {
	case "bolt":
		store, err = boltkv.Open(*db, boltkv.Options{MaxBatch: *maxBatch})
	case "sqlite":
		store, err = sqlitekv.Open(*db, sqlitekv.SQLiteOptions{Synchronous: *syncMode, MaxBatch: *maxBatch, CacheMB: *cacheMB})
	default:
		err = fmt.Errorf("unknown store %q", *backend)
	}
	if err != nil {
		return err
	}
	defer store.Close()
	var rk []ed25519.PublicKey
	for _, k := range strings.Split(*relKeys, ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid release key %q", k)
		}
		rk = append(rk, ed25519.PublicKey(b))
	}
	r := relay.New(store, signer, relay.Config{RegisterBits: uint8(*regBits), IntroBaseBits: uint8(*introBits), PollInterval: 5 * time.Second, IgnoreGrantRate: *benchRate, ReleaseKeys: rk}, nil)
	r.Version = version
	ho := relay.HTTPOptions{TrustProxy: *trustProxy}
	if *noLimits {
		ho.PostRate, ho.GetRate, ho.RegisterRate = -1, -1, -1
	}
	srv := &http.Server{Addr: *addr, Handler: relay.Handler(r, ho), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.Sweep(ctx, 1000)
			}
		}
	}()
	if *debugAddr != "" {
		if !strings.HasPrefix(*debugAddr, "127.0.0.1:") && !strings.HasPrefix(*debugAddr, "localhost:") {
			return errors.New("--debug-addr must be a loopback address")
		}
		go http.ListenAndServe(*debugAddr, http.DefaultServeMux)
	}
	slog.Info("silk relay listening", "addr", *addr, "db", *db, "origin", signer.Origin, "ledger_key", signer.VKey)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
