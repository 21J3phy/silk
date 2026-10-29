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
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/pgkv"
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
	backend := fs.String("store", "sqlite", "storage engine: sqlite (default), bolt, or existing postgres")
	dsnEnv := fs.String("dsn-env", "SILK_POSTGRES_DSN", "postgres: environment variable containing the existing database connection string")
	keyEnv := fs.String("key-env", "", "environment variable containing the existing ledger signing key (exclusive with --key)")
	expectedKey := fs.String("expected-ledger-key", "", "expected PUBLIC ledger verifier key (required for postgres)")
	cacheMB := fs.Int("cache-mb", 4, "SQLite writer page cache in MB")
	relKeys := fs.String("release-keys", "", "comma-separated base64 Ed25519 keys allowed to publish releases to this relay's ledger")
	trustProxy := fs.Bool("trust-proxy", false, "rate-limit by X-Forwarded-For")
	noLimits := fs.Bool("no-ip-limits", false, "disable per-IP request limits (benchmarks)")
	benchRate := fs.Bool("bench-unlimited-rate", false, "ignore per-conversation rate windows and backlog caps (benchmarks only)")
	maxBatch := fs.Int("max-batch", 512, "max writes per group commit (1 disables grouping)")
	debugAddr := fs.String("debug-addr", "", "serve Go pprof on this loopback address (diagnostics only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *backend != "sqlite" && *backend != "bolt" && *backend != "postgres" {
		return errors.New("unknown storage engine")
	}
	if *backend == "postgres" && (*expectedKey == "" || (*keyEnv == "" && *keyFile == "")) {
		return errors.New("postgres requires an existing --key or --key-env and --expected-ledger-key; no keys are generated")
	}
	if *keyFile == "" && *keyEnv == "" {
		*keyFile = *db + ".ledger-key"
	}
	if os.Getenv("GOGC") == "" {
		// Measured: peak memory under load −4–5% for ~7% more CPU (still ~10× below v1).
		debug.SetGCPercent(50)
	}
	if os.Getenv("GOMAXPROCS") == "" {
		// One writer goroutine owns the database; a few procs for TLS/HTTP/signature work
		// measured both faster and lighter than one per core.
		runtime.GOMAXPROCS(min(4, runtime.NumCPU()))
	}
	signer, err := loadRelaySigner(*keyFile, *keyEnv, *origin, *expectedKey, *backend != "postgres" && *expectedKey == "")
	if err != nil {
		return err
	}
	var store kv.Store
	switch *backend {
	case "postgres":
		dsn := strings.TrimSpace(os.Getenv(*dsnEnv))
		if dsn == "" {
			return errors.New("postgres connection environment variable is missing or empty")
		}
		connectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		store, err = pgkv.Open(connectCtx, dsn, pgkv.Options{MaxConns: 4, MaxBatch: *maxBatch, ExistingOnly: true})
		cancel()
		if err != nil {
			return errors.New("could not open existing PostgreSQL store; check its secure connection settings and existing silk_kv table")
		}
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
	if *backend == "postgres" {
		// A blank/wrong database must never start a new history under an old key.
		var size int64
		err = store.View(ctx, func(tx kv.Tx) error { var e error; size, e = ledger.Size(tx); return e })
		if err != nil || size == 0 {
			return errors.New("postgres migration requires an existing nonempty ledger; refusing to initialize a new history")
		}
	}
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
	r := relay.New(store, signer, relay.Config{RegisterBits: uint8(*regBits), IntroBaseBits: uint8(*introBits), PollInterval: 5 * time.Second, IgnoreGrantRate: *benchRate, ReleaseKeys: rk, MaxPendingPerGrant: benchBacklog(*benchRate)}, nil)
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
	slog.Info("silk relay listening", "addr", *addr, "store", *backend, "origin", signer.Origin, "ledger_key", signer.VKey)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// benchBacklog lifts the per-conversation backlog cap in benchmark mode, where
// thousands of messages are sent through one conversation without acknowledgments.
func benchBacklog(bench bool) uint32 {
	if bench {
		return 1 << 30
	}
	return 0 // default
}
