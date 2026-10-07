// Package handler is the Vercel Function entrypoint for the hosted Silk relay.
// Storage is PostgreSQL (Neon via the Vercel Marketplace); the ledger signing
// key comes from the SILK_LEDGER_KEY environment variable.
package handler

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/21J3phy/silk/pkg/kv/pgkv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
)

var (
	once    sync.Once
	h       http.Handler
	initErr error
)

// Version is replaced at bundle time.
const Version = "dev"

func envBits(name string, def uint8) uint8 {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 && v <= 40 {
		return uint8(v)
	}
	return def
}

func setup() {
	dsn := os.Getenv("DATABASE_URL_UNPOOLED")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	skey := strings.TrimSpace(os.Getenv("SILK_LEDGER_KEY"))
	if dsn == "" || skey == "" {
		initErr = errMissing
		return
	}
	signer, err := ledger.NewSigner(skey)
	if err != nil {
		initErr = err
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := pgkv.Open(ctx, dsn, pgkv.Options{MaxConns: 4})
	if err != nil {
		initErr = err
		return
	}
	var releaseKeys []ed25519.PublicKey
	for _, k := range strings.Split(os.Getenv("SILK_RELEASE_KEYS"), ",") {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k)); err == nil && len(b) == ed25519.PublicKeySize {
			releaseKeys = append(releaseKeys, ed25519.PublicKey(b))
		}
	}
	r := relay.New(store, signer, relay.Config{
		RegisterBits:  envBits("SILK_REGISTER_BITS", 24),
		IntroBaseBits: envBits("SILK_INTRO_BITS", 20),
		PollInterval:  time.Second, // instances share the database, not memory
		ReleaseKeys:   releaseKeys,
	}, nil)
	r.Version = Version
	h = relay.Handler(r, relay.HTTPOptions{TrustProxy: true, MaxWait: 25 * time.Second})
}

type setupError string

func (e setupError) Error() string { return string(e) }

const errMissing = setupError("relay storage or ledger key is not configured")

// Handler serves every route of the relay API.
func Handler(w http.ResponseWriter, r *http.Request) {
	once.Do(setup)
	if initErr != nil {
		slog.Error("silk relay unavailable", "err", initErr)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"status": 503, "code": "unavailable", "message": "the relay is starting or misconfigured; retry shortly"}})
		return
	}
	h.ServeHTTP(w, r)
}
