package main

import (
	"context"
	"flag"
	"fmt"
	"net/http/httptest"
	"time"

	"github.com/21J3phy/silk/pkg/kv/pgkv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
)

// pgRoundTrips reports database round trips and latency per message on PostgreSQL.
func pgRoundTrips(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pgrtt", flag.ExitOnError)
	dsn := fs.String("dsn", "", "disposable PostgreSQL DSN")
	n := fs.Int("n", 200, "messages")
	fs.Parse(args)
	store, err := pgkv.Open(ctx, *dsn, pgkv.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	skey, _, _ := ledger.GenerateKey("pgrtt")
	signer, _ := ledger.NewSigner(skey)
	r := relay.New(store, signer, relay.Config{RegisterBits: 8, IntroBaseBits: 8, IgnoreGrantRate: true}, nil)
	srv := httptest.NewServer(relay.Handler(r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1}))
	defer srv.Close()
	a := newAPI(srv.URL, 1)
	ps, err := setupPairs(ctx, a, 1, uint32(*n+10))
	if err != nil {
		return err
	}
	p := ps[0]
	m0, _ := p.sealAB([]byte(text)) // warm caches
	a.submit(ctx, m0.Raw)
	before := store.RoundTrips.Load()
	t := time.Now()
	for i := 0; i < *n; i++ {
		m, _ := p.sealAB([]byte(text))
		if _, err := a.submit(ctx, m.Raw); err != nil {
			return err
		}
	}
	el := time.Since(t)
	fmt.Printf("%.2f database round trips per message, %.2f ms per message (sequential, local PostgreSQL)\n",
		float64(store.RoundTrips.Load()-before)/float64(*n), float64(el.Microseconds())/1000/float64(*n))
	return nil
}
