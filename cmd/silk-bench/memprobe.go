package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
)

func memProbe(ctx context.Context, args []string) error {
	stage := func(name string) {
		runtime.GC()
		debug.FreeOSMemory()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		rss, _, _ := procStat(os.Getpid())
		fmt.Printf("%-22s rss %5.1fMB  go-sys %5.1fMB  heap-inuse %5.1fMB  stack %4.1fMB  goroutines %d\n", name, rss,
			float64(m.Sys)/(1<<20), float64(m.HeapInuse)/(1<<20), float64(m.StackSys)/(1<<20), runtime.NumGoroutine())
	}
	stage("start")
	dir, _ := os.MkdirTemp("", "memprobe")
	defer os.RemoveAll(dir)
	var store kv.Store
	var err error
	if len(args) > 0 && args[0] == "bolt" {
		store, err = boltkv.Open(filepath.Join(dir, "r.db"), boltkv.Options{})
	} else {
		store, err = sqlitekv.Open(filepath.Join(dir, "r.db"), sqlitekv.SQLiteOptions{})
	}
	if err != nil {
		return err
	}
	stage("store open")
	skey, _, _ := ledger.GenerateKey("probe")
	signer, _ := ledger.NewSigner(skey)
	r := relay.New(store, signer, relay.Config{RegisterBits: 8, IntroBaseBits: 8, IgnoreGrantRate: true}, nil)
	srv := httptest.NewServer(relay.Handler(r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1}))
	defer srv.Close()
	http.Get(srv.URL + "/healthz")
	stage("relay serving")
	a := newAPI(srv.URL, 16)
	pairs, err := setupPairs(ctx, a, 16, 100000)
	if err != nil {
		return err
	}
	stage("16 pairs set up")
	for i := 0; i < 2000; i++ {
		m, _ := pairs[i%16].sealAB([]byte(text))
		if _, err := a.submit(ctx, m.Raw); err != nil {
			return err
		}
	}
	stage("2000 msgs")
	f, _ := os.Create("/tmp/memprobe/heap.prof")
	pprof.WriteHeapProfile(f)
	f.Close()
	time.Sleep(10 * time.Millisecond)
	return nil
}

// loadExisting drives an already-running relay (for profiling it externally).
func loadExisting(ctx context.Context, args []string) error {
	base, c, n := args[0], 64, 20000
	fmt.Sscan(args[1], &c)
	fmt.Sscan(args[2], &n)
	a := newAPI(base, c)
	pairs, err := setupPairs(ctx, a, c, uint32(n))
	if err != nil {
		return err
	}
	frames := make([][][]byte, c)
	for w := range frames {
		for i := 0; i < n/c+1; i++ {
			m, _ := pairs[w].sealAB([]byte(text))
			frames[w] = append(frames[w], m.Raw)
		}
	}
	t := time.Now()
	done := make(chan struct{})
	for w := 0; w < c; w++ {
		go func(w int) {
			for _, f := range frames[w] {
				a.submit(ctx, f)
			}
			done <- struct{}{}
		}(w)
	}
	for w := 0; w < c; w++ {
		<-done
	}
	fmt.Printf("%d msgs in %v (%.0f/s)\n", n, time.Since(t), float64(n)/time.Since(t).Seconds())
	return nil
}
