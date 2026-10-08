package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
)

func writeResult(path string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ---------------------------------------------------------------------------
// pow: measured stamp cost on this machine

func powBench(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pow", flag.ExitOnError)
	outPath := fs.String("out", "bench/results/pow.json", "result file")
	fs.Parse(args)
	type row struct {
		Bits         uint8   `json:"bits"`
		Expected     float64 `json:"expected_hashes"`
		Trials       int     `json:"trials"`
		AllCoresMean float64 `json:"all_cores_mean_ms"`
		AllCoresP90  float64 `json:"all_cores_p90_ms"`
		OneCoreMean  float64 `json:"one_core_mean_ms"`
	}
	var rows []row
	for b := uint8(12); b <= 26; b += 2 {
		trials := 40
		if b >= 22 {
			trials = 12
		}
		if b >= 26 {
			trials = 6
		}
		var all, one []float64
		for i := 0; i < trials; i++ {
			var d [32]byte
			rand.Read(d[:])
			t := time.Now()
			if _, err := pow.Solve(ctx, d, b, 0); err != nil {
				return err
			}
			all = append(all, float64(time.Since(t).Microseconds())/1000)
			if b <= 22 {
				rand.Read(d[:])
				t = time.Now()
				pow.Solve(ctx, d, b, 1)
				one = append(one, float64(time.Since(t).Microseconds())/1000)
			}
		}
		pa := percentiles(all)
		r := row{Bits: b, Expected: pow.ExpectedHashes(b), Trials: trials, AllCoresMean: pa.Mean, AllCoresP90: pa.P90}
		if len(one) > 0 {
			r.OneCoreMean = percentiles(one).Mean
		}
		fmt.Fprintf(os.Stderr, "bits %2d: all-cores mean %8.1fms p90 %8.1fms  one-core mean %8.1fms\n", b, r.AllCoresMean, r.AllCoresP90, r.OneCoreMean)
		rows = append(rows, r)
	}
	// Verification cost.
	var d [32]byte
	rand.Read(d[:])
	n := 2_000_000
	t := time.Now()
	for i := 0; i < n; i++ {
		pow.Check(d, 20, uint64(i))
	}
	verifyNs := float64(time.Since(t).Nanoseconds()) / float64(n)
	// Hash rate.
	t = time.Now()
	hn := 0
	for time.Since(t) < time.Second {
		for i := 0; i < 10000; i++ {
			pow.Check(d, 64, uint64(hn))
			hn++
		}
	}
	single := float64(hn) / time.Since(t).Seconds()
	fmt.Fprintf(os.Stderr, "verify %.0f ns/stamp; %.1f MH/s single core\n", verifyNs, single/1e6)
	return writeResult(*outPath, map[string]any{"machine": machine(), "cores": runtime.NumCPU(), "rows": rows, "verify_ns": math.Round(verifyNs),
		"single_core_hashes_per_sec": math.Round(single), "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

// ---------------------------------------------------------------------------
// spam: attacker model driven by the relay's actual pricing functions

func spamSim(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("spam", flag.ExitOnError)
	outPath := fs.String("out", "bench/results/spam.json", "result file")
	laptop := fs.Float64("laptop-hps", 56e6, "legitimate sender hash rate (measured on the benchmark machine, all cores)")
	fs.Parse(args)
	cfg := relay.Config{}
	def := relay.New(nil, nil, cfg, nil).Config()
	cap := int(def.MaxPendingPerRecipient)
	type attacker struct {
		Name string  `json:"name"`
		HPS  float64 `json:"hashes_per_sec"`
	}
	attackers := []attacker{{"laptop CPU", 56e6}, {"consumer GPU", 2e9}, {"high-end GPU", 2e10}, {"GPU farm", 1e12}}
	const hour = 3600.0

	// 1. Fill phase: how long until an attacker fills a recipient's stranger queue
	//    (each request needs a fresh identity: one pending request per sender/recipient pair).
	type fill struct {
		Attacker     string       `json:"attacker"`
		HPS          float64      `json:"hashes_per_sec"`
		SecondsToCap float64      `json:"seconds_to_fill"`
		Curve        [][2]float64 `json:"curve"`
		MinBitsHeld  uint8        `json:"cheapest_slot_bits"`
	}
	var fills []fill
	for _, a := range attackers {
		f := fill{Attacker: a.Name, HPS: a.HPS}
		t := 0.0
		var arrivals []float64
		f.Curve = append(f.Curve, [2]float64{0, 0})
		for n := 0; n < cap; n++ {
			recent := 0
			for _, at := range arrivals {
				if t-at < hour {
					recent++
				}
			}
			bits := relay.IntroPrice(cfg, 0, float64(n+recent), 0)
			if n == 0 {
				f.MinBitsHeld = bits
			}
			t += (math.Exp2(float64(def.RegisterBits)) + math.Exp2(float64(bits))) / a.HPS
			arrivals = append(arrivals, t)
			if n%8 == 7 || n < 8 {
				f.Curve = append(f.Curve, [2]float64{t, float64(n + 1)})
			}
		}
		f.SecondsToCap = math.Round(t*100) / 100
		fmt.Fprintf(os.Stderr, "fill: %-14s %10.2fs to fill %d slots\n", a.Name, t, cap)
		fills = append(fills, f)
	}

	// 2. Blocking a legitimate stranger. Old rule (iteration 1): a full queue
	//    rejects everyone, so blocking costs only the fill. New rule: a full
	//    queue is an auction; to keep out a sender willing to pay B bits the
	//    attacker must hold every slot at >= B bits, re-buying a slot each time
	//    one is outbid.
	type block struct {
		Bits         uint8              `json:"legit_bits"`
		LegitLaptopS float64            `json:"legit_seconds_laptop"`
		AttackerS    map[string]float64 `json:"attacker_seconds_to_block"`
		Ratio        float64            `json:"attacker_to_legit_work_ratio"`
	}
	var blocks []block
	for b := uint8(20); b <= 32; b += 2 {
		bl := block{Bits: b, LegitLaptopS: math.Round(math.Exp2(float64(b)) / *laptop * 1000) / 1000, AttackerS: map[string]float64{}}
		need := relay.AuctionPrice(cfg, 0, b-1, 0) // price a legit sender faces when the cheapest held slot has b-1 bits
		_ = need
		work := float64(cap) * math.Exp2(float64(b))
		for _, a := range attackers {
			bl.AttackerS[a.Name] = math.Round(work/a.HPS*1000) / 1000
		}
		bl.Ratio = float64(cap)
		blocks = append(blocks, bl)
	}

	// 3. Price table (fill phase) and penalties.
	var table [][2]float64
	for _, load := range []float64{0, 8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512} {
		table = append(table, [2]float64{load, float64(relay.IntroPrice(cfg, 0, load, 0))})
	}
	var penalty [][2]float64
	for d := 0; d <= 8; d++ {
		penalty = append(penalty, [2]float64{float64(d), float64(relay.IntroPrice(cfg, 0, 0, float64(d)))})
	}
	return writeResult(*outPath, map[string]any{
		"model":  "Uses the relay's IntroPrice and AuctionPrice functions. Each pending stranger request needs a fresh identity (registration stamp) because a sender may have one pending request per recipient. Trusted senders (same owner, or on the recipient owner's signed policy) pay 0 bits and bypass the queue entirely.",
		"config": map[string]any{"register_bits": def.RegisterBits, "intro_base_bits": def.IntroBaseBits, "max_surge_bits": def.MaxSurgeBits, "queue_slots": cap},
		"fill":   fills, "blocking": blocks, "price_by_load": table, "price_by_declines": penalty, "legit_hps": *laptop,
		"old_rule":  "Iteration 1: when the queue was full, every new stranger request was rejected (recipient_full), so an attacker only had to fill it once.",
		"new_rule":  "Iteration 2: full queue = auction. A legitimate stranger evicts the cheapest pending request by paying one bit more; trusted contacts never queue.",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ---------------------------------------------------------------------------
// ledger: append cost, proof size, verification time

func ledgerBench(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ledger", flag.ExitOnError)
	outPath := fs.String("out", "bench/results/ledger.json", "result file")
	maxN := fs.Int("n", 200000, "ledger size to grow to")
	fs.Parse(args)
	dir, _ := os.MkdirTemp("", "silk-ledger-bench-")
	defer os.RemoveAll(dir)
	store, err := sqlitekv.Open(filepath.Join(dir, "l.db"), sqlitekv.SQLiteOptions{Synchronous: "NORMAL"})
	if err != nil {
		return err
	}
	defer store.Close()
	type point struct {
		Size          int64   `json:"size"`
		AppendUsEach  float64 `json:"append_us_each"`
		InclusionHash int     `json:"inclusion_proof_hashes"`
		InclusionB    int     `json:"inclusion_proof_bytes"`
		ConsistencyB  int     `json:"consistency_proof_bytes"`
		VerifyUs      float64 `json:"verify_inclusion_us"`
		ProveUs       float64 `json:"prove_inclusion_us"`
		ChainProofB   int64   `json:"hash_chain_proof_bytes"`
	}
	var pts []point
	var n int64
	checkpoints := []int64{10, 100, 1000, 10000, 100000, 200000, 500000, 1000000}
	leaf := make([]byte, ledger.LeafLen)
	for _, target := range checkpoints {
		if target > int64(*maxN) {
			break
		}
		batch := int64(1000)
		t := time.Now()
		appended := int64(0)
		for n < target {
			k := batch
			if target-n < k {
				k = target - n
			}
			err := store.Update(ctx, func(tx kv.Tx) error {
				for i := int64(0); i < k; i++ {
					rand.Read(leaf[9:])
					if _, err := ledger.Append(tx, leaf); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			n += k
			appended += k
		}
		appendUs := float64(time.Since(t).Microseconds()) / float64(appended)
		var proof tlog.RecordProof
		var root tlog.Hash
		var cproof tlog.TreeProof
		var leafData []byte
		idx := n / 3
		var proveUs float64
		err := store.View(ctx, func(tx kv.Tx) error {
			var err error
			if root, err = ledger.Root(tx, n); err != nil {
				return err
			}
			t := time.Now()
			reps := 200
			for i := 0; i < reps; i++ {
				if proof, err = ledger.ProveInclusion(tx, idx, n); err != nil {
					return err
				}
			}
			proveUs = float64(time.Since(t).Microseconds()) / float64(reps)
			if cproof, err = ledger.ProveConsistency(tx, n/2+1, n); err != nil {
				return err
			}
			ls, err := ledger.Leaves(tx, idx, 1)
			leafData = ls[0]
			return err
		})
		if err != nil {
			return err
		}
		t = time.Now()
		reps := 5000
		for i := 0; i < reps; i++ {
			if err := ledger.VerifyInclusion(proof, n, root, idx, leafData); err != nil {
				return err
			}
		}
		verifyUs := float64(time.Since(t).Nanoseconds()) / float64(reps) / 1000
		p := point{Size: n, AppendUsEach: math.Round(appendUs*100) / 100, InclusionHash: len(proof), InclusionB: 32 * len(proof),
			ConsistencyB: 32 * len(cproof), VerifyUs: math.Round(verifyUs*100) / 100, ProveUs: math.Round(proveUs*100) / 100, ChainProofB: 32 * (n - idx)}
		fmt.Fprintf(os.Stderr, "n=%7d append %.1fus  proof %d hashes (%dB)  prove %.1fus  verify %.2fus\n", n, p.AppendUsEach, p.InclusionHash, p.InclusionB, p.ProveUs, p.VerifyUs)
		pts = append(pts, p)
	}
	return writeResult(*outPath, map[string]any{"points": pts, "leaf_bytes": ledger.LeafLen,
		"note":      "Append measured in 1000-leaf transactions on SQLite (synchronous=NORMAL). hash_chain_proof_bytes is what a simple hash chain would need to prove the same entry (all later links), for comparison.",
		"timestamp": time.Now().UTC().Format(time.RFC3339)})
}

// ---------------------------------------------------------------------------
// crash: kill -9 the relay under load and verify nothing acknowledged is lost

func crashTest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("crash", flag.ExitOnError)
	silk := fs.String("silk", "", "path to the silk binary")
	outPath := fs.String("out", "bench/results/crash.json", "result file")
	rounds := fs.Int("rounds", 20, "kill/restart cycles")
	workers := fs.Int("workers", 16, "concurrent senders")
	fs.Parse(args)
	dir, _ := os.MkdirTemp("", "silk-crash-")
	defer os.RemoveAll(dir)
	db := filepath.Join(dir, "relay.db")
	addr := freePort()
	start := func() (*server, error) {
		srv := &server{addr: addr, base: "http://" + addr}
		srv.cmd = execCommand(*silk, "relay", "--addr", addr, "--db", db, "--register-bits", "8", "--intro-bits", "8", "--no-ip-limits", "--bench-unlimited-rate", "--sync", "FULL")
		if err := srv.cmd.Start(); err != nil {
			return nil, err
		}
		a := newAPI(srv.base, 1)
		for i := 0; i < 2000; i++ {
			if _, _, err := a.do(ctx, "GET", "/healthz", nil, ""); err == nil {
				return srv, nil
			}
			time.Sleep(5 * time.Millisecond)
		}
		return nil, fmt.Errorf("relay did not start")
	}
	srv, err := start()
	if err != nil {
		return err
	}
	a := newAPI(srv.base, *workers)
	pairs, err := setupPairs(ctx, a, *workers, 1_000_000)
	if err != nil {
		return err
	}
	type acked struct {
		commit string
		idx    int64
	}
	var mu sync.Mutex
	var all []acked
	type roundRes struct {
		Round         int   `json:"round"`
		KilledAfterMs int64 `json:"killed_after_ms"`
		Acked         int   `json:"acknowledged"`
		Lost          int   `json:"lost"`
		Ambiguous     int   `json:"in_flight_at_kill"`
		LedgerBefore  int64 `json:"ledger_size_before_kill"`
		LedgerAfter   int64 `json:"ledger_size_after_restart"`
		Consistent    bool  `json:"consistent"`
	}
	var results []roundRes
	totalLost := 0
	for r := 1; r <= *rounds; r++ {
		var stop atomic.Bool
		var inflight atomic.Int64
		var wg sync.WaitGroup
		roundAcked := 0
		var lastCP []byte
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func(p *pair) {
				defer wg.Done()
				for !stop.Load() {
					m, err := p.sealAB([]byte(text))
					if err != nil {
						return
					}
					inflight.Add(1)
					res, err := a.submit(ctx, m.Raw)
					inflight.Add(-1)
					if err != nil {
						continue
					}
					sum := sha256.Sum256(m.Raw)
					mu.Lock()
					all = append(all, acked{hex.EncodeToString(sum[:]), res.LedgerIdx})
					roundAcked++
					mu.Unlock()
				}
			}(pairs[w])
		}
		// Grab a checkpoint shortly before the kill.
		killAfter := time.Duration(200+mrand.IntN(1300)) * time.Millisecond
		time.Sleep(killAfter / 2)
		if raw, _, err := a.do(ctx, "GET", "/v2/ledger/checkpoint", nil, ""); err == nil {
			lastCP = raw
		}
		time.Sleep(killAfter / 2)
		amb := inflight.Load()
		srv.cmd.Process.Kill() // SIGKILL: no shutdown hooks run
		srv.cmd.Wait()
		stop.Store(true)
		wg.Wait()
		srv, err = start()
		if err != nil {
			return err
		}
		a.http.CloseIdleConnections()
		// Verify every acknowledged frame is in the ledger at the index we were given.
		lost := 0
		mu.Lock()
		check := append([]acked{}, all...)
		mu.Unlock()
		for _, ak := range check {
			data, _, err := a.do(ctx, "GET", "/v2/ledger/find?commitment="+ak.commit, nil, "")
			var f struct {
				Index int64 `json:"index"`
			}
			if err != nil || json.Unmarshal(data, &f) != nil || f.Index != ak.idx {
				lost++
			}
		}
		// The new tree must extend the pre-kill checkpoint.
		rr := roundRes{Round: r, KilledAfterMs: killAfter.Milliseconds(), Acked: roundAcked, Lost: lost, Ambiguous: int(amb)}
		var info struct {
			LedgerKey string `json:"ledger_key"`
		}
		if data, _, err := a.do(ctx, "GET", "/v2/info", nil, ""); err == nil {
			json.Unmarshal(data, &info)
		}
		newRaw, _, err := a.do(ctx, "GET", "/v2/ledger/checkpoint", nil, "")
		if err == nil && lastCP != nil {
			oldCP, err1 := ledger.OpenCheckpoint(lastCP, info.LedgerKey)
			newCP, err2 := ledger.OpenCheckpoint(newRaw, info.LedgerKey)
			if err1 == nil && err2 == nil {
				rr.LedgerBefore, rr.LedgerAfter = oldCP.Size, newCP.Size
				var p relay.Proof
				if oldCP.Size == 0 || oldCP.Size == newCP.Size {
					rr.Consistent = oldCP.Size == 0 || oldCP.Root == newCP.Root
				} else if data, _, err := a.do(ctx, "GET", fmt.Sprintf("/v2/ledger/consistency?old=%d&size=%d", oldCP.Size, newCP.Size), nil, ""); err == nil && json.Unmarshal(data, &p) == nil {
					hs := make(tlog.TreeProof, len(p.Hashes))
					for i, h := range p.Hashes {
						copy(hs[i][:], h)
					}
					rr.Consistent = ledger.VerifyConsistency(hs, newCP.Size, newCP.Root, oldCP.Size, oldCP.Root) == nil
				}
			}
		}
		totalLost += lost
		fmt.Fprintf(os.Stderr, "round %2d: killed after %4dms, %5d acknowledged this round, %d total checked, lost %d, in-flight %d, ledger %d -> %d consistent=%v\n",
			r, killAfter.Milliseconds(), roundAcked, len(check), lost, amb, rr.LedgerBefore, rr.LedgerAfter, rr.Consistent)
		results = append(results, rr)
		// Re-sync sender sessions: frames in flight at the kill may or may not have landed; new frames use fresh seqs anyway.
	}
	srv.cmd.Process.Kill()
	srv.cmd.Wait()
	return writeResult(*outPath, map[string]any{"rounds": results, "total_acknowledged": len(all), "total_lost": totalLost,
		"method":    "Relay (SQLite WAL, synchronous=FULL, group commit) under 16 concurrent senders is killed with SIGKILL at a random time, restarted on the same database, and every previously acknowledged message is looked up by its SHA-256 commitment; its ledger index must match the index returned at acknowledgment. The post-restart checkpoint must be provably consistent with a checkpoint fetched before the kill.",
		"note":      strings.TrimSpace("Requests in flight at the kill have an unknown outcome to the client; the protocol makes retrying them safe (identical frames are deduplicated)."),
		"timestamp": time.Now().UTC().Format(time.RFC3339)})
}

func execCommand(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }

var _ = sort.Ints
