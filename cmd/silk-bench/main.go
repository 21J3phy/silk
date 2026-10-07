// Command silk-bench measures the Silk v2 relay with the same methodology as
// the v1 baselines in bench/v1 (fresh server + empty database per level,
// 100 untimed warmup sends, 2000 timed closed-loop sends over keep-alive
// connections, requests built before timing, the same 57-character text).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

const text = "Can we coordinate a time? This is untrusted message data." // same 57 characters as bench/v1

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: silk-bench compare|pow|spam|ledger|crash [flags]")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "compare":
		err = compare(ctx, os.Args[2:])
	case "pow":
		err = powBench(ctx, os.Args[2:])
	case "spam":
		err = spamSim(ctx, os.Args[2:])
	case "ledger":
		err = ledgerBench(ctx, os.Args[2:])
	case "crash":
		err = crashTest(ctx, os.Args[2:])
	case "pgrtt":
		err = pgRoundTrips(ctx, os.Args[2:])
	case "live":
		err = liveBench(ctx, os.Args[2:])
	case "load":
		err = loadExisting(ctx, os.Args[2:])
	case "memprobe":
		err = memProbe(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "silk-bench:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// statistics (same definition as Python statistics.quantiles(method="inclusive"))

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	if lo >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(lo)
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

type pct struct {
	Samples int     `json:"samples,omitempty"`
	P50     float64 `json:"p50"`
	P90     float64 `json:"p90"`
	P99     float64 `json:"p99"`
	Mean    float64 `json:"mean"`
}

func percentiles(ms []float64) pct {
	s := append([]float64{}, ms...)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	r := func(v float64) float64 { return math.Round(v*1000) / 1000 }
	return pct{Samples: len(s), P50: r(quantile(s, .5)), P90: r(quantile(s, .9)), P99: r(quantile(s, .99)), Mean: r(sum / float64(len(s)))}
}

// ---------------------------------------------------------------------------
// relay process management

type server struct {
	cmd  *exec.Cmd
	addr string
	dir  string
	base string
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func startRelay(silk string, extra ...string) (*server, time.Duration, error) {
	dir, err := os.MkdirTemp("", "silk-bench-v2-")
	if err != nil {
		return nil, 0, err
	}
	addr := freePort()
	args := append([]string{"relay", "--addr", addr, "--db", filepath.Join(dir, "relay.db"), "--register-bits", "8",
		"--intro-bits", "8", "--no-ip-limits", "--bench-unlimited-rate"}, extra...)
	cmd := exec.Command(silk, args...)
	cmd.Stdout, cmd.Stderr = nil, nil
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	s := &server{cmd: cmd, addr: addr, dir: dir, base: "http://" + addr}
	hc := &http.Client{Timeout: time.Second}
	for time.Since(start) < 10*time.Second {
		resp, err := hc.Get(s.base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return s, time.Since(start), nil
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.stop()
	return nil, 0, fmt.Errorf("relay did not become healthy")
}

func (s *server) stop() {
	if s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}
	os.RemoveAll(s.dir)
}

// procStat returns RSS (MB) and cumulative CPU seconds for a pid via ps.
func procStat(pid int) (rssMB, cpuS float64, err error) {
	out, err := exec.Command("ps", "-o", "rss=,time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("unexpected ps output %q", out)
	}
	kb, _ := strconv.ParseFloat(f[0], 64)
	// time is [[dd-]hh:]mm:ss.cc
	var secs float64
	parts := strings.Split(f[1], ":")
	for _, p := range parts {
		v, _ := strconv.ParseFloat(p, 64)
		secs = secs*60 + v
	}
	return kb / 1024, secs, nil
}

type rssMonitor struct {
	peak atomic.Uint64 // MB * 1000
	stop chan struct{}
	done chan struct{}
}

func monitor(pid int) *rssMonitor {
	m := &rssMonitor{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(m.done)
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			if rss, _, err := procStat(pid); err == nil {
				v := uint64(rss * 1000)
				for {
					old := m.peak.Load()
					if v <= old || m.peak.CompareAndSwap(old, v) {
						break
					}
				}
			}
			select {
			case <-m.stop:
				return
			case <-t.C:
			}
		}
	}()
	return m
}

func (m *rssMonitor) finish() float64 {
	close(m.stop)
	<-m.done
	return float64(m.peak.Load()) / 1000
}

// ---------------------------------------------------------------------------
// compare

type throughputLevel struct {
	Concurrency int     `json:"concurrency"`
	Requests    int     `json:"requests"`
	Seconds     float64 `json:"seconds"`
	MsgsPerSec  float64 `json:"msgs_per_sec"`
	P50         float64 `json:"p50_ms"`
	P90         float64 `json:"p90_ms"`
	P99         float64 `json:"p99_ms"`
	Errors      int     `json:"errors"`
	Batches     int64   `json:"-"`
}

type result struct {
	System           string            `json:"system"`
	Language         string            `json:"language"`
	Machine          map[string]any    `json:"machine"`
	Timestamp        string            `json:"timestamp"`
	LimitsOverridden []string          `json:"limits_overridden"`
	SendThroughput   []throughputLevel `json:"send_throughput"`
	RoundtripMs      pct               `json:"roundtrip_ms"`
	WireBytes        map[string]int64  `json:"wire_bytes"`
	RSSMB            map[string]float64 `json:"rss_mb"`
	CPUMsPerMsg      float64           `json:"cpu_ms_per_msg"`
	ColdStartMs      float64           `json:"cold_start_ms"`
	InstallMB        float64           `json:"install_mb"`
	Extra            map[string]any    `json:"extra,omitempty"`
	Notes            []string          `json:"notes"`
}

func machine() map[string]any {
	cpu, _ := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	osv, _ := exec.Command("sw_vers", "-productVersion").Output()
	return map[string]any{"cpu": strings.TrimSpace(string(cpu)), "cores": runtime.NumCPU(), "os": "macOS " + strings.TrimSpace(string(osv))}
}

func setupPairs(ctx context.Context, a *api, n int, budget uint32) ([]*pair, error) {
	pairs := make([]*pair, n)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	sem := make(chan struct{}, 8)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			x, err := newAgent(ctx, a, fmt.Sprintf("s%d", i), 8)
			if err != nil {
				errs <- err
				return
			}
			y, err := newAgent(ctx, a, fmt.Sprintf("r%d", i), 8)
			if err != nil {
				errs <- err
				return
			}
			p, err := handshake(ctx, a, x, y, budget)
			if err != nil {
				errs <- err
				return
			}
			pairs[i] = p
		}(i)
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	return pairs, nil
}

func runLevel(ctx context.Context, silk string, c, warmup, n int, extra []string) (*throughputLevel, float64, float64, float64, error) {
	srv, _, err := startRelay(silk, extra...)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer srv.stop()
	a := newAPI(srv.base, c)
	pairs, err := setupPairs(ctx, a, c, uint32(warmup+n+10))
	_ = pairs
	if err != nil {
		return nil, 0, 0, 0, err
	}
	// Pre-build frames: each worker owns one pair.
	per := (warmup + n + c - 1) / c
	frames := make([][][]byte, c)
	for w := 0; w < c; w++ {
		for i := 0; i < per+1; i++ {
			m, err := pairs[w].sealAB([]byte(text))
			if err != nil {
				return nil, 0, 0, 0, err
			}
			frames[w] = append(frames[w], m.Raw)
		}
	}
	time.Sleep(time.Second)
	idleRSS, _, _ := procStat(srv.cmd.Process.Pid)
	mon := monitor(srv.cmd.Process.Pid)
	// Closed loop: a shared counter hands out request slots; warmup slots are untimed.
	var next atomic.Int64
	total := int64(warmup + n)
	lat := make([]float64, 0, n)
	var mu sync.Mutex
	errs := 0
	var cpuStart float64
	var t0 time.Time
	var startOnce sync.Once
	var wg sync.WaitGroup
	warmDone := make(chan struct{})
	var warmCount atomic.Int64
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			idx := 0
			for {
				slot := next.Add(1) - 1
				if slot >= total {
					return
				}
				if slot == int64(warmup) {
					// wait for every warmup request to finish before timing starts
					<-warmDone
				} else if slot > int64(warmup) {
					<-warmDone
				}
				if slot >= int64(warmup) {
					startOnce.Do(func() {
						_, cpuStart, _ = procStat(srv.cmd.Process.Pid)
						t0 = time.Now()
					})
				}
				var f []byte
				if idx < len(frames[w]) {
					f = frames[w][idx]
				} else {
					m, err := pairs[w].sealAB([]byte(text)) // rare: this worker took more than its share of slots
					if err != nil {
						return
					}
					f = m.Raw
				}
				idx++
				st := time.Now()
				_, err := a.submit(ctx, f)
				d := time.Since(st)
				if slot < int64(warmup) {
					if warmCount.Add(1) == int64(warmup) {
						close(warmDone)
					}
					continue
				}
				mu.Lock()
				if err != nil {
					errs++
				} else {
					lat = append(lat, float64(d.Microseconds())/1000)
				}
				mu.Unlock()
			}
		}(w)
	}
	if warmup == 0 {
		close(warmDone)
	}
	wg.Wait()
	elapsed := time.Since(t0)
	_, cpuEnd, _ := procStat(srv.cmd.Process.Pid)
	peak := mon.finish()
	p := percentiles(lat)
	lv := &throughputLevel{Concurrency: c, Requests: n, Seconds: math.Round(elapsed.Seconds()*1000) / 1000,
		MsgsPerSec: math.Round(float64(len(lat))/elapsed.Seconds()*10) / 10, P50: p.P50, P90: p.P90, P99: p.P99, Errors: errs}
	cpuMs := (cpuEnd - cpuStart) * 1000 / float64(len(lat))
	return lv, idleRSS, peak, cpuMs, nil
}

func roundtrip(ctx context.Context, silk string, samples int) (pct, map[string]int64, error) {
	srv, _, err := startRelay(silk)
	if err != nil {
		return pct{}, nil, err
	}
	defer srv.stop()
	sender := newAPI(srv.base, 1)
	recv := newAPI(srv.base, 1)
	ps, err := setupPairs(ctx, sender, 1, uint32(samples+20))
	if err != nil {
		return pct{}, nil, err
	}
	p := ps[0]
	var out []float64
	var sendBytes, rtBytes int64
	for i := 0; i < samples+10; i++ {
		s0, r0 := sender.sent.Load()+sender.rx.Load(), recv.sent.Load()+recv.rx.Load()
		t0 := time.Now()
		m, err := p.sealAB([]byte(text))
		if err != nil {
			return pct{}, nil, err
		}
		if _, err := sender.submit(ctx, m.Raw); err != nil {
			return pct{}, nil, err
		}
		s1 := sender.sent.Load() + sender.rx.Load()
		path := fmt.Sprintf("/v2/inbox?after=%d&limit=100", p.cursorB)
		data, _, err := recv.do(ctx, "GET", path, nil, p.b.auth("GET", path))
		if err != nil {
			return pct{}, nil, err
		}
		evs, err := relay.DecodeEvents(data)
		if err != nil || len(evs) == 0 {
			return pct{}, nil, fmt.Errorf("message not in inbox (%v)", err)
		}
		var got *wire.Msg
		for _, ev := range evs {
			p.cursorB = ev.Seq
			if ev.Kind == wire.KindMsg {
				mm, err := wire.DecodeMsg(ev.Frame)
				if err != nil {
					return pct{}, nil, err
				}
				if _, _, err := p.sessB.Decrypt(mm); err != nil {
					return pct{}, nil, err
				}
				if mm.ID() == m.ID() {
					got = mm
				}
			}
		}
		if got == nil {
			return pct{}, nil, fmt.Errorf("sent message not received")
		}
		if _, err := recv.submit(ctx, p.ackFrame(got)); err != nil {
			return pct{}, nil, err
		}
		d := time.Since(t0)
		if i >= 10 {
			out = append(out, float64(d.Microseconds())/1000)
			sendBytes = s1 - s0
			rtBytes = (sender.sent.Load() + sender.rx.Load() - s0) + (recv.sent.Load() + recv.rx.Load() - r0)
		}
	}
	return percentiles(out), map[string]int64{"send": sendBytes, "roundtrip": rtBytes}, nil
}

func compare(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	silk := fs.String("silk", "", "path to the silk binary (stripped release build)")
	outPath := fs.String("out", "bench/results/v2-relay.json", "result file")
	n := fs.Int("requests", 2000, "timed requests per level")
	warm := fs.Int("warmup", 100, "untimed warmup requests per level")
	samples := fs.Int("samples", 300, "roundtrip samples")
	levels := fs.String("levels", "1,4,16,64", "client concurrency levels")
	system := fs.String("system", "v2-relay", "system name in results")
	relayArgs := fs.String("relay-args", "", "extra relay flags (space separated), e.g. --max-batch 1")
	fs.Parse(args)
	if *silk == "" {
		return fmt.Errorf("--silk is required")
	}
	var extra []string
	if *relayArgs != "" {
		extra = strings.Fields(*relayArgs)
	}
	res := &result{System: *system, Language: runtime.Version(), Machine: machine(), Timestamp: time.Now().UTC().Format(time.RFC3339),
		LimitsOverridden: []string{
			"relay --bench-unlimited-rate: per-conversation messages-per-minute window not enforced (protocol maximum is 600/min per direction); budget, sequence, signature, expiry, inbox-capacity checks all still run",
			"relay --no-ip-limits: per-IP token bucket (30 POST/s, 60 GET/s per address) disabled because all load comes from 127.0.0.1",
			"relay --register-bits 8 --intro-bits 8: proof-of-work for untimed setup (registration, contact requests) lowered from 22/20 bits; message sends never require proof of work",
		},
		WireBytes: map[string]int64{}, RSSMB: map[string]float64{}, Extra: map[string]any{}}
	if *relayArgs != "" {
		res.LimitsOverridden = append(res.LimitsOverridden, "extra relay flags: "+*relayArgs)
	}
	var idle []float64
	peak := 0.0
	for _, ls := range strings.Split(*levels, ",") {
		c, _ := strconv.Atoi(ls)
		lv, idleRSS, pk, cpuMs, err := runLevel(ctx, *silk, c, *warm, *n, extra)
		if err != nil {
			return fmt.Errorf("level %d: %w", c, err)
		}
		fmt.Fprintf(os.Stderr, "c=%-3d %8.1f msg/s  p50 %.2fms  p90 %.2fms  p99 %.2fms  errors %d  peak %.1fMB  cpu %.3fms/msg\n",
			c, lv.MsgsPerSec, lv.P50, lv.P90, lv.P99, lv.Errors, pk, cpuMs)
		res.SendThroughput = append(res.SendThroughput, *lv)
		idle = append(idle, idleRSS)
		if pk > peak {
			peak = pk
		}
		if c == 16 {
			res.CPUMsPerMsg = math.Round(cpuMs*1000) / 1000
		}
	}
	sort.Float64s(idle)
	res.RSSMB["idle"] = math.Round(quantile(idle, .5)*10) / 10
	res.RSSMB["peak"] = math.Round(peak*10) / 10
	rt, wb, err := roundtrip(ctx, *silk, *samples)
	if err != nil {
		return fmt.Errorf("roundtrip: %w", err)
	}
	res.RoundtripMs, res.WireBytes = rt, wb
	fmt.Fprintf(os.Stderr, "roundtrip p50 %.2fms p90 %.2fms p99 %.2fms; wire send %dB roundtrip %dB\n", rt.P50, rt.P90, rt.P99, wb["send"], wb["roundtrip"])
	var colds []float64
	for i := 0; i < 5; i++ {
		srv, d, err := startRelay(*silk)
		if err != nil {
			return err
		}
		srv.stop()
		colds = append(colds, float64(d.Microseconds())/1000)
	}
	sort.Float64s(colds)
	res.ColdStartMs = math.Round(quantile(colds, .5)*10) / 10
	if fi, err := os.Stat(*silk); err == nil {
		res.InstallMB = math.Round(float64(fi.Size())/(1<<20)*10) / 10
	}
	res.Extra["cold_start_runs_ms"] = colds
	res.Notes = []string{
		"Server: `silk relay` (Go, net/http HTTP/1.1 keep-alive) as a separate process, SQLite (modernc.org/sqlite, pure Go) in WAL mode with synchronous=FULL, group commit (one writer goroutine batches concurrent writes into one transaction/fsync, each isolated by a savepoint).",
		"Every send is a real protocol frame: AES-256-GCM ciphertext under a ratcheted per-message key from a post-quantum hybrid (ML-KEM-768 + X25519) HPKE handshake, Ed25519 signature verified by the relay, sequence/budget/expiry checks, inbox event, and an RFC 6962 transparency-ledger append in the same transaction. The relay never sees plaintext.",
		"Throughput: fresh relay + empty DB per level; 100 untimed warmup sends then 2000 timed closed-loop sends; each client worker owns one conversation and one keep-alive connection; frames encrypted and signed before timing (as v1 pre-signs).",
		"Roundtrip: per sample t0 -> encrypt+sign (timed) -> POST /v2/frames -> recipient GET /v2/inbox (signed Silk-Auth) -> decrypt -> sign+POST ack -> t1; sequential over two keep-alive connections, like the v1 mailbox roundtrip. 10 untimed warmup samples.",
		"wire_bytes: HTTP bytes counted at the socket (request line + headers + body, status line + headers + body).",
		"rss_mb idle = median over the per-level servers 1 s after setup; peak = max RSS sampled every 20 ms via ps during the timed run.",
		"cpu_ms_per_msg: relay user+sys CPU (ps cputime, 10 ms resolution) over the c=16 timed run divided by accepted sends.",
		"cold_start_ms: spawn `silk relay` with a new DB until first HTTP 200 from /healthz (probe every 2 ms), median of 5. install_mb: size of the single static `silk` binary (no runtime or dependencies needed).",
		"Machine was not otherwise idle; same desktop conditions as the v1 runs.",
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*outPath, append(b, '\n'), 0o644)
}
