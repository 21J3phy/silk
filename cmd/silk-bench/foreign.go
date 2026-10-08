package main

// foreign runs another system's HTTP server under exactly the methodology of
// `compare`: fresh server per concurrency level, 100 untimed warmup sends,
// 2000 timed closed-loop sends over keep-alive connections, RSS/CPU sampled
// from the server PID, bytes counted at the socket.
//
// The system is described by a spec.json (see bench/competitors/*/spec.json):
// a launch command, a health path, and request templates for setup, send,
// receive and ack. Templates may use {PORT}, {W} (worker index), {ID} (fresh
// per request), {N} (request counter), {TEXT}, and variables captured from
// earlier responses.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
)

type capture struct {
	From string `json:"from"` // "header" or "json"
	Name string `json:"name"` // header name, or dotted JSON path (numbers index arrays)
	Var  string `json:"var"`
}

type reqTmpl struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	Capture []capture         `json:"capture"`
	As      string            `json:"as"` // "sender" (default) or "recipient" connection
}

type foreignSpec struct {
	System       string            `json:"system"`
	Version      string            `json:"version"`
	Language     string            `json:"language"`
	Launch       []string          `json:"launch"`
	Env          map[string]string `json:"env"`
	Health       string            `json:"health"`
	Setup        []reqTmpl         `json:"per_worker_setup"`
	Send         *reqTmpl          `json:"send"`
	Receive      *reqTmpl          `json:"receive"`
	Ack          *reqTmpl          `json:"ack"`
	InstallPaths []string          `json:"install_paths"`
	Notes        string            `json:"notes"`
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func subst(s string, vars map[string]string) string {
	if !strings.Contains(s, "{") {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

// jsonPath walks a dotted path through decoded JSON.
func jsonPath(v any, path string) (any, bool) {
	for _, p := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, v != nil
}

// sseData returns the last "data:" payload of an event-stream body.
func sseData(b []byte) []byte {
	var last []byte
	for _, line := range strings.Split(string(b), "\n") {
		if d, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "data:"); ok {
			last = []byte(strings.TrimSpace(d))
		}
	}
	return last
}

// worker holds one simulated client: its connections and captured variables.
type worker struct {
	sender, recipient *api
	vars              map[string]string
	n                 int
}

func (sp *foreignSpec) do(ctx context.Context, w *worker, t *reqTmpl) error {
	w.n++
	w.vars["ID"], w.vars["N"] = newID(), strconv.Itoa(w.n)
	a := w.sender
	if t.As == "recipient" {
		a = w.recipient
	}
	var body io.Reader
	if len(t.Body) > 0 {
		body = strings.NewReader(subst(string(t.Body), w.vars))
	}
	req, err := http.NewRequestWithContext(ctx, t.Method, a.base+subst(t.Path, w.vars), body)
	if err != nil {
		return err
	}
	for k, v := range t.Headers {
		req.Header.Set(k, subst(v, w.vars))
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return &apiErr{resp.StatusCode, string(data)}
	}
	var decoded any
	decodedOK := false
	for _, c := range t.Capture {
		switch c.From {
		case "header":
			w.vars[c.Var] = resp.Header.Get(c.Name)
		case "json":
			if !decodedOK {
				js := data
				if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
					js = sseData(data)
				}
				if err := json.Unmarshal(js, &decoded); err != nil {
					return fmt.Errorf("capture %s: %w", c.Var, err)
				}
				decodedOK = true
			}
			v, ok := jsonPath(decoded, c.Name)
			if !ok {
				return fmt.Errorf("capture %s: no %s in %s", c.Var, c.Name, truncate(data, 300))
			}
			switch x := v.(type) {
			case string:
				w.vars[c.Var] = x
			default:
				b, _ := json.Marshal(x)
				w.vars[c.Var] = string(b)
			}
		}
	}
	// JSON-RPC errors arrive with HTTP 200.
	if bytesContainsRPCError(data) {
		return fmt.Errorf("json-rpc error: %s", truncate(data, 300))
	}
	return nil
}

func bytesContainsRPCError(b []byte) bool {
	s := string(b)
	return strings.Contains(s, `"error":{`) || strings.Contains(s, `"error": {`) || strings.Contains(s, `"isError":true`) || strings.Contains(s, `"isError": true`)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

func (sp *foreignSpec) start(port string) (*server, time.Duration, error) {
	dir, err := os.MkdirTemp("", "silk-bench-foreign-")
	if err != nil {
		return nil, 0, err
	}
	vars := map[string]string{"PORT": port, "DATADIR": dir}
	args := make([]string, len(sp.Launch))
	for i, a := range sp.Launch {
		args[i] = subst(a, vars)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range sp.Env {
		cmd.Env = append(cmd.Env, k+"="+subst(v, vars))
	}
	logf, _ := os.Create(filepath.Join(dir, "server.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	s := &server{cmd: cmd, dir: dir, base: "http://127.0.0.1:" + port}
	hc := &http.Client{Timeout: time.Second}
	for time.Since(t0) < 60*time.Second {
		resp, err := hc.Get(s.base + sp.Health)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return s, time.Since(t0), nil
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "server.log"))
	s.stop()
	return nil, 0, fmt.Errorf("%s did not become healthy: %s", sp.System, truncate(log, 2000))
}

func (sp *foreignSpec) newWorker(ctx context.Context, base string, idx, conns int) (*worker, error) {
	w := &worker{sender: newAPI(base, conns), recipient: newAPI(base, conns), vars: map[string]string{"W": strconv.Itoa(idx), "TEXT": text}}
	for i := range sp.Setup {
		if err := sp.do(ctx, w, &sp.Setup[i]); err != nil {
			return nil, fmt.Errorf("setup step %d: %w", i, err)
		}
	}
	return w, nil
}

func (sp *foreignSpec) level(ctx context.Context, c, warmup, n int) (*throughputLevel, float64, float64, float64, error) {
	port := strings.Split(freePort(), ":")[1]
	srv, _, err := sp.start(port)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer srv.stop()
	workers := make([]*worker, c)
	for i := range workers {
		if workers[i], err = sp.newWorker(ctx, srv.base, i, 1); err != nil {
			return nil, 0, 0, 0, err
		}
	}
	time.Sleep(time.Second)
	idleRSS, _, _ := procStat(srv.cmd.Process.Pid)
	mon := monitor(srv.cmd.Process.Pid)
	var next, warmCount atomic.Int64
	total := int64(warmup + n)
	warmDone := make(chan struct{})
	if warmup == 0 {
		close(warmDone)
	}
	lat := make([]float64, 0, n)
	var mu sync.Mutex
	errs := 0
	var firstErr error
	var cpuStart float64
	var t0 time.Time
	var once sync.Once
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(w *worker) {
			defer wg.Done()
			for {
				slot := next.Add(1) - 1
				if slot >= total {
					return
				}
				if slot >= int64(warmup) {
					<-warmDone
					once.Do(func() {
						_, cpuStart, _ = procStat(srv.cmd.Process.Pid)
						t0 = time.Now()
					})
				}
				st := time.Now()
				err := sp.do(ctx, w, sp.Send)
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
					if firstErr == nil {
						firstErr = err
					}
				} else {
					lat = append(lat, float64(d.Microseconds())/1000)
				}
				mu.Unlock()
			}
		}(workers[i])
	}
	wg.Wait()
	elapsed := time.Since(t0)
	_, cpuEnd, _ := procStat(srv.cmd.Process.Pid)
	peak := mon.finish()
	if firstErr != nil {
		fmt.Fprintf(os.Stderr, "  first error at c=%d: %v\n", c, firstErr)
	}
	if len(lat) == 0 {
		return nil, 0, 0, 0, fmt.Errorf("no successful sends: %v", firstErr)
	}
	p := percentiles(lat)
	lv := &throughputLevel{Concurrency: c, Requests: n, Seconds: math.Round(elapsed.Seconds()*1000) / 1000,
		MsgsPerSec: math.Round(float64(len(lat))/elapsed.Seconds()*10) / 10, P50: p.P50, P90: p.P90, P99: p.P99, Errors: errs}
	return lv, idleRSS, peak, (cpuEnd - cpuStart) * 1000 / float64(len(lat)), nil
}

func (sp *foreignSpec) roundtrip(ctx context.Context, samples int) (pct, map[string]int64, error) {
	port := strings.Split(freePort(), ":")[1]
	srv, _, err := sp.start(port)
	if err != nil {
		return pct{}, nil, err
	}
	defer srv.stop()
	w, err := sp.newWorker(ctx, srv.base, 0, 1)
	if err != nil {
		return pct{}, nil, err
	}
	bytesNow := func() int64 {
		return w.sender.sent.Load() + w.sender.rx.Load() + w.recipient.sent.Load() + w.recipient.rx.Load()
	}
	var out []float64
	var sendBytes, rtBytes int64
	for i := 0; i < samples+10; i++ {
		b0 := bytesNow()
		t0 := time.Now()
		if err := sp.do(ctx, w, sp.Send); err != nil {
			return pct{}, nil, fmt.Errorf("send: %w", err)
		}
		b1 := bytesNow()
		for _, t := range []*reqTmpl{sp.Receive, sp.Ack} {
			if t != nil {
				if err := sp.do(ctx, w, t); err != nil {
					return pct{}, nil, err
				}
			}
		}
		d := time.Since(t0)
		if i >= 10 {
			out = append(out, float64(d.Microseconds())/1000)
			sendBytes, rtBytes = b1-b0, bytesNow()-b0
		}
	}
	return percentiles(out), map[string]int64{"send": sendBytes, "roundtrip": rtBytes}, nil
}

func duMB(paths []string) float64 {
	total := 0.0
	for _, p := range paths {
		out, err := exec.Command("du", "-sk", p).Output()
		if err != nil {
			continue
		}
		f := strings.Fields(string(out))
		if len(f) > 0 {
			kb, _ := strconv.ParseFloat(f[0], 64)
			total += kb / 1024
		}
	}
	return math.Round(total*10) / 10
}

func foreign(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("foreign", flag.ExitOnError)
	specPath := fs.String("spec", "", "path to spec.json")
	outPath := fs.String("out", "", "result file")
	n := fs.Int("requests", 2000, "timed requests per level")
	warm := fs.Int("warmup", 100, "untimed warmup requests per level")
	samples := fs.Int("samples", 300, "roundtrip samples")
	levels := fs.String("levels", "1,4,16,64", "client concurrency levels")
	fs.Parse(args)
	raw, err := os.ReadFile(*specPath)
	if err != nil {
		return err
	}
	var sp foreignSpec
	if err := json.Unmarshal(raw, &sp); err != nil {
		return err
	}
	res := &result{System: sp.System, Language: sp.Language, Machine: machine(), Timestamp: time.Now().UTC().Format(time.RFC3339),
		WireBytes: map[string]int64{}, RSSMB: map[string]float64{}, Extra: map[string]any{"version": sp.Version, "driver": "silk-bench foreign " + runtime.Version()}}
	var idle []float64
	peak := 0.0
	for _, ls := range strings.Split(*levels, ",") {
		c, _ := strconv.Atoi(ls)
		lv, idleRSS, pk, cpuMs, err := sp.level(ctx, c, *warm, *n)
		if err != nil {
			return fmt.Errorf("level %d: %w", c, err)
		}
		fmt.Fprintf(os.Stderr, "%s c=%-3d %8.1f msg/s  p50 %.2fms  p99 %.2fms  errors %d  peak %.1fMB  cpu %.3fms/msg\n",
			sp.System, c, lv.MsgsPerSec, lv.P50, lv.P99, lv.Errors, pk, cpuMs)
		res.SendThroughput = append(res.SendThroughput, *lv)
		idle = append(idle, idleRSS)
		peak = math.Max(peak, pk)
		if c == 16 {
			res.CPUMsPerMsg = math.Round(cpuMs*1000) / 1000
		}
	}
	sort.Float64s(idle)
	res.RSSMB["idle"] = math.Round(quantile(idle, .5)*10) / 10
	res.RSSMB["peak"] = math.Round(peak*10) / 10
	if res.RoundtripMs, res.WireBytes, err = sp.roundtrip(ctx, *samples); err != nil {
		return fmt.Errorf("roundtrip: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s roundtrip p50 %.2fms p99 %.2fms; bytes send %d roundtrip %d\n", sp.System, res.RoundtripMs.P50, res.RoundtripMs.P99, res.WireBytes["send"], res.WireBytes["roundtrip"])
	var colds []float64
	for range 5 {
		srv, d, err := sp.start(strings.Split(freePort(), ":")[1])
		if err != nil {
			return err
		}
		srv.stop()
		colds = append(colds, float64(d.Microseconds())/1000)
	}
	sort.Float64s(colds)
	res.ColdStartMs = math.Round(quantile(colds, .5)*10) / 10
	res.Extra["cold_start_runs_ms"] = colds
	res.InstallMB = duMB(sp.InstallPaths)
	res.Notes = []string{sp.Notes, "Same driver and method as the Silk v2 run (silk-bench compare): fresh server per level, 100 untimed warmup sends, 2000 timed closed-loop sends, one keep-alive connection per client, server RSS/CPU from ps, bytes counted at the socket."}
	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*outPath, append(b, '\n'), 0o644)
}

// external runs a system whose client logic must run in its own driver
// program (for example a library-only end-to-end encryption client): the
// server is launched and sampled exactly as in `foreign`, and the driver
// reports send latencies and throughput as JSON ({"level": {...},
// "roundtrip_pct": {...}} with silk-bench's keys).
func external(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("external", flag.ExitOnError)
	specPath := fs.String("spec", "", "path to spec.json (launch, health, install_paths)")
	driver := fs.String("driver", "", "driver command; {URL} {N} {C} {WARMUP} {RT} {RTWARM} are substituted")
	outPath := fs.String("out", "", "result file")
	n := fs.Int("requests", 2000, "timed requests per level")
	warm := fs.Int("warmup", 100, "untimed warmup requests per level")
	samples := fs.Int("samples", 300, "roundtrip samples")
	levels := fs.String("levels", "1,4,16,64", "client concurrency levels")
	fs.Parse(args)
	raw, err := os.ReadFile(*specPath)
	if err != nil {
		return err
	}
	var sp foreignSpec
	if err := json.Unmarshal(raw, &sp); err != nil {
		return err
	}
	type driverOut struct {
		Level     throughputLevel `json:"level"`
		Roundtrip pct             `json:"roundtrip_pct"`
	}
	runDriver := func(url string, c, n, warmup, rt, rtWarm int) (*driverOut, error) {
		vars := map[string]string{"URL": url, "N": strconv.Itoa(n), "C": strconv.Itoa(c), "WARMUP": strconv.Itoa(warmup),
			"RT": strconv.Itoa(rt), "RTWARM": strconv.Itoa(rtWarm)}
		argv := strings.Fields(subst(*driver, vars))
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Dir = os.TempDir()
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("driver: %v: %s", err, truncate([]byte(stderr.String()), 2000))
		}
		var d driverOut
		if err := json.Unmarshal(out, &d); err != nil {
			return nil, fmt.Errorf("driver output: %v: %s", err, truncate(out, 500))
		}
		return &d, nil
	}
	res := &result{System: sp.System, Language: sp.Language, Machine: machine(), Timestamp: time.Now().UTC().Format(time.RFC3339),
		WireBytes: map[string]int64{}, RSSMB: map[string]float64{}, Extra: map[string]any{"version": sp.Version, "driver": *driver}}
	var idle []float64
	peak := 0.0
	for _, ls := range strings.Split(*levels, ",") {
		c, _ := strconv.Atoi(ls)
		port := strings.Split(freePort(), ":")[1]
		srv, _, err := sp.start(port)
		if err != nil {
			return err
		}
		time.Sleep(time.Second)
		idleRSS, cpu0, _ := procStat(srv.cmd.Process.Pid)
		mon := monitor(srv.cmd.Process.Pid)
		d, err := runDriver(srv.base, c, *n, *warm, 1, 0)
		_, cpu1, _ := procStat(srv.cmd.Process.Pid)
		pk := mon.finish()
		srv.stop()
		if err != nil {
			return fmt.Errorf("level %d: %w", c, err)
		}
		// Server CPU covers setup, warmup and the timed sends; scale to the timed share.
		cpuMs := (cpu1 - cpu0) * 1000 / float64(*n+*warm)
		fmt.Fprintf(os.Stderr, "%s c=%-3d %8.1f msg/s  p50 %.2fms  p99 %.2fms  errors %d  peak %.1fMB  cpu %.3fms/msg\n",
			sp.System, c, d.Level.MsgsPerSec, d.Level.P50, d.Level.P99, d.Level.Errors, pk, cpuMs)
		res.SendThroughput = append(res.SendThroughput, d.Level)
		idle = append(idle, idleRSS)
		peak = math.Max(peak, pk)
		if c == 16 {
			res.CPUMsPerMsg = math.Round(cpuMs*1000) / 1000
		}
	}
	sort.Float64s(idle)
	res.RSSMB["idle"] = math.Round(quantile(idle, .5)*10) / 10
	res.RSSMB["peak"] = math.Round(peak*10) / 10
	port := strings.Split(freePort(), ":")[1]
	srv, _, err := sp.start(port)
	if err != nil {
		return err
	}
	// Route the roundtrip run through a byte-counting proxy: every byte both
	// clients exchange with the server, divided by messages delivered.
	proxy, total, err := countingProxy("127.0.0.1:" + port)
	if err != nil {
		srv.stop()
		return err
	}
	d, err := runDriver("http://"+proxy, 1, 1, 0, *samples, 10)
	srv.stop()
	if err != nil {
		return fmt.Errorf("roundtrip: %w", err)
	}
	res.RoundtripMs = d.Roundtrip
	res.WireBytes["roundtrip"] = total.Load() / int64(*samples+10+1)
	var colds []float64
	for range 5 {
		srv, dur, err := sp.start(strings.Split(freePort(), ":")[1])
		if err != nil {
			return err
		}
		srv.stop()
		colds = append(colds, float64(dur.Microseconds())/1000)
	}
	sort.Float64s(colds)
	res.ColdStartMs = math.Round(quantile(colds, .5)*10) / 10
	res.Extra["cold_start_runs_ms"] = colds
	res.InstallMB = duMB(sp.InstallPaths)
	res.Notes = []string{sp.Notes, "Server launched and sampled exactly as in silk-bench foreign; sends driven by the system's own client library (" + *driver + ")."}
	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*outPath, append(b, '\n'), 0o644)
}

// countingProxy forwards TCP connections to target and counts bytes both ways.
func countingProxy(target string) (string, *atomic.Int64, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	total := &atomic.Int64{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				pipe := func(dst, src net.Conn) {
					n, _ := io.Copy(dst, src)
					total.Add(n)
					if tc, ok := dst.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					done <- struct{}{}
				}
				go pipe(up, c)
				go pipe(c, up)
				<-done
				<-done
			}()
		}
	}()
	return l.Addr().String(), total, nil
}
