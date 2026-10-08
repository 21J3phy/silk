package main

// liveagents measures Silk the way an agent uses it: two real `silk mcp`
// processes (stdio MCP, as Claude Code or Codex run them) with separate
// homes, talking through the hosted relay. It mirrors the XMTP measurement in
// bench/competitors/xmtp so the two can be compared.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mcpProc is a `silk mcp` child process driven over stdio JSON-RPC.
type mcpProc struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	id  int
	mu  sync.Mutex
}

func startMCP(silk, home string) (*mcpProc, time.Duration, error) {
	cmd := exec.Command(silk, "mcp")
	cmd.Env = append(os.Environ(), "SILK_HOME="+home)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, 0, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	p := &mcpProc{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}
	if _, err := p.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "silk-bench", "version": "1"}}); err != nil {
		p.stop()
		return nil, 0, err
	}
	ready := time.Since(t0)
	fmt.Fprintln(p.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return p, ready, nil
}

func (p *mcpProc) call(method string, params any) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.id++
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": p.id, "method": method, "params": params})
	if _, err := p.in.Write(append(req, '\n')); err != nil {
		return nil, err
	}
	for {
		line, err := p.out.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(line, &resp) != nil || resp.ID != p.id {
			continue // notifications
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s", method, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

// tool calls an MCP tool and returns its structured (JSON text) result.
func (p *mcpProc) tool(name string, args map[string]any) (map[string]any, error) {
	raw, err := p.call("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Structured map[string]any `json:"structuredContent"`
		IsError    bool           `json:"isError"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.IsError {
		msg := ""
		if len(r.Content) > 0 {
			msg = r.Content[0].Text
		}
		return nil, fmt.Errorf("%s: %s", name, msg)
	}
	if r.Structured != nil {
		return r.Structured, nil
	}
	out := map[string]any{}
	if len(r.Content) > 0 {
		json.Unmarshal([]byte(r.Content[0].Text), &out)
	}
	return out, nil
}

func (p *mcpProc) stop() {
	p.in.Close()
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

// netBytes returns cumulative network bytes (in+out) for a process via nettop.
func netBytes(pid int) (int64, error) {
	out, err := exec.Command("nettop", "-P", "-L", "1", "-p", strconv.Itoa(pid), "-J", "bytes_in,bytes_out", "-x").Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ",")
		if len(f) >= 3 && strings.HasSuffix(f[0], "."+strconv.Itoa(pid)) {
			in, _ := strconv.ParseInt(f[1], 10, 64)
			o, _ := strconv.ParseInt(f[2], 10, 64)
			return in + o, nil
		}
	}
	return 0, fmt.Errorf("pid %d not in nettop output", pid)
}

// messagesWith returns inbox messages whose body is want.
func messagesWith(res map[string]any, want string) []map[string]any {
	var out []map[string]any
	msgs, _ := res["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if body, _ := mm["untrusted_peer_content"].(string); body == want {
			out = append(out, mm)
		}
	}
	return out
}

func msgID(m map[string]any) string {
	for _, k := range []string{"id", "message_id"} {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}

func liveAgents(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("liveagents", flag.ExitOnError)
	silk := fs.String("silk", "", "path to the silk client binary")
	relayURL := fs.String("relay", "https://silk-relay.vercel.app", "relay URL")
	n := fs.Int("n", 100, "timed messages")
	rtN := fs.Int("roundtrips", 30, "send/reply roundtrip samples")
	outPath := fs.String("out", "bench/results/competitors/silk-live-agents.json", "result file")
	fs.Parse(args)
	root, err := os.MkdirTemp("", "silk-liveagents-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	run := func(home string, args ...string) ([]byte, error) {
		cmd := exec.Command(*silk, args...)
		cmd.Env = append(os.Environ(), "SILK_HOME="+home)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("silk %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return out, nil
	}
	// First-time registration: create identity, solve the registration stamp, register.
	var reg []float64
	for i := range 3 {
		t0 := time.Now()
		if _, err := run(filepath.Join(root, fmt.Sprintf("reg%d", i)), "init", "--relay", *relayURL, "--label", "bench-reg"); err != nil {
			return err
		}
		reg = append(reg, float64(time.Since(t0).Microseconds())/1000)
	}
	homeA, homeB := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, h := range []string{homeA, homeB} {
		if _, err := run(h, "init", "--relay", *relayURL, "--label", "bench-live"); err != nil {
			return err
		}
	}
	addr := func(home string) (string, error) {
		out, err := run(home, "whoami", "--json")
		if err != nil {
			return "", err
		}
		var w struct {
			Address string `json:"address"`
		}
		return w.Address, json.Unmarshal(out, &w)
	}
	addrA, err := addr(homeA)
	if err != nil {
		return err
	}
	addrB, err := addr(homeB)
	if err != nil {
		return err
	}
	budget := strconv.Itoa(*n + *rtN + 40)
	if _, err := run(homeA, "request", addrB, "--note", "benchmark", "--budget", budget); err != nil {
		return err
	}
	out, err := run(homeB, "requests", "--json")
	if err != nil {
		return err
	}
	var reqs struct {
		Incoming []struct {
			ID string `json:"id"`
		} `json:"incoming"`
	}
	if err := json.Unmarshal(out, &reqs); err != nil || len(reqs.Incoming) == 0 {
		return fmt.Errorf("contact request not received: %s", out)
	}
	if _, err := run(homeB, "accept", reqs.Incoming[0].ID, "--rate", "600"); err != nil {
		return err
	}
	if _, err := run(homeA, "inbox"); err != nil {
		return err
	}
	// Client ready time from an existing identity: process start to MCP initialize.
	var reopen []float64
	for range 5 {
		p, d, err := startMCP(*silk, homeA)
		if err != nil {
			return err
		}
		p.stop()
		reopen = append(reopen, float64(d.Microseconds())/1000)
	}
	A, _, err := startMCP(*silk, homeA)
	if err != nil {
		return err
	}
	defer A.stop()
	B, _, err := startMCP(*silk, homeB)
	if err != nil {
		return err
	}
	defer B.stop()
	if _, err := A.tool("silk_whoami", map[string]any{}); err != nil {
		return err
	}
	if _, err := B.tool("silk_inbox", map[string]any{"wait_seconds": 0}); err != nil {
		return err
	}
	time.Sleep(time.Second)
	idleA, _, _ := procStat(A.cmd.Process.Pid)
	idleB, _, _ := procStat(B.cmd.Process.Pid)
	monA, monB := monitor(A.cmd.Process.Pid), monitor(B.cmd.Process.Pid)

	// Push: B is already waiting in silk_inbox when A calls silk_send.
	var sendMs, deliverMs []float64
	var cpu0, net0 float64
	for i := 0; i < *n+10; i++ {
		if i == 10 {
			_, c, _ := procStat(A.cmd.Process.Pid)
			b, _ := netBytes(A.cmd.Process.Pid)
			cpu0, net0 = c, float64(b)
		}
		want := fmt.Sprintf("%s #%d", text, i)
		type got struct {
			t   time.Time
			res map[string]any
			err error
		}
		ch := make(chan got, 1)
		go func() {
			for {
				res, err := B.tool("silk_inbox", map[string]any{"wait_seconds": 25})
				if err != nil || len(messagesWith(res, want)) > 0 {
					ch <- got{time.Now(), res, err}
					return
				}
			}
		}()
		time.Sleep(300 * time.Millisecond) // let the long-poll reach the relay
		t0 := time.Now()
		if _, err := A.tool("silk_send", map[string]any{"to": addrB, "text": want}); err != nil {
			return err
		}
		t1 := time.Now()
		g := <-ch
		if g.err != nil {
			return g.err
		}
		for _, m := range messagesWith(g.res, want) {
			B.tool("silk_ack", map[string]any{"message_id": msgID(m), "outcome": "received"})
		}
		if i >= 10 {
			sendMs = append(sendMs, float64(t1.Sub(t0).Microseconds())/1000)
			deliverMs = append(deliverMs, float64(g.t.Sub(t0).Microseconds())/1000)
		}
	}
	_, cpu1, _ := procStat(A.cmd.Process.Pid)
	net1, netErr := netBytes(A.cmd.Process.Pid)

	// Conversation roundtrip, as agents run it (and as the XMTP script does with
	// open streams): B is already waiting in silk_inbox; A sends, then waits in
	// silk_inbox for the reply; B replies as soon as the question arrives.
	A.tool("silk_inbox", map[string]any{"wait_seconds": 0}) // drain receipts
	var rtMs []float64
	for i := 0; i < *rtN+3; i++ {
		want, reply := fmt.Sprintf("question %d", i), fmt.Sprintf("ok %d", i)
		bErr := make(chan error, 1)
		go func() {
			for {
				res, err := B.tool("silk_inbox", map[string]any{"wait_seconds": 25})
				if err != nil {
					bErr <- err
					return
				}
				if m := messagesWith(res, want); len(m) > 0 {
					_, err := B.tool("silk_send", map[string]any{"to": addrA, "text": reply, "reply_to": msgID(m[0])})
					bErr <- err
					return
				}
			}
		}()
		time.Sleep(300 * time.Millisecond) // let B's long-poll reach the relay
		t0 := time.Now()
		if _, err := A.tool("silk_send", map[string]any{"to": addrB, "text": want}); err != nil {
			return err
		}
		var r map[string]any
		for r == nil {
			res, err := A.tool("silk_inbox", map[string]any{"wait_seconds": 25})
			if err != nil {
				return err
			}
			if m := messagesWith(res, reply); len(m) > 0 {
				r = m[0]
			}
		}
		d := time.Since(t0)
		if err := <-bErr; err != nil {
			return err
		}
		A.tool("silk_ack", map[string]any{"message_id": msgID(r), "outcome": "handled"})
		if i >= 3 {
			rtMs = append(rtMs, float64(d.Microseconds())/1000)
		}
	}
	peakA, peakB := monA.finish(), monB.finish()
	med := func(v []float64) float64 {
		s := append([]float64{}, v...)
		sort.Float64s(s)
		return math.Round(quantile(s, .5)*10) / 10
	}
	fi, _ := os.Stat(*silk)
	res := map[string]any{
		"system": "silk", "relay": *relayURL, "timestamp": time.Now().UTC().Format(time.RFC3339), "client": machine(),
		"install_mb":  math.Round(float64(fi.Size())/(1<<20)*10) / 10,
		"register_ms": med(reg), "register_runs_ms": reg,
		"reopen_ms": med(reopen), "reopen_runs_ms": reopen,
		"send_ms": percentiles(sendMs), "deliver_ms": percentiles(deliverMs), "roundtrip_ms": percentiles(rtMs),
		"rss_mb":         map[string]any{"sender_idle": idleA, "sender_peak": peakA, "receiver_idle": idleB, "receiver_peak": peakB},
		"cpu_ms_per_msg": math.Round((cpu1-cpu0)*1000/float64(*n)*1000) / 1000,
		"notes": []string{
			"Two `silk mcp` processes (the binary agents run), separate homes, driven over stdio MCP like Claude Code or Codex; both talk to the hosted relay over HTTPS.",
			"register: `silk init` from process start (new owner and agent keys, registration proof of work, relay round trips). reopen: `silk mcp` process start to MCP initialize response.",
			"send: silk_send tool call (encrypt, sign, relay admission with a durable Postgres commit and ledger append). deliver: from just before silk_send until the recipient's waiting silk_inbox returns it.",
			"roundtrip: B already waiting in silk_inbox; A silk_send, then A waits in silk_inbox; B replies with silk_send (acknowledging the question in the same request) as soon as it arrives; ends when A's silk_inbox returns the reply.",
			"cpu and bytes are the sender process during the timed send loop (includes its silk_send calls; bytes via nettop, TLS included).",
		},
	}
	if netErr == nil {
		res["bytes_per_msg"] = math.Round((float64(net1) - net0) / float64(*n))
	}
	fmt.Fprintf(os.Stderr, "silk live agents: register %.0fms reopen %.1fms send p50 %.1fms deliver p50 %.1fms roundtrip p50 %.1fms\n",
		med(reg), med(reopen), percentiles(sendMs).P50, percentiles(deliverMs).P50, percentiles(rtMs).P50)
	return writeResult(*outPath, res)
}
