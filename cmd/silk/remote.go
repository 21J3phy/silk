package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/mcp"
)

// runMCP serves the agent's MCP tools: over stdio for agents on this machine,
// or with --http for agents in someone else's cloud (grok.com, Grok Bot,
// Meta Muse, OpenAI Dots, ChatGPT, claude.ai).
func runMCP(ctx context.Context, g *globals, args []string) error {
	fs := newFlags("mcp", g)
	useHTTP := fs.Bool("http", false, "serve over HTTP for cloud agents instead of stdio")
	addr := fs.String("addr", "127.0.0.1:8765", "with --http: listen address")
	public := fs.String("public-url", "", "with --http: external https base URL (tunnel or reverse proxy)")
	tunnel := fs.Bool("tunnel", false, "with --http: open a public https URL with cloudflared")
	reset := fs.Bool("reset", false, "with --http: disconnect every cloud agent and issue a new connect token")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *tunnel || *public != "" || *reset {
		*useHTTP = true
	}
	if !*useHTTP {
		s := &mcp.Server{Version: version, Open: func() (*client.Agent, error) { return openAgent(g) }}
		if a, err := openAgent(g); err == nil {
			s.Agent = a
		} else {
			// Serve anyway: every tool explains the one-time setup until it is done.
			fmt.Fprintln(os.Stderr, "silk mcp: no identity yet (", err, "); tools will explain `silk init`")
		}
		return s.Serve(ctx, os.Stdin, os.Stdout)
	}

	a, err := openAgent(g)
	if err != nil {
		return fmt.Errorf("no Silk identity here yet; run `silk init --label <name> --passphrase` first (%w)", err)
	}
	name := a.Label
	if a.Cert.Handle != "" {
		name = "@" + a.Cert.Handle
	}
	h := &mcp.HTTP{
		Server:    &mcp.Server{Agent: a, Version: version},
		StatePath: filepath.Join(g.home, "mcp-remote-"+safeFile(a.Label)+".json"),
		PublicURL: strings.TrimRight(*public, "/"),
		Agent:     name,
		Logf:      func(f string, v ...any) { fmt.Fprintf(os.Stderr, f+"\n", v...) },
	}
	if err := h.Load(*reset); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	local := "http://" + loopback(ln.Addr().String())
	if *tunnel {
		u, err := startTunnel(ctx, local)
		if err != nil {
			ln.Close()
			return err
		}
		h.PublicURL = u
	}
	base := h.PublicURL
	if base == "" {
		base = local
	}
	fmt.Printf(`Silk MCP over HTTP for %s
  Endpoint:      %s/mcp
  Pairing code:  %s

Connect a cloud agent (grok.com, Grok Bot, Meta Muse, OpenAI Dots, ChatGPT, claude.ai):
  add %s/mcp as a custom MCP connector. When its sign-in page opens, enter the pairing code.
Agents that take a header (Muse Code, Grok Build, the xAI and OpenAI APIs):
  Authorization: Bearer %s
Agents that only take a URL, with no sign-in:
  %s/mcp/%s

Anyone with the token or that URL can read this agent's inbox and send in approved
conversations; keep them secret. Contact requests still need you: silk accept <id>.
`, name, base, h.PairingCode(), base, h.Token(), base, h.Token())
	if h.PublicURL == "" {
		fmt.Println("\nCloud agents cannot reach this address. Add --tunnel (needs cloudflared), or put it behind https and pass --public-url.")
	}
	if c := h.Clients(); len(c) > 0 {
		fmt.Printf("\nConnected: %s (silk mcp --http --reset disconnects them all)\n", strings.Join(c, ", "))
	}
	return h.Serve(ctx, ln)
}

func safeFile(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// loopback turns a wildcard listen address into one this machine can dial.
func loopback(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// tunnelURL finds cloudflared's https://<name>.trycloudflare.com in a log line.
func tunnelURL(line string) string {
	const suffix = ".trycloudflare.com"
	end := strings.Index(line, suffix)
	if end < 0 {
		return ""
	}
	start := end
	for start > 0 && (line[start-1] >= 'a' && line[start-1] <= 'z' || line[start-1] >= '0' && line[start-1] <= '9' || line[start-1] == '-') {
		start--
	}
	if start == end || !strings.HasSuffix(line[:start], "https://") {
		return ""
	}
	return "https://" + line[start:end+len(suffix)]
}

// startTunnel opens a Cloudflare quick tunnel (no account needed) and returns
// its public https URL. The URL changes every time; for a fixed address use
// a named tunnel, Tailscale Funnel, ngrok, or a server, with --public-url.
func startTunnel(ctx context.Context, local string) (string, error) {
	bin, err := exec.LookPath("cloudflared")
	if err != nil {
		return "", errors.New("--tunnel needs cloudflared: brew install cloudflared, or see https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
	}
	cmd := exec.CommandContext(ctx, bin, "tunnel", "--no-autoupdate", "--url", local)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if u := tunnelURL(sc.Text()); u != "" {
				select {
				case found <- u:
				default:
				}
			}
		} // keep draining so cloudflared never blocks on a full pipe
	}()
	go cmd.Wait()
	select {
	case u := <-found:
		// A new quick-tunnel hostname takes a few seconds to resolve; wait
		// so the URL printed is one a cloud agent can use right away.
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			resp, err := http.Get(u + "/.well-known/oauth-protected-resource")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			time.Sleep(time.Second)
		}
		return u, nil
	case <-time.After(45 * time.Second):
		cmd.Process.Kill()
		return "", errors.New("cloudflared did not report a tunnel URL within 45s")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
