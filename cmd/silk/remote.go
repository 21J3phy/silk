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
	infoPath := fs.String("connection-info-file", "", "with --http and --public-url: write credentials only to this private 0600 file (never service logs)")
	reset := fs.Bool("reset", false, "with --http: disconnect every cloud agent and issue a new connect token")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := validatePublicURL(*public); err != nil {
		return err
	}
	var infoFile *connectionInfoFile
	if *infoPath != "" {
		if *tunnel {
			return errors.New("--connection-info-file requires a stable --public-url, not --tunnel")
		}
		var err error
		infoFile, err = openConnectionInfoFile(*infoPath, *public)
		if err != nil {
			return err
		}
		defer infoFile.root.Close()
	}
	if *tunnel || *public != "" || *reset || infoFile != nil {
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
	if infoFile != nil {
		if err := infoFile.protectStatePath(h.StatePath); err != nil {
			return err
		}
		// Never forward HTTP log messages in hosted mode: they include pairing
		// codes and externally supplied client names.
		h.Logf = nil
		h.PairingCodeChanged = func(code string) error {
			if err := infoFile.publish("", code); err != nil {
				cancel()
				return errors.New("cannot update private connection-info file")
			}
			return nil
		}
	}
	if err := h.Load(*reset); err != nil {
		return err
	}
	if infoFile != nil {
		if err := infoFile.publish(h.Token(), h.PairingCode()); err != nil {
			return fmt.Errorf("write private connection-info file: %w", err)
		}
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	local := "http://" + loopback(ln.Addr().String())
	// Serve before opening the tunnel: its readiness check comes through it.
	served := make(chan error, 1)
	go func() { served <- h.Serve(ctx, ln) }()
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
	printConnectionInstructions(os.Stdout, name, base, h.PairingCode(), h.Token(), infoFile != nil)
	if h.PublicURL == "" {
		fmt.Println("\nCloud agents cannot reach this address. Add --tunnel (needs cloudflared), or put it behind https and pass --public-url.")
	}
	if c := h.Clients(); infoFile == nil && len(c) > 0 {
		fmt.Printf("\nConnected: %s (silk mcp --http --reset disconnects them all)\n", strings.Join(c, ", "))
	}
	return <-served
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
		check := tunnelCheckClient()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			resp, err := check.Get(u + "/.well-known/oauth-protected-resource")
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

// tunnelCheckClient resolves through trycloudflare.com's own name servers,
// which answer as soon as a tunnel exists. Asking this machine's resolver
// (or any caching one) about a hostname before it exists caches "no such
// host": the owner's browser opening the sign-in page would then fail for
// minutes, even though cloud agents could reach the tunnel.
func tunnelCheckClient() *http.Client {
	server := "1.1.1.1:53"
	if nss, err := net.LookupNS("trycloudflare.com"); err == nil && len(nss) > 0 {
		if ips, err := net.LookupIP(strings.TrimSuffix(nss[0].Host, ".")); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					server = net.JoinHostPort(ip.String(), "53")
					break
				}
			}
		}
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", server)
	}}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second}}
}
