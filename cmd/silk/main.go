// Command silk is the Silk v2 CLI: identity, consent, encrypted messaging,
// ledger verification, an MCP server for AI agents, and a self-hostable relay.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	_ "net/http/pprof" // only served when --debug-addr is set
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/mcp"
	"github.com/21J3phy/silk/pkg/relay"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = "2.0.0-dev"

// DefaultRelay is the public relay used when none is configured.
var DefaultRelay = "https://silk-relay.vercel.app"

const usage = `silk — consent-first, end-to-end encrypted messaging between AI agents

Identity
  silk init [--relay URL] [--label NAME] [--handle NAME] [--passphrase]   create owner + agent, register
  silk whoami                                   show this agent's address
  silk rotate                                   rotate agent keys (owner)

Consent
  silk request <@handle|id> --note "why"        ask to start a conversation (proof-of-work stamped)
  silk requests                                 list contact requests (incoming and sent)
  silk accept <request-id> [--in N --out N --days D --rate R]   approve (owner)
  silk decline <request-id>                     refuse (owner); raises the sender's future cost
  silk conversations                            list approved conversations
  silk trust <@handle|id> [--owner] [--remove]  let a peer skip postage and the stranger queue (owner)
  silk policy                                   show who this agent trusts
  silk revoke <conversation> [--owner]          end a conversation

Messaging
  silk send <@handle|id|conversation> <text...> [--json] [--reply ID]
  silk inbox [--wait SECONDS] [--all]           sync and show messages
  silk ack <message-id> [received|handled|declined]
  silk status <message-id>                      delivery state of a sent message

Verification
  silk audit                                    verify ledger checkpoint, consistency, inclusion

Agents & servers
  silk mcp                                      run the MCP server (stdio) for an AI agent
  silk relay [--addr :8790] [--db FILE]         run a relay
  silk version

Global flags: --home DIR (default ~/.silk or $SILK_HOME), --agent LABEL, --json
`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Print(usage)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	if err := run(ctx, cmd, args); err != nil {
		fmt.Fprintln(os.Stderr, "silk:", err)
		os.Exit(1)
	}
}

type globals struct {
	home, agent string
	json        bool
}

func newFlags(name string, g *globals) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&g.home, "home", client.DefaultHome(), "silk home directory")
	fs.StringVar(&g.agent, "agent", "", "agent label (default: the configured default)")
	fs.BoolVar(&g.json, "json", false, "print JSON")
	return fs
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func open(g *globals) (*client.Client, error) {
	c, err := client.Open(g.home)
	if err != nil {
		return nil, err
	}
	c.Passphrase = func() (string, error) {
		if p := os.Getenv("SILK_PASSPHRASE"); p != "" {
			return p, nil
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", client.ErrPassphrase
		}
		fmt.Fprint(os.Stderr, "Owner passphrase: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return c, nil
}

func openAgent(g *globals) (*client.Agent, error) {
	c, err := open(g)
	if err != nil {
		return nil, err
	}
	return c.Agent(g.agent)
}

func out(g *globals, v any, human func(w io.Writer)) {
	if g.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(v)
		return
	}
	human(os.Stdout)
}

func ago(ms int64) string {
	d := time.Since(time.UnixMilli(ms)).Round(time.Second)
	if d < 0 {
		return "in " + (-d).String()
	}
	return d.String() + " ago"
}

func peerName(id, handle string) string {
	if handle != "" {
		return "@" + handle
	}
	return id
}

func run(ctx context.Context, cmd string, args []string) error {
	g := &globals{}
	switch cmd {
	case "version", "--version":
		fmt.Println("silk", version, "(protocol "+relay.Protocol+")")
		return nil

	case "init":
		fs := newFlags("init", g)
		relayURL := fs.String("relay", "", "relay URL (default "+DefaultRelay+")")
		label := fs.String("label", "", "agent label, e.g. claude (default: hostname-based)")
		handle := fs.String("handle", "", "public @handle (optional, first come first served)")
		usePass := fs.Bool("passphrase", false, "protect the owner key with a passphrase (recommended when agents can run shell commands)")
		closed := fs.Bool("closed", false, "do not accept contact requests")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		c, err := open(g)
		if err != nil {
			return err
		}
		if *relayURL == "" && c.Config.Relay == "" {
			*relayURL = DefaultRelay
		}
		if *label == "" {
			*label = "agent"
		}
		pass := os.Getenv("SILK_PASSPHRASE")
		if *usePass && pass == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("--passphrase needs a terminal or SILK_PASSPHRASE")
			}
			fmt.Fprint(os.Stderr, "New owner passphrase: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			pass = string(b)
		}
		fmt.Fprintln(os.Stderr, "Generating keys and a registration proof of work…")
		start := time.Now()
		a, res, err := c.Init(ctx, client.InitOptions{Relay: *relayURL, Label: *label, Handle: *handle, Passphrase: pass, AcceptIntros: !*closed})
		if err != nil {
			return err
		}
		out(g, map[string]any{"address": a.Address(), "id": a.ID.String(), "ledger_index": res.LedgerIdx, "relay": c.Config.Relay}, func(w io.Writer) {
			fmt.Fprintf(w, "Agent %q registered in %v.\n  address: %s\n  id:      %s\n  relay:   %s\n  ledger:  entry #%d\n  home:    %s\n",
				a.Label, time.Since(start).Round(time.Millisecond), a.Address(), a.ID, c.Config.Relay, res.LedgerIdx, g.home)
			fmt.Fprintf(w, "\nConnect an AI agent (Claude Code example):\n  claude mcp add silk -- silk mcp --agent %s\n", a.Label)
		})
		return nil

	case "whoami":
		fs := newFlags("whoami", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		out(g, map[string]any{"address": a.Address(), "id": a.ID.String(), "label": a.Label, "handle": a.Cert.Handle, "serial": a.Cert.Serial,
			"relay": a.Client().Config.Relay, "expires": time.UnixMilli(a.Cert.Expires).UTC()}, func(w io.Writer) {
			fmt.Fprintf(w, "%s  (%s)\n  id:      %s\n  relay:   %s\n  keys:    serial %d, expires %s\n", a.Address(), a.Label, a.ID,
				a.Client().Config.Relay, a.Cert.Serial, time.UnixMilli(a.Cert.Expires).Format("2006-01-02"))
		})
		return nil

	case "rotate":
		fs := newFlags("rotate", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		res, err := a.Rotate(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Rotated to key serial %d (ledger entry #%d).\n", a.Cert.Serial, res.LedgerIdx)
		return nil

	case "request":
		fs := newFlags("request", g)
		note := fs.String("note", "", "why you want to talk (encrypted to the recipient)")
		budget := fs.Uint("budget", 100, "messages requested in each direction")
		scope := fs.String("scope", "chat", "purpose label")
		days := fs.Int("days", 30, "requested conversation lifetime in days")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk request <@handle|id> --note \"why\"")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Computing proof-of-work postage…")
		o, err := a.RequestContact(ctx, pos[0], client.IntroOptions{Note: *note, Budget: uint32(*budget), Scope: *scope, GrantTTL: time.Duration(*days) * 24 * time.Hour})
		if err != nil {
			return err
		}
		out(g, o, func(w io.Writer) {
			fmt.Fprintf(w, "Contact request %s sent to %s (%d-bit stamp in %dms, ledger #%d).\nTheir owner must approve it; run `silk inbox` to see when they do.\n",
				o.ID, peerName(o.To, o.ToHandle), o.PoWBits, o.PoWMs, o.LedgerIdx)
		})
		return nil

	case "requests":
		fs := newFlags("requests", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		a.Sync(ctx, 0)
		snap, err := a.Snapshot()
		if err != nil {
			return err
		}
		out(g, map[string]any{"incoming": snap.InIntros, "sent": snap.OutIntros}, func(w io.Writer) {
			tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "INCOMING\tFROM\tSTATUS\tBUDGET\tNOTE")
			for _, in := range snap.InIntros {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%q\n", in.ID, peerName(in.From, in.FromHandle), in.Status, in.Budget, in.Note)
			}
			fmt.Fprintln(tw, "\nSENT\tTO\tSTATUS\t\t")
			for _, o := range snap.OutIntros {
				fmt.Fprintf(tw, "%s\t%s\t%s\t\t\n", o.ID, peerName(o.To, o.ToHandle), o.Status)
			}
			tw.Flush()
		})
		return nil

	case "accept":
		fs := newFlags("accept", g)
		in := fs.Uint("in", 0, "messages the requester may send (default: what they asked for)")
		outN := fs.Uint("out", 0, "messages you may send back (default: what they asked for)")
		days := fs.Int("days", 0, "conversation lifetime in days (default: what they asked for)")
		rate := fs.Uint("rate", 60, "max messages per minute per direction")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk accept <request-id>")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		gi, err := a.Accept(ctx, pos[0], client.AcceptOptions{FromPeer: uint32(*in), ToPeer: uint32(*outN), TTL: time.Duration(*days) * 24 * time.Hour, Rate: uint16(*rate)})
		if err != nil {
			return err
		}
		out(g, gi, func(w io.Writer) {
			fmt.Fprintf(w, "Approved. Conversation %s with %s (they may send %d, you may send %d, until %s). Ledger #%d.\n",
				gi.ID, peerName(gi.Peer, gi.PeerHandle), gi.RecvBudget, gi.SendBudget, time.UnixMilli(gi.ExpiresMs).Format("2006-01-02"), gi.LedgerIdx)
		})
		return nil

	case "decline":
		fs := newFlags("decline", g)
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk decline <request-id>")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		if err := a.Decline(ctx, pos[0]); err != nil {
			return err
		}
		fmt.Println("Declined.")
		return nil

	case "trust":
		fs := newFlags("trust", g)
		whole := fs.Bool("owner", false, "trust every agent of that peer's owner")
		remove := fs.Bool("remove", false, "remove instead of add")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk trust <@handle|id> [--owner] [--remove]")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		p, res, err := a.Trust(ctx, pos[0], *whole, *remove)
		if err != nil {
			return err
		}
		out(g, p, func(w io.Writer) {
			verb := "Trusted"
			if *remove {
				verb = "Removed"
			}
			fmt.Fprintf(w, "%s %s. Policy v%d published (ledger #%d): %d trusted agents, %d trusted owners, same-owner=%v.\n",
				verb, pos[0], p.Serial, res.LedgerIdx, len(p.Agents), len(p.Owners), p.SameOwner)
		})
		return nil

	case "policy":
		fs := newFlags("policy", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		p, err := a.Policy()
		if err != nil {
			return err
		}
		out(g, p, func(w io.Writer) {
			fmt.Fprintf(w, "Policy v%d  same-owner agents trusted: %v\n", p.Serial, p.SameOwner)
			for _, x := range p.Agents {
				fmt.Fprintln(w, "  agent", x)
			}
			for _, x := range p.Owners {
				fmt.Fprintln(w, "  owner", x)
			}
			fmt.Fprintln(w, "Trusted senders skip proof-of-work postage and the stranger queue. You still approve every conversation.")
		})
		return nil

	case "conversations", "convos":
		fs := newFlags("conversations", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		a.Sync(ctx, 0)
		snap, err := a.Snapshot()
		if err != nil {
			return err
		}
		out(g, snap.Grants, func(w io.Writer) {
			tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "CONVERSATION\tPEER\tSTATUS\tSEND BUDGET\tRECEIVED\tEXPIRES")
			for _, gi := range snap.Grants {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n", gi.ID, peerName(gi.Peer, gi.PeerHandle), gi.Status, gi.SendBudget, gi.Received,
					time.UnixMilli(gi.ExpiresMs).Format("2006-01-02"))
			}
			tw.Flush()
		})
		return nil

	case "revoke":
		fs := newFlags("revoke", g)
		asOwner := fs.Bool("owner", false, "sign with the owner key")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk revoke <conversation>")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		res, err := a.Revoke(ctx, pos[0], *asOwner)
		if err != nil {
			return err
		}
		fmt.Printf("Revoked (ledger #%d). Undelivered messages were purged.\n", res.LedgerIdx)
		return nil

	case "send":
		fs := newFlags("send", g)
		asJSON := fs.Bool("json-body", false, "mark the body as JSON")
		reply := fs.String("reply", "", "message id this replies to")
		ttl := fs.Duration("ttl", 24*time.Hour, "how long the message waits for delivery")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) < 2 {
			return errors.New("usage: silk send <@handle|id|conversation> <text...>  (use - to read stdin)")
		}
		body := strings.Join(pos[1:], " ")
		if body == "-" {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
			if err != nil {
				return err
			}
			body = string(b)
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		s, err := a.Send(ctx, pos[0], body, client.SendOptions{ReplyTo: *reply, TTL: *ttl, JSON: *asJSON})
		if err != nil && s == nil {
			return err
		}
		out(g, s, func(w io.Writer) {
			fmt.Fprintf(w, "%s  %s (ledger #%d)\n", s.ID, s.Status, s.LedgerIdx)
			if err != nil {
				fmt.Fprintln(w, " ", err)
			}
		})
		return nil

	case "inbox", "sync":
		fs := newFlags("inbox", g)
		wait := fs.Int("wait", 0, "long-poll up to N seconds for new events")
		all := fs.Bool("all", false, "include acknowledged messages")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		res, err := a.Sync(ctx, time.Duration(*wait)*time.Second)
		if err != nil {
			return err
		}
		snap, err := a.Snapshot()
		if err != nil {
			return err
		}
		var msgs []*client.Message
		for _, m := range snap.Inbox {
			if *all || m.Acked == "" {
				msgs = append(msgs, m)
			}
		}
		out(g, map[string]any{"messages": msgs, "sync": res}, func(w io.Writer) {
			for _, gi := range res.Grants {
				fmt.Fprintf(w, "✓ %s approved your request — conversation %s\n", peerName(gi.Peer, gi.PeerHandle), gi.ID)
			}
			for _, id := range res.Declined {
				fmt.Fprintf(w, "✗ request %s was declined\n", id)
			}
			for _, r := range res.Receipts {
				fmt.Fprintf(w, "↩ %s: %s (ledger #%d)\n", r.ID, r.Status, r.AckIdx)
			}
			for _, in := range res.Intros {
				fmt.Fprintf(w, "? contact request %s from %s: %q — `silk accept %s` or `silk decline %s`\n", in.ID, peerName(in.From, in.FromHandle), in.Note, in.ID, in.ID)
			}
			for _, id := range res.Revoked {
				fmt.Fprintf(w, "⊘ conversation %s was revoked\n", id)
			}
			if len(msgs) == 0 {
				fmt.Fprintln(w, "No unread messages.")
			}
			for _, m := range msgs {
				state := ""
				if m.Acked != "" {
					state = " [" + m.Acked + "]"
				}
				if m.Error != "" {
					fmt.Fprintf(w, "%s  from %s  ERROR: %s\n", m.ID, peerName(m.From, m.FromHandle), m.Error)
					continue
				}
				fmt.Fprintf(w, "%s  from %s  %s%s\n  %s\n", m.ID, peerName(m.From, m.FromHandle), ago(m.SentMs), state, strings.ReplaceAll(m.Body, "\n", "\n  "))
			}
		})
		return nil

	case "ack":
		fs := newFlags("ack", g)
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) < 1 || len(pos) > 2 {
			return errors.New("usage: silk ack <message-id> [received|handled|declined]")
		}
		outcome := "received"
		if len(pos) == 2 {
			outcome = pos[1]
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		res, err := a.Ack(ctx, pos[0], outcome)
		if err != nil {
			return err
		}
		fmt.Printf("Acknowledged as %s (ledger #%d).\n", outcome, res.LedgerIdx)
		return nil

	case "status":
		fs := newFlags("status", g)
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: silk status <message-id>")
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		st, err := a.MessageStatus(ctx, pos[0])
		if err != nil {
			return err
		}
		out(g, st, func(w io.Writer) {
			fmt.Fprintf(w, "%s: %s (message ledger #%d", st.ID, st.Status, st.LedgerIdx)
			if st.AckIdx > 0 {
				fmt.Fprintf(w, ", ack ledger #%d", st.AckIdx)
			}
			fmt.Fprintln(w, ")")
		})
		return nil

	case "audit":
		fs := newFlags("audit", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		ar, err := a.Audit(ctx)
		if err != nil {
			return err
		}
		out(g, ar, func(w io.Writer) {
			fmt.Fprintf(w, "Ledger %s verified.\n  size:      %d entries\n  root:      %s\n  signature: valid (pinned key)\n", ar.Origin, ar.Size, ar.Root)
			if ar.PreviousSize > 0 {
				fmt.Fprintf(w, "  history:   consistent with previously seen size %d\n", ar.PreviousSize)
			} else {
				fmt.Fprintln(w, "  history:   first checkpoint stored for future consistency checks")
			}
			fmt.Fprintf(w, "  inclusion: %d of your recent entries proven\n", ar.Checked)
		})
		return nil

	case "mcp":
		fs := newFlags("mcp", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		s := &mcp.Server{Agent: a, Version: version}
		return s.Serve(ctx, os.Stdin, os.Stdout)

	case "relay":
		return runRelay(ctx, args)

	case "ledger-keygen":
		fs := flag.NewFlagSet("ledger-keygen", flag.ContinueOnError)
		origin := fs.String("origin", "", "ledger origin, e.g. silk-relay.example.com/v2")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *origin == "" {
			return errors.New("--origin is required")
		}
		skey, vkey, err := ledger.GenerateKey(*origin)
		if err != nil {
			return err
		}
		fmt.Printf("private: %s\npublic:  %s\n", skey, vkey)
		return nil
	}
	return fmt.Errorf("unknown command %q (see `silk help`)", cmd)
}

func runRelay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8790", "listen address")
	db := fs.String("db", "silk-relay.db", "SQLite database file")
	keyFile := fs.String("key", "", "ledger signing key file (default: <db>.ledger-key, created if missing)")
	origin := fs.String("origin", "", "ledger origin name for a new key (default: hostname/silk)")
	regBits := fs.Uint("register-bits", 24, "proof-of-work bits for new identities")
	introBits := fs.Uint("intro-bits", 20, "base proof-of-work bits for contact requests")
	syncMode := fs.String("sync", "FULL", "SQLite synchronous mode: FULL or NORMAL")
	backend := fs.String("store", "sqlite", "storage engine: sqlite (default) or bolt")
	trustProxy := fs.Bool("trust-proxy", false, "rate-limit by X-Forwarded-For")
	noLimits := fs.Bool("no-ip-limits", false, "disable per-IP request limits (benchmarks)")
	benchRate := fs.Bool("bench-unlimited-rate", false, "ignore per-conversation rate windows (benchmarks only)")
	maxBatch := fs.Int("max-batch", 512, "max writes per group commit (1 disables grouping)")
	debugAddr := fs.String("debug-addr", "", "serve Go pprof on this loopback address (diagnostics only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		*keyFile = *db + ".ledger-key"
	}
	if os.Getenv("GOMAXPROCS") == "" {
		// One writer goroutine owns the database; a few procs for TLS/HTTP/signature work
		// measured both faster and lighter than one per core.
		runtime.GOMAXPROCS(min(4, runtime.NumCPU()))
	}
	skey, err := os.ReadFile(*keyFile)
	if errors.Is(err, os.ErrNotExist) {
		if *origin == "" {
			host, _ := os.Hostname()
			*origin = strings.ToLower(strings.Split(host, ".")[0]) + ".silk.relay"
		}
		s, _, err := ledger.GenerateKey(*origin)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*keyFile), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(*keyFile, []byte(s), 0o600); err != nil {
			return err
		}
		skey = []byte(s)
	} else if err != nil {
		return err
	}
	signer, err := ledger.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		return err
	}
	var store kv.Store
	switch *backend {
	case "bolt":
		store, err = boltkv.Open(*db, boltkv.Options{MaxBatch: *maxBatch})
	case "sqlite":
		store, err = sqlitekv.Open(*db, sqlitekv.SQLiteOptions{Synchronous: *syncMode, MaxBatch: *maxBatch})
	default:
		err = fmt.Errorf("unknown store %q", *backend)
	}
	if err != nil {
		return err
	}
	defer store.Close()
	r := relay.New(store, signer, relay.Config{RegisterBits: uint8(*regBits), IntroBaseBits: uint8(*introBits), PollInterval: 5 * time.Second, IgnoreGrantRate: *benchRate}, nil)
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
	slog.Info("silk relay listening", "addr", *addr, "db", *db, "origin", signer.Origin, "ledger_key", signer.VKey)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
