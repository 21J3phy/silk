// Command silk is the Silk v2 CLI: identity, consent, encrypted messaging,
// ledger verification, an MCP server for AI agents, and a self-hostable relay.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = "2.0.0-dev"

// DefaultRelay is the public relay used when none is configured.
var DefaultRelay = "https://silk-relay.vercel.app"

// defaultLedgerKey pins the default relay's checkpoint signing key so that even
// the first `silk init` cannot be pointed at an impostor ledger.
const defaultLedgerKey = "silk-relay.vercel.app+031d237c+ATTDAINdtt1STMevKzsNDCvOAQ+Vm+N3uD8aa2KRHSn6"

// releaseKeys may sign Silk releases. `silk update` installs only releases signed
// by one of these keys AND proven to be on the relay's public ledger.
var releaseKeys = []string{"6yNx4g71m+r/5TGYhrRLZyO12VlKwLhKw8cAVTmbJZI="}

func pinnedReleaseKeys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, k := range releaseKeys {
		if b, err := base64.StdEncoding.DecodeString(k); err == nil && len(b) == ed25519.PublicKeySize {
			out = append(out, ed25519.PublicKey(b))
		}
	}
	return out
}

const usage = `silk — consent-first, end-to-end encrypted messaging between AI agents

Identity
  silk init [--relay URL] [--label NAME] [--handle NAME] [--passphrase]   create owner + agent, register
  silk whoami                                   show this agent's address
  silk rotate                                   rotate agent keys (owner)

Consent
  silk request <@handle|id|invite> --note "why" ask to start a conversation (proof-of-work stamped)
  silk invite [--days 7]                        create a single-use invite (no postage) to share (owner)
  silk requests                                 list contact requests (incoming and sent)
  silk accept <request-id> [--in N --out N --days D --rate R]   approve (owner)
  silk decline <request-id>                     refuse (owner); raises the sender's future cost
  silk conversations                            list approved conversations
  silk trust <@handle|id> [--owner] [--remove]  let a peer skip postage and the stranger queue (owner)
  silk policy                                   show who this agent trusts
  silk revoke <conversation> [--owner]          end a conversation

Messaging
  silk send <@handle|id|conversation> <text...> [--json] [--reply ID]
  silk inbox [--wait SECONDS] [--all] [--follow] sync and show messages (--follow streams them)
  silk ack <message-id> [received|handled|declined]
  silk status <message-id>                      delivery state of a sent message

Verification
  silk audit                                    verify ledger checkpoint, consistency, inclusion
  silk doctor                                   check setup: relay, clock, keys, ledger pin, MCP

Agents & servers
  silk mcp                                      run the MCP server (stdio) for an agent on this machine
  silk mcp --http [--tunnel] [--public-url URL] serve it over HTTPS for cloud agents (grok.com, Grok Bot,
                                                Meta Muse, OpenAI Dots, ChatGPT, claude.ai); --reset disconnects them
  silk relay [--addr :8790] [--db FILE]         run a relay
  silk update [--check]                         install the latest signed, ledger-logged release
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

// safeText neutralizes terminal control sequences in peer-written text:
// everything below U+0020 (except newline and tab), DEL, and C1 controls is
// shown escaped instead of being interpreted by the terminal.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
		if (*relayURL == DefaultRelay || (*relayURL == "" && c.Config.Relay == DefaultRelay)) && c.Config.LedgerKey == "" {
			c.Config.LedgerKey = defaultLedgerKey
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
		out(g, o.Public(), func(w io.Writer) {
			fmt.Fprintf(w, "Contact request %s sent to %s (%d-bit stamp in %dms, ledger #%d).\nTheir owner must approve it; run `silk inbox` to see when they do.\n",
				o.ID, peerName(o.To, o.ToHandle), o.PoWBits, o.PoWMs, o.LedgerIdx)
		})
		return nil

	case "invite":
		fs := newFlags("invite", g)
		days := fs.Int("days", 7, "invite lifetime in days (max 90)")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		inv, err := a.CreateInvite(time.Duration(*days) * 24 * time.Hour)
		if err != nil {
			return err
		}
		out(g, map[string]any{"invite": inv, "agent": a.Address()}, func(w io.Writer) {
			fmt.Fprintf(w, "%s\n\nShare this once. The holder can request a conversation with %s without proof-of-work;\nyou still approve it. Valid %d days, single use.\n", inv, a.Address(), *days)
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
			fmt.Fprintln(tw, "CONVERSATION\tPEER\tSTATUS\tSEND BUDGET\tRECEIVED\tKEY TURNS\tEXPIRES")
			for _, gi := range snap.Grants {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n", gi.ID, peerName(gi.Peer, gi.PeerHandle), gi.Status, gi.SendBudget, gi.Received,
					gi.KeyTurns, time.UnixMilli(gi.ExpiresMs).Format("2006-01-02"))
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
		follow := fs.Bool("follow", false, "keep running and print events as they arrive (Ctrl-C to stop)")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		a, err := openAgent(g)
		if err != nil {
			return err
		}
		if *follow {
			return followInbox(ctx, g, a)
		}
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
				fmt.Fprintf(w, "%s  from %s  %s%s\n  %s\n", m.ID, peerName(m.From, m.FromHandle), ago(m.SentMs), state, strings.ReplaceAll(safeText(m.Body), "\n", "\n  "))
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
		return runMCP(ctx, g, args)

	case "relay":
		return runRelay(ctx, args)

	case "update":
		fs := newFlags("update", g)
		check := fs.Bool("check", false, "only report whether an update is available")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		c, err := open(g)
		if err != nil {
			return err
		}
		if c.Config.Relay == "" {
			c.Config.Relay = DefaultRelay
		}
		if c.Config.LedgerKey == "" && c.Config.Relay == DefaultRelay {
			c.Config.LedgerKey = defaultLedgerKey
		}
		chk, err := c.CheckRelease(ctx, pinnedReleaseKeys(), version)
		if err != nil {
			return err
		}
		if !chk.Newer {
			fmt.Printf("silk %s is current (latest release %s, ledger #%d).\n", version, chk.Latest, chk.LedgerIdx)
			return nil
		}
		if *check {
			fmt.Printf("Update available: %s → %s (signed release, ledger #%d). Run `silk update`.\n", version, chk.Latest, chk.LedgerIdx)
			return nil
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		if err := c.ApplyUpdate(ctx, chk, exe); err != nil {
			return err
		}
		fmt.Printf("Updated silk %s → %s. Signature, ledger inclusion (#%d) and SHA-256 verified.\n", version, chk.Latest, chk.LedgerIdx)
		return nil

	case "release-publish":
		return publishRelease(ctx, args)

	case "witness":
		fs := newFlags("witness", g)
		dir := fs.String("dir", "ledger-witness", "directory holding the witnessed checkpoints")
		relayURL := fs.String("relay", DefaultRelay, "relay to witness")
		key := fs.String("ledger-key", "", "pinned ledger key (default: built-in key for the default relay)")
		if _, err := parse(fs, args); err != nil {
			return err
		}
		c := &client.Client{Config: client.Config{Relay: *relayURL, LedgerKey: *key}, HTTP: &http.Client{Timeout: time.Minute}}
		if c.Config.LedgerKey == "" && *relayURL == DefaultRelay {
			c.Config.LedgerKey = defaultLedgerKey
		}
		latest := filepath.Join(*dir, "latest.checkpoint")
		prev, err := os.ReadFile(latest)
		if errors.Is(err, os.ErrNotExist) {
			prev, err = nil, nil
		}
		if err != nil {
			return err
		}
		cp, err := c.Witness(ctx, prev)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(*dir, 0o755); err != nil {
			return err
		}
		raw := cp.Raw
		if err := os.WriteFile(latest, raw, 0o644); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(*dir, "checkpoints.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		fmt.Fprintf(f, "%s %d %s\n", time.Now().UTC().Format(time.RFC3339), cp.Size, base64.StdEncoding.EncodeToString(cp.Root[:]))
		fmt.Printf("Witnessed %s at size %d; consistent with the previous checkpoint.\n", cp.Origin, cp.Size)
		return nil

	case "doctor":
		fs := newFlags("doctor", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		return doctor(ctx, g)

	case "self-verify":
		fs := newFlags("self-verify", g)
		if _, err := parse(fs, args); err != nil {
			return err
		}
		c, err := open(g)
		if err != nil {
			return err
		}
		if c.Config.Relay == "" {
			c.Config.Relay = DefaultRelay
		}
		if c.Config.LedgerKey == "" && c.Config.Relay == DefaultRelay {
			c.Config.LedgerKey = defaultLedgerKey
		}
		chk, err := c.CheckReleaseVersion(ctx, pinnedReleaseKeys(), version, version)
		if err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := client.VerifyBinary(chk, exe); err != nil {
			return err
		}
		fmt.Printf("silk %s (%s) verified: release signature, ledger inclusion #%d, SHA-256.\n", version, client.Platform(), chk.LedgerIdx)
		return nil

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

// publishRelease signs a manifest for prebuilt binaries and records it on the
// relay's ledger. Maintainer-only: needs the release signing key.
func publishRelease(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("release-publish", flag.ContinueOnError)
	ver := fs.String("version", "", "release version, e.g. 2.0.1")
	keyFile := fs.String("key", "", "file with the base64 Ed25519 release seed")
	dir := fs.String("dir", "", "directory of binaries named silk-<os>-<arch>[.exe]")
	base := fs.String("url-base", "", "public URL prefix where the binaries are hosted")
	urlMap := fs.String("url-map", "", "JSON file mapping binary file names to their exact public URLs (overrides --url-base)")
	relayURL := fs.String("relay", DefaultRelay, "relay to publish to")
	notes := fs.String("notes", "", "release notes")
	record := fs.String("record", "releases", "directory to record the published manifest in (<version>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	urls := map[string]string{}
	if *urlMap != "" {
		b, err := os.ReadFile(*urlMap)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &urls); err != nil {
			return fmt.Errorf("url map: %w", err)
		}
	}
	if *ver == "" || *keyFile == "" || *dir == "" || (!strings.HasPrefix(*base, "https://") && len(urls) == 0) {
		return errors.New("--version, --key, --dir and an https --url-base or --url-map are required")
	}
	kb, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(kb)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("release key file must hold a base64 32-byte seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	m := client.Manifest{Version: *ver, Protocol: relay.Protocol, Created: time.Now().UTC().Format(time.RFC3339), Notes: *notes, Files: map[string]client.ManifestFile{}}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "silk-") || e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		plat := strings.TrimSuffix(strings.TrimPrefix(name, "silk-"), ".exe")
		u := strings.TrimRight(*base, "/") + "/" + name
		if mapped, ok := urls[name]; ok {
			u = mapped
		} else if len(urls) > 0 {
			return fmt.Errorf("no URL for %s in --url-map", name)
		}
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("URL for %s must be https", name)
		}
		m.Files[plat] = client.ManifestFile{URL: u, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	}
	if len(m.Files) == 0 {
		return errors.New("no silk-<os>-<arch> binaries found")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	rel := &wire.Release{Version: *ver, Created: time.Now().UnixMilli(), Manifest: body}
	rel.Sign(key)
	c := &client.Client{Config: client.Config{Relay: *relayURL}, HTTP: &http.Client{Timeout: time.Minute}}
	res, err := c.Submit(ctx, rel.Raw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "manifest.json"), body, 0o644); err != nil {
		return err
	}
	if *record != "" {
		if err := os.MkdirAll(*record, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*record, *ver+".json"), body, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("Published silk %s: %d builds, ledger #%d.\n", *ver, len(m.Files), res.LedgerIdx)
	return nil
}

// followInbox long-polls forever, printing events as they arrive.
func followInbox(ctx context.Context, g *globals, a *client.Agent) error {
	fmt.Fprintf(os.Stderr, "Listening as %s (Ctrl-C to stop)…\n", a.Address())
	backoff := time.Second
	for ctx.Err() == nil {
		res, err := a.Sync(ctx, 25*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "silk:", err, "(retrying)")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if g.json {
			if len(res.Messages)+len(res.Intros)+len(res.Grants)+len(res.Receipts)+len(res.Declined)+len(res.Revoked) > 0 {
				json.NewEncoder(os.Stdout).Encode(res)
			}
			continue
		}
		for _, gi := range res.Grants {
			fmt.Printf("✓ %s approved your request — conversation %s\n", peerName(gi.Peer, gi.PeerHandle), gi.ID)
		}
		for _, in := range res.Intros {
			fmt.Printf("? contact request %s from %s: %q — `silk accept %s`\n", in.ID, peerName(in.From, in.FromHandle), safeText(in.Note), in.ID)
		}
		for _, r := range res.Receipts {
			fmt.Printf("↩ %s: %s (ledger #%d)\n", r.ID, r.Status, r.AckIdx)
		}
		for _, id := range res.Revoked {
			fmt.Printf("⊘ conversation %s was revoked\n", id)
		}
		for _, m := range res.Messages {
			if m.Error != "" {
				fmt.Printf("%s  from %s  ERROR: %s\n", m.ID, peerName(m.From, m.FromHandle), m.Error)
				continue
			}
			fmt.Printf("%s  from %s\n  %s\n", m.ID, peerName(m.From, m.FromHandle), strings.ReplaceAll(safeText(m.Body), "\n", "\n  "))
		}
	}
	return nil
}

// doctor checks everything a working setup needs and says how to fix what is missing.
func doctor(ctx context.Context, g *globals) error {
	ok := true
	check := func(pass bool, what, fix string) {
		mark := "✓"
		if !pass {
			mark, ok = "✗", false
		}
		fmt.Printf("%s %s\n", mark, what)
		if !pass && fix != "" {
			fmt.Printf("    → %s\n", fix)
		}
	}
	c, err := open(g)
	if err != nil {
		return err
	}
	fmt.Printf("silk %s, home %s\n", version, g.home)
	if c.Config.Relay == "" {
		check(false, "relay configured", "run `silk init --label <name>`")
		return nil
	}
	start := time.Now()
	info, err := c.Info(ctx)
	rtt := time.Since(start).Round(time.Millisecond)
	check(err == nil, fmt.Sprintf("relay %s reachable (%v)", c.Config.Relay, rtt), "check your network or the relay URL")
	if err != nil {
		return nil
	}
	skew := time.Duration(info.TimeMs-time.Now().UnixMilli()) * time.Millisecond
	check(skew < time.Minute && skew > -time.Minute, fmt.Sprintf("clock within a minute of the relay (%v)", skew.Round(time.Millisecond)), "sync your system clock; frames more than 5 minutes off are rejected")
	check(c.Config.LedgerKey != "" && c.Config.LedgerKey == info.LedgerKey, "relay ledger key matches the pinned key", "the relay's signing key changed; do not proceed until you know why")
	if chk, err := c.CheckRelease(ctx, pinnedReleaseKeys(), version); err == nil {
		check(!chk.Newer, fmt.Sprintf("silk is up to date (latest %s)", chk.Latest), "run `silk update`")
	}
	agents, _ := c.Agents()
	check(len(agents) > 0, fmt.Sprintf("%d local agent(s)", len(agents)), "run `silk init --label <name>`")
	if b, err := os.ReadFile(filepath.Join(g.home, "owner.key")); err == nil {
		var f struct {
			KDF string `json:"kdf"`
		}
		json.Unmarshal(b, &f)
		check(f.KDF != "none", "owner key is passphrase-protected", "agents with shell access could approve contacts themselves; recreate with `silk init --passphrase` in a new home if that matters to you")
	}
	for _, label := range agents {
		g2 := *g
		g2.agent = label
		a, err := openAgent(&g2)
		if err != nil {
			check(false, "agent "+label+" loads", err.Error())
			continue
		}
		_, _, lerr := a.Lookup(ctx, a.ID.String())
		check(lerr == nil, fmt.Sprintf("agent %s (%s) registered and its keys match the relay", label, a.Address()), "if you restored an old home, run `silk rotate`")
		ar, aerr := a.Audit(ctx)
		if aerr == nil {
			check(true, fmt.Sprintf("ledger verified for %s (size %d, %d own entries proven)", label, ar.Size, ar.Checked), "")
		} else {
			check(false, "ledger audit for "+label, aerr.Error())
		}
		fmt.Printf("    MCP: claude mcp add silk-%s -- silk mcp --agent %s\n", label, label)
	}
	if ok {
		fmt.Println("All good.")
	}
	return nil
}
