package main

// Owner and agent on different computers. An agent on its own cloud computer
// (Grok Bot, OpenAI Dots, Meta Muse) runs `silk init --owner KEY` and holds
// only agent keys. Owner operations there print a `silk sign` line for the
// owner to run where the owner key is; the owner sends back a `silk signed`
// line that finishes the operation.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/wire"
)

func parseOwnerKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("--owner takes the 64-character owner key that `silk owner` prints")
	}
	return ed25519.PublicKey(b), nil
}

// printNeed tells the agent how to get its owner's signature.
func printNeed(need *client.OwnerSignatureNeeded, asJSON bool) {
	cmd := "silk sign " + need.Request
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"status": "needs_owner_signature", "op": need.Op, "owner_command": cmd,
			"next": "Give owner_command to your owner to run where their owner key is, then run the `silk signed silk-sig:...` line they send back."})
		return
	}
	fmt.Printf("Not done yet: the owner key is on another device, so your owner signs this.\n\n"+
		"1. Your owner runs this where the owner key is (it shows them what they approve):\n\n%s\n\n"+
		"2. It prints a line starting with `silk signed`. Run that line here to finish.\n", cmd)
}

func runOwner(g *globals, args []string) error {
	fs := newFlags("owner", g)
	usePass := fs.Bool("passphrase", false, "protect a new owner key with a passphrase")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, err := open(g)
	if err != nil {
		return err
	}
	pass := ""
	if _, err := c.OwnerPublic(); err != nil && *usePass {
		if pass, err = newPassphrase(); err != nil {
			return err
		}
	}
	pub, created, err := c.CreateOwner(pass)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(pub)
	out(g, map[string]any{"owner_key": key, "created": created, "home": g.home}, func(w io.Writer) {
		if created {
			fmt.Fprintf(w, "Created your owner key in %s.\n\n", g.home)
		}
		fmt.Fprintf(w, "Owner key: %s\n\n", key)
		fmt.Fprintf(w, "To give an agent on another computer (Grok Bot, OpenAI Dots, Meta Muse, a server) its own\n"+
			"Silk identity, tell it:\n\n"+
			"  Read https://silk-relay.vercel.app/skill.md, then set up Silk with owner key %s\n\n"+
			"It runs `silk init --owner %s --label <name>` and hands you a `silk sign ...` line; run that here.\n", key, key)
	})
	return nil
}

func newPassphrase() (string, error) {
	if p := os.Getenv("SILK_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("--passphrase needs a terminal or SILK_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, "New owner passphrase: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func runSign(ctx context.Context, g *globals, args []string) error {
	fs := newFlags("sign", g)
	yes := fs.Bool("yes", false, "sign without asking (you have read the request)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: silk sign <silk-sign:...>")
	}
	c, err := open(g)
	if err != nil {
		return err
	}
	_, frame, err := client.ParseSignRequest(pos[0])
	if err != nil {
		return err
	}
	if c.Config.Relay == "" {
		c.Config.Relay = DefaultRelay
	}
	fmt.Fprintln(os.Stderr, describeRequest(ctx, c, frame))
	if !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("read the request above, then run this in a terminal to confirm it (or add --yes)")
		}
		fmt.Fprint(os.Stderr, "\nSign this with your owner key? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return errors.New("not signed")
		}
	}
	sig, err := c.SignRequest(pos[0])
	if err != nil {
		return err
	}
	line := "silk signed " + sig
	out(g, map[string]any{"signature": sig, "agent_command": line}, func(w io.Writer) {
		fmt.Fprintf(w, "\nSigned. Send this line back to your agent to run:\n\n%s\n", line)
	})
	return nil
}

// describeRequest says in plain words what an owner signature would approve.
// Everything shown comes from the signed bytes; peer names come from their
// certificates on the relay.
func describeRequest(ctx context.Context, c *client.Client, frame any) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	name := func(id wire.ID) string {
		if cert, err := c.LookupCert(ctx, id); err == nil && cert.Handle != "" {
			return "@" + cert.Handle + " (" + id.String() + ")"
		}
		return id.String()
	}
	day := func(ms int64) string { return time.UnixMilli(ms).Format("2006-01-02 15:04") }
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	var b strings.Builder
	switch f := frame.(type) {
	case *wire.Cert:
		addr := f.ID().String()
		if f.Handle != "" {
			addr = "@" + f.Handle + " (" + addr + ")"
		}
		if f.Serial == 1 {
			fmt.Fprintf(&b, "Create your agent %q on the computer that asked.\n", f.Label)
		} else {
			fmt.Fprintf(&b, "Replace the keys of your agent %q (key serial %d).\n", f.Label, f.Serial)
		}
		fmt.Fprintf(&b, "  address:      %s\n  valid until:  %s\n  strangers may ask to talk: %s\n", addr, day(f.Expires), yn(f.Flags&wire.CertAcceptsIntros != 0))
		b.WriteString("It can message only in conversations you approve; it cannot approve them.")
	case *wire.Grant:
		fmt.Fprintf(&b, "Approve a conversation.\n  with:          %s\n  your agent:    %s\n", name(f.From), name(f.To))
		fmt.Fprintf(&b, "  they may send %d messages and your agent %d, at most %d a minute each way, until %s.", f.BudgetAB, f.BudgetBA, f.Rate, day(f.Expires))
	case *wire.Decline:
		fmt.Fprintf(&b, "Decline contact request %s to your agent %s.", f.IntroID, name(f.By))
	case *wire.Revoke:
		fmt.Fprintf(&b, "End conversation %s of your agent %s, as its owner.", f.GrantID, name(f.By))
	case *wire.Policy:
		fmt.Fprintf(&b, "Publish contact policy v%d for your agent %s.\n  your other agents skip postage: %s\n", f.Serial, name(f.Agent), yn(f.Flags&wire.PolicyTrustSameOwner != 0))
		for _, a := range f.Agents {
			fmt.Fprintf(&b, "  trusted agent: %s\n", name(a))
		}
		for _, o := range f.Owners {
			fmt.Fprintf(&b, "  trusted owner: %s\n", hex.EncodeToString(o[:]))
		}
		b.WriteString("Trusted senders skip postage and the stranger queue; you still approve every conversation.")
	case *wire.Ticket:
		fmt.Fprintf(&b, "Create a single-use invite to your agent %s, valid until %s.\nWhoever holds it can ask to talk without postage; you still approve.", name(f.Recipient), day(f.Expires))
	}
	return b.String()
}

func runSigned(ctx context.Context, g *globals, args []string) error {
	fs := newFlags("signed", g)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: silk signed <silk-sig:...>")
	}
	c, err := open(g)
	if err != nil {
		return err
	}
	if a, res, found, err := c.CompleteInit(ctx, pos[0]); err != nil {
		return err
	} else if found {
		out(g, map[string]any{"op": "init", "address": a.Address(), "id": a.ID.String(), "ledger_index": res.LedgerIdx, "relay": c.Config.Relay}, func(w io.Writer) {
			fmt.Fprintf(w, "Agent %q registered.\n  address: %s\n  id:      %s\n  ledger:  entry #%d\n  home:    %s\n",
				a.Label, a.Address(), a.ID, res.LedgerIdx, g.home)
			fmt.Fprintln(w, "\nYour owner approves contacts from their own device: owner commands here print a `silk sign` line for them.")
		})
		return nil
	}
	labels, err := c.Agents()
	if err != nil {
		return err
	}
	for _, label := range labels {
		a, err := c.Agent(label)
		if err != nil {
			continue
		}
		res, found, err := a.CompleteOwner(ctx, pos[0])
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		out(g, res, func(w io.Writer) {
			switch res.Op {
			case "accept":
				gi := res.Grant
				fmt.Fprintf(w, "Approved. Conversation %s with %s (they may send %d, you may send %d, until %s). Ledger #%d.\n",
					gi.ID, peerName(gi.Peer, gi.PeerHandle), gi.RecvBudget, gi.SendBudget, time.UnixMilli(gi.ExpiresMs).Format("2006-01-02"), gi.LedgerIdx)
			case "decline":
				fmt.Fprintf(w, "Declined (ledger #%d).\n", res.LedgerIdx)
			case "revoke":
				fmt.Fprintf(w, "Revoked (ledger #%d). Undelivered messages were purged.\n", res.LedgerIdx)
			case "trust":
				fmt.Fprintf(w, "Policy v%d published (ledger #%d): %d trusted agents, %d trusted owners, same-owner=%v.\n",
					res.Policy.Serial, res.LedgerIdx, len(res.Policy.Agents), len(res.Policy.Owners), res.Policy.SameOwner)
			case "invite":
				fmt.Fprintf(w, "%s\n\nShare this once. The holder can request a conversation with %s without proof-of-work;\nyour owner still approves it. Single use.\n", res.Invite, res.Address)
			case "rotate":
				fmt.Fprintf(w, "Rotated %s's keys (ledger #%d).\n", res.Agent, res.LedgerIdx)
			}
		})
		return nil
	}
	return errors.New("nothing on this computer is waiting for that signature (is it for another computer, or already used?)")
}
