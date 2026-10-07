package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

// PolicyConfig is the local copy of this agent's contact policy.
type PolicyConfig struct {
	Serial    uint32   `json:"serial"`
	SameOwner bool     `json:"trust_same_owner"`
	Owners    []string `json:"trusted_owners"` // hex Ed25519 owner keys
	Agents    []string `json:"trusted_agents"` // agent ids
}

func (a *Agent) policyPath() string { return filepath.Join(a.dir, "policy.json") }

// Policy returns the local policy (default: trust agents with the same owner).
func (a *Agent) Policy() (*PolicyConfig, error) {
	p := &PolicyConfig{SameOwner: true}
	if err := readJSON(a.policyPath(), p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return p, nil
}

// Trust adds a peer (its agent id, or with wholeOwner every agent of its owner)
// to the policy, signs it with the owner key, and publishes it.
func (a *Agent) Trust(ctx context.Context, ref string, wholeOwner, remove bool) (*PolicyConfig, *relay.Result, error) {
	// Pinned and proven on the ledger: trusting the wrong owner key would let a
	// stranger skip postage and the queue.
	_, cert, err := a.resolvePeer(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	p, err := a.Policy()
	if err != nil {
		return nil, nil, err
	}
	target := cert.ID().String()
	list := &p.Agents
	if wholeOwner {
		target, list = hex.EncodeToString(cert.OwnerPub[:]), &p.Owners
	}
	var out []string
	found := false
	for _, x := range *list {
		if x == target {
			found = true
			if remove {
				continue
			}
		}
		out = append(out, x)
	}
	if !found && !remove {
		out = append(out, target)
	}
	*list = out
	res, err := a.PublishPolicy(ctx, p)
	return p, res, err
}

// PublishPolicy signs (owner key) and submits the policy with the next serial.
func (a *Agent) PublishPolicy(ctx context.Context, p *PolicyConfig) (*relay.Result, error) {
	owner, err := a.c.OwnerKey()
	if err != nil {
		return nil, err
	}
	pol := &wire.Policy{Agent: a.ID, Serial: p.Serial + 1, Created: a.c.Now().UnixMilli()}
	if p.SameOwner {
		pol.Flags |= wire.PolicyTrustSameOwner
	}
	for _, o := range p.Owners {
		b, err := hex.DecodeString(o)
		if err != nil || len(b) != wire.PubLen {
			return nil, fmt.Errorf("bad owner key %q", o)
		}
		var k [wire.PubLen]byte
		copy(k[:], b)
		pol.Owners = append(pol.Owners, k)
	}
	for _, s := range p.Agents {
		id, err := wire.ParseID(s)
		if err != nil {
			return nil, err
		}
		pol.Agents = append(pol.Agents, id)
	}
	if len(pol.Owners) > wire.MaxPolicyOwners || len(pol.Agents) > wire.MaxPolicyAgents {
		return nil, errors.New("policy lists are too long")
	}
	pol.Sign(owner)
	res, err := a.c.Submit(ctx, pol.Raw)
	if err != nil {
		return nil, err
	}
	p.Serial = pol.Serial
	return res, writeJSON(a.policyPath(), p, 0o600)
}

// CreateInvite signs a single-use invite (owner operation). Whoever holds it
// can send one contact request to this agent without proof-of-work postage.
func (a *Agent) CreateInvite(ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > wire.MaxTicketTTL {
		return "", fmt.Errorf("invite lifetime must be between 1s and %v", wire.MaxTicketTTL)
	}
	owner, err := a.c.OwnerKey()
	if err != nil {
		return "", err
	}
	t := &wire.Ticket{Recipient: a.ID, Expires: a.c.Now().Add(ttl).UnixMilli()}
	rand.Read(t.TicketID[:])
	t.Sign(owner)
	return t.String(), nil
}
