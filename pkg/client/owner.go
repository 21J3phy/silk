package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

// Owner operations when the owner key lives on another device.
//
// An agent on its own cloud computer (Grok Bot, OpenAI Dots, Meta Muse) holds
// only its agent keys. Every owner operation (creating the agent, approving or
// declining a contact, invites, trust, owner revocation, key rotation) then
// stops with an OwnerSignatureNeeded carrying a request. The owner runs
// `silk sign <request>` where the owner key lives, sees exactly what it
// approves, and hands back a signature; `silk signed <signature>` on the
// agent's computer finishes the operation.

const (
	SignRequestPrefix = "silk-sign:"
	OwnerSigPrefix    = "silk-sig:"
)

// OwnerSignatureNeeded means an owner operation is waiting for the owner,
// whose key is on another device, to sign Request.
type OwnerSignatureNeeded struct {
	Op      string `json:"op"`
	Request string `json:"request"`
}

func (e *OwnerSignatureNeeded) Error() string {
	return "waiting for the owner's signature: the owner runs `silk sign <request>` where the owner key is, then this agent runs `silk signed <signature>`"
}

// OwnerRequest is an owner operation waiting for a signature.
type OwnerRequest struct {
	Op        string        `json:"op"` // accept, decline, revoke, trust, invite
	Body      []byte        `json:"body"`
	Ref       string        `json:"ref,omitempty"` // contact request or conversation
	Policy    *PolicyConfig `json:"policy,omitempty"`
	Session   *seal.Session `json:"session,omitempty"`
	Grant     *GrantInfo    `json:"grant,omitempty"`
	CreatedMs int64         `json:"created_ms"`
}

func (r *OwnerRequest) needed() *OwnerSignatureNeeded {
	return &OwnerSignatureNeeded{Op: r.Op, Request: SignRequestPrefix + base64.RawURLEncoding.EncodeToString(r.Body)}
}

// ownerRequest returns the request already waiting for op on ref, if any.
func (st *agentState) ownerRequest(op, ref string) *OwnerRequest {
	for _, r := range st.OwnerRequests {
		if r.Op == op && r.Ref == ref {
			return r
		}
	}
	return nil
}

func (st *agentState) addOwnerRequest(r *OwnerRequest) *OwnerSignatureNeeded {
	if st.OwnerRequests == nil {
		st.OwnerRequests = map[string]*OwnerRequest{}
	}
	h := sha256.Sum256(r.Body)
	st.OwnerRequests[hex.EncodeToString(h[:8])] = r
	return r.needed()
}

// ParseSignRequest decodes a "silk-sign:..." request into the unsigned body
// and the frame it describes (see wire.DecodeUnsigned).
func ParseSignRequest(s string) ([]byte, any, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, SignRequestPrefix) {
		return nil, nil, fmt.Errorf("a signing request starts with %q", SignRequestPrefix)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, SignRequestPrefix))
	if err != nil {
		return nil, nil, errors.New("the signing request is damaged (was it copied in full?)")
	}
	frame, err := wire.DecodeUnsigned(body)
	if err != nil {
		return nil, nil, err
	}
	return body, frame, nil
}

func parseOwnerSig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, OwnerSigPrefix) {
		return nil, fmt.Errorf("an owner signature starts with %q", OwnerSigPrefix)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, OwnerSigPrefix))
	if err != nil || len(sig) != wire.SigLen {
		return nil, errors.New("the owner signature is damaged (was it copied in full?)")
	}
	return sig, nil
}

// frameOwner is the owner key a frame names, if it names one.
func frameOwner(frame any) ed25519.PublicKey {
	switch f := frame.(type) {
	case *wire.Cert:
		return f.OwnerPub[:]
	case *wire.Grant:
		return f.OwnerPub[:]
	case *wire.Decline:
		return f.OwnerPub[:]
	case *wire.Policy:
		return f.OwnerPub[:]
	case *wire.Ticket:
		return f.OwnerPub[:]
	}
	return nil
}

// OwnerPublic returns the owner key on this device.
func (c *Client) OwnerPublic() (ed25519.PublicKey, error) { return ownerPublic(c.ownerPath()) }

// CreateOwner returns this device's owner key, creating it first if there is
// none; created reports whether it is new.
func (c *Client) CreateOwner(passphrase string) (pub ed25519.PublicKey, created bool, err error) {
	if pub, err := c.OwnerPublic(); err == nil {
		return pub, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if err := os.MkdirAll(c.Home, 0o700); err != nil {
		return nil, false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	return pub, true, saveOwner(c.ownerPath(), priv, passphrase)
}

// SignRequest signs an owner request with this device's owner key. Show the
// owner what ParseSignRequest decodes before calling it.
func (c *Client) SignRequest(req string) (string, error) {
	body, frame, err := ParseSignRequest(req)
	if err != nil {
		return "", err
	}
	pub, err := c.OwnerPublic()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("there is no owner key on this device (create one with `silk owner`)")
		}
		return "", err
	}
	if want := frameOwner(frame); want != nil && !want.Equal(pub) {
		return "", errors.New("this request is for a different owner key")
	}
	owner, err := c.OwnerKey()
	if err != nil {
		return "", err
	}
	sig, err := wire.SignOwner(owner, body)
	if err != nil {
		return "", err
	}
	return OwnerSigPrefix + base64.RawURLEncoding.EncodeToString(sig), nil
}

// LookupCert fetches and checks a public agent certificate, e.g. to name the
// peer in a request the owner is about to sign.
func (c *Client) LookupCert(ctx context.Context, id wire.ID) (*wire.Cert, error) {
	var info relay.AgentInfo
	if err := c.getJSON(ctx, "/v2/agents/"+id.String(), nil, &info); err != nil {
		return nil, err
	}
	cert, err := wire.DecodeCert(info.Cert)
	if err != nil {
		return nil, err
	}
	if cert.ID() != id || !cert.VerifySigs() {
		return nil, errors.New("relay returned a certificate for a different agent")
	}
	return cert, nil
}

// OwnerHere reports whether this agent's owner key is on this device.
func (a *Agent) OwnerHere() bool { return a.ownerHere() }

func (a *Agent) ownerHere() bool {
	pub, err := a.c.OwnerPublic()
	return err == nil && pub.Equal(ed25519.PublicKey(a.Cert.OwnerPub[:]))
}

func (a *Agent) ownerPub() ed25519.PublicKey { return ed25519.PublicKey(a.Cert.OwnerPub[:]) }

// OwnerResult is what an owner operation finished by `silk signed` produced.
type OwnerResult struct {
	Op        string        `json:"op"`
	Agent     string        `json:"agent"`
	Address   string        `json:"address"`
	Grant     *GrantInfo    `json:"conversation,omitempty"`
	Invite    string        `json:"invite,omitempty"`
	Policy    *PolicyConfig `json:"policy,omitempty"`
	LedgerIdx int64         `json:"ledger_index,omitempty"`
}

// CompleteOwner finishes the operation of this agent that sig signs. found is
// false when none of its waiting requests matches.
func (a *Agent) CompleteOwner(ctx context.Context, sigText string) (res *OwnerResult, found bool, err error) {
	sig, err := parseOwnerSig(sigText)
	if err != nil {
		return nil, false, err
	}
	res = &OwnerResult{Agent: a.Label, Address: a.Address()}
	var pend pendingRotation
	pendingPath := filepath.Join(a.dir, "rotate.pending.json")
	if err := readJSON(pendingPath, &pend); err == nil && pend.Cert == nil && pend.Body != nil {
		if raw, err := wire.AttachOwner(pend.Body, sig, a.ownerPub(), ed25519.NewKeyFromSeed(pend.SignSeed)); err == nil {
			pend.Cert = raw
			if err := writeJSON(pendingPath, pend, 0o600); err != nil {
				return nil, true, err
			}
			r, err := a.Rotate(ctx)
			if err != nil {
				return nil, true, err
			}
			res.Op, res.LedgerIdx = "rotate", r.LedgerIdx
			return res, true, nil
		}
	}
	var key string
	var req *OwnerRequest
	var frame []byte
	var stale error
	err = a.withState(func(st *agentState) error {
		for k, r := range st.OwnerRequests {
			raw, err := wire.AttachOwner(r.Body, sig, a.ownerPub(), nil)
			if err != nil {
				continue
			}
			key, req, frame = k, r, raw
			if r.Op == "accept" {
				// Hand the signed grant to Accept's resume path.
				delete(st.OwnerRequests, k)
				ii := st.InIntros[r.Ref]
				if ii == nil || ii.Status != "pending" {
					stale = fmt.Errorf("contact request %s is no longer pending", r.Ref)
					return nil
				}
				st.Sessions[r.Ref], st.Grants[r.Ref] = r.Session, r.Grant
				ii.Status, ii.GrantFrame = "accepting", raw
			}
			return nil
		}
		return nil
	})
	if err == nil {
		err = stale
	}
	if err != nil || req == nil {
		return nil, req != nil, err
	}
	res.Op = req.Op
	done := func(fn func(st *agentState)) error {
		return a.withState(func(st *agentState) error {
			delete(st.OwnerRequests, key)
			if fn != nil {
				fn(st)
			}
			return nil
		})
	}
	switch req.Op {
	case "accept":
		gi, err := a.Accept(ctx, req.Ref, AcceptOptions{})
		if err != nil {
			return nil, true, err
		}
		res.Grant, res.LedgerIdx = gi, gi.LedgerIdx
	case "invite":
		t, err := wire.DecodeTicket(frame)
		if err != nil {
			return nil, true, err
		}
		res.Invite = t.String()
		return res, true, done(nil)
	default: // decline, revoke, trust: a signed frame for the relay
		r, err := a.c.Submit(ctx, frame)
		if err != nil {
			return nil, true, err
		}
		res.LedgerIdx = r.LedgerIdx
		if req.Op == "trust" {
			pol, err := wire.DecodePolicy(frame)
			if err != nil {
				return nil, true, err
			}
			req.Policy.Serial = pol.Serial
			res.Policy = req.Policy
			if err := writeJSON(a.policyPath(), req.Policy, 0o600); err != nil {
				return nil, true, err
			}
		}
		return res, true, done(func(st *agentState) {
			switch req.Op {
			case "decline":
				if ii := st.InIntros[req.Ref]; ii != nil {
					ii.Status, ii.Frame = "declined", nil
				}
			case "revoke":
				if gi := st.Grants[req.Ref]; gi != nil {
					gi.Status = "revoked"
				}
			}
		})
	}
	return res, true, nil
}

// pendingInit is an agent created on this computer whose owner key is on
// another device, waiting for the owner to sign its certificate.
type pendingInit struct {
	Body     []byte `json:"body"`
	SignSeed []byte `json:"sign_seed"`
	KEM      []byte `json:"kem"`
}

func (c *Client) pendingInitPath(label string) string {
	return filepath.Join(c.Home, "pending", "init-"+label+".json")
}

// CompleteInit registers the agent whose certificate sig signs. found is false
// when no agent on this computer is waiting for that signature.
func (c *Client) CompleteInit(ctx context.Context, sigText string) (a *Agent, res *relay.Result, found bool, err error) {
	sig, err := parseOwnerSig(sigText)
	if err != nil {
		return nil, nil, false, err
	}
	paths, _ := filepath.Glob(filepath.Join(c.Home, "pending", "init-*.json"))
	for _, path := range paths {
		var p pendingInit
		if err := readJSON(path, &p); err != nil {
			continue
		}
		frame, err := wire.DecodeUnsigned(p.Body)
		if err != nil {
			continue
		}
		cert, ok := frame.(*wire.Cert)
		if !ok {
			continue
		}
		sign := ed25519.NewKeyFromSeed(p.SignSeed)
		raw, err := wire.AttachOwner(p.Body, sig, cert.OwnerPub[:], sign)
		if err != nil {
			continue
		}
		if cert, err = wire.DecodeCert(raw); err != nil {
			return nil, nil, true, err
		}
		kem, err := seal.LoadKEMKey(p.KEM)
		if err != nil {
			return nil, nil, true, err
		}
		keys := &agentKeys{serial: cert.Serial, sign: sign, kem: kem, prev: map[uint32]*seal.KEMKey{}, retired: map[uint32]int64{}}
		info, err := c.Info(ctx)
		if err != nil {
			return nil, nil, true, fmt.Errorf("contact relay: %w", err)
		}
		a, res, err := c.register(ctx, info, cert, keys)
		if err != nil {
			return nil, nil, true, err
		}
		os.Remove(path)
		return a, res, true, nil
	}
	return nil, nil, false, nil
}
