package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

// Agent is one local agent identity.
type Agent struct {
	c     *Client
	Label string
	dir   string
	ID    wire.ID
	Cert  *wire.Cert
	keys  *agentKeys
}

var processLocks sync.Map // dir -> *sync.Mutex

func (a *Agent) authHeader(method, pathQuery string) string {
	return wire.SignAuth(a.ID, a.keys.sign, a.c.Now().UnixMilli(), method, a.c.relayHost(), pathQuery)
}

func (c *Client) agentDir(label string) string { return filepath.Join(c.Home, "agents", label) }

// Agents lists local agent labels.
func (c *Client) Agents() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(c.Home, "agents"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// Agent loads a local agent (label "" selects the default).
func (c *Client) Agent(label string) (*Agent, error) {
	if label == "" {
		label = c.Config.DefaultAgent
	}
	if label == "" {
		return nil, errors.New("no agent selected (run `silk init` or pass --agent)")
	}
	dir := c.agentDir(label)
	keys, err := loadKeys(filepath.Join(dir, "keys.json"))
	if err != nil {
		return nil, fmt.Errorf("agent %q: %w", label, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cert.bin"))
	if err != nil {
		return nil, fmt.Errorf("agent %q certificate: %w", label, err)
	}
	cert, err := wire.DecodeCert(raw)
	if err != nil {
		return nil, err
	}
	return &Agent{c: c, Label: label, dir: dir, ID: cert.ID(), Cert: cert, keys: keys}, nil
}

// Client returns the agent's client.
func (a *Agent) Client() *Client { return a.c }

// Address is the agent's shareable address: @handle if it has one, else its ID.
func (a *Agent) Address() string {
	if a.Cert.Handle != "" {
		return "@" + a.Cert.Handle
	}
	return a.ID.String()
}

// withState runs fn under the agent lock with freshly loaded state, then saves it.
func (a *Agent) withState(fn func(st *agentState) error) error {
	m, _ := processLocks.LoadOrStore(a.dir, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	unlock, err := lockFile(filepath.Join(a.dir, "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	st := newState()
	path := filepath.Join(a.dir, "state.json")
	if err := readJSON(path, st); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read state: %w", err)
	}
	if st.Sessions == nil {
		*st = *newState()
	}
	if err := fn(st); err != nil {
		return err
	}
	st.trim(a.c.Now().UnixMilli())
	return writeJSON(path, st, 0o600)
}

// readState returns a snapshot of the state without holding the lock afterwards.
func (a *Agent) readState() (*agentState, error) {
	var out *agentState
	err := a.withState(func(st *agentState) error { out = st; return nil })
	return out, err
}

func (c *Client) ownerPath() string { return filepath.Join(c.Home, "owner.key") }

// OwnerKey loads the owner's private key (may prompt for a passphrase).
func (c *Client) OwnerKey() (ed25519.PrivateKey, error) {
	return loadOwner(c.ownerPath(), c.Passphrase)
}

// ---------------------------------------------------------------------------
// Identity

// InitOptions configures a new agent.
type InitOptions struct {
	Relay        string
	Label        string
	Handle       string
	Passphrase   string // used only when creating a new owner key
	AcceptIntros bool
	MinPoW       uint8
	Validity     time.Duration
	// Owner, when set to a key that is not on this device, creates the agent
	// for an owner elsewhere: Init returns an OwnerSignatureNeeded, and
	// CompleteInit registers the agent once the owner has signed.
	Owner ed25519.PublicKey
}

// Init creates (if needed) the owner key, creates agent keys, and registers the agent.
func (c *Client) Init(ctx context.Context, o InitOptions) (*Agent, *relay.Result, error) {
	if !wire.ValidLabel(o.Label) {
		return nil, nil, fmt.Errorf("label %q must be 1-32 chars of a-z 0-9 . _ -", o.Label)
	}
	if o.Handle != "" && !wire.ValidLabel(o.Handle) {
		return nil, nil, fmt.Errorf("handle %q must be 1-32 chars of a-z 0-9 . _ -", o.Handle)
	}
	if o.Validity == 0 {
		o.Validity = 365 * 24 * time.Hour
	}
	if o.Relay != "" {
		c.Config.Relay = o.Relay
	}
	info, err := c.Info(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("contact relay: %w", err)
	}
	if c.Config.LedgerKey != "" && c.Config.LedgerKey != info.LedgerKey {
		return nil, nil, fmt.Errorf("relay ledger key changed from the pinned key; refusing (pinned %s)", c.Config.LedgerKey)
	}
	c.Config.LedgerKey, c.Config.Origin = info.LedgerKey, info.Origin
	if err := os.MkdirAll(c.Home, 0o700); err != nil {
		return nil, nil, err
	}
	if o.Owner != nil {
		if len(o.Owner) != ed25519.PublicKeySize {
			return nil, nil, errors.New("owner key must be 32 bytes")
		}
		if pub, err := c.OwnerPublic(); err != nil || !pub.Equal(o.Owner) {
			return nil, nil, c.initForOwner(o)
		}
	}
	var owner ed25519.PrivateKey
	if _, err := os.Stat(c.ownerPath()); errors.Is(err, os.ErrNotExist) {
		_, owner, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := saveOwner(c.ownerPath(), owner, o.Passphrase); err != nil {
			return nil, nil, err
		}
	} else if owner, err = c.OwnerKey(); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(filepath.Join(c.agentDir(o.Label), "keys.json")); err == nil {
		return nil, nil, fmt.Errorf("agent %q already exists in %s", o.Label, c.agentDir(o.Label))
	}
	cert, keys, err := c.newAgentCert(o, owner.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	cert.Sign(owner, keys.sign)
	return c.register(ctx, info, cert, keys)
}

// newAgentCert makes fresh agent keys and their certificate, unsigned.
func (c *Client) newAgentCert(o InitOptions, owner ed25519.PublicKey) (*wire.Cert, *agentKeys, error) {
	if o.Validity == 0 {
		o.Validity = 365 * 24 * time.Hour
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	kem, err := seal.NewKEMKey()
	if err != nil {
		return nil, nil, err
	}
	keys := &agentKeys{serial: 1, sign: sign, kem: kem, prev: map[uint32]*seal.KEMKey{}, retired: map[uint32]int64{}}
	now := c.Now()
	cert := &wire.Cert{Label: o.Label, Handle: o.Handle, Serial: 1, Suite: wire.Suite1, KEMPub: kem.Public(),
		Created: now.UnixMilli(), Expires: now.Add(o.Validity).UnixMilli(), MinPoW: o.MinPoW}
	copy(cert.OwnerPub[:], owner)
	copy(cert.SignPub[:], sign.Public().(ed25519.PublicKey))
	if o.AcceptIntros {
		cert.Flags |= wire.CertAcceptsIntros
	}
	return cert, keys, nil
}

// initForOwner prepares an agent whose owner key is on another device and
// returns the request the owner signs. Running it again returns the same request.
func (c *Client) initForOwner(o InitOptions) error {
	if _, err := os.Stat(filepath.Join(c.agentDir(o.Label), "keys.json")); err == nil {
		return fmt.Errorf("agent %q already exists in %s", o.Label, c.agentDir(o.Label))
	}
	path := c.pendingInitPath(o.Label)
	var p pendingInit
	if err := readJSON(path, &p); err == nil {
		if frame, err := wire.DecodeUnsigned(p.Body); err == nil && frameOwner(frame).Equal(o.Owner) {
			return (&OwnerRequest{Op: "init", Body: p.Body}).needed()
		}
	}
	cert, keys, err := c.newAgentCert(o, o.Owner)
	if err != nil {
		return err
	}
	p = pendingInit{Body: cert.Unsigned(), SignSeed: keys.sign.Seed(), KEM: keys.kem.Bytes()}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeJSON(path, p, 0o600); err != nil {
		return err
	}
	if err := c.SaveConfig(); err != nil { // the relay and its pinned ledger key
		return err
	}
	return (&OwnerRequest{Op: "init", Body: p.Body}).needed()
}

// register pays the registration postage, registers a signed certificate,
// and saves the agent.
func (c *Client) register(ctx context.Context, info *Info, cert *wire.Cert, keys *agentKeys) (*Agent, *relay.Result, error) {
	nonce, err := pow.Solve(ctx, pow.Digest(pow.DomainRegister, cert.Raw), info.PoW.RegisterBits, 0)
	if err != nil {
		return nil, nil, err
	}
	data, _, err := c.do(ctx, "POST", "/v2/agents", relay.EncodeRegistration(cert.Raw, info.PoW.RegisterBits, nonce), nil)
	if err != nil {
		return nil, nil, err
	}
	var res relay.Result
	if err := jsonUnmarshal(data, &res); err != nil {
		return nil, nil, err
	}
	dir := c.agentDir(cert.Label)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := keys.save(filepath.Join(dir, "keys.json")); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.bin"), cert.Raw, 0o600); err != nil {
		return nil, nil, err
	}
	if c.Config.DefaultAgent == "" {
		c.Config.DefaultAgent = cert.Label
	}
	if err := c.SaveConfig(); err != nil {
		return nil, nil, err
	}
	a := &Agent{c: c, Label: cert.Label, dir: dir, ID: cert.ID(), Cert: cert, keys: keys}
	return a, &res, nil
}

// Rotate replaces the agent's signing and encryption keys (owner operation).
// The previous encryption key is kept so pending contact requests still open.
func (a *Agent) Rotate(ctx context.Context) (*relay.Result, error) {
	pendingPath := filepath.Join(a.dir, "rotate.pending.json")
	var pend pendingRotation
	if err := readJSON(pendingPath, &pend); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if pend.Cert == nil && pend.Body != nil {
		return nil, (&OwnerRequest{Op: "rotate", Body: pend.Body}).needed()
	}
	if pend.Cert == nil {
		// Fresh rotation: generate and persist everything before telling the relay,
		// so an ambiguous network failure can be resumed with the identical frame.
		var owner ed25519.PrivateKey
		if a.ownerHere() {
			var err error
			if owner, err = a.c.OwnerKey(); err != nil {
				return nil, err
			}
		}
		_, sign, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		kem, err := seal.NewKEMKey()
		if err != nil {
			return nil, err
		}
		cert := *a.Cert
		cert.Serial++
		cert.KEMPub = kem.Public()
		cert.Created = a.c.Now().UnixMilli()
		copy(cert.SignPub[:], sign.Public().(ed25519.PublicKey))
		pend = pendingRotation{SignSeed: sign.Seed(), KEM: kem.Bytes()}
		if owner != nil {
			pend.Cert = cert.Sign(owner, sign)
		} else {
			pend.Body = cert.Unsigned()
		}
		if err := writeJSON(pendingPath, pend, 0o600); err != nil {
			return nil, err
		}
		if owner == nil {
			return nil, (&OwnerRequest{Op: "rotate", Body: pend.Body}).needed()
		}
	}
	cert, err := wire.DecodeCert(pend.Cert)
	if err != nil {
		return nil, err
	}
	sign := ed25519.NewKeyFromSeed(pend.SignSeed)
	kem, err := seal.LoadKEMKey(pend.KEM)
	if err != nil {
		return nil, err
	}
	data, _, err := a.c.do(ctx, "POST", "/v2/agents", relay.EncodeRegistration(cert.Raw, 0, 0), nil)
	if err != nil {
		if retryable(err) {
			return nil, fmt.Errorf("rotation not confirmed (%w); run `silk rotate` again to resume it", err)
		}
		os.Remove(pendingPath)
		return nil, err
	}
	var res relay.Result
	if err := jsonUnmarshal(data, &res); err != nil {
		return nil, err
	}
	a.keys.retire(a.keys.serial, a.keys.kem, a.c.Now().UnixMilli())
	a.keys.serial, a.keys.sign, a.keys.kem = cert.Serial, sign, kem
	if err := a.keys.save(filepath.Join(a.dir, "keys.json")); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(a.dir, "cert.bin"), cert.Raw, 0o600); err != nil {
		return nil, err
	}
	os.Remove(pendingPath)
	a.Cert = cert
	return &res, nil
}

type pendingRotation struct {
	Cert     []byte `json:"cert"`
	Body     []byte `json:"body,omitempty"` // unsigned, while the owner signs elsewhere
	SignSeed []byte `json:"sign_seed"`
	KEM      []byte `json:"kem"`
}

// Lookup resolves and verifies a peer certificate. For IDs, the certificate
// must hash to the ID, so the relay cannot substitute another owner's keys.
func (a *Agent) Lookup(ctx context.Context, ref string) (*relay.AgentInfo, *wire.Cert, error) {
	var info relay.AgentInfo
	path := "/v2/agents/" + url.PathEscape(ref) + "?from=" + a.ID.String()
	if err := a.c.getJSON(ctx, path, a, &info); err != nil {
		return nil, nil, err
	}
	cert, err := wire.DecodeCert(info.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("peer certificate: %w", err)
	}
	if !cert.VerifySigs() {
		return nil, nil, errors.New("peer certificate signatures do not verify")
	}
	if cert.ID().String() != info.ID {
		return nil, nil, errors.New("relay returned a certificate for a different agent")
	}
	if id, err := wire.ParseID(ref); err == nil {
		if id != cert.ID() {
			return nil, nil, errors.New("relay returned a certificate that does not match the requested address")
		}
	} else if h := strings.TrimPrefix(ref, "@"); cert.Handle != h {
		return nil, nil, fmt.Errorf("relay returned an agent whose certificate does not claim @%s", h)
	}
	if cert.Expires <= a.c.Now().UnixMilli() {
		return nil, nil, errors.New("peer certificate expired")
	}
	return &info, cert, nil
}

// resolvePeer looks up a peer for a trust-sensitive operation: it pins
// @handle -> agent ID on first use (a later remapping is refused) and proves
// the certificate is recorded in the relay's ledger.
func (a *Agent) resolvePeer(ctx context.Context, ref string) (*relay.AgentInfo, *wire.Cert, error) {
	info, cert, err := a.Lookup(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	if _, perr := wire.ParseID(ref); perr != nil {
		h := strings.TrimPrefix(ref, "@")
		var pinned string
		if err := a.withState(func(st *agentState) error {
			if st.Handles == nil {
				st.Handles = map[string]string{}
			}
			if pinned = st.Handles[h]; pinned == "" {
				st.Handles[h] = cert.ID().String()
			}
			return nil
		}); err != nil {
			return nil, nil, err
		}
		if pinned != "" && pinned != cert.ID().String() {
			return nil, nil, fmt.Errorf("@%s now resolves to %s, not the agent %s you used before; confirm with its owner, then remove it from %s", h, cert.ID(), pinned, filepath.Join(a.dir, "state.json"))
		}
	}
	if err := a.VerifyFrame(ctx, cert.Raw, info.LedgerIdx, wire.KindCert); err != nil {
		return nil, nil, fmt.Errorf("peer certificate is not provably on the ledger: %w", err)
	}
	return info, cert, nil
}

func (a *Agent) peerCert(ctx context.Context, id wire.ID, st *agentState) (*wire.Cert, error) {
	if st != nil {
		if ct, ok := st.Contacts[id.String()]; ok {
			if c, err := wire.DecodeCert(ct.Cert); err == nil && c.Expires > a.c.Now().UnixMilli() {
				return c, nil
			}
		}
	}
	_, c, err := a.Lookup(ctx, id.String())
	return c, err
}

// ---------------------------------------------------------------------------
// Contact requests

// IntroOptions configures a contact request.
type IntroOptions struct {
	Scope    string
	Note     string
	Budget   uint32        // messages requested in each direction
	GrantTTL time.Duration // requested conversation lifetime
	TTL      time.Duration // how long the request stays open
}

// RequestContact sends a proof-of-work-stamped, end-to-end encrypted contact request.
func (a *Agent) RequestContact(ctx context.Context, ref string, o IntroOptions) (*OutIntro, error) {
	if o.Scope == "" {
		o.Scope = "chat"
	}
	if o.Budget == 0 {
		o.Budget = 100
	}
	if o.GrantTTL == 0 {
		o.GrantTTL = 30 * 24 * time.Hour
	}
	if o.TTL == 0 {
		o.TTL = 72 * time.Hour
	}
	if !wire.ValidLabel(o.Scope) {
		return nil, fmt.Errorf("scope %q must be 1-32 chars of a-z 0-9 . _ -", o.Scope)
	}
	var ticket *wire.Ticket
	if strings.HasPrefix(strings.TrimSpace(ref), wire.TicketPrefix) {
		t, err := wire.ParseInvite(ref)
		if err != nil {
			return nil, err
		}
		if !t.VerifySig() {
			return nil, errors.New("invite signature does not verify")
		}
		ticket, ref = t, t.Recipient.String()
	}
	var out *OutIntro
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		lookup := a.resolvePeer
		if attempt > 0 {
			lookup = a.Lookup // already pinned and proven on the first attempt
		}
		info, cert, err := lookup(ctx, ref)
		if err != nil {
			return nil, err
		}
		if ticket != nil {
			if ticket.OwnerPub != cert.OwnerPub {
				return nil, errors.New("invite was not signed by this agent's owner")
			}
			info.IntroPoWBits = 0 // the invite replaces postage
		}
		if !info.AcceptIntros {
			return nil, fmt.Errorf("%s does not accept contact requests", ref)
		}
		now := a.c.Now()
		in := &wire.Intro{From: a.ID, To: cert.ID(), ToSerial: cert.Serial, Created: now.UnixMilli(),
			Expires: now.Add(o.TTL).UnixMilli(), Scope: o.Scope, Budget: o.Budget, GrantTTL: uint32(o.GrantTTL / time.Second)}
		rand.Read(in.IntroID[:])
		eph, err := seal.NewKEMKey()
		if err != nil {
			return nil, err
		}
		in.EphPub = eph.Public()
		if ticket != nil {
			in.Ticket = ticket.Raw
		}
		k1, err := seal.SealIntro(in, cert.KEMPub, o.Note)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		nonce, err := pow.Solve(ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), info.IntroPoWBits, 0)
		if err != nil {
			return nil, err
		}
		in.PoWBits, in.PoWNonce = info.IntroPoWBits, nonce
		in.Sign(a.keys.sign)
		hash := wire.Hash(in.Raw)
		out = &OutIntro{ID: in.IntroID.String(), To: cert.ID().String(), ToHandle: cert.Handle, Scope: o.Scope, Note: o.Note,
			EphKEM: eph.Bytes(), K1: k1, IntroHash: hash[:], ExpiresMs: in.Expires, Status: "pending",
			PoWBits: in.PoWBits, PoWMs: time.Since(start).Milliseconds(), Budget: in.Budget, GrantTTL: in.GrantTTL, Frame: in.Raw}
		// Persist the ephemeral secret before sending so a crash cannot strand the grant.
		if err := a.withState(func(st *agentState) error {
			st.OutIntros[out.ID] = out
			st.Contacts[cert.ID().String()] = &Contact{Handle: cert.Handle, Cert: cert.Raw, FetchedMs: now.UnixMilli()}
			return nil
		}); err != nil {
			return nil, err
		}
		res, err := a.c.Submit(ctx, in.Raw)
		if err == nil {
			out.LedgerIdx, out.Frame = res.LedgerIdx, nil
			return out, a.withState(func(st *agentState) error {
				if o := st.OutIntros[out.ID]; o != nil {
					o.LedgerIdx, o.Frame = res.LedgerIdx, nil
				}
				return nil
			})
		}
		lastErr = err
		if retryable(err) {
			// Outcome unknown: keep the request (and its secrets) and resend the identical frame later.
			a.withState(func(st *agentState) error {
				if o := st.OutIntros[out.ID]; o != nil {
					o.Status = "queued"
				}
				return nil
			})
			return out, fmt.Errorf("request queued, will retry: %w", err)
		}
		a.withState(func(st *agentState) error { delete(st.OutIntros, out.ID); return nil })
		switch Code(err) {
		case "pow_required", "stale_recipient_key", "outbid":
			continue // demand changed between lookup and submit; re-price and retry
		case "clock_skew":
			a.c.Info(ctx)
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

// AcceptOptions sets the terms of consent.
type AcceptOptions struct {
	FromPeer uint32 // messages the requester may send (default: requested budget)
	ToPeer   uint32 // messages this agent may send back (default: requested budget)
	TTL      time.Duration
	Rate     uint16
}

// Accept grants a pending contact request (owner operation). The grant and
// its session are saved before the relay is told, so an ambiguous network
// failure can be resumed by calling Accept again (the identical frame is resent).
func (a *Agent) Accept(ctx context.Context, introID string, o AcceptOptions) (*GrantInfo, error) {
	var frame []byte
	var need *OwnerSignatureNeeded
	err := a.withState(func(st *agentState) (err error) {
		ii := st.InIntros[introID]
		if ii != nil && ii.Status == "accepting" && ii.GrantFrame != nil {
			frame = ii.GrantFrame // resume
			return nil
		}
		if ii == nil || ii.Status != "pending" {
			return fmt.Errorf("no pending contact request %s", introID)
		}
		var owner ed25519.PrivateKey
		if !a.ownerHere() {
			if r := st.ownerRequest("accept", introID); r != nil {
				need = r.needed()
				return nil
			}
		} else if owner, err = a.c.OwnerKey(); err != nil {
			return err
		}
		in, err := wire.DecodeIntro(ii.Frame)
		if err != nil {
			return err
		}
		kem := a.keys.kemFor(in.ToSerial)
		if kem == nil {
			return errors.New("the encryption key this request was sent to is no longer available")
		}
		_, k1, err := seal.OpenIntro(in, kem)
		if err != nil {
			return err
		}
		now := a.c.Now()
		// The relay rejects terms beyond what was requested; clamp to them.
		ttl := time.Duration(in.GrantTTL) * time.Second
		if o.TTL > 0 && o.TTL < ttl {
			ttl = o.TTL
		}
		if o.FromPeer == 0 || o.FromPeer > in.Budget {
			o.FromPeer = in.Budget
		}
		if o.ToPeer == 0 || o.ToPeer > in.Budget {
			o.ToPeer = in.Budget
		}
		if o.Rate == 0 {
			o.Rate = 60
		}
		g := &wire.Grant{GrantID: in.IntroID, IntroHash: wire.Hash(in.Raw), From: in.From, To: a.ID, Created: now.UnixMilli(),
			Expires: now.Add(ttl).UnixMilli(), BudgetAB: o.FromPeer, BudgetBA: o.ToPeer, Rate: o.Rate}
		copy(g.OwnerPub[:], a.ownerPub())
		k2, err := seal.SealGrant(g, in.EphPub)
		if err != nil {
			return err
		}
		root, err := seal.Root(k1, k2, g.IntroHash, g)
		if err != nil {
			return err
		}
		sess, err := seal.NewSession(g.GrantID, root, false)
		if err != nil {
			return err
		}
		gi := &GrantInfo{ID: ii.ID, Peer: ii.From, PeerHandle: ii.FromHandle, Scope: ii.Scope, SendBudget: g.BudgetBA,
			RecvBudget: g.BudgetAB, Rate: g.Rate, ExpiresMs: g.Expires, Status: "pending"}
		if owner == nil {
			// The owner signs elsewhere; the session waits with the request.
			need = st.addOwnerRequest(&OwnerRequest{Op: "accept", Ref: ii.ID, Body: g.Unsigned(a.ownerPub()),
				Session: sess, Grant: gi, CreatedMs: now.UnixMilli()})
			return nil
		}
		g.Sign(owner)
		st.Sessions[ii.ID], st.Grants[ii.ID] = sess, gi
		ii.Status, ii.GrantFrame = "accepting", g.Raw
		frame = g.Raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	if need != nil {
		return nil, need
	}
	res, err := a.c.Submit(ctx, frame)
	if err != nil && retryable(err) {
		return nil, fmt.Errorf("approval not confirmed (%w); run accept again to resend it", err)
	}
	var gi *GrantInfo
	serr := a.withState(func(st *agentState) error {
		ii := st.InIntros[introID]
		if ii == nil {
			return nil
		}
		if err != nil { // rejected: undo the local session
			delete(st.Sessions, introID)
			delete(st.Grants, introID)
			ii.Status, ii.GrantFrame = "pending", nil
			return nil
		}
		gi = st.Grants[introID]
		if gi != nil {
			gi.Status, gi.LedgerIdx = "active", res.LedgerIdx
		}
		ii.Status, ii.Frame, ii.GrantFrame = "accepted", nil, nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gi, serr
}

// Decline refuses a pending contact request (owner operation). Declines raise the sender's future PoW cost.
func (a *Agent) Decline(ctx context.Context, introID string) error {
	var owner ed25519.PrivateKey
	if a.ownerHere() {
		var err error
		if owner, err = a.c.OwnerKey(); err != nil {
			return err
		}
	}
	var need *OwnerSignatureNeeded
	err := a.withState(func(st *agentState) error {
		ii := st.InIntros[introID]
		if ii == nil || ii.Status != "pending" {
			return fmt.Errorf("no pending contact request %s", introID)
		}
		in, err := wire.DecodeIntro(ii.Frame)
		if err != nil {
			return err
		}
		d := &wire.Decline{IntroID: in.IntroID, IntroHash: wire.Hash(in.Raw), By: a.ID, Created: a.c.Now().UnixMilli()}
		if owner == nil {
			if r := st.ownerRequest("decline", introID); r != nil {
				need = r.needed()
			} else {
				need = st.addOwnerRequest(&OwnerRequest{Op: "decline", Ref: introID, Body: d.Unsigned(a.ownerPub()), CreatedMs: d.Created})
			}
			return nil
		}
		d.Sign(owner)
		if _, err := a.c.Submit(ctx, d.Raw); err != nil {
			return err
		}
		ii.Status, ii.Frame = "declined", nil
		return nil
	})
	if err == nil && need != nil {
		return need
	}
	return err
}

// ---------------------------------------------------------------------------
// Sync

// SyncResult summarizes newly processed events.
type SyncResult struct {
	Messages []*Message   `json:"messages,omitempty"`
	Intros   []*InIntro   `json:"contact_requests,omitempty"`
	Grants   []*GrantInfo `json:"new_conversations,omitempty"`
	Receipts []*Sent      `json:"receipts,omitempty"`
	Declined []string     `json:"declined_requests,omitempty"`
	Revoked  []string     `json:"revoked,omitempty"`
	Cursor   uint64       `json:"cursor"`
}

// Sync fetches new events (long-polling up to wait), decrypts, and persists them.
// Processing is idempotent: events at or below the stored cursor are skipped.
func (a *Agent) Sync(ctx context.Context, wait time.Duration) (*SyncResult, error) {
	a.Flush(ctx)
	st0, err := a.readState()
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v2/inbox?after=%d&limit=200&wait=%d", st0.Cursor, int(wait/time.Second))
	data, _, err := a.c.do(ctx, "GET", path, nil, a)
	if err != nil {
		return nil, err
	}
	evs, err := relay.DecodeEvents(data)
	if err != nil {
		return nil, err
	}
	// Fetch peer certificates outside the lock.
	certs := map[wire.ID]*wire.Cert{}
	for _, ev := range evs {
		var peer wire.ID
		switch ev.Kind {
		case wire.KindIntro:
			if in, err := wire.DecodeIntro(ev.Frame); err == nil {
				peer = in.From
			}
		case wire.KindGrant:
			if g, err := wire.DecodeGrant(ev.Frame); err == nil {
				peer = g.To
			}
		default:
			continue
		}
		if _, ok := certs[peer]; !ok && !peer.IsZero() {
			var c *wire.Cert
			var err error
			if ev.Kind == wire.KindIntro {
				_, c, err = a.Lookup(ctx, peer.String()) // fresh: the sender may have rotated keys
			} else {
				c, err = a.peerCert(ctx, peer, st0) // owner keys never change for an address
			}
			if err == nil {
				certs[peer] = c
			}
		}
	}
	res := &SyncResult{}
	err = a.withState(func(st *agentState) error {
		for _, ev := range evs {
			if ev.Seq <= st.Cursor {
				continue
			}
			a.apply(st, ev, certs, res)
			st.Cursor = ev.Seq
		}
		res.Cursor = st.Cursor
		return nil
	})
	return res, err
}

func (a *Agent) apply(st *agentState, ev *relay.Event, certs map[wire.ID]*wire.Cert, res *SyncResult) {
	now := a.c.Now().UnixMilli()
	switch ev.Kind {
	case wire.KindIntro:
		in, err := wire.DecodeIntro(ev.Frame)
		if err != nil || in.To != a.ID {
			return
		}
		ii := &InIntro{ID: in.IntroID.String(), From: in.From.String(), Scope: in.Scope, Budget: in.Budget, GrantTTL: in.GrantTTL,
			ExpiresMs: in.Expires, Frame: ev.Frame, LedgerIdx: ev.LedgerIdx, PoWBits: in.PoWBits, Status: "pending"}
		c := certs[in.From]
		switch {
		case c == nil:
			ii.Status, ii.Frame = "unverifiable: sender certificate unavailable", nil
		case !in.VerifySig(c.SignPub[:]):
			ii.Status, ii.Frame = "rejected: bad signature", nil
		default:
			ii.FromHandle = c.Handle
			st.Contacts[in.From.String()] = &Contact{Handle: c.Handle, Cert: c.Raw, FetchedMs: now}
			kem := a.keys.kemFor(in.ToSerial)
			if kem == nil {
				ii.Status, ii.Frame = "rejected: encryption key unavailable", nil
				break
			}
			note, _, err := seal.OpenIntro(in, kem)
			if err != nil {
				ii.Status, ii.Frame = "rejected: cannot decrypt", nil
				break
			}
			ii.Note = note
		}
		st.InIntros[ii.ID] = ii
		res.Intros = append(res.Intros, ii)
	case wire.KindGrant:
		g, err := wire.DecodeGrant(ev.Frame)
		if err != nil {
			return
		}
		id := g.GrantID.String()
		out := st.OutIntros[id]
		if out == nil || out.EphKEM == nil || g.From != a.ID {
			return
		}
		c := certs[g.To]
		if c == nil || !g.VerifySig() || c.OwnerPub != g.OwnerPub || hex.EncodeToString(g.IntroHash[:]) != hex.EncodeToString(out.IntroHash) || g.To.String() != out.To {
			out.Status = "rejected: grant failed verification"
			return
		}
		if out.Budget > 0 && (g.BudgetAB > out.Budget || g.BudgetBA > out.Budget || g.Expires-g.Created > int64(out.GrantTTL)*1000) {
			out.Status = "rejected: grant exceeds the requested terms"
			return
		}
		eph, err := seal.LoadKEMKey(out.EphKEM)
		if err != nil {
			return
		}
		k2, err := seal.OpenGrant(g, eph)
		if err != nil {
			out.Status = "rejected: cannot complete key exchange"
			return
		}
		var ih [32]byte
		copy(ih[:], out.IntroHash)
		root, err := seal.Root(out.K1, k2, ih, g)
		if err != nil {
			return
		}
		sess, err := seal.NewSession(g.GrantID, root, true)
		if err != nil {
			return
		}
		st.Sessions[id] = sess
		gi := &GrantInfo{ID: id, Peer: g.To.String(), PeerHandle: c.Handle, Initiator: true, Scope: out.Scope, SendBudget: g.BudgetAB,
			RecvBudget: g.BudgetBA, Rate: g.Rate, ExpiresMs: g.Expires, Status: "active", LedgerIdx: ev.LedgerIdx}
		st.Grants[id] = gi
		out.Status, out.EphKEM, out.K1 = "accepted", nil, nil // forward secrecy: forget handshake secrets
		res.Grants = append(res.Grants, gi)
	case wire.KindEvicted:
		if out := st.OutIntros[ev.Ref.String()]; out != nil && out.Status == "pending" {
			out.Status, out.EphKEM, out.K1 = "evicted: outbid in a full queue (retry with `silk request`)", nil, nil
			res.Declined = append(res.Declined, out.ID)
		}
	case wire.KindDecline:
		d, err := wire.DecodeDecline(ev.Frame)
		if err != nil {
			return
		}
		if out := st.OutIntros[d.IntroID.String()]; out != nil {
			out.Status, out.EphKEM, out.K1 = "declined", nil, nil
			res.Declined = append(res.Declined, out.ID)
		}
	case wire.KindMsg:
		m, err := wire.DecodeMsg(ev.Frame)
		if err != nil {
			return
		}
		id := m.ID().String()
		for _, existing := range st.Inbox {
			if existing.ID == id {
				return
			}
		}
		gid := m.GrantID.String()
		msg := &Message{ID: id, Grant: gid, Seq: m.Seq, SentMs: m.Created, ReceivedMs: now, LedgerIdx: ev.LedgerIdx}
		if gi := st.Grants[gid]; gi != nil {
			msg.From, msg.FromHandle = gi.Peer, gi.PeerHandle
			gi.Received++
		}
		if m.ReplyTo != nil {
			msg.ReplyTo = m.ReplyTo.String()
		}
		sess := st.Sessions[gid]
		if sess == nil {
			msg.Error = "no session for this conversation"
		} else if ctype, body, err := sess.Decrypt(m); err != nil {
			msg.Error = err.Error()
		} else {
			msg.Body = string(body)
			msg.Type = map[byte]string{seal.TypeText: "text", seal.TypeJSON: "json"}[ctype]
		}
		st.Inbox = append(st.Inbox, msg)
		res.Messages = append(res.Messages, msg)
	case wire.KindAck:
		ack, err := wire.DecodeAck(ev.Frame)
		if err != nil {
			return
		}
		id := ack.MsgID.String()
		for _, s := range st.Sent {
			if s.ID == id {
				s.Status, s.AckIdx, s.Frame = wire.OutcomeName(ack.Outcome), ev.LedgerIdx, nil
				res.Receipts = append(res.Receipts, s)
				break
			}
		}
	case wire.KindRevoke:
		v, err := wire.DecodeRevoke(ev.Frame)
		if err != nil {
			return
		}
		if gi := st.Grants[v.GrantID.String()]; gi != nil {
			gi.Status = "revoked"
			res.Revoked = append(res.Revoked, gi.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Messaging

// ResolveGrant finds the active conversation for a grant ID, peer ID, or @handle.
func (st *agentState) resolveGrant(to string, now int64) (*GrantInfo, error) {
	if gi, ok := st.Grants[to]; ok {
		return gi, nil
	}
	handle := to
	if len(handle) > 0 && handle[0] == '@' {
		handle = handle[1:]
	}
	var best *GrantInfo
	for _, gi := range st.Grants {
		if gi.Status != "active" || gi.ExpiresMs <= now {
			continue
		}
		if gi.Peer == to || (gi.PeerHandle != "" && gi.PeerHandle == handle) {
			if best == nil || gi.ExpiresMs > best.ExpiresMs {
				best = gi
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no active conversation with %s (request contact first)", to)
	}
	return best, nil
}

// SendOptions configures a message.
type SendOptions struct {
	ReplyTo string
	TTL     time.Duration
	JSON    bool
	// KeepUnacked skips the automatic "handled" acknowledgment of the message
	// being replied to (normally sent in the same request as the reply).
	KeepUnacked bool
}

// Send encrypts and sends a message. The ratchet step and the sealed frame are
// persisted before transmission; if the network fails, the frame stays in the
// outbox and is retransmitted unchanged (the relay deduplicates it).
func (a *Agent) Send(ctx context.Context, to, body string, o SendOptions) (*Sent, error) {
	if o.TTL == 0 {
		o.TTL = 24 * time.Hour
	}
	if o.TTL > wire.MaxMsgTTL {
		o.TTL = wire.MaxMsgTTL
	}
	var sent *Sent
	var ackFrame []byte
	var ackFor string
	err := a.withState(func(st *agentState) error {
		now := a.c.Now()
		gi, err := st.resolveGrant(to, now.UnixMilli())
		if err != nil {
			return err
		}
		if gi.Status != "active" {
			return fmt.Errorf("conversation %s is %s", gi.ID, gi.Status)
		}
		sess := st.Sessions[gi.ID]
		if sess == nil {
			return fmt.Errorf("no session keys for conversation %s", gi.ID)
		}
		if sess.Send.N >= gi.SendBudget {
			return fmt.Errorf("message budget for this conversation is used up (%d)", gi.SendBudget)
		}
		gid, _ := wire.ParseID(gi.ID)
		m := &wire.Msg{GrantID: gid, Created: now.UnixMilli(), TTL: uint32(o.TTL / time.Second)}
		if o.ReplyTo != "" {
			rid, err := wire.ParseID(o.ReplyTo)
			if err != nil {
				return fmt.Errorf("reply_to: %w", err)
			}
			m.ReplyTo = &rid
		}
		ctype := byte(seal.TypeText)
		if o.JSON {
			ctype = seal.TypeJSON
		}
		if err := sess.Encrypt(m, ctype, []byte(body)); err != nil {
			return err
		}
		m.Sign(a.keys.sign)
		preview := body
		if len(preview) > 80 {
			preview = preview[:80]
		}
		fh := wire.Hash(m.Raw)
		sent = &Sent{ID: m.ID().String(), Grant: gi.ID, To: gi.Peer, Seq: m.Seq, SentMs: m.Created, Frame: m.Raw, Status: "queued", Preview: preview, Hash: fh[:]}
		st.Sent = append(st.Sent, sent)
		// Replying implies the original was handled: acknowledge it in the same request.
		if m.ReplyTo != nil && !o.KeepUnacked {
			for _, in := range st.Inbox {
				if in.ID == o.ReplyTo && in.Grant == gi.ID && in.Acked == "" && in.Error == "" {
					ack := &wire.Ack{MsgID: *m.ReplyTo, GrantID: gid, Outcome: wire.AckHandled, Created: now.UnixMilli()}
					ackFrame, ackFor = ack.Sign(a.keys.sign), in.ID
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var res *relay.Result
	if ackFrame != nil {
		items, berr := a.c.SubmitBatch(ctx, [][]byte{ackFrame, sent.Frame})
		err = berr
		if berr == nil && len(items) != 2 {
			err = fmt.Errorf("relay returned %d results for 2 frames", len(items))
		}
		if err == nil {
			if it := items[1]; it.Error != nil {
				err = &RelayError{Status: it.Error.Status, Code: it.Error.Code, Message: it.Error.Message}
			} else if it.Result == nil {
				err = errors.New("relay returned an empty result")
			} else {
				res = it.Result
			}
			if it := items[0]; it.Error == nil || it.Error.Code == "already_acked" {
				a.withState(func(st *agentState) error {
					for _, in := range st.Inbox {
						if in.ID == ackFor {
							in.Acked = "handled"
						}
					}
					return nil
				})
			}
		}
	} else {
		res, err = a.c.Submit(ctx, sent.Frame)
	}
	if err != nil && retryable(err) {
		return sent, fmt.Errorf("queued in outbox, will retry: %w", err)
	}
	return sent, a.withState(func(st *agentState) error {
		for _, s := range st.Sent {
			if s.ID != sent.ID {
				continue
			}
			if err != nil {
				s.Status, s.Frame = "failed: "+Code(err), nil
			} else if s.Status == "queued" {
				s.Status, s.LedgerIdx, s.Frame = "accepted", res.LedgerIdx, nil
			}
			*sent = *s
		}
		if err != nil {
			return err
		}
		return nil
	})
}

// Flush retransmits queued outbox frames in one batch. Returns how many were accepted.
func (a *Agent) Flush(ctx context.Context) (int, error) {
	st, err := a.readState()
	if err != nil {
		return 0, err
	}
	for _, o := range st.OutIntros {
		if o.Status == "queued" && o.Frame != nil {
			res, err := a.c.Submit(ctx, o.Frame)
			if err != nil && retryable(err) {
				continue
			}
			id := o.ID
			a.withState(func(st *agentState) error {
				if q := st.OutIntros[id]; q != nil && q.Status == "queued" {
					if err != nil {
						q.Status, q.Frame, q.EphKEM, q.K1 = "failed: "+Code(err), nil, nil, nil
					} else {
						q.Status, q.Frame, q.LedgerIdx = "pending", nil, res.LedgerIdx
					}
				}
				return nil
			})
		}
	}
	var frames [][]byte
	var ids []string
	for _, s := range st.Sent {
		if s.Frame != nil && s.Status == "queued" && len(frames) < relay.MaxBatch {
			frames, ids = append(frames, s.Frame), append(ids, s.ID)
		}
	}
	if len(frames) == 0 {
		return 0, nil
	}
	items, err := a.c.SubmitBatch(ctx, frames)
	if err != nil {
		return 0, err
	}
	if len(items) != len(frames) {
		return 0, fmt.Errorf("relay returned %d results for %d frames", len(items), len(frames))
	}
	n := 0
	err = a.withState(func(st *agentState) error {
		byID := map[string]*Sent{}
		for _, s := range st.Sent {
			byID[s.ID] = s
		}
		for i, it := range items {
			s := byID[ids[i]]
			if s == nil || s.Status != "queued" {
				continue
			}
			switch {
			case i >= len(ids):
				continue
			case it.Error == nil && it.Result != nil:
				s.Status, s.LedgerIdx, s.Frame = "accepted", it.Result.LedgerIdx, nil
				n++
			case it.Error != nil && it.Error.Status < 500 && it.Error.Code != "slow_down":
				s.Status, s.Frame = "failed: "+it.Error.Code, nil
			}
		}
		return nil
	})
	return n, err
}

// Ack acknowledges a received message. Outcome: "received", "declined", or "handled".
func (a *Agent) Ack(ctx context.Context, msgID, outcome string) (*relay.Result, error) {
	codes := map[string]uint8{"received": wire.AckReceived, "declined": wire.AckDeclined, "handled": wire.AckHandled}
	oc, ok := codes[outcome]
	if !ok {
		return nil, fmt.Errorf("outcome must be received, declined, or handled")
	}
	mid, err := wire.ParseID(msgID)
	if err != nil {
		return nil, err
	}
	st, err := a.readState()
	if err != nil {
		return nil, err
	}
	var grant string
	for _, m := range st.Inbox {
		if m.ID == msgID {
			grant = m.Grant
		}
	}
	if grant == "" {
		return nil, fmt.Errorf("message %s is not in the local inbox (sync first)", msgID)
	}
	gid, _ := wire.ParseID(grant)
	ack := &wire.Ack{MsgID: mid, GrantID: gid, Outcome: oc, Created: a.c.Now().UnixMilli()}
	ack.Sign(a.keys.sign)
	res, err := a.c.Submit(ctx, ack.Raw)
	if err != nil {
		return nil, err
	}
	return res, a.withState(func(st *agentState) error {
		for _, m := range st.Inbox {
			if m.ID == msgID {
				m.Acked = outcome
			}
		}
		return nil
	})
}

// Revoke ends a conversation. With asOwner, the owner key signs (prompting for a passphrase if set).
func (a *Agent) Revoke(ctx context.Context, grant string, asOwner bool) (*relay.Result, error) {
	gid, err := wire.ParseID(grant)
	if err != nil {
		return nil, err
	}
	v := &wire.Revoke{GrantID: gid, By: a.ID, Created: a.c.Now().UnixMilli(), Role: wire.RoleAgent}
	if asOwner && !a.ownerHere() {
		v.Role = wire.RoleOwner
		var need *OwnerSignatureNeeded
		err := a.withState(func(st *agentState) error {
			if r := st.ownerRequest("revoke", grant); r != nil {
				need = r.needed()
			} else {
				need = st.addOwnerRequest(&OwnerRequest{Op: "revoke", Ref: grant, Body: v.Unsigned(), CreatedMs: v.Created})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return nil, need
	}
	if asOwner {
		owner, err := a.c.OwnerKey()
		if err != nil {
			return nil, err
		}
		v.Role = wire.RoleOwner
		v.Sign(owner)
	} else {
		v.Sign(a.keys.sign)
	}
	res, err := a.c.Submit(ctx, v.Raw)
	if err != nil {
		return nil, err
	}
	return res, a.withState(func(st *agentState) error {
		if gi := st.Grants[grant]; gi != nil {
			gi.Status = "revoked"
		}
		return nil
	})
}

// MessageStatus asks the relay for a message's delivery state.
func (a *Agent) MessageStatus(ctx context.Context, msgID string) (*relay.MessageStatus, error) {
	var ms relay.MessageStatus
	return &ms, a.c.getJSON(ctx, "/v2/messages/"+url.PathEscape(msgID), a, &ms)
}

// Snapshot returns the local state for display.
type Snapshot struct {
	Inbox     []*Message   `json:"inbox"`
	Sent      []*Sent      `json:"sent"`
	Grants    []*GrantInfo `json:"conversations"`
	InIntros  []*InIntro   `json:"contact_requests"`
	OutIntros []*OutIntro  `json:"sent_requests"`
}

func (a *Agent) Snapshot() (*Snapshot, error) {
	st, err := a.readState()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Inbox: st.Inbox, Sent: st.Sent}
	for _, g := range st.Grants {
		if sess := st.Sessions[g.ID]; sess != nil {
			g.KeyTurns = sess.SendEpoch + sess.RecvEpoch
		}
		s.Grants = append(s.Grants, g)
	}
	sort.Slice(s.Grants, func(i, j int) bool { return s.Grants[i].ExpiresMs > s.Grants[j].ExpiresMs })
	for _, in := range st.InIntros {
		cp := *in
		cp.Frame = nil
		s.InIntros = append(s.InIntros, &cp)
	}
	for _, out := range st.OutIntros {
		s.OutIntros = append(s.OutIntros, out.Public())
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Ledger verification

// AuditResult reports what was verified.
type AuditResult struct {
	Origin       string `json:"origin"`
	Size         int64  `json:"size"`
	Root         string `json:"root"`
	PreviousSize int64  `json:"previous_size"`
	Consistent   bool   `json:"consistent"`
	Checked      int    `json:"inclusion_checked"`
}

// ErrLedgerFork means the relay presented two incompatible histories.
var ErrLedgerFork = errors.New("LEDGER INCONSISTENCY: the relay's history does not extend the history it showed before")

// Audit fetches the signed checkpoint, verifies it against the pinned ledger
// key, proves it consistent with the last checkpoint this home verified, and
// checks inclusion of this agent's recent ledger entries.
func (a *Agent) Audit(ctx context.Context) (*AuditResult, error) {
	c := a.c
	if c.Config.LedgerKey == "" {
		return nil, errors.New("no pinned ledger key")
	}
	raw, _, err := c.do(ctx, "GET", "/v2/ledger/checkpoint", nil, nil)
	if err != nil {
		return nil, err
	}
	cp, err := ledger.OpenCheckpoint(raw, c.Config.LedgerKey)
	if err != nil {
		return nil, err
	}
	res := &AuditResult{Origin: cp.Origin, Size: cp.Size, Root: hex.EncodeToString(cp.Root[:]), Consistent: true}
	cpPath := filepath.Join(c.Home, "checkpoint")
	if prevRaw, err := os.ReadFile(cpPath); err == nil {
		prev, err := ledger.OpenCheckpoint(prevRaw, c.Config.LedgerKey)
		if err != nil {
			return nil, fmt.Errorf("stored checkpoint: %w", err)
		}
		res.PreviousSize = prev.Size
		switch {
		case prev.Size > cp.Size:
			return res, fmt.Errorf("%w (shrank from %d to %d)", ErrLedgerFork, prev.Size, cp.Size)
		case prev.Size == cp.Size && prev.Root != cp.Root:
			return res, fmt.Errorf("%w (two roots for size %d)", ErrLedgerFork, cp.Size)
		case prev.Size > 0 && prev.Size < cp.Size:
			var p relay.Proof
			if err := c.getJSON(ctx, fmt.Sprintf("/v2/ledger/consistency?old=%d&size=%d", prev.Size, cp.Size), nil, &p); err != nil {
				return res, err
			}
			if err := ledger.VerifyConsistency(toTreeProof(p.Hashes), cp.Size, cp.Root, prev.Size, prev.Root); err != nil {
				return res, fmt.Errorf("%w: %v", ErrLedgerFork, err)
			}
		}
	}
	// Inclusion of this agent's recent frames.
	st, err := a.readState()
	if err != nil {
		return res, err
	}
	checked := 0
	for i := len(st.Sent) - 1; i >= 0 && checked < 5; i-- {
		s := st.Sent[i]
		if s.LedgerIdx <= 0 || s.LedgerIdx >= cp.Size || len(s.Hash) != 32 {
			continue
		}
		var h [32]byte
		copy(h[:], s.Hash)
		if err := a.verifyCommitment(ctx, cp, s.LedgerIdx, h, wire.KindMsg); err != nil {
			return res, err
		}
		checked++
	}
	if a.Cert != nil {
		if info, _, err := a.Lookup(ctx, a.ID.String()); err == nil && info.LedgerIdx < cp.Size {
			if err := a.verifyCommitment(ctx, cp, info.LedgerIdx, wire.Hash(a.Cert.Raw), wire.KindCert); err != nil {
				return res, fmt.Errorf("this agent's own certificate: %w", err)
			}
			checked++
		}
	}
	res.Checked = checked
	if err := writeFileAtomic(cpPath, raw, 0o600); err != nil {
		return res, err
	}
	return res, nil
}

// verifyCommitment proves that leaf idx in checkpoint cp records a frame of
// the given kind whose SHA-256 is commitment.
func (a *Agent) verifyCommitment(ctx context.Context, cp *ledger.Checkpoint, idx int64, commitment [32]byte, kind wire.Kind) error {
	var p relay.Proof
	if err := a.c.getJSON(ctx, "/v2/ledger/proof?index="+strconv.FormatInt(idx, 10)+"&size="+strconv.FormatInt(cp.Size, 10), nil, &p); err != nil {
		return err
	}
	leaf, err := ledger.ParseLeaf(p.Leaf)
	if err != nil {
		return err
	}
	if leaf.Commitment != commitment || leaf.Kind != kind {
		return fmt.Errorf("ledger leaf %d does not record this %s", idx, kind)
	}
	if err := ledger.VerifyInclusion(toRecordProof(p.Hashes), cp.Size, cp.Root, idx, p.Leaf); err != nil {
		return fmt.Errorf("inclusion proof for leaf %d failed: %w", idx, err)
	}
	return nil
}

// VerifyFrame proves that a frame of the given kind is recorded in the ledger
// at idx under the current checkpoint (verified with the pinned key).
func (a *Agent) VerifyFrame(ctx context.Context, frame []byte, idx int64, kind wire.Kind) error {
	raw, _, err := a.c.do(ctx, "GET", "/v2/ledger/checkpoint", nil, nil)
	if err != nil {
		return err
	}
	cp, err := ledger.OpenCheckpoint(raw, a.c.Config.LedgerKey)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= cp.Size {
		return fmt.Errorf("ledger index %d is outside the checkpoint (size %d)", idx, cp.Size)
	}
	return a.verifyCommitment(ctx, cp, idx, wire.Hash(frame), kind)
}
