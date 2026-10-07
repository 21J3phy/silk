// Package relay implements the Silk v2 relay: it authenticates and admits
// signed frames, enforces consent (owner-signed grants), spam postage
// (proof of work with surge pricing), budgets, rates, and expiry, stores
// end-to-end encrypted messages it cannot read, and appends every event to
// the transparency ledger in the same transaction.
package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/wire"
)

// Error is a protocol error with a stable code.
type Error struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Config holds relay policy. Zero values take defaults.
type Config struct {
	RegisterBits            uint8         // PoW for creating a new identity (default 24)
	IntroBaseBits           uint8         // base PoW for a contact request (default 20)
	MaxSurgeBits            uint8         // cap on surge pricing (default 12)
	MaxPenaltyBits          uint8         // cap on sender reputation penalty (default 12)
	MaxPendingPerRecipient  uint32        // hard cap on pending intros per recipient (default 256)
	MaxOutstandingPerSender uint32        // hard cap on pending intros per sender (default 32)
	MaxPendingPerInbox      uint64        // hard cap on undelivered events per agent (default 50000)
	PollInterval            time.Duration // long-poll storage re-check for multi-instance deployments (default 1s)
	SweepEvery              time.Duration // expiry sweep cadence (default 30s)
	// ReleaseKeys are the Ed25519 keys allowed to publish software releases.
	ReleaseKeys []ed25519.PublicKey
	// PolicyEvery is the minimum time between an agent's policy changes (default 30s);
	// each change is a permanent ledger entry and costs no postage.
	PolicyEvery time.Duration
	// MaxPendingPerGrant caps undelivered messages per conversation direction (default 1000),
	// so one peer cannot fill a recipient's whole inbox.
	MaxPendingPerGrant uint32
	// IgnoreGrantRate disables per-grant per-minute rate windows. Benchmarks only:
	// throughput tests would otherwise measure the rate limiter, not the relay.
	IgnoreGrantRate bool
}

func (c *Config) defaults() {
	if c.RegisterBits == 0 {
		c.RegisterBits = 24
	}
	if c.IntroBaseBits == 0 {
		c.IntroBaseBits = 20
	}
	if c.MaxSurgeBits == 0 {
		c.MaxSurgeBits = 12
	}
	if c.MaxPenaltyBits == 0 {
		c.MaxPenaltyBits = 12
	}
	if c.MaxPendingPerRecipient == 0 {
		c.MaxPendingPerRecipient = 256
	}
	if c.MaxOutstandingPerSender == 0 {
		c.MaxOutstandingPerSender = 32
	}
	if c.MaxPendingPerInbox == 0 {
		c.MaxPendingPerInbox = 50000
	}
	if c.MaxPendingPerGrant == 0 {
		c.MaxPendingPerGrant = 1000
	}
	if c.PolicyEvery == 0 {
		c.PolicyEvery = 30 * time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = time.Second
	}
	if c.SweepEvery == 0 {
		c.SweepEvery = 30 * time.Second
	}
}

// Relay is safe for concurrent use.
type Relay struct {
	store  kv.Store
	signer *ledger.Signer
	cfg    Config
	now    func() time.Time
	notify notifier

	certs     sync.Map // wire.ID -> cachedCertEntry (short-lived; every use is rechecked in-transaction)
	nCerts    atomic.Int64
	grants    sync.Map // wire.ID -> *wire.Grant (immutable frames; status is always read in-transaction)
	nGrants   atomic.Int64
	cp        atomic.Pointer[signedCheckpoint]
	lastSweep atomic.Int64
	Version   string
}

type signedCheckpoint struct {
	size int64
	raw  []byte
}

// New creates a relay over a store. clock may be nil.
func New(store kv.Store, signer *ledger.Signer, cfg Config, clock func() time.Time) *Relay {
	cfg.defaults()
	if clock == nil {
		clock = time.Now
	}
	r := &Relay{store: store, signer: signer, cfg: cfg, now: clock, Version: "dev"}
	r.notify.waiters = map[wire.ID]map[chan struct{}]struct{}{}
	if w, ok := store.(kv.Watcher); ok {
		r.notify.watcher = w
	}
	return r
}

// Config returns the effective policy.
func (r *Relay) Config() Config { return r.cfg }

// Origin is the ledger origin (checkpoint name).
func (r *Relay) Origin() string { return r.signer.Origin }

// VerifierKey is the public note key that verifies checkpoints.
func (r *Relay) VerifierKey() string { return r.signer.VKey }

// Result describes an admitted frame.
type Result struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	LedgerIdx int64  `json:"ledger_index"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

// ---------------------------------------------------------------------------
// Transaction helpers

type txState struct {
	tx     kv.Tx
	now    int64
	notify []wire.ID
}

func (r *Relay) update(ctx context.Context, fn func(*txState) error) error {
	var notify []wire.ID
	err := r.store.Update(ctx, func(tx kv.Tx) error {
		st := &txState{tx: tx, now: wire.Millis(r.now())}
		if err := fn(st); err != nil {
			return err
		}
		notify = st.notify
		return nil
	})
	if err == nil {
		for _, id := range notify {
			r.notify.fire(id)
		}
	}
	return err
}

func (st *txState) ledger(kind wire.Kind, frame []byte) (int64, error) {
	idx, err := ledger.Append(st.tx, ledger.Leaf(kind, st.now, frame))
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(frame)
	return idx, st.tx.Put(kv.Key(bFind, sum[:]), kv.U64(uint64(idx)))
}

func (st *txState) push(agent wire.ID, ev *Event) error {
	seqKey := kv.Key(bEventSeq, agent[:])
	seq, err := getU64(st.tx, seqKey)
	if err != nil {
		return err
	}
	seq++
	if err := st.tx.Put(seqKey, kv.U64(seq)); err != nil {
		return err
	}
	ev.Seq = seq
	ev.Millis = st.now
	st.notify = append(st.notify, agent)
	kv.Notify(st.tx, agent.Hex()) // wake waiters on other instances when this commits
	return st.tx.Put(kv.Key(bEvent, agent[:], kv.U64(seq)), ev.encode())
}

func (st *txState) stat(name string, delta int64) error {
	_, err := addU64(st.tx, kv.Key(bStat, []byte(name)), delta)
	return err
}

func getAgent(tx kv.Tx, id wire.ID) (*agentRec, error) {
	v, err := tx.Get(kv.Key(bAgent, id[:]))
	if err != nil || v == nil {
		return nil, err
	}
	return decodeAgent(v)
}

func getGrant(tx kv.Tx, id wire.ID) (*grantRec, error) {
	v, err := tx.Get(kv.Key(bGrant, id[:]))
	if err != nil || v == nil {
		return nil, err
	}
	return decodeGrant(v)
}

func getIntro(tx kv.Tx, id wire.ID) (*introRec, error) {
	v, err := tx.Get(kv.Key(bIntro, id[:]))
	if err != nil || v == nil {
		return nil, err
	}
	return decodeIntro(v)
}

func expiryKey(ms int64, kind wire.Kind, id wire.ID) []byte {
	return kv.Key(bExpiry, kv.U64(uint64(ms)), []byte{byte(kind)}, id[:])
}

func skewOK(created, now int64) bool {
	skew := wire.MaxClockSkew.Milliseconds()
	return created > 0 && created < wire.MaxTime && created-now <= skew && now-created <= skew
}

func certLive(c *wire.Cert, now int64) bool { return c.Expires > now }

// cachedCert returns a certificate for signature checks outside the write transaction.
type cachedCertEntry struct {
	cert *wire.Cert
	at   time.Time
}

// certTTL bounds how long another instance's rotation can go unnoticed for
// signature checks outside the write transaction (in-transaction checks are exact).
const certTTL = 15 * time.Second

func (r *Relay) cachedCert(ctx context.Context, id wire.ID) (*wire.Cert, error) {
	if v, ok := r.certs.Load(id); ok {
		if e := v.(cachedCertEntry); time.Since(e.at) < certTTL {
			return e.cert, nil
		}
	}
	return r.freshCert(ctx, id)
}

// freshCert reads the current certificate, bypassing the cache.
func (r *Relay) freshCert(ctx context.Context, id wire.ID) (*wire.Cert, error) {
	var rec *agentRec
	err := r.store.View(ctx, func(tx kv.Tx) error {
		var err error
		rec, err = getAgent(tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errf(404, "unknown_agent", "agent %s is not registered", id)
	}
	if rec.Status == statusActive {
		if r.nCerts.Add(1) > 100_000 {
			r.certs.Clear()
			r.nCerts.Store(0)
		}
		r.certs.Store(id, cachedCertEntry{cert: rec.Cert, at: time.Now()})
	}
	return rec.Cert, nil
}

// verifiedCert returns the sender's certificate whose signing key verifies,
// refetching once if the cached key fails (the agent may have rotated keys
// through another relay instance).
func (r *Relay) verifiedCert(ctx context.Context, id wire.ID, ok func(pub []byte) bool) (*wire.Cert, error) {
	c, err := r.cachedCert(ctx, id)
	if err != nil {
		return nil, err
	}
	if ok(c.SignPub[:]) {
		return c, nil
	}
	f, err := r.freshCert(ctx, id)
	if err != nil {
		return nil, err
	}
	if f.SignPub != c.SignPub && ok(f.SignPub[:]) {
		return f, nil
	}
	return nil, errf(401, "invalid_signature", "signature does not verify for agent %s", id)
}

// currentCert re-reads the agent inside the transaction and checks the key used for verification is still current.
func currentCert(st *txState, id wire.ID, verified *wire.Cert) (*agentRec, error) {
	rec, err := getAgent(st.tx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errf(404, "unknown_agent", "agent %s is not registered", id)
	}
	if rec.Status != statusActive || !certLive(rec.Cert, st.now) {
		return nil, errf(403, "agent_inactive", "agent %s is revoked or its certificate expired", id)
	}
	if verified != nil && rec.Cert.SignPub != verified.SignPub {
		return nil, errf(409, "key_rotated", "agent %s rotated keys; retry", id)
	}
	return rec, nil
}

// currentKey is the hot-path variant of currentCert: it reads only the compact key record.
func currentKey(st *txState, id wire.ID, verified *wire.Cert) error {
	v, err := st.tx.Get(kv.Key(bAgentKey, id[:]))
	if err != nil {
		return err
	}
	if v == nil {
		return errf(404, "unknown_agent", "agent %s is not registered", id)
	}
	k, err := decodeAgentKey(v)
	if err != nil {
		return err
	}
	if k.Status != statusActive || k.Expires <= st.now {
		return errf(403, "agent_inactive", "agent %s is revoked or its certificate expired", id)
	}
	if verified != nil && k.SignPub != verified.SignPub {
		return errf(409, "key_rotated", "agent %s rotated keys; retry", id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Submit dispatches any signed frame.

func (r *Relay) Submit(ctx context.Context, frame []byte) (*Result, error) {
	if len(frame) > wire.MaxFrame {
		return nil, errf(413, "frame_too_large", "frames are limited to %d bytes", wire.MaxFrame)
	}
	kind, err := wire.PeekKind(frame)
	if err != nil {
		return nil, errf(400, "malformed", "%v", err)
	}
	r.maybeSweep(ctx)
	res, err := r.dispatch(ctx, kind, frame)
	var e *Error
	if errors.As(err, &e) && e.Code == "key_rotated" {
		r.certs.Clear() // another instance saw a rotation first; verify again with fresh keys
		r.nCerts.Store(0)
		res, err = r.dispatch(ctx, kind, frame)
	}
	return res, err
}

func (r *Relay) dispatch(ctx context.Context, kind wire.Kind, frame []byte) (*Result, error) {
	switch kind {
	case wire.KindIntro:
		return r.submitIntro(ctx, frame)
	case wire.KindGrant:
		return r.submitGrant(ctx, frame)
	case wire.KindDecline:
		return r.submitDecline(ctx, frame)
	case wire.KindMsg:
		return r.submitMsg(ctx, frame)
	case wire.KindAck:
		return r.submitAck(ctx, frame)
	case wire.KindRevoke:
		return r.submitRevoke(ctx, frame)
	case wire.KindPolicy:
		return r.submitPolicy(ctx, frame)
	case wire.KindRelease:
		return r.submitRelease(ctx, frame)
	case wire.KindCert:
		return nil, errf(400, "use_register", "certificates are submitted through registration")
	}
	return nil, errf(400, "unknown_kind", "unknown frame kind %d", kind)
}

func malformed(err error) error { return errf(400, "malformed", "%v", err) }

// ---------------------------------------------------------------------------
// Registration

// EncodeRegistration builds a registration body: u32 len | cert | u8 bits | u64 nonce.
func EncodeRegistration(cert []byte, bits uint8, nonce uint64) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(cert)))
	b = append(b, cert...)
	b = append(b, bits)
	return binary.BigEndian.AppendUint64(b, nonce)
}

// Register admits a new agent certificate (PoW required) or a newer serial for an existing agent.
func (r *Relay) Register(ctx context.Context, body []byte) (*Result, error) {
	if len(body) < 4+9 || len(body) > wire.MaxFrame {
		return nil, errf(400, "malformed", "invalid registration body")
	}
	n := binary.BigEndian.Uint32(body)
	if int(n) != len(body)-4-9 {
		return nil, errf(400, "malformed", "registration length mismatch")
	}
	certRaw := body[4 : 4+n]
	bits := body[4+n]
	nonce := binary.BigEndian.Uint64(body[5+n:])
	cert, err := wire.DecodeCert(append([]byte{}, certRaw...))
	if err != nil {
		return nil, malformed(err)
	}
	powOK := bits >= r.cfg.RegisterBits && pow.Check(pow.Digest(pow.DomainRegister, cert.Raw), bits, nonce)
	if !powOK {
		// Without a stamp this can only be a key rotation of an existing agent.
		if _, err := r.cachedCert(ctx, cert.ID()); err != nil {
			return nil, errf(402, "pow_required", "registration requires a %d-bit proof-of-work stamp", r.cfg.RegisterBits)
		}
	}
	if !cert.VerifySigs() {
		return nil, errf(401, "invalid_signature", "certificate signatures do not verify")
	}
	now := wire.Millis(r.now())
	if cert.Created > now+wire.MaxClockSkew.Milliseconds() || cert.Expires <= now {
		return nil, errf(400, "invalid_lifetime", "certificate is not yet valid or already expired")
	}
	id := cert.ID()
	res := &Result{Kind: "cert", ID: id.String()}
	err = r.update(ctx, func(st *txState) error {
		existing, err := getAgent(st.tx, id)
		if err != nil {
			return err
		}
		if existing != nil {
			if bytes.Equal(existing.Cert.Raw, cert.Raw) {
				res.LedgerIdx, res.Duplicate = existing.LedgerIdx, true
				return nil
			}
			if existing.Status != statusActive {
				return errf(403, "agent_revoked", "this agent address was revoked")
			}
			if cert.Serial <= existing.Cert.Serial {
				return errf(409, "stale_serial", "certificate serial must exceed %d", existing.Cert.Serial)
			}
			if err := st.tx.Put(kv.Key(bAgentHist, id[:], kv.U32(existing.Cert.Serial)), existing.Cert.Raw); err != nil {
				return err
			}
			if existing.Cert.Handle != cert.Handle && existing.Cert.Handle != "" {
				if err := st.tx.Delete(kv.Key(bHandle, []byte(existing.Cert.Handle))); err != nil {
					return err
				}
			}
		} else if !powOK {
			return errf(402, "pow_required", "registration requires a %d-bit proof-of-work stamp", r.cfg.RegisterBits)
		}
		if cert.Handle != "" && (existing == nil || existing.Cert.Handle != cert.Handle) {
			owner, err := st.tx.Get(kv.Key(bHandle, []byte(cert.Handle)))
			if err != nil {
				return err
			}
			if owner != nil && !bytes.Equal(owner, id[:]) {
				return errf(409, "handle_taken", "handle @%s is already registered", cert.Handle)
			}
			if err := st.tx.Put(kv.Key(bHandle, []byte(cert.Handle)), id[:]); err != nil {
				return err
			}
		}
		idx, err := st.ledger(wire.KindCert, cert.Raw)
		if err != nil {
			return err
		}
		rec := &agentRec{Status: statusActive, Registered: st.now, LedgerIdx: idx, Cert: cert}
		if existing != nil {
			rec.Registered = existing.Registered
		} else if err := st.stat("agents", 1); err != nil {
			return err
		}
		res.LedgerIdx = idx
		key := &agentKey{Status: statusActive, Serial: cert.Serial, Expires: cert.Expires, SignPub: cert.SignPub}
		if err := st.tx.Put(kv.Key(bAgentKey, id[:]), key.encode()); err != nil {
			return err
		}
		return st.tx.Put(kv.Key(bAgent, id[:]), rec.encode())
	})
	if err != nil {
		return nil, err
	}
	r.certs.Delete(id)
	return res, nil
}

// AgentInfo is the public directory entry for an agent.
type AgentInfo struct {
	ID           string `json:"id"`
	Handle       string `json:"handle,omitempty"`
	Cert         []byte `json:"cert"`
	Registered   int64  `json:"registered_ms"`
	LedgerIdx    int64  `json:"ledger_index"`
	AcceptIntros bool   `json:"accepts_intros"`
	IntroPoWBits uint8  `json:"intro_pow_bits"`
}

// LookupAgent resolves an ID or handle. If from is non-zero, the PoW requirement includes that sender's penalty.
func (r *Relay) LookupAgent(ctx context.Context, ref string, from wire.ID) (*AgentInfo, error) {
	var info *AgentInfo
	err := r.store.View(ctx, func(tx kv.Tx) error {
		id, err := wire.ParseID(ref)
		if err != nil {
			h := ref
			if len(h) > 0 && h[0] == '@' {
				h = h[1:]
			}
			if !wire.ValidLabel(h) {
				return errf(400, "invalid_ref", "use an agent id or @handle")
			}
			v, err := tx.Get(kv.Key(bHandle, []byte(h)))
			if err != nil {
				return err
			}
			if v == nil {
				return errf(404, "unknown_agent", "no agent with handle @%s", h)
			}
			copy(id[:], v)
		}
		rec, err := getAgent(tx, id)
		if err != nil {
			return err
		}
		if rec == nil || rec.Status != statusActive {
			return errf(404, "unknown_agent", "agent %s is not registered", id)
		}
		now := wire.Millis(r.now())
		bits, err := r.introBits(tx, from, id, rec.Cert, now)
		if err != nil {
			return err
		}
		info = &AgentInfo{ID: id.String(), Handle: rec.Cert.Handle, Cert: rec.Cert.Raw, Registered: rec.Registered,
			LedgerIdx: rec.LedgerIdx, AcceptIntros: rec.Cert.Flags&wire.CertAcceptsIntros != 0, IntroPoWBits: bits}
		return nil
	})
	return info, err
}

// ---------------------------------------------------------------------------
// Spam pricing

const hourMs = int64(time.Hour / time.Millisecond)

func (p *pressure) roll(now int64) {
	switch {
	case p.WinStart == 0 || now-p.WinStart >= 2*hourMs:
		p.WinStart, p.WinCount, p.Prev = now, 0, 0
	case now-p.WinStart >= hourMs:
		p.WinStart, p.Prev, p.WinCount = p.WinStart+hourMs, p.WinCount, 0
	}
}

// recent estimates intros received in the last hour (sliding window).
func (p *pressure) recent(now int64) float64 {
	q := *p
	q.roll(now)
	w := 1 - float64(now-q.WinStart)/float64(hourMs)
	if w < 0 {
		w = 0
	}
	return float64(q.WinCount) + float64(q.Prev)*w
}

const halfLifeMs = 24 * hourMs

func (rep *reputation) score(now int64) float64 {
	if rep.Milli == 0 {
		return 0
	}
	age := float64(now - rep.Updated)
	if age < 0 {
		age = 0
	}
	return float64(rep.Milli) / 1000 * math.Pow(0.5, age/float64(halfLifeMs))
}

// introBits is the stamp a specific sender needs right now: 0 if trusted;
// otherwise the stranger price (base + surge + penalty) while the stranger
// queue has room, and an auction once it is full: one bit more than the
// cheapest pending request (plus penalty), which that request is evicted for.
func (r *Relay) introBits(tx kv.Tx, sender, recipient wire.ID, rc *wire.Cert, now int64) (uint8, error) {
	var rep float64
	if !sender.IsZero() {
		ar, err := getAgent(tx, sender)
		if err != nil {
			return 0, err
		}
		if ar != nil {
			ok, err := trusts(tx, recipient, rc, sender, ar.Cert)
			if err != nil {
				return 0, err
			}
			if ok {
				return 0, nil
			}
		}
		rv, err := tx.Get(kv.Key(bReputation, sender[:]))
		if err != nil {
			return 0, err
		}
		rep = decodeReputation(rv).score(now)
	}
	pv, err := tx.Get(kv.Key(bRecipient, recipient[:]))
	if err != nil {
		return 0, err
	}
	p := decodePressure(pv)
	if p.Pending < r.cfg.MaxPendingPerRecipient {
		return IntroPrice(r.cfg, rc.MinPoW, float64(p.Pending)+p.recent(now), rep), nil
	}
	_, minBits, err := cheapestPending(tx, recipient)
	if err != nil {
		return 0, err
	}
	return AuctionPrice(r.cfg, rc.MinPoW, minBits, rep), nil
}

// AuctionPrice is the price when a recipient's stranger queue is full.
func AuctionPrice(cfg Config, recipientMin, cheapestPending uint8, reputation float64) uint8 {
	cfg.defaults()
	bits := int(max(cfg.IntroBaseBits, recipientMin, cheapestPending+1))
	bits += int(math.Min(2*math.Round(reputation), float64(cfg.MaxPenaltyBits)))
	return uint8(min(bits, wire.MaxPoWBits))
}

// IntroPrice is the proof-of-work pricing rule for contact requests:
// base = max(relay base, recipient minimum); surge adds 2 bits (4x cost) each
// time the recipient's load (pending + last-hour intros) doubles past 16;
// penalty adds 2 bits per (decaying) declined request by this sender.
func IntroPrice(cfg Config, recipientMin uint8, load, reputation float64) uint8 {
	cfg.defaults()
	base := cfg.IntroBaseBits
	if recipientMin > base {
		base = recipientMin
	}
	surge := uint8(2 * math.Floor(math.Log2(1+load/16)))
	if surge > cfg.MaxSurgeBits {
		surge = cfg.MaxSurgeBits
	}
	penalty := uint8(math.Min(2*math.Round(reputation), float64(cfg.MaxPenaltyBits)))
	bits := int(base) + int(surge) + int(penalty)
	if bits > wire.MaxPoWBits {
		bits = wire.MaxPoWBits
	}
	return uint8(bits)
}

func penalize(st *txState, sender wire.ID, amount float64) error {
	key := kv.Key(bReputation, sender[:])
	v, err := st.tx.Get(key)
	if err != nil {
		return err
	}
	rep := decodeReputation(v)
	s := rep.score(st.now) + amount
	rep.Milli, rep.Updated = uint32(math.Min(s*1000, math.MaxUint32)), st.now
	return st.tx.Put(key, rep.encode())
}

// ---------------------------------------------------------------------------
// Intro

func (r *Relay) submitIntro(ctx context.Context, frame []byte) (*Result, error) {
	in, err := wire.DecodeIntro(frame)
	if err != nil {
		return nil, malformed(err)
	}
	now := wire.Millis(r.now())
	if !skewOK(in.Created, now) {
		return nil, errf(400, "clock_skew", "intro creation time is more than %v from relay time", wire.MaxClockSkew)
	}
	if in.Expires <= now {
		return nil, errf(410, "expired", "intro already expired")
	}
	// Cheapest check first: a stamp costs the relay one SHA-256 to reject, so
	// spam is dropped before any signature verification or storage access.
	// Zero bits is allowed only for trusted senders (checked in the transaction).
	if in.PoWBits > 0 && !pow.Check(pow.Digest(pow.DomainIntro, in.PoWPrefix()), in.PoWBits, in.PoWNonce) {
		return nil, errf(402, "pow_required", "the proof-of-work stamp is invalid")
	}
	sc, err := r.verifiedCert(ctx, in.From, in.VerifySig)
	if err != nil {
		return nil, err
	}
	res := &Result{Kind: "intro", ID: in.IntroID.String()}
	var evicted *wire.ID
	err = r.update(ctx, func(st *txState) error {
		if existing, err := getIntro(st.tx, in.IntroID); err != nil {
			return err
		} else if existing != nil {
			if bytes.Equal(existing.Intro.Raw, frame) {
				res.LedgerIdx, res.Duplicate = existing.LedgerIdx, true
				return nil
			}
			return errf(409, "id_conflict", "intro id already used for a different intro")
		}
		if _, err := currentCert(st, in.From, sc); err != nil {
			return err
		}
		rc, err := currentCert(st, in.To, nil)
		if err != nil {
			return err
		}
		if rc.Cert.Flags&wire.CertAcceptsIntros == 0 {
			return errf(403, "intros_closed", "recipient does not accept contact requests")
		}
		if in.ToSerial != rc.Cert.Serial {
			return errf(409, "stale_recipient_key", "recipient keys changed; fetch the current certificate")
		}
		pairKey := kv.Key(bPairPending, in.From[:], in.To[:])
		if v, err := st.tx.Get(pairKey); err != nil {
			return err
		} else if v != nil {
			return errf(409, "intro_pending", "a contact request to this agent is already pending")
		}
		trusted, err := trusts(st.tx, in.To, rc.Cert, in.From, sc)
		if err != nil {
			return err
		}
		var ticketKey []byte
		if len(in.Ticket) > 0 {
			tk, err := wire.DecodeTicket(in.Ticket)
			if err != nil || !tk.VerifySig() || tk.Recipient != in.To || tk.OwnerPub != rc.Cert.OwnerPub {
				return errf(403, "invalid_invite", "the invite is not a valid invite from this agent's owner")
			}
			if tk.Expires <= st.now {
				return errf(410, "invite_expired", "the invite has expired")
			}
			ticketKey = kv.Key(bTicketUsed, tk.Recipient[:], tk.TicketID[:])
			if v, err := st.tx.Get(ticketKey); err != nil {
				return err
			} else if v != nil {
				return errf(409, "invite_used", "this invite was already used")
			}
			trusted = true
		}
		outKey := kv.Key(bOutstanding, in.From[:])
		out, err := getU32(st.tx, outKey)
		if err != nil {
			return err
		}
		if out >= r.cfg.MaxOutstandingPerSender {
			return errf(429, "too_many_pending", "sender has %d unanswered contact requests", out)
		}
		rec := &introRec{Status: statusPending, Trusted: trusted, Intro: in}
		var puts []struct{ k, v []byte }
		if trusted {
			tk := kv.Key(bTrustedPend, in.To[:])
			n, err := getU32(st.tx, tk)
			if err != nil {
				return err
			}
			if n >= r.cfg.MaxPendingPerRecipient*4 {
				return errf(429, "recipient_full", "recipient has too many pending contact requests")
			}
			puts = append(puts, struct{ k, v []byte }{tk, kv.U32(n + 1)})
		} else {
			need, err := r.introBits(st.tx, in.From, in.To, rc.Cert, st.now)
			if err != nil {
				return err
			}
			pk := kv.Key(bRecipient, in.To[:])
			pv, err := st.tx.Get(pk)
			if err != nil {
				return err
			}
			full := decodePressure(pv).Pending >= r.cfg.MaxPendingPerRecipient
			if in.PoWBits < need {
				if full {
					return errf(429, "outbid", "recipient's request queue is full; a stamp of at least %d bits outbids the cheapest pending request", need)
				}
				return errf(402, "pow_required", "this contact request requires a %d-bit proof-of-work stamp", need)
			}
			if full {
				// Full: the cheapest pending stranger request is evicted by this higher bid.
				minRec, _, err := cheapestPending(st.tx, in.To)
				if err != nil {
					return err
				}
				if minRec == nil {
					return errf(429, "recipient_full", "recipient has too many pending contact requests")
				}
				if err := closeIntro(st, minRec, statusEvicted); err != nil {
					return err
				}
				id := minRec.Intro.IntroID
				evicted = &id
				if err := st.push(minRec.Intro.From, &Event{Kind: wire.KindEvicted, LedgerIdx: -1, Ref: id}); err != nil {
					return err
				}
			}
			pv, err = st.tx.Get(pk)
			if err != nil {
				return err
			}
			p := decodePressure(pv)
			p.roll(st.now)
			p.Pending++
			p.WinCount++
			puts = append(puts, struct{ k, v []byte }{pk, p.encode()}, struct{ k, v []byte }{queueKey(in), nil})
		}
		idx, err := st.ledger(wire.KindIntro, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		rec.LedgerIdx = idx
		if ticketKey != nil {
			puts = append(puts, struct{ k, v []byte }{ticketKey, in.IntroID[:]})
		}
		puts = append(puts,
			struct{ k, v []byte }{kv.Key(bIntro, in.IntroID[:]), rec.encode()},
			struct{ k, v []byte }{pairKey, in.IntroID[:]},
			struct{ k, v []byte }{outKey, kv.U32(out + 1)},
			struct{ k, v []byte }{expiryKey(in.Expires, wire.KindIntro, in.IntroID), nil},
		)
		for _, op := range puts {
			if err := st.tx.Put(op.k, op.v); err != nil {
				return err
			}
		}
		if err := st.stat("intros", 1); err != nil {
			return err
		}
		return st.push(in.To, &Event{Kind: wire.KindIntro, LedgerIdx: idx, Ref: in.IntroID, Frame: frame})
	})
	if err != nil {
		return nil, err
	}
	_ = evicted
	return res, nil
}

// trusts applies the recipient's contact policy (default: trust agents with the same owner).
func trusts(tx kv.Tx, recipient wire.ID, rc *wire.Cert, sender wire.ID, sc *wire.Cert) (bool, error) {
	pv, err := tx.Get(kv.Key(bPolicy, recipient[:]))
	if err != nil {
		return false, err
	}
	if len(pv) <= 8 {
		return sc.OwnerPub == rc.OwnerPub, nil
	}
	pol, err := wire.DecodePolicy(append([]byte{}, pv[8:]...))
	if err != nil {
		return false, errCorrupt
	}
	return pol.Trusts(sender, sc.OwnerPub), nil
}

// cheapestPending returns the lowest-bid pending stranger request for a recipient.
func cheapestPending(tx kv.Tx, recipient wire.ID) (*introRec, uint8, error) {
	prefix := kv.Key(bQueue, recipient[:])
	var id wire.ID
	var bits uint8
	found := false
	if err := tx.Scan(prefix, kv.PrefixEnd(prefix), 1, func(k, _ []byte) bool {
		bits = k[len(prefix)]
		copy(id[:], k[len(prefix)+9:])
		found = true
		return false
	}); err != nil || !found {
		return nil, 0, err
	}
	rec, err := getIntro(tx, id)
	return rec, bits, err
}

// closeIntro clears pending bookkeeping for an intro leaving the pending state.
func closeIntro(st *txState, rec *introRec, status uint8) error {
	in := rec.Intro
	rec.Status = status
	if err := st.tx.Put(kv.Key(bIntro, in.IntroID[:]), rec.encode()); err != nil {
		return err
	}
	if err := st.tx.Delete(kv.Key(bPairPending, in.From[:], in.To[:])); err != nil {
		return err
	}
	if err := st.tx.Delete(expiryKey(in.Expires, wire.KindIntro, in.IntroID)); err != nil {
		return err
	}
	if err := addU32(st.tx, kv.Key(bOutstanding, in.From[:]), -1); err != nil {
		return err
	}
	if rec.Trusted {
		return addU32(st.tx, kv.Key(bTrustedPend, in.To[:]), -1)
	}
	if err := st.tx.Delete(queueKey(in)); err != nil {
		return err
	}
	pk := kv.Key(bRecipient, in.To[:])
	pv, err := st.tx.Get(pk)
	if err != nil {
		return err
	}
	p := decodePressure(pv)
	if p.Pending > 0 {
		p.Pending--
	}
	return st.tx.Put(pk, p.encode())
}

// ---------------------------------------------------------------------------
// Policy


func (r *Relay) submitPolicy(ctx context.Context, frame []byte) (*Result, error) {
	pol, err := wire.DecodePolicy(frame)
	if err != nil {
		return nil, malformed(err)
	}
	if !pol.VerifySig() {
		return nil, errf(401, "invalid_signature", "policy signature does not verify")
	}
	res := &Result{Kind: "policy", ID: pol.Agent.String()}
	err = r.update(ctx, func(st *txState) error {
		if !skewOK(pol.Created, st.now) {
			return errf(400, "clock_skew", "policy creation time is more than %v from relay time", wire.MaxClockSkew)
		}
		ar, err := currentCert(st, pol.Agent, nil)
		if err != nil {
			return err
		}
		if ar.Cert.OwnerPub != pol.OwnerPub {
			return errf(403, "not_owner", "policy must be signed by the agent's owner")
		}
		key := kv.Key(bPolicy, pol.Agent[:])
		if v, err := st.tx.Get(key); err != nil {
			return err
		} else if len(v) > 8 {
			old, err := wire.DecodePolicy(append([]byte{}, v[8:]...))
			if err != nil {
				return errCorrupt
			}
			if bytes.Equal(old.Raw, frame) {
				res.Duplicate = true
				return nil
			}
			if pol.Serial <= old.Serial {
				return errf(409, "stale_serial", "policy serial must exceed %d", old.Serial)
			}
			if st.now-int64(binary.BigEndian.Uint64(v)) < r.cfg.PolicyEvery.Milliseconds() {
				return errf(429, "slow_down", "an agent's policy can change at most once every %v", r.cfg.PolicyEvery)
			}
		}
		idx, err := st.ledger(wire.KindPolicy, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		return st.tx.Put(key, append(kv.U64(uint64(st.now)), frame...))
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Grant (owner consent)

func (r *Relay) submitGrant(ctx context.Context, frame []byte) (*Result, error) {
	g, err := wire.DecodeGrant(frame)
	if err != nil {
		return nil, malformed(err)
	}
	if !g.VerifySig() {
		return nil, errf(401, "invalid_signature", "grant signature does not verify")
	}
	if err := r.precheckDecision(ctx, g.GrantID, g.IntroHash, g.OwnerPub, frame, true); err != nil {
		return nil, err
	}
	res := &Result{Kind: "grant", ID: g.GrantID.String()}
	err = r.update(ctx, func(st *txState) error {
		if existing, err := getGrant(st.tx, g.GrantID); err != nil {
			return err
		} else if existing != nil {
			if bytes.Equal(existing.Grant.Raw, frame) {
				res.LedgerIdx, res.Duplicate = existing.LedgerIdx, true
				return nil
			}
			return errf(409, "already_decided", "this contact request already has a grant")
		}
		if !skewOK(g.Created, st.now) {
			return errf(400, "clock_skew", "grant creation time is more than %v from relay time", wire.MaxClockSkew)
		}
		if g.Expires <= st.now {
			return errf(400, "invalid_lifetime", "grant already expired")
		}
		ir, err := getIntro(st.tx, g.GrantID)
		if err != nil {
			return err
		}
		if ir == nil {
			return errf(404, "unknown_intro", "no contact request %s", g.GrantID)
		}
		if ir.Status != statusPending || ir.Intro.Expires <= st.now {
			return errf(409, "intro_closed", "contact request is no longer pending")
		}
		in := ir.Intro
		if wire.Hash(in.Raw) != g.IntroHash || g.From != in.From || g.To != in.To {
			return errf(400, "grant_mismatch", "grant does not match the contact request")
		}
		if g.BudgetAB > in.Budget || g.BudgetBA > in.Budget || g.Expires-g.Created > int64(in.GrantTTL)*1000 {
			return errf(400, "terms_exceed_request", "a grant may not allow more messages or time than the request asked for")
		}
		rc, err := currentCert(st, g.To, nil)
		if err != nil {
			return err
		}
		if rc.Cert.OwnerPub != g.OwnerPub {
			return errf(403, "not_owner", "grant must be signed by the recipient agent's owner")
		}
		if _, err := currentCert(st, g.From, nil); err != nil {
			return err
		}
		if err := closeIntro(st, ir, statusAccepted); err != nil {
			return err
		}
		idx, err := st.ledger(wire.KindGrant, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		rec := &grantRec{Status: statusActive, LedgerIdx: idx, Grant: g}
		if err := st.tx.Put(kv.Key(bGrant, g.GrantID[:]), rec.encode()); err != nil {
			return err
		}
		ctr := &grantCtr{Status: statusActive}
		if err := st.tx.Put(kv.Key(bGrantCtr, g.GrantID[:]), ctr.encode()); err != nil {
			return err
		}
		if err := st.stat("grants", 1); err != nil {
			return err
		}
		return st.push(g.From, &Event{Kind: wire.KindGrant, LedgerIdx: idx, Ref: g.GrantID, Frame: frame})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (r *Relay) submitDecline(ctx context.Context, frame []byte) (*Result, error) {
	d, err := wire.DecodeDecline(frame)
	if err != nil {
		return nil, malformed(err)
	}
	if !d.VerifySig() {
		return nil, errf(401, "invalid_signature", "decline signature does not verify")
	}
	if err := r.precheckDecision(ctx, d.IntroID, d.IntroHash, d.OwnerPub, frame, false); err != nil {
		return nil, err
	}
	res := &Result{Kind: "decline", ID: d.IntroID.String()}
	err = r.update(ctx, func(st *txState) error {
		ir, err := getIntro(st.tx, d.IntroID)
		if err != nil {
			return err
		}
		if ir == nil {
			return errf(404, "unknown_intro", "no contact request %s", d.IntroID)
		}
		if ir.Status == statusDeclined {
			res.Duplicate = true
			return nil
		}
		if ir.Status != statusPending {
			return errf(409, "intro_closed", "contact request is no longer pending")
		}
		in := ir.Intro
		if wire.Hash(in.Raw) != d.IntroHash || d.By != in.To {
			return errf(400, "decline_mismatch", "decline does not match the contact request")
		}
		rc, err := getAgent(st.tx, in.To)
		if err != nil {
			return err
		}
		if rc == nil || rc.Cert.OwnerPub != d.OwnerPub {
			return errf(403, "not_owner", "decline must be signed by the recipient agent's owner")
		}
		if err := closeIntro(st, ir, statusDeclined); err != nil {
			return err
		}
		if err := penalize(st, in.From, 1); err != nil {
			return err
		}
		idx, err := st.ledger(wire.KindDecline, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		return st.push(in.From, &Event{Kind: wire.KindDecline, LedgerIdx: idx, Ref: in.IntroID, Frame: frame})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// precheckDecision rejects grants and declines that cannot succeed before they
// reach the serialized writer: the intro must exist, match, and belong to an
// agent owned by the signer. Exact replays of an accepted grant pass through so
// they can be answered idempotently.
func (r *Relay) precheckDecision(ctx context.Context, introID wire.ID, introHash [wire.HashLen]byte, owner [wire.PubLen]byte, frame []byte, isGrant bool) error {
	return r.store.View(ctx, func(tx kv.Tx) error {
		if isGrant {
			if gr, err := getGrant(tx, introID); err != nil {
				return err
			} else if gr != nil {
				return nil // duplicate or conflict: decided in the transaction
			}
		}
		ir, err := getIntro(tx, introID)
		if err != nil {
			return err
		}
		if ir == nil {
			return errf(404, "unknown_intro", "no contact request %s", introID)
		}
		if wire.Hash(ir.Intro.Raw) != introHash {
			return errf(400, "decision_mismatch", "decision does not match the contact request")
		}
		ar, err := getAgent(tx, ir.Intro.To)
		if err != nil {
			return err
		}
		if ar == nil || ar.Cert.OwnerPub != owner {
			return errf(403, "not_owner", "only the recipient agent's owner can decide this request")
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Messages

func parties(g *wire.Grant, dir uint8) (sender, recipient wire.ID) {
	if dir == wire.DirAB {
		return g.From, g.To
	}
	return g.To, g.From
}

func (r *Relay) cachedGrant(ctx context.Context, id wire.ID) (*wire.Grant, error) {
	if g, ok := r.grants.Load(id); ok {
		return g.(*wire.Grant), nil
	}
	var rec *grantRec
	err := r.store.View(ctx, func(tx kv.Tx) error {
		var err error
		rec, err = getGrant(tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errf(404, "unknown_grant", "no grant %s", id)
	}
	if r.nGrants.Add(1) > 200_000 {
		r.grants.Clear()
		r.nGrants.Store(0)
	}
	r.grants.Store(id, rec.Grant)
	return rec.Grant, nil
}

func (r *Relay) submitMsg(ctx context.Context, frame []byte) (*Result, error) {
	m, err := wire.DecodeMsg(frame)
	if err != nil {
		return nil, malformed(err)
	}
	now := wire.Millis(r.now())
	if !skewOK(m.Created, now) {
		return nil, errf(400, "clock_skew", "message creation time is more than %v from relay time", wire.MaxClockSkew)
	}
	g, err := r.cachedGrant(ctx, m.GrantID)
	if err != nil {
		return nil, err
	}
	sender, recipient := parties(g, m.Dir)
	sc, err := r.verifiedCert(ctx, sender, m.VerifySig)
	if err != nil {
		return nil, err
	}
	id := m.ID()
	res := &Result{Kind: "msg", ID: id.String()}
	err = r.update(ctx, func(st *txState) error {
		msgKey := kv.Key(bMsg, id[:])
		// One round trip for everything this admission reads (remote stores).
		if err := kv.Prefetch(st.tx, msgKey, kv.Key(bGrantCtr, m.GrantID[:]), kv.Key(bAgentKey, sender[:]),
			kv.Key(bSeq, m.GrantID[:], []byte{m.Dir}, kv.U32(m.Seq)), kv.Key(bStat, []byte("inbox."), recipient[:]),
			kv.Key(bEventSeq, recipient[:]), ledger.SizeKey(), kv.Key(bStat, []byte("msgs")), kv.Key(bStat, []byte("msg_bytes"))); err != nil {
			return err
		}
		if v, err := st.tx.Get(msgKey); err != nil {
			return err
		} else if v != nil {
			mr, err := decodeMsg(v)
			if err != nil {
				return err
			}
			res.LedgerIdx, res.Duplicate = mr.LedgerIdx, true
			return nil
		}
		// The grant frame is immutable (cached); its mutable state is the small counter record.
		ctrKey := kv.Key(bGrantCtr, m.GrantID[:])
		cv, err := st.tx.Get(ctrKey)
		if err != nil {
			return err
		}
		if cv == nil {
			return errf(404, "unknown_grant", "no grant %s", m.GrantID)
		}
		ctr, err := decodeGrantCtr(cv)
		if err != nil {
			return err
		}
		if ctr.Status != statusActive {
			return errf(403, "grant_inactive", "grant is revoked")
		}
		if g.Expires <= st.now {
			return errf(403, "grant_expired", "grant expired")
		}
		expires := m.Created + int64(m.TTL)*1000
		if expires <= st.now {
			return errf(410, "expired", "message already expired")
		}
		if expires > g.Expires {
			expires = g.Expires
		}
		if err := currentKey(st, sender, sc); err != nil {
			return err
		}
		if m.Seq >= g.Budget(m.Dir) {
			return errf(429, "budget_exhausted", "grant allows %d messages in this direction", g.Budget(m.Dir))
		}
		seqKey := kv.Key(bSeq, m.GrantID[:], []byte{m.Dir}, kv.U32(m.Seq))
		if v, err := st.tx.Get(seqKey); err != nil {
			return err
		} else if v != nil {
			return errf(409, "seq_reused", "sequence %d was already used with different content", m.Seq)
		}
		if st.now-ctr.WinStart >= 60_000 {
			ctr.WinStart, ctr.WinCount = st.now, [2]uint16{}
		}
		if ctr.WinCount[m.Dir] >= g.Rate && !r.cfg.IgnoreGrantRate {
			return errf(429, "rate_limited", "grant allows %d messages per minute in this direction", g.Rate)
		}
		if ctr.Pending[m.Dir] >= r.cfg.MaxPendingPerGrant {
			// Expired messages may not have been swept yet; clear this conversation's first.
			if err := expireGrantBacklog(st, m.GrantID, 500); err != nil {
				return err
			}
			if cv, err = st.tx.Get(ctrKey); err != nil {
				return err
			}
			if ctr, err = decodeGrantCtr(cv); err != nil {
				return err
			}
			if st.now-ctr.WinStart >= 60_000 {
				ctr.WinStart, ctr.WinCount = st.now, [2]uint16{}
			}
			if ctr.Pending[m.Dir] >= r.cfg.MaxPendingPerGrant {
				return errf(429, "backlog_full", "the recipient has %d unacknowledged messages in this conversation", ctr.Pending[m.Dir])
			}
		}
		pending, err := getU64(st.tx, kv.Key(bStat, []byte("inbox."), recipient[:]))
		if err != nil {
			return err
		}
		if pending >= r.cfg.MaxPendingPerInbox {
			return errf(507, "inbox_full", "recipient inbox is full")
		}
		if ctr.WinCount[m.Dir] < 0xffff {
			ctr.WinCount[m.Dir]++
		}
		ctr.Used[m.Dir]++
		ctr.Pending[m.Dir]++
		idx, err := st.ledger(wire.KindMsg, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		ev := &Event{Kind: wire.KindMsg, LedgerIdx: idx, Ref: id, Frame: frame}
		if err := st.push(recipient, ev); err != nil {
			return err
		}
		mr := &msgRec{Status: statusPending, Grant: m.GrantID, Dir: m.Dir, Seq: m.Seq, Sender: sender, Recipient: recipient,
			EvSeq: ev.Seq, Expires: expires, LedgerIdx: idx, AckIdx: -1}
		for _, op := range []struct{ k, v []byte }{
			{msgKey, mr.encode()},
			{seqKey, id[:]},
			{ctrKey, ctr.encode()},
			{kv.Key(bGrantOpen, m.GrantID[:], id[:]), nil},
			{expiryKey(expires, wire.KindMsg, id), nil},
			{kv.Key(bStat, []byte("inbox."), recipient[:]), kv.U64(pending + 1)},
		} {
			if err := st.tx.Put(op.k, op.v); err != nil {
				return err
			}
		}
		if err := st.stat("msgs", 1); err != nil {
			return err
		}
		return st.stat("msg_bytes", int64(len(frame)))
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// expireGrantBacklog closes up to limit expired pending messages of one grant.
func expireGrantBacklog(st *txState, grant wire.ID, limit int) error {
	prefix := kv.Key(bGrantOpen, grant[:])
	var ids []wire.ID
	if err := st.tx.Scan(prefix, kv.PrefixEnd(prefix), 0, func(k, _ []byte) bool {
		var id wire.ID
		copy(id[:], k[len(prefix):])
		ids = append(ids, id)
		return true
	}); err != nil {
		return err
	}
	closed := 0
	for _, id := range ids {
		if closed >= limit {
			break
		}
		v, err := st.tx.Get(kv.Key(bMsg, id[:]))
		if err != nil || v == nil {
			continue
		}
		mr, err := decodeMsg(v)
		if err != nil || mr.Status != statusPending || mr.Expires > st.now {
			continue
		}
		if err := closeMsg(st, id, mr, statusExpired); err != nil {
			return err
		}
		closed++
	}
	return nil
}

// closeMsg removes a pending message's content and inbox entry.
func closeMsg(st *txState, id wire.ID, mr *msgRec, status uint8) error {
	mr.Status = status
	for _, k := range [][]byte{
		kv.Key(bEvent, mr.Recipient[:], kv.U64(mr.EvSeq)),
		kv.Key(bGrantOpen, mr.Grant[:], id[:]),
		expiryKey(mr.Expires, wire.KindMsg, id),
	} {
		if err := st.tx.Delete(k); err != nil {
			return err
		}
	}
	if _, err := addU64(st.tx, kv.Key(bStat, []byte("inbox."), mr.Recipient[:]), -1); err != nil {
		return err
	}
	ctrKey := kv.Key(bGrantCtr, mr.Grant[:])
	if cv, err := st.tx.Get(ctrKey); err != nil {
		return err
	} else if cv != nil {
		ctr, err := decodeGrantCtr(cv)
		if err != nil {
			return err
		}
		if ctr.Pending[mr.Dir] > 0 {
			ctr.Pending[mr.Dir]--
		}
		if err := st.tx.Put(ctrKey, ctr.encode()); err != nil {
			return err
		}
	}
	return st.tx.Put(kv.Key(bMsg, id[:]), mr.encode())
}

func (r *Relay) submitAck(ctx context.Context, frame []byte) (*Result, error) {
	a, err := wire.DecodeAck(frame)
	if err != nil {
		return nil, malformed(err)
	}
	now := wire.Millis(r.now())
	if !skewOK(a.Created, now) {
		return nil, errf(400, "clock_skew", "ack creation time is more than %v from relay time", wire.MaxClockSkew)
	}
	g, err := r.cachedGrant(ctx, a.GrantID)
	if err != nil {
		return nil, err
	}
	res := &Result{Kind: "ack", ID: a.MsgID.String()}
	var verifiedFor wire.ID
	var verifiedCert *wire.Cert
	// The acker must be the message recipient; try both grant parties' keys outside the transaction.
	for _, party := range []wire.ID{g.From, g.To} {
		if c, err := r.verifiedCert(ctx, party, a.VerifySig); err == nil {
			verifiedFor, verifiedCert = party, c
			break
		}
	}
	if verifiedCert == nil {
		return nil, errf(401, "invalid_signature", "ack signature does not verify for either grant party")
	}
	err = r.update(ctx, func(st *txState) error {
		if err := kv.Prefetch(st.tx, kv.Key(bMsg, a.MsgID[:]), kv.Key(bAgentKey, verifiedFor[:]), ledger.SizeKey(), kv.Key(bGrantCtr, a.GrantID[:]),
			kv.Key(bStat, []byte("acks")), kv.Key(bStat, []byte("inbox."), verifiedFor[:])); err != nil {
			return err
		}
		v, err := st.tx.Get(kv.Key(bMsg, a.MsgID[:]))
		if err != nil {
			return err
		}
		if v == nil {
			return errf(404, "unknown_message", "no message %s", a.MsgID)
		}
		mr, err := decodeMsg(v)
		if err != nil {
			return err
		}
		if mr.Grant != a.GrantID || mr.Recipient != verifiedFor {
			return errf(403, "not_recipient", "only the message recipient can acknowledge it")
		}
		if mr.Status == statusAcked {
			if bytes.Equal(mr.AckFrame, frame) {
				res.LedgerIdx, res.Duplicate = mr.AckIdx, true
				return nil
			}
			return errf(409, "already_acked", "message was already acknowledged")
		}
		if mr.Status != statusPending {
			return errf(410, "message_closed", "message expired or its grant was revoked")
		}
		if err := currentKey(st, verifiedFor, verifiedCert); err != nil {
			return err
		}
		idx, err := st.ledger(wire.KindAck, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		mr.AckIdx, mr.AckFrame = idx, frame
		if err := closeMsg(st, a.MsgID, mr, statusAcked); err != nil {
			return err
		}
		if err := st.stat("acks", 1); err != nil {
			return err
		}
		return st.push(mr.Sender, &Event{Kind: wire.KindAck, LedgerIdx: idx, Ref: a.MsgID, Frame: frame})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (r *Relay) submitRevoke(ctx context.Context, frame []byte) (*Result, error) {
	v, err := wire.DecodeRevoke(frame)
	if err != nil {
		return nil, malformed(err)
	}
	now := wire.Millis(r.now())
	if !skewOK(v.Created, now) {
		return nil, errf(400, "clock_skew", "revoke creation time is more than %v from relay time", wire.MaxClockSkew)
	}
	// Authenticate outside the writer: the grant frame is immutable, and owner
	// keys never change for an agent address.
	g0, err := r.cachedGrant(ctx, v.GrantID)
	if err != nil {
		return nil, err
	}
	if v.By != g0.From && v.By != g0.To {
		return nil, errf(403, "not_participant", "only a grant participant can revoke it")
	}
	var signer *wire.Cert
	if v.Role == wire.RoleOwner {
		c, err := r.cachedCert(ctx, v.By)
		if err != nil {
			return nil, err
		}
		if !v.VerifySig(c.OwnerPub[:]) {
			return nil, errf(401, "invalid_signature", "revoke signature does not verify")
		}
	} else if signer, err = r.verifiedCert(ctx, v.By, v.VerifySig); err != nil {
		return nil, err
	}
	res := &Result{Kind: "revoke", ID: v.GrantID.String()}
	err = r.update(ctx, func(st *txState) error {
		gr, err := getGrant(st.tx, v.GrantID)
		if err != nil {
			return err
		}
		if gr == nil {
			return errf(404, "unknown_grant", "no grant %s", v.GrantID)
		}
		g := gr.Grant
		if signer != nil {
			if err := currentKey(st, v.By, signer); err != nil {
				return err
			}
		}
		if gr.Status == statusRevoked {
			res.LedgerIdx, res.Duplicate = gr.LedgerIdx, true
			return nil
		}
		// Purge every undelivered message in the grant.
		var open []wire.ID
		prefix := kv.Key(bGrantOpen, g.GrantID[:])
		if err := st.tx.Scan(prefix, kv.PrefixEnd(prefix), 0, func(k, _ []byte) bool {
			var id wire.ID
			copy(id[:], k[len(prefix):])
			open = append(open, id)
			return true
		}); err != nil {
			return err
		}
		for _, id := range open {
			mv, err := st.tx.Get(kv.Key(bMsg, id[:]))
			if err != nil {
				return err
			}
			mr, err := decodeMsg(mv)
			if err != nil {
				return err
			}
			if err := closeMsg(st, id, mr, statusPurged); err != nil {
				return err
			}
		}
		idx, err := st.ledger(wire.KindRevoke, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		gr.Status = statusRevoked
		if err := st.tx.Put(kv.Key(bGrant, g.GrantID[:]), gr.encode()); err != nil {
			return err
		}
		ctrKey := kv.Key(bGrantCtr, g.GrantID[:])
		cv, err := st.tx.Get(ctrKey)
		if err != nil {
			return err
		}
		ctr, err := decodeGrantCtr(cv)
		if err != nil {
			return err
		}
		ctr.Status = statusRevoked
		if err := st.tx.Put(ctrKey, ctr.encode()); err != nil {
			return err
		}
		other := g.From
		if v.By == g.From {
			other = g.To
		}
		return st.push(other, &Event{Kind: wire.KindRevoke, LedgerIdx: idx, Ref: g.GrantID, Frame: frame})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Expiry

func (r *Relay) maybeSweep(ctx context.Context) {
	now := r.now().UnixMilli()
	last := r.lastSweep.Load()
	if now-last < r.cfg.SweepEvery.Milliseconds() || !r.lastSweep.CompareAndSwap(last, now) {
		return
	}
	// Synchronous and small: a serverless instance may be frozen after it
	// responds, and a background sweep must never hold the writer lock then.
	r.Sweep(context.WithoutCancel(ctx), 100)
}

// Sweep expires up to limit intros and messages whose deadlines passed.
func (r *Relay) Sweep(ctx context.Context, limit int) (int, error) {
	n := 0
	err := r.update(ctx, func(st *txState) error {
		var keys [][]byte
		start := []byte{bExpiry}
		end := kv.Key(bExpiry, kv.U64(uint64(st.now)))
		if err := st.tx.Scan(start, end, limit, func(k, _ []byte) bool {
			keys = append(keys, append([]byte{}, k...))
			return true
		}); err != nil {
			return err
		}
		for _, k := range keys {
			if len(k) != 1+8+1+wire.IDLen {
				if err := st.tx.Delete(k); err != nil {
					return err
				}
				continue
			}
			kind := wire.Kind(k[9])
			var id wire.ID
			copy(id[:], k[10:])
			switch kind {
			case wire.KindIntro:
				ir, err := getIntro(st.tx, id)
				if err != nil {
					return err
				}
				if ir != nil && ir.Status == statusPending {
					if err := closeIntro(st, ir, statusExpired); err != nil {
						return err
					}
					if err := penalize(st, ir.Intro.From, 0.25); err != nil {
						return err
					}
				}
			case wire.KindMsg:
				v, err := st.tx.Get(kv.Key(bMsg, id[:]))
				if err != nil {
					return err
				}
				if v != nil {
					mr, err := decodeMsg(v)
					if err != nil {
						return err
					}
					if mr.Status == statusPending {
						if err := closeMsg(st, id, mr, statusExpired); err != nil {
							return err
						}
					}
				}
			}
			if err := st.tx.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// ---------------------------------------------------------------------------
// Reads

const maxInboxBytes = 1 << 20

// Inbox returns up to limit events after cursor for agent.
func (r *Relay) Inbox(ctx context.Context, agent wire.ID, after uint64, limit int) ([]*Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var out []*Event
	bytesOut := 0
	now := wire.Millis(r.now())
	err := r.store.View(ctx, func(tx kv.Tx) error {
		prefix := kv.Key(bEvent, agent[:])
		var derr error
		err := tx.Scan(kv.Key(bEvent, agent[:], kv.U64(after+1)), kv.PrefixEnd(prefix), limit, func(k, v []byte) bool {
			seq := binary.BigEndian.Uint64(k[len(prefix):])
			ev, err := decodeEvent(seq, v)
			if err != nil {
				derr = err
				return false
			}
			if ev.Kind == wire.KindMsg {
				if m, err := wire.DecodeMsg(ev.Frame); err == nil && m.Created+int64(m.TTL)*1000 <= now {
					return true // expired; the sweep will remove it
				}
			}
			out = append(out, ev)
			bytesOut += len(ev.Frame)
			return bytesOut < maxInboxBytes // a response carries at most ~1 MiB of frames
		})
		if err != nil {
			return err
		}
		return derr
	})
	return out, err
}

// WaitInbox long-polls for events after cursor, up to wait.
func (r *Relay) WaitInbox(ctx context.Context, agent wire.ID, after uint64, limit int, wait time.Duration) ([]*Event, error) {
	if wait > 0 && r.notify.waiting(agent) >= maxWaitersPerAgent {
		return nil, errf(429, "too_many_waits", "this agent already has %d open long-polls", maxWaitersPerAgent)
	}
	deadline := time.Now().Add(wait)
	attempt := 0
	for {
		ch, cancel := r.notify.subscribe(agent)
		evs, err := r.Inbox(ctx, agent, after, limit)
		if err != nil || len(evs) > 0 || wait <= 0 {
			cancel()
			return evs, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			cancel()
			return nil, nil
		}
		// Back off storage re-checks (250ms, 500ms, 1s, ... up to 3x PollInterval):
		// in-process wakeups are instant; this fallback covers writers on other
		// instances without keeping a scale-to-zero database awake.
		poll := min(r.cfg.PollInterval/4<<min(attempt, 6), 3*r.cfg.PollInterval)
		attempt++
		if remaining < poll {
			poll = remaining
		}
		t := time.NewTimer(poll)
		select {
		case <-ch:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return nil, ctx.Err()
		}
		t.Stop()
		cancel()
	}
}

// MessageStatus reports a message's delivery state to its sender or recipient.
type MessageStatus struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Grant     string `json:"grant"`
	Seq       uint32 `json:"seq"`
	LedgerIdx int64  `json:"ledger_index"`
	AckIdx    int64  `json:"ack_ledger_index,omitempty"`
	Ack       []byte `json:"ack,omitempty"`
}

func (r *Relay) MessageStatus(ctx context.Context, agent, id wire.ID) (*MessageStatus, error) {
	var out *MessageStatus
	err := r.store.View(ctx, func(tx kv.Tx) error {
		v, err := tx.Get(kv.Key(bMsg, id[:]))
		if err != nil {
			return err
		}
		if v == nil {
			return errf(404, "unknown_message", "no message %s", id)
		}
		mr, err := decodeMsg(v)
		if err != nil {
			return err
		}
		if agent != mr.Sender && agent != mr.Recipient {
			return errf(404, "unknown_message", "no message %s", id)
		}
		status := map[uint8]string{statusPending: "pending", statusAcked: "acked", statusPurged: "revoked", statusExpired: "expired"}[mr.Status]
		if mr.Status == statusAcked {
			if a, err := wire.DecodeAck(mr.AckFrame); err == nil {
				status = wire.OutcomeName(a.Outcome)
			}
		}
		out = &MessageStatus{ID: id.String(), Status: status, Grant: mr.Grant.String(), Seq: mr.Seq, LedgerIdx: mr.LedgerIdx, Ack: mr.AckFrame}
		if mr.AckIdx >= 0 {
			out.AckIdx = mr.AckIdx
		}
		return nil
	})
	return out, err
}

// Checkpoint returns the current signed tree head.
func (r *Relay) Checkpoint(ctx context.Context) ([]byte, int64, error) {
	var size int64
	var root [32]byte
	err := r.store.View(ctx, func(tx kv.Tx) error {
		var err error
		if size, err = ledger.Size(tx); err != nil {
			return err
		}
		if c := r.cp.Load(); c != nil && c.size == size {
			return nil
		}
		h, err := ledger.Root(tx, size)
		root = h
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	if c := r.cp.Load(); c != nil && c.size == size {
		return c.raw, size, nil
	}
	raw, err := r.signer.Sign(size, root)
	if err != nil {
		return nil, 0, err
	}
	if c := r.cp.Load(); c == nil || c.size < size {
		r.cp.Store(&signedCheckpoint{size: size, raw: raw})
	}
	return raw, size, nil
}

// Proof is a list of hashes.
type Proof struct {
	Index  int64    `json:"index,omitempty"`
	Old    int64    `json:"old,omitempty"`
	Size   int64    `json:"size"`
	Leaf   []byte   `json:"leaf,omitempty"`
	Hashes [][]byte `json:"hashes"`
}

func (r *Relay) InclusionProof(ctx context.Context, index, size int64) (*Proof, error) {
	out := &Proof{Index: index, Size: size}
	err := r.store.View(ctx, func(tx kv.Tx) error {
		n, err := ledger.Size(tx)
		if err != nil {
			return err
		}
		if size <= 0 || size > n || index < 0 || index >= size {
			return errf(400, "invalid_range", "index must be < size <= %d", n)
		}
		p, err := ledger.ProveInclusion(tx, index, size)
		if err != nil {
			return err
		}
		leaves, err := ledger.Leaves(tx, index, 1)
		if err != nil || len(leaves) != 1 {
			return errors.Join(err, errors.New("leaf missing"))
		}
		out.Leaf = leaves[0]
		for _, h := range p {
			out.Hashes = append(out.Hashes, append([]byte{}, h[:]...))
		}
		return nil
	})
	return out, err
}

func (r *Relay) ConsistencyProof(ctx context.Context, old, size int64) (*Proof, error) {
	out := &Proof{Old: old, Size: size}
	err := r.store.View(ctx, func(tx kv.Tx) error {
		n, err := ledger.Size(tx)
		if err != nil {
			return err
		}
		if old <= 0 || old > size || size > n {
			return errf(400, "invalid_range", "require 0 < old <= size <= %d", n)
		}
		p, err := ledger.ProveConsistency(tx, old, size)
		if err != nil {
			return err
		}
		for _, h := range p {
			out.Hashes = append(out.Hashes, append([]byte{}, h[:]...))
		}
		return nil
	})
	return out, err
}

func (r *Relay) Leaves(ctx context.Context, start, count int64) ([][]byte, error) {
	if count <= 0 || count > 1000 {
		count = 1000
	}
	var out [][]byte
	err := r.store.View(ctx, func(tx kv.Tx) error {
		var err error
		out, err = ledger.Leaves(tx, start, count)
		return err
	})
	return out, err
}

// Find returns the ledger index of a frame commitment, or -1.
func (r *Relay) Find(ctx context.Context, commitment []byte) (int64, error) {
	idx := int64(-1)
	err := r.store.View(ctx, func(tx kv.Tx) error {
		v, err := tx.Get(kv.Key(bFind, commitment))
		if err != nil || len(v) != 8 {
			return err
		}
		idx = int64(binary.BigEndian.Uint64(v))
		return nil
	})
	return idx, err
}

// Stats are public aggregate counters.
type Stats struct {
	Agents     uint64 `json:"agents"`
	Intros     uint64 `json:"intros"`
	Grants     uint64 `json:"grants"`
	Messages   uint64 `json:"messages"`
	Acks       uint64 `json:"acks"`
	MsgBytes   uint64 `json:"message_bytes"`
	LedgerSize int64  `json:"ledger_size"`
}

func (r *Relay) Stats(ctx context.Context) (*Stats, error) {
	s := &Stats{}
	err := r.store.View(ctx, func(tx kv.Tx) error {
		for _, f := range []struct {
			name string
			dst  *uint64
		}{{"agents", &s.Agents}, {"intros", &s.Intros}, {"grants", &s.Grants}, {"msgs", &s.Messages}, {"acks", &s.Acks}, {"msg_bytes", &s.MsgBytes}} {
			v, err := getU64(tx, kv.Key(bStat, []byte(f.name)))
			if err != nil {
				return err
			}
			*f.dst = v
		}
		var err error
		s.LedgerSize, err = ledger.Size(tx)
		return err
	})
	return s, err
}

// AuthCert returns the signing certificate for authenticating an agent's reads.
// AuthKey returns the agent's current signing key for authenticating reads.
// It reads the compact key record every time, so a rotation through any
// relay instance takes effect immediately.
func (r *Relay) AuthKey(ctx context.Context, id wire.ID) ([]byte, error) {
	var k *agentKey
	err := r.store.View(ctx, func(tx kv.Tx) error {
		v, err := tx.Get(kv.Key(bAgentKey, id[:]))
		if err != nil || v == nil {
			return err
		}
		k, err = decodeAgentKey(v)
		return err
	})
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, errf(404, "unknown_agent", "agent %s is not registered", id)
	}
	if k.Status != statusActive || k.Expires <= wire.Millis(r.now()) {
		return nil, errf(403, "agent_inactive", "agent is revoked or its certificate expired")
	}
	return k.SignPub[:], nil
}

// ---------------------------------------------------------------------------
// Notifications (in-process long-poll wakeups)

type notifier struct {
	mu      sync.Mutex
	waiters map[wire.ID]map[chan struct{}]struct{}
	count   int
	// Cross-instance wakeups: while count > 0 and the store is a kv.Watcher,
	// one goroutine listens for topics committed by other instances.
	watcher  kv.Watcher
	stopWait context.CancelFunc
	idle     *time.Timer
}

func (n *notifier) subscribe(id wire.ID) (chan struct{}, func()) {
	ch := make(chan struct{})
	n.mu.Lock()
	set := n.waiters[id]
	if set == nil {
		set = map[chan struct{}]struct{}{}
		n.waiters[id] = set
	}
	set[ch] = struct{}{}
	n.count++
	n.startWatchLocked()
	n.mu.Unlock()
	return ch, func() {
		n.mu.Lock()
		if s := n.waiters[id]; s != nil {
			if _, ok := s[ch]; ok { // not already fired
				delete(s, ch)
				close(ch)
				n.count--
			}
			if len(s) == 0 {
				delete(n.waiters, id)
			}
		}
		n.stopWatchLaterLocked()
		n.mu.Unlock()
	}
}

func (n *notifier) startWatchLocked() {
	if n.idle != nil {
		n.idle.Stop()
		n.idle = nil
	}
	if n.watcher == nil || n.stopWait != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stopWait = cancel
	go n.watcher.Watch(ctx, func(topic string) {
		if topic == "" {
			n.fireAll()
			return
		}
		if id, err := wire.ParseID(topic); err == nil {
			n.fire(id)
		}
	})
}

// stopWatchLaterLocked releases the listener a few seconds after the last waiter
// leaves, so back-to-back long-polls reuse it and an idle database can suspend.
func (n *notifier) stopWatchLaterLocked() {
	if n.count > 0 || n.stopWait == nil || n.idle != nil {
		return
	}
	n.idle = time.AfterFunc(10*time.Second, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.count == 0 && n.stopWait != nil {
			n.stopWait()
			n.stopWait = nil
		}
		n.idle = nil
	})
}

const maxWaitersPerAgent = 4

func (n *notifier) waiting(id wire.ID) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.waiters[id])
}

func (n *notifier) fire(id wire.ID) {
	n.mu.Lock()
	for ch := range n.waiters[id] {
		close(ch)
	}
	n.count -= len(n.waiters[id])
	delete(n.waiters, id)
	n.stopWatchLaterLocked()
	n.mu.Unlock()
}

func (n *notifier) fireAll() {
	n.mu.Lock()
	for id, set := range n.waiters {
		for ch := range set {
			close(ch)
		}
		n.count -= len(set)
		delete(n.waiters, id)
	}
	n.stopWatchLaterLocked()
	n.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Releases (software transparency)

func (r *Relay) submitRelease(ctx context.Context, frame []byte) (*Result, error) {
	rel, err := wire.DecodeRelease(frame)
	if err != nil {
		return nil, malformed(err)
	}
	allowed := false
	for _, k := range r.cfg.ReleaseKeys {
		if bytes.Equal(k, rel.Signer[:]) {
			allowed = true
		}
	}
	if !allowed || !rel.VerifySig() {
		return nil, errf(403, "not_release_key", "releases must be signed by a configured release key")
	}
	res := &Result{Kind: "release", ID: rel.Version}
	err = r.update(ctx, func(st *txState) error {
		vkey := kv.Key(bRelease, []byte("v:"+rel.Version))
		if v, err := st.tx.Get(vkey); err != nil {
			return err
		} else if v != nil {
			if bytes.Equal(v[8:], frame) {
				res.LedgerIdx, res.Duplicate = int64(binary.BigEndian.Uint64(v)), true
				return nil
			}
			return errf(409, "version_exists", "release %s was already published", rel.Version)
		}
		if v, err := st.tx.Get(kv.Key(bRelease, []byte("latest"))); err != nil {
			return err
		} else if v != nil {
			old, err := wire.DecodeRelease(append([]byte{}, v[8:]...))
			if err == nil && rel.Created <= old.Created {
				return errf(409, "stale_release", "a newer release (%s) is already published", old.Version)
			}
		}
		idx, err := st.ledger(wire.KindRelease, frame)
		if err != nil {
			return err
		}
		res.LedgerIdx = idx
		val := append(kv.U64(uint64(idx)), frame...)
		if err := st.tx.Put(vkey, val); err != nil {
			return err
		}
		return st.tx.Put(kv.Key(bRelease, []byte("latest")), val)
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// VerifyRelease checks a stored release frame against the configured release keys.
func (r *Relay) VerifyRelease(rel *wire.Release) bool {
	for _, k := range r.cfg.ReleaseKeys {
		if bytes.Equal(k, rel.Signer[:]) && rel.VerifySig() {
			return true
		}
	}
	return false
}

// ReleaseInfo is a published release with its ledger position.
type ReleaseInfo struct {
	Frame     []byte `json:"frame"`
	LedgerIdx int64  `json:"ledger_index"`
}

// LatestRelease returns the newest release, or version-specific one.
func (r *Relay) LatestRelease(ctx context.Context, version string) (*ReleaseInfo, error) {
	key := kv.Key(bRelease, []byte("latest"))
	if version != "" {
		key = kv.Key(bRelease, []byte("v:"+version))
	}
	var out *ReleaseInfo
	err := r.store.View(ctx, func(tx kv.Tx) error {
		v, err := tx.Get(key)
		if err != nil {
			return err
		}
		if len(v) < 9 {
			return errf(404, "no_release", "no release published")
		}
		out = &ReleaseInfo{LedgerIdx: int64(binary.BigEndian.Uint64(v)), Frame: append([]byte{}, v[8:]...)}
		return nil
	})
	return out, err
}
