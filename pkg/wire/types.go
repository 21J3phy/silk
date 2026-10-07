package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Version is the only protocol version this package encodes or accepts.
const Version = 2

// Kind identifies a frame type. It is the second byte of every frame.
type Kind uint8

const (
	KindCert    Kind = 1
	KindIntro   Kind = 2
	KindGrant   Kind = 3
	KindDecline Kind = 4
	KindMsg     Kind = 5
	KindAck     Kind = 6
	KindRevoke  Kind = 7
	KindPolicy  Kind = 8
	// KindEvicted is a relay notice (no frame): a pending contact request was outbid.
	KindEvicted Kind = 9
	KindTicket  Kind = 10
)

func (k Kind) String() string {
	switch k {
	case KindCert:
		return "cert"
	case KindIntro:
		return "intro"
	case KindGrant:
		return "grant"
	case KindDecline:
		return "decline"
	case KindMsg:
		return "msg"
	case KindAck:
		return "ack"
	case KindRevoke:
		return "revoke"
	case KindPolicy:
		return "policy"
	case KindEvicted:
		return "evicted"
	case KindTicket:
		return "ticket"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Suite 1: HPKE MLKEM768-X25519 (X-Wing) + HKDF-SHA256 + AES-256-GCM for
// handshakes, AES-256-GCM with ratcheted keys for messages, Ed25519 signatures.
const (
	Suite1        = 1
	KEMPublicLen  = 1216
	KEMEncLen     = 1120
	SigLen        = ed25519.SignatureSize
	PubLen        = ed25519.PublicKeySize
	AEADTagLen    = 16
	IDLen         = 16
	HashLen       = 32
	MaxFrame      = 64 << 10
	MaxPlaintext  = 32 << 10
	MaxNote       = 1024
	MaxIntroTTL   = 7 * 24 * time.Hour
	MaxGrantTTL   = 366 * 24 * time.Hour
	MaxMsgTTL     = 7 * 24 * time.Hour
	MaxBudget     = 1_000_000
	MaxRate       = 600
	MaxClockSkew  = 5 * time.Minute
	MaxPoWBits    = 40
	MaxLabelLen   = 32
	MaxHandleLen  = 32
	MaxScopeLen   = 32
)

// Signature domains. Each signed object uses its own domain so a signature
// over one kind can never be replayed as another.
const (
	DomainCertOwner = "silk/v2/cert/owner"
	DomainCertAgent = "silk/v2/cert/agent"
	DomainIntro     = "silk/v2/intro"
	DomainGrant     = "silk/v2/grant"
	DomainDecline   = "silk/v2/decline"
	DomainMsg       = "silk/v2/msg"
	DomainAck       = "silk/v2/ack"
	DomainRevoke    = "silk/v2/revoke"
	DomainPolicy    = "silk/v2/policy"
	DomainTicket    = "silk/v2/ticket"
	DomainAuth      = "silk/v2/auth"
)

// ID is a 16-byte identifier: agent IDs, intro/grant IDs, and message IDs.
type ID [IDLen]byte

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// String renders the ID as 26 lowercase base32 characters.
func (id ID) String() string { return b32.EncodeToString(id[:]) }

// Hex renders the ID as 32 hex characters.
func (id ID) Hex() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether the ID is all zero bytes.
func (id ID) IsZero() bool { return id == ID{} }

// ParseID accepts the base32 or hex form.
func ParseID(s string) (ID, error) {
	var id ID
	s = strings.TrimSpace(strings.ToLower(s))
	var raw []byte
	var err error
	switch len(s) {
	case 26:
		raw, err = b32.DecodeString(s)
	case 32:
		raw, err = hex.DecodeString(s)
	default:
		return id, fmt.Errorf("invalid id %q", s)
	}
	if err != nil || len(raw) != IDLen {
		return id, fmt.Errorf("invalid id %q", s)
	}
	copy(id[:], raw)
	// Reject non-canonical base32 (nonzero padding bits).
	if len(s) == 26 && id.String() != s {
		return ID{}, fmt.Errorf("non-canonical id %q", s)
	}
	return id, nil
}

// AgentID derives an agent's stable address from its owner key and owner-local
// label. Agent keys can rotate without changing the address.
func AgentID(ownerPub ed25519.PublicKey, label string) ID {
	h := sha256.New()
	h.Write([]byte("silk/v2/agent-id\x00"))
	h.Write(ownerPub)
	h.Write([]byte(label))
	var id ID
	copy(id[:], h.Sum(nil))
	return id
}

// FrameID is the identifier of a stored frame: the first 16 bytes of SHA-256.
func FrameID(frame []byte) ID {
	sum := sha256.Sum256(frame)
	var id ID
	copy(id[:], sum[:IDLen])
	return id
}

// Hash is SHA-256 of a frame.
func Hash(frame []byte) [HashLen]byte { return sha256.Sum256(frame) }

func validName(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '.' || s[len(s)-1] == '-' || s[len(s)-1] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// ValidLabel reports whether s is an acceptable agent label, handle, or scope.
func ValidLabel(s string) bool { return len(s) <= MaxLabelLen && validName(s) }

func signWith(priv ed25519.PrivateKey, domain string, body []byte) []byte {
	msg := make([]byte, 0, len(domain)+1+len(body))
	msg = append(msg, domain...)
	msg = append(msg, 0)
	msg = append(msg, body...)
	return ed25519.Sign(priv, msg)
}

// Verify checks an Ed25519 signature over domain || 0x00 || body.
func Verify(pub ed25519.PublicKey, domain string, body, sig []byte) bool {
	if len(pub) != PubLen || len(sig) != SigLen {
		return false
	}
	msg := make([]byte, 0, len(domain)+1+len(body))
	msg = append(msg, domain...)
	msg = append(msg, 0)
	msg = append(msg, body...)
	return ed25519.Verify(pub, msg, sig)
}

// Sign signs domain || 0x00 || body.
func Sign(priv ed25519.PrivateKey, domain string, body []byte) []byte {
	return signWith(priv, domain, body)
}

// Millis converts a time to protocol Unix milliseconds.
func Millis(t time.Time) int64 { return t.UnixMilli() }

// ---------------------------------------------------------------------------
// Cert: an owner-signed delegation binding an agent address to agent keys.

type Cert struct {
	OwnerPub  [PubLen]byte
	Label     string
	Handle    string
	Serial    uint32
	SignPub   [PubLen]byte
	Suite     uint16
	KEMPub    []byte
	Created   int64
	Expires   int64
	MinPoW    uint8
	Flags     uint8
	OwnerSig  [SigLen]byte
	AgentSig  [SigLen]byte
	Raw       []byte
}

// CertAcceptsIntros is the policy flag allowing unsolicited contact requests.
const CertAcceptsIntros = 1

// ID returns the agent address this certificate is for.
func (c *Cert) ID() ID { return AgentID(c.OwnerPub[:], c.Label) }

func (c *Cert) body() []byte {
	w := writer{b: make([]byte, 0, 1400)}
	w.u8(Version)
	w.u8(uint8(KindCert))
	w.raw(c.OwnerPub[:])
	w.str8(c.Label)
	w.str8(c.Handle)
	w.u32(c.Serial)
	w.raw(c.SignPub[:])
	w.u16(c.Suite)
	w.bytes16(c.KEMPub)
	w.i64(c.Created)
	w.i64(c.Expires)
	w.u8(c.MinPoW)
	w.u8(c.Flags)
	return w.b
}

// Sign fills both signatures: the owner's delegation and the agent's proof of possession.
func (c *Cert) Sign(owner, agent ed25519.PrivateKey) []byte {
	body := c.body()
	copy(c.OwnerSig[:], signWith(owner, DomainCertOwner, body))
	copy(c.AgentSig[:], signWith(agent, DomainCertAgent, body))
	c.Raw = append(append(body, c.OwnerSig[:]...), c.AgentSig[:]...)
	return c.Raw
}

// VerifySigs checks the owner and agent signatures.
func (c *Cert) VerifySigs() bool {
	body := c.Raw[:len(c.Raw)-2*SigLen]
	return Verify(c.OwnerPub[:], DomainCertOwner, body, c.OwnerSig[:]) &&
		Verify(c.SignPub[:], DomainCertAgent, body, c.AgentSig[:])
}

func DecodeCert(b []byte) (*Cert, error) {
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("%w: cert too large", ErrMalformed)
	}
	r := reader{b: b}
	c := &Cert{}
	r.header(KindCert)
	r.fixed(c.OwnerPub[:])
	c.Label = r.str8(1, MaxLabelLen, validName, "label")
	c.Handle = r.str8(0, MaxHandleLen, validName, "handle")
	c.Serial = r.u32()
	r.fixed(c.SignPub[:])
	c.Suite = r.u16()
	if r.err == nil && c.Suite != Suite1 {
		r.fail("unsupported suite %d", c.Suite)
	}
	c.KEMPub = r.bytes16(KEMPublicLen, KEMPublicLen, "kem public key")
	c.Created = r.i64()
	c.Expires = r.i64()
	c.MinPoW = r.u8()
	c.Flags = r.u8()
	r.fixed(c.OwnerSig[:])
	r.fixed(c.AgentSig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	if c.MinPoW > MaxPoWBits || c.Flags&^CertAcceptsIntros != 0 || c.Expires <= c.Created {
		return nil, fmt.Errorf("%w: invalid cert policy or lifetime", ErrMalformed)
	}
	c.Raw = b
	return c, nil
}

// ---------------------------------------------------------------------------
// Intro: a proof-of-work-stamped, signed contact request.

type Intro struct {
	IntroID  ID
	From     ID
	To       ID
	ToSerial uint32
	Created  int64
	Expires  int64
	Scope    string
	Budget   uint32
	GrantTTL uint32 // seconds
	Enc      []byte // HPKE encapsulation to the recipient's static key
	Note     []byte // HPKE-sealed purpose text, readable only by the recipient
	EphPub   []byte // initiator's ephemeral HPKE public key (forward secrecy)
	Ticket   []byte // optional invite ticket from the recipient's owner (skips postage)
	PoWBits  uint8
	PoWNonce uint64
	Sig      [SigLen]byte
	Raw      []byte
}

// Header returns the fixed context bound into HPKE info and the PoW.
func (in *Intro) Header() []byte {
	w := writer{b: make([]byte, 0, 128)}
	w.u8(Version)
	w.u8(uint8(KindIntro))
	w.raw(in.IntroID[:])
	w.raw(in.From[:])
	w.raw(in.To[:])
	w.u32(in.ToSerial)
	w.i64(in.Created)
	w.i64(in.Expires)
	w.str8(in.Scope)
	w.u32(in.Budget)
	w.u32(in.GrantTTL)
	return w.b
}

// PoWPrefix is everything the proof of work commits to (all but the stamp and signature).
func (in *Intro) PoWPrefix() []byte {
	w := writer{b: in.Header()}
	w.bytes16(in.Enc)
	w.bytes16(in.Note)
	w.bytes16(in.EphPub)
	w.bytes16(in.Ticket)
	return w.b
}

func (in *Intro) body() []byte {
	w := writer{b: in.PoWPrefix()}
	w.u8(in.PoWBits)
	w.u64(in.PoWNonce)
	return w.b
}

func (in *Intro) Sign(agent ed25519.PrivateKey) []byte {
	body := in.body()
	copy(in.Sig[:], signWith(agent, DomainIntro, body))
	in.Raw = append(body, in.Sig[:]...)
	return in.Raw
}

func (in *Intro) VerifySig(pub []byte) bool {
	return Verify(pub, DomainIntro, in.Raw[:len(in.Raw)-SigLen], in.Sig[:])
}

func DecodeIntro(b []byte) (*Intro, error) {
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("%w: intro too large", ErrMalformed)
	}
	r := reader{b: b}
	in := &Intro{}
	r.header(KindIntro)
	r.fixed(in.IntroID[:])
	r.fixed(in.From[:])
	r.fixed(in.To[:])
	in.ToSerial = r.u32()
	in.Created = r.i64()
	in.Expires = r.i64()
	in.Scope = r.str8(1, MaxScopeLen, validName, "scope")
	in.Budget = r.u32()
	in.GrantTTL = r.u32()
	in.Enc = r.bytes16(KEMEncLen, KEMEncLen, "enc")
	in.Note = r.bytes16(AEADTagLen, MaxNote+AEADTagLen, "note")
	in.EphPub = r.bytes16(KEMPublicLen, KEMPublicLen, "ephemeral key")
	in.Ticket = r.bytes16(0, MaxTicket, "ticket")
	in.PoWBits = r.u8()
	in.PoWNonce = r.u64()
	r.fixed(in.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	switch {
	case in.From == in.To:
		return nil, fmt.Errorf("%w: intro to self", ErrMalformed)
	case in.Budget == 0 || in.Budget > MaxBudget:
		return nil, fmt.Errorf("%w: budget outside 1..%d", ErrMalformed, MaxBudget)
	case in.GrantTTL == 0 || time.Duration(in.GrantTTL)*time.Second > MaxGrantTTL:
		return nil, fmt.Errorf("%w: grant ttl out of range", ErrMalformed)
	case in.Expires <= in.Created || time.Duration(in.Expires-in.Created)*time.Millisecond > MaxIntroTTL:
		return nil, fmt.Errorf("%w: intro lifetime out of range", ErrMalformed)
	case in.PoWBits > MaxPoWBits:
		return nil, fmt.Errorf("%w: pow bits out of range", ErrMalformed)
	}
	in.Raw = b
	return in, nil
}

// ---------------------------------------------------------------------------
// Grant: the recipient owner's signed consent, which also completes the key exchange.

type Grant struct {
	GrantID   ID // equals the intro ID
	IntroHash [HashLen]byte
	From      ID // intro sender ("a")
	To        ID // granting recipient ("b")
	Created   int64
	Expires   int64
	BudgetAB  uint32
	BudgetBA  uint32
	Rate      uint16 // messages per minute per direction
	Enc       []byte // HPKE encapsulation to the intro's ephemeral key
	OwnerPub  [PubLen]byte
	Sig       [SigLen]byte
	Raw       []byte
}

func (g *Grant) Header() []byte {
	w := writer{b: make([]byte, 0, 160)}
	w.u8(Version)
	w.u8(uint8(KindGrant))
	w.raw(g.GrantID[:])
	w.raw(g.IntroHash[:])
	w.raw(g.From[:])
	w.raw(g.To[:])
	w.i64(g.Created)
	w.i64(g.Expires)
	w.u32(g.BudgetAB)
	w.u32(g.BudgetBA)
	w.u16(g.Rate)
	return w.b
}

func (g *Grant) body() []byte {
	w := writer{b: g.Header()}
	w.bytes16(g.Enc)
	w.raw(g.OwnerPub[:])
	return w.b
}

func (g *Grant) Sign(owner ed25519.PrivateKey) []byte {
	copy(g.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	body := g.body()
	copy(g.Sig[:], signWith(owner, DomainGrant, body))
	g.Raw = append(body, g.Sig[:]...)
	return g.Raw
}

func (g *Grant) VerifySig() bool {
	return Verify(g.OwnerPub[:], DomainGrant, g.Raw[:len(g.Raw)-SigLen], g.Sig[:])
}

// Budget returns the budget for a direction (DirAB or DirBA).
func (g *Grant) Budget(dir uint8) uint32 {
	if dir == DirAB {
		return g.BudgetAB
	}
	return g.BudgetBA
}

func DecodeGrant(b []byte) (*Grant, error) {
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("%w: grant too large", ErrMalformed)
	}
	r := reader{b: b}
	g := &Grant{}
	r.header(KindGrant)
	r.fixed(g.GrantID[:])
	r.fixed(g.IntroHash[:])
	r.fixed(g.From[:])
	r.fixed(g.To[:])
	g.Created = r.i64()
	g.Expires = r.i64()
	g.BudgetAB = r.u32()
	g.BudgetBA = r.u32()
	g.Rate = r.u16()
	g.Enc = r.bytes16(KEMEncLen, KEMEncLen, "enc")
	r.fixed(g.OwnerPub[:])
	r.fixed(g.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	switch {
	case g.From == g.To:
		return nil, fmt.Errorf("%w: grant to self", ErrMalformed)
	case g.BudgetAB > MaxBudget || g.BudgetBA > MaxBudget || g.BudgetAB+g.BudgetBA == 0:
		return nil, fmt.Errorf("%w: budget out of range", ErrMalformed)
	case g.Rate == 0 || g.Rate > MaxRate:
		return nil, fmt.Errorf("%w: rate out of range", ErrMalformed)
	case g.Expires <= g.Created || time.Duration(g.Expires-g.Created)*time.Millisecond > MaxGrantTTL:
		return nil, fmt.Errorf("%w: grant lifetime out of range", ErrMalformed)
	}
	g.Raw = b
	return g, nil
}

// ---------------------------------------------------------------------------
// Decline: the recipient owner's signed refusal of an intro.

type Decline struct {
	IntroID   ID
	IntroHash [HashLen]byte
	By        ID
	Created   int64
	OwnerPub  [PubLen]byte
	Sig       [SigLen]byte
	Raw       []byte
}

func (d *Decline) body() []byte {
	w := writer{b: make([]byte, 0, 140)}
	w.u8(Version)
	w.u8(uint8(KindDecline))
	w.raw(d.IntroID[:])
	w.raw(d.IntroHash[:])
	w.raw(d.By[:])
	w.i64(d.Created)
	w.raw(d.OwnerPub[:])
	return w.b
}

func (d *Decline) Sign(owner ed25519.PrivateKey) []byte {
	copy(d.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	body := d.body()
	copy(d.Sig[:], signWith(owner, DomainDecline, body))
	d.Raw = append(body, d.Sig[:]...)
	return d.Raw
}

func (d *Decline) VerifySig() bool {
	return Verify(d.OwnerPub[:], DomainDecline, d.Raw[:len(d.Raw)-SigLen], d.Sig[:])
}

func DecodeDecline(b []byte) (*Decline, error) {
	r := reader{b: b}
	d := &Decline{}
	r.header(KindDecline)
	r.fixed(d.IntroID[:])
	r.fixed(d.IntroHash[:])
	r.fixed(d.By[:])
	d.Created = r.i64()
	r.fixed(d.OwnerPub[:])
	r.fixed(d.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	d.Raw = b
	return d, nil
}

// ---------------------------------------------------------------------------
// Msg: an end-to-end encrypted message inside a grant.

const (
	DirAB = 0 // intro sender -> granting recipient
	DirBA = 1 // granting recipient -> intro sender

	msgFlagDir   = 1
	msgFlagReply = 2
)

type Msg struct {
	GrantID ID
	Dir     uint8
	Seq     uint32
	Created int64
	TTL     uint32 // seconds
	ReplyTo *ID
	CT      []byte
	Sig     [SigLen]byte
	Raw     []byte
}

// Header is the AEAD associated data: every field except the ciphertext and signature.
func (m *Msg) Header() []byte {
	w := writer{b: make([]byte, 0, 64)}
	w.u8(Version)
	w.u8(uint8(KindMsg))
	w.raw(m.GrantID[:])
	flags := m.Dir & msgFlagDir
	if m.ReplyTo != nil {
		flags |= msgFlagReply
	}
	w.u8(flags)
	w.u32(m.Seq)
	w.i64(m.Created)
	w.u32(m.TTL)
	if m.ReplyTo != nil {
		w.raw(m.ReplyTo[:])
	}
	return w.b
}

func (m *Msg) body() []byte {
	w := writer{b: m.Header()}
	w.bytes32(m.CT)
	return w.b
}

func (m *Msg) Sign(agent ed25519.PrivateKey) []byte {
	body := m.body()
	copy(m.Sig[:], signWith(agent, DomainMsg, body))
	m.Raw = append(body, m.Sig[:]...)
	return m.Raw
}

func (m *Msg) VerifySig(pub []byte) bool {
	return Verify(pub, DomainMsg, m.Raw[:len(m.Raw)-SigLen], m.Sig[:])
}

// ID is the message identifier derived from the complete signed frame.
func (m *Msg) ID() ID { return FrameID(m.Raw) }

func DecodeMsg(b []byte) (*Msg, error) {
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("%w: message too large", ErrMalformed)
	}
	r := reader{b: b}
	m := &Msg{}
	r.header(KindMsg)
	r.fixed(m.GrantID[:])
	flags := r.u8()
	if r.err == nil && flags&^(msgFlagDir|msgFlagReply) != 0 {
		r.fail("unknown message flags")
	}
	m.Dir = flags & msgFlagDir
	m.Seq = r.u32()
	m.Created = r.i64()
	m.TTL = r.u32()
	if flags&msgFlagReply != 0 {
		var id ID
		r.fixed(id[:])
		m.ReplyTo = &id
	}
	m.CT = r.bytes32(1+AEADTagLen, MaxPlaintext+1+AEADTagLen, "ciphertext")
	r.fixed(m.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	if m.TTL == 0 || time.Duration(m.TTL)*time.Second > MaxMsgTTL {
		return nil, fmt.Errorf("%w: message ttl out of range", ErrMalformed)
	}
	m.Raw = b
	return m, nil
}

// ---------------------------------------------------------------------------
// Ack: the recipient agent's signed acknowledgment of one message.

const (
	AckReceived = 1
	AckDeclined = 2
	AckHandled  = 3
)

type Ack struct {
	MsgID   ID
	GrantID ID
	Outcome uint8
	Created int64
	Sig     [SigLen]byte
	Raw     []byte
}

func (a *Ack) body() []byte {
	w := writer{b: make([]byte, 0, 48)}
	w.u8(Version)
	w.u8(uint8(KindAck))
	w.raw(a.MsgID[:])
	w.raw(a.GrantID[:])
	w.u8(a.Outcome)
	w.i64(a.Created)
	return w.b
}

func (a *Ack) Sign(agent ed25519.PrivateKey) []byte {
	body := a.body()
	copy(a.Sig[:], signWith(agent, DomainAck, body))
	a.Raw = append(body, a.Sig[:]...)
	return a.Raw
}

func (a *Ack) VerifySig(pub []byte) bool {
	return Verify(pub, DomainAck, a.Raw[:len(a.Raw)-SigLen], a.Sig[:])
}

func DecodeAck(b []byte) (*Ack, error) {
	r := reader{b: b}
	a := &Ack{}
	r.header(KindAck)
	r.fixed(a.MsgID[:])
	r.fixed(a.GrantID[:])
	a.Outcome = r.u8()
	a.Created = r.i64()
	r.fixed(a.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	if a.Outcome < AckReceived || a.Outcome > AckHandled {
		return nil, fmt.Errorf("%w: unknown ack outcome", ErrMalformed)
	}
	a.Raw = b
	return a, nil
}

// OutcomeName renders an ack outcome.
func OutcomeName(o uint8) string {
	switch o {
	case AckReceived:
		return "received"
	case AckDeclined:
		return "declined"
	case AckHandled:
		return "handled"
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Revoke: either participant ends a grant. Signed by an agent key or owner key.

const (
	RoleAgent = 0
	RoleOwner = 1
)

type Revoke struct {
	GrantID ID
	By      ID
	Role    uint8
	Created int64
	Sig     [SigLen]byte
	Raw     []byte
}

func (v *Revoke) body() []byte {
	w := writer{b: make([]byte, 0, 48)}
	w.u8(Version)
	w.u8(uint8(KindRevoke))
	w.raw(v.GrantID[:])
	w.raw(v.By[:])
	w.u8(v.Role)
	w.i64(v.Created)
	return w.b
}

func (v *Revoke) Sign(key ed25519.PrivateKey) []byte {
	body := v.body()
	copy(v.Sig[:], signWith(key, DomainRevoke, body))
	v.Raw = append(body, v.Sig[:]...)
	return v.Raw
}

func (v *Revoke) VerifySig(pub []byte) bool {
	return Verify(pub, DomainRevoke, v.Raw[:len(v.Raw)-SigLen], v.Sig[:])
}

func DecodeRevoke(b []byte) (*Revoke, error) {
	r := reader{b: b}
	v := &Revoke{}
	r.header(KindRevoke)
	r.fixed(v.GrantID[:])
	r.fixed(v.By[:])
	v.Role = r.u8()
	v.Created = r.i64()
	r.fixed(v.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	if v.Role > RoleOwner {
		return nil, fmt.Errorf("%w: unknown revoke role", ErrMalformed)
	}
	v.Raw = b
	return v, nil
}

// ---------------------------------------------------------------------------
// Policy: an owner-signed contact policy for one agent. Senders it trusts
// skip proof-of-work postage and the stranger queue.

const (
	PolicyTrustSameOwner = 1 // agents with the same owner key are trusted
	MaxPolicyOwners      = 64
	MaxPolicyAgents      = 1024
)

type Policy struct {
	Agent    ID
	Serial   uint32
	Created  int64
	Flags    uint8
	Owners   [][PubLen]byte
	Agents   []ID
	OwnerPub [PubLen]byte
	Sig      [SigLen]byte
	Raw      []byte
}

func (p *Policy) body() []byte {
	w := writer{b: make([]byte, 0, 64+len(p.Owners)*PubLen+len(p.Agents)*IDLen)}
	w.u8(Version)
	w.u8(uint8(KindPolicy))
	w.raw(p.Agent[:])
	w.u32(p.Serial)
	w.i64(p.Created)
	w.u8(p.Flags)
	w.u8(uint8(len(p.Owners)))
	for _, o := range p.Owners {
		w.raw(o[:])
	}
	w.u16(uint16(len(p.Agents)))
	for _, a := range p.Agents {
		w.raw(a[:])
	}
	w.raw(p.OwnerPub[:])
	return w.b
}

func (p *Policy) Sign(owner ed25519.PrivateKey) []byte {
	copy(p.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	body := p.body()
	copy(p.Sig[:], signWith(owner, DomainPolicy, body))
	p.Raw = append(body, p.Sig[:]...)
	return p.Raw
}

func (p *Policy) VerifySig() bool {
	return Verify(p.OwnerPub[:], DomainPolicy, p.Raw[:len(p.Raw)-SigLen], p.Sig[:])
}

// Trusts reports whether the policy trusts a sender agent with the given owner key.
func (p *Policy) Trusts(sender ID, senderOwner [PubLen]byte) bool {
	if p.Flags&PolicyTrustSameOwner != 0 && senderOwner == p.OwnerPub {
		return true
	}
	for _, o := range p.Owners {
		if o == senderOwner {
			return true
		}
	}
	for _, a := range p.Agents {
		if a == sender {
			return true
		}
	}
	return false
}

func DecodePolicy(b []byte) (*Policy, error) {
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("%w: policy too large", ErrMalformed)
	}
	r := reader{b: b}
	p := &Policy{}
	r.header(KindPolicy)
	r.fixed(p.Agent[:])
	p.Serial = r.u32()
	p.Created = r.i64()
	p.Flags = r.u8()
	if r.err == nil && p.Flags&^PolicyTrustSameOwner != 0 {
		r.fail("unknown policy flags")
	}
	no := int(r.u8())
	if r.err == nil && no > MaxPolicyOwners {
		r.fail("too many trusted owners")
	}
	for i := 0; i < no && r.err == nil; i++ {
		var o [PubLen]byte
		r.fixed(o[:])
		p.Owners = append(p.Owners, o)
	}
	na := int(r.u16())
	if r.err == nil && na > MaxPolicyAgents {
		r.fail("too many trusted agents")
	}
	for i := 0; i < na && r.err == nil; i++ {
		var a ID
		r.fixed(a[:])
		p.Agents = append(p.Agents, a)
	}
	r.fixed(p.OwnerPub[:])
	r.fixed(p.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	p.Raw = b
	return p, nil
}

// ---------------------------------------------------------------------------
// Ticket: a single-use invite signed by an agent's owner. An intro that
// carries a valid unused ticket for its recipient is trusted: no postage, no
// stranger queue. Owners hand tickets out like invite links.

const (
	MaxTicket    = 256
	TicketPrefix = "silk-invite:"
	MaxTicketTTL = 90 * 24 * time.Hour
)

type Ticket struct {
	Recipient ID
	TicketID  ID
	Expires   int64
	OwnerPub  [PubLen]byte
	Sig       [SigLen]byte
	Raw       []byte
}

func (t *Ticket) body() []byte {
	w := writer{b: make([]byte, 0, 80)}
	w.u8(Version)
	w.u8(uint8(KindTicket))
	w.raw(t.Recipient[:])
	w.raw(t.TicketID[:])
	w.i64(t.Expires)
	w.raw(t.OwnerPub[:])
	return w.b
}

func (t *Ticket) Sign(owner ed25519.PrivateKey) []byte {
	copy(t.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	body := t.body()
	copy(t.Sig[:], signWith(owner, DomainTicket, body))
	t.Raw = append(body, t.Sig[:]...)
	return t.Raw
}

func (t *Ticket) VerifySig() bool {
	return Verify(t.OwnerPub[:], DomainTicket, t.Raw[:len(t.Raw)-SigLen], t.Sig[:])
}

// String renders the ticket as a shareable invite.
func (t *Ticket) String() string { return TicketPrefix + base64.RawURLEncoding.EncodeToString(t.Raw) }

func DecodeTicket(b []byte) (*Ticket, error) {
	r := reader{b: b}
	t := &Ticket{}
	r.header(KindTicket)
	r.fixed(t.Recipient[:])
	r.fixed(t.TicketID[:])
	t.Expires = r.i64()
	r.fixed(t.OwnerPub[:])
	r.fixed(t.Sig[:])
	if err := r.done(); err != nil {
		return nil, err
	}
	t.Raw = b
	return t, nil
}

// ParseInvite decodes a "silk-invite:..." string.
func ParseInvite(s string) (*Ticket, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, TicketPrefix) {
		return nil, fmt.Errorf("not a silk invite")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s[len(TicketPrefix):])
	if err != nil {
		return nil, fmt.Errorf("invite encoding: %w", err)
	}
	return DecodeTicket(raw)
}
