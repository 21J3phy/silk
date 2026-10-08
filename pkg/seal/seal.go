// Package seal implements Silk's end-to-end encryption.
//
// Handshake (once per relationship, RFC 9180 HPKE with the hybrid
// post-quantum KEM MLKEM768-X25519 "X-Wing", HKDF-SHA256, AES-256-GCM):
//
//	intro:  A encapsulates to B's static key  -> K1, and seals the purpose note.
//	        A also sends a fresh ephemeral X-Wing public key.
//	grant:  B encapsulates to A's ephemeral key -> K2. A deletes the ephemeral
//	        secret after deriving, so later compromise of either party's
//	        long-term keys does not reveal the conversation (forward secrecy).
//	root  = HKDF-Extract(salt = SHA-256(intro hash || grant header), K1 || K2)
//
// Messages use one symmetric hash ratchet per direction: each message key is
// used once and deleted (forward secrecy within a chain).
//
// On top of that, each direction's chain is re-keyed with a fresh X25519
// exchange once per turn of the conversation (post-compromise security). Every
// message starts with a cleartext, authenticated 49-byte header carrying the
// sender's current ratchet public key. A sender starts a new epoch when it has
// seen a newer key from the peer and the peer has seen its current epoch:
//
//	ck' = HKDF(salt = HMAC(ck, 0x04), ikm = X25519(fresh, peer key),
//	           info = "silk/v2 ratchet" || grant || dir || epoch || start || keys)
//
// Someone who steals a device's session state can follow the conversation only
// until both sides have exchanged fresh keys (about one round trip per
// direction). The steps are classical X25519; the post-quantum handshake secret
// stays mixed into every chain, so recorded traffic still needs it.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/21J3phy/silk/pkg/wire"
)

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()

	ErrDecrypt = errors.New("message could not be decrypted")
)

// KEMKey is a private X-Wing key (32-byte seed form).
type KEMKey struct {
	priv hpke.PrivateKey
}

// NewKEMKey generates a fresh hybrid post-quantum key.
func NewKEMKey() (*KEMKey, error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &KEMKey{priv: k}, nil
}

// LoadKEMKey restores a key from its serialized private form.
func LoadKEMKey(b []byte) (*KEMKey, error) {
	k, err := kem.NewPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &KEMKey{priv: k}, nil
}

// Bytes is the serialized private key.
func (k *KEMKey) Bytes() []byte {
	b, err := k.priv.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// Public is the serialized public key (1216 bytes).
func (k *KEMKey) Public() []byte { return k.priv.PublicKey().Bytes() }

func introInfo(in *wire.Intro) []byte { return append([]byte("silk/v2 intro\x00"), in.Header()...) }
func grantInfo(g *wire.Grant) []byte  { return append([]byte("silk/v2 grant\x00"), g.Header()...) }

// SealIntro encapsulates to the recipient's static key, sets in.Enc and
// in.Note (sealed purpose text), and returns K1.
func SealIntro(in *wire.Intro, recipientKEMPub []byte, note string) (k1 []byte, err error) {
	if len(note) > wire.MaxNote || !utf8.ValidString(note) {
		return nil, fmt.Errorf("note must be valid UTF-8 up to %d bytes", wire.MaxNote)
	}
	pk, err := kem.NewPublicKey(recipientKEMPub)
	if err != nil {
		return nil, fmt.Errorf("recipient key: %w", err)
	}
	enc, s, err := hpke.NewSender(pk, kdf, aead, introInfo(in))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(nil, []byte(note))
	if err != nil {
		return nil, err
	}
	in.Enc, in.Note = enc, ct
	return s.Export("silk/v2 k1", 32)
}

// OpenIntro decapsulates with the recipient's static key and returns the purpose note and K1.
func OpenIntro(in *wire.Intro, k *KEMKey) (note string, k1 []byte, err error) {
	r, err := hpke.NewRecipient(in.Enc, k.priv, kdf, aead, introInfo(in))
	if err != nil {
		return "", nil, ErrDecrypt
	}
	pt, err := r.Open(nil, in.Note)
	if err != nil || !utf8.Valid(pt) {
		return "", nil, ErrDecrypt
	}
	k1, err = r.Export("silk/v2 k1", 32)
	return string(pt), k1, err
}

// SealGrant encapsulates to the intro's ephemeral key, sets g.Enc, and returns K2.
func SealGrant(g *wire.Grant, ephPub []byte) (k2 []byte, err error) {
	pk, err := kem.NewPublicKey(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	enc, s, err := hpke.NewSender(pk, kdf, aead, grantInfo(g))
	if err != nil {
		return nil, err
	}
	g.Enc = enc
	return s.Export("silk/v2 k2", 32)
}

// OpenGrant recovers K2 with the initiator's ephemeral key.
func OpenGrant(g *wire.Grant, eph *KEMKey) ([]byte, error) {
	r, err := hpke.NewRecipient(g.Enc, eph.priv, kdf, aead, grantInfo(g))
	if err != nil {
		return nil, ErrDecrypt
	}
	return r.Export("silk/v2 k2", 32)
}

// Root combines both handshake secrets with the transcript.
func Root(k1, k2 []byte, introHash [32]byte, g *wire.Grant) ([]byte, error) {
	salt := sha256.New()
	salt.Write([]byte("silk/v2 root\x00"))
	salt.Write(introHash[:])
	salt.Write(g.Header())
	ikm := append(append([]byte{}, k1...), k2...)
	return hkdf.Extract(sha256.New, ikm, salt.Sum(nil))
}

// Chain is one direction of the symmetric ratchet.
type Chain struct {
	Key []byte `json:"k"`
	N   uint32 `json:"n"`
}

func mac(key []byte, label byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{label})
	return h.Sum(nil)
}

// step returns this position's message key and nonce, and advances the chain.
func (c *Chain) step() (key, nonce []byte) {
	key = mac(c.Key, 1)
	nonce = mac(c.Key, 3)[:12]
	next := mac(c.Key, 2)
	clear(c.Key)
	c.Key = next
	c.N++
	return key, nonce
}

// MaxSkip bounds how many message keys a receiver will derive ahead of order.
const MaxSkip = 2000

// Session is one participant's view of a grant: a send chain, a receive
// chain, a bounded set of skipped (out-of-order) receive keys, and the
// ratchet state that re-keys each chain once per turn.
type Session struct {
	GrantID string            `json:"grant"`
	SendDir uint8             `json:"dir"`
	Send    Chain             `json:"send"`
	Recv    Chain             `json:"recv"`
	Skipped map[uint32][]byte `json:"skipped,omitempty"` // seq -> key||nonce

	SendEpoch uint32            `json:"se,omitempty"`   // epochs re-keyed in the send direction
	SendStart uint32            `json:"ss,omitempty"`   // first seq of the current send epoch
	SendRef   uint32            `json:"sref,omitempty"` // peer epoch whose key keyed it
	Mine      map[uint32][]byte `json:"mine,omitempty"` // own ratchet keys (private || public) by send epoch
	RecvEpoch uint32            `json:"re,omitempty"`
	RecvPub   []byte            `json:"rpub,omitempty"` // peer's ratchet key for RecvEpoch
	PeerSeen  uint32            `json:"seen,omitempty"` // newest own epoch the peer has decrypted
}

// NewSession derives both chains. isInitiator is true for the intro sender (A).
func NewSession(grantID wire.ID, root []byte, isInitiator bool) (*Session, error) {
	ab, err := hkdf.Expand(sha256.New, root, "silk/v2 chain a>b", 32)
	if err != nil {
		return nil, err
	}
	ba, err := hkdf.Expand(sha256.New, root, "silk/v2 chain b>a", 32)
	if err != nil {
		return nil, err
	}
	s := &Session{GrantID: grantID.String()}
	if isInitiator {
		s.SendDir, s.Send.Key, s.Recv.Key = wire.DirAB, ab, ba
	} else {
		s.SendDir, s.Send.Key, s.Recv.Key = wire.DirBA, ba, ab
	}
	return s, s.ensureKey()
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// Content types inside the encrypted payload.
const (
	TypeText = 1
	TypeJSON = 2
)

const ratchetVersion = 1

// header is the cleartext ratchet header at the start of a message's CT.
type header struct {
	Epoch uint32 // sender's send epoch
	Start uint32 // first seq of that epoch
	Ref   uint32 // receiver epoch whose ratchet key keyed it (epoch > 0)
	Seen  uint32 // newest receiver epoch the sender has decrypted
	Pub   [32]byte
}

func (h *header) encode() []byte {
	b := make([]byte, wire.RatchetHeaderLen)
	b[0] = ratchetVersion
	binary.BigEndian.PutUint32(b[1:], h.Epoch)
	binary.BigEndian.PutUint32(b[5:], h.Start)
	binary.BigEndian.PutUint32(b[9:], h.Ref)
	binary.BigEndian.PutUint32(b[13:], h.Seen)
	copy(b[17:], h.Pub[:])
	return b
}

func parseHeader(ct []byte) (*header, error) {
	if len(ct) < wire.RatchetHeaderLen+1+wire.AEADTagLen || ct[0] != ratchetVersion {
		return nil, fmt.Errorf("%w: unsupported ratchet header", ErrDecrypt)
	}
	h := &header{Epoch: binary.BigEndian.Uint32(ct[1:]), Start: binary.BigEndian.Uint32(ct[5:]),
		Ref: binary.BigEndian.Uint32(ct[9:]), Seen: binary.BigEndian.Uint32(ct[13:])}
	copy(h.Pub[:], ct[17:wire.RatchetHeaderLen])
	return h, nil
}

// StepKey re-keys a chain at the start of a new epoch. chainKey is the old
// chain's key at position start; dh is the X25519 output between the sender's
// fresh key and the receiver's advertised key.
func StepKey(chainKey, dh []byte, grantID string, dir uint8, epoch, start uint32, senderPub, receiverPub []byte) ([]byte, error) {
	info := make([]byte, 0, 128)
	info = append(info, "silk/v2 ratchet\x00"...)
	info = append(info, grantID...)
	info = append(info, dir)
	info = binary.BigEndian.AppendUint32(info, epoch)
	info = binary.BigEndian.AppendUint32(info, start)
	info = append(append(info, senderPub...), receiverPub...)
	return hkdf.Key(sha256.New, dh, mac(chainKey, 4), string(info), 32)
}

func x25519(priv, peerPub []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return k.ECDH(p) // rejects low-order peer keys (all-zero output)
}

func newRatchetKey() ([]byte, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return append(k.Bytes(), k.PublicKey().Bytes()...), nil
}

// ensureKey creates the epoch-0 ratchet key (also for sessions stored by
// clients that predate the ratchet).
func (s *Session) ensureKey() error {
	if s.Mine == nil {
		s.Mine = map[uint32][]byte{}
	}
	if len(s.Mine[s.SendEpoch]) == 64 {
		return nil
	}
	if s.SendEpoch != 0 {
		return errors.New("ratchet state lost its current key")
	}
	k, err := newRatchetKey()
	s.Mine[0] = k
	return err
}

// step starts a new send epoch when the peer has advertised a newer key and
// has decrypted the current epoch (so the receiver never has to jump epochs).
func (s *Session) step() error {
	if err := s.ensureKey(); err != nil {
		return err
	}
	if s.RecvPub == nil || (s.SendEpoch > 0 && (s.RecvEpoch <= s.SendRef || s.PeerSeen < s.SendEpoch)) {
		return nil
	}
	k, err := newRatchetKey()
	if err != nil {
		return err
	}
	dh, err := x25519(k[:32], s.RecvPub)
	if err != nil {
		return err
	}
	e := s.SendEpoch + 1
	next, err := StepKey(s.Send.Key, dh, s.GrantID, s.SendDir, e, s.Send.N, k[32:], s.RecvPub)
	clear(dh)
	if err != nil {
		return err
	}
	clear(s.Send.Key)
	s.Send.Key, s.SendEpoch, s.SendStart, s.SendRef = next, e, s.Send.N, s.RecvEpoch
	s.Mine[e] = k
	s.prune()
	return nil
}

// prune forgets own ratchet keys the peer can no longer reference.
func (s *Session) prune() {
	for e, k := range s.Mine {
		if e < s.PeerSeen && e != s.SendEpoch {
			clear(k)
			delete(s.Mine, e)
		}
	}
}

// Encrypt assigns the next sequence number to m, sets its direction, and
// fills m.CT (ratchet header || AES-GCM ciphertext). It may start a new
// epoch, so the caller must persist the session before transmitting.
func (s *Session) Encrypt(m *wire.Msg, ctype byte, body []byte) error {
	if len(body) > wire.MaxPlaintext {
		return fmt.Errorf("message body exceeds %d bytes", wire.MaxPlaintext)
	}
	if ctype == TypeText && !utf8.Valid(body) {
		return errors.New("text must be valid UTF-8")
	}
	if err := s.step(); err != nil {
		return err
	}
	h := header{Epoch: s.SendEpoch, Start: s.SendStart, Ref: s.SendRef, Seen: s.RecvEpoch}
	copy(h.Pub[:], s.Mine[s.SendEpoch][32:])
	hb := h.encode()
	m.Dir, m.Seq, m.Ratchet = s.SendDir, s.Send.N, true
	key, nonce := s.Send.step()
	pt := make([]byte, 0, 1+len(body))
	pt = append(append(pt, ctype), body...)
	out := make([]byte, len(hb), len(hb)+len(pt)+wire.AEADTagLen)
	copy(out, hb)
	m.CT = gcm(key).Seal(out, nonce, pt, append(m.Header(), hb...))
	clear(key)
	return nil
}

// Decrypt opens a message in the receive direction. Each key works once.
// A failed attempt leaves the session unchanged.
func (s *Session) Decrypt(m *wire.Msg) (ctype byte, body []byte, err error) {
	if m.Dir == s.SendDir {
		return 0, nil, fmt.Errorf("%w: message is in this session's send direction", ErrDecrypt)
	}
	ct, aad := m.CT, m.Header()
	var h *header
	if m.Ratchet {
		if h, err = parseHeader(m.CT); err != nil {
			return 0, nil, err
		}
		ct, aad = m.CT[wire.RatchetHeaderLen:], append(aad, m.CT[:wire.RatchetHeaderLen]...)
	}
	if m.Seq < s.Recv.N {
		kn, ok := s.Skipped[m.Seq]
		if !ok {
			return 0, nil, fmt.Errorf("%w: key for seq %d already used", ErrDecrypt, m.Seq)
		}
		pt, err := gcm(kn[:32]).Open(nil, kn[32:], ct, aad)
		if err != nil {
			return 0, nil, ErrDecrypt
		}
		delete(s.Skipped, m.Seq)
		if h != nil {
			s.learn(h)
		}
		return split(pt)
	}
	// Derive on a copy so a forged message cannot advance the real chain.
	trial := Chain{Key: append([]byte{}, s.Recv.Key...), N: s.Recv.N}
	skipped := map[uint32][]byte{}
	advance := func(to uint32) error {
		if int(to-trial.N)+len(skipped)+len(s.Skipped) > MaxSkip {
			return fmt.Errorf("%w: too many skipped messages", ErrDecrypt)
		}
		for trial.N < to {
			n := trial.N
			k, nn := trial.step()
			skipped[n] = append(k, nn...)
		}
		return nil
	}
	newEpoch := h != nil && h.Epoch == s.RecvEpoch+1
	switch {
	case h == nil || h.Epoch == s.RecvEpoch:
		if h != nil && (h.Start > m.Seq || (s.RecvPub != nil && !bytes.Equal(h.Pub[:], s.RecvPub))) {
			return 0, nil, ErrDecrypt
		}
	case newEpoch:
		mine := s.Mine[h.Ref]
		if len(mine) != 64 || h.Start < s.Recv.N || h.Start > m.Seq {
			return 0, nil, fmt.Errorf("%w: unknown ratchet epoch", ErrDecrypt)
		}
		if err := advance(h.Start); err != nil {
			return 0, nil, err
		}
		dh, err := x25519(mine[:32], h.Pub[:])
		if err != nil {
			return 0, nil, ErrDecrypt
		}
		next, err := StepKey(trial.Key, dh, s.GrantID, m.Dir, h.Epoch, h.Start, h.Pub[:], mine[32:])
		clear(dh)
		if err != nil {
			return 0, nil, err
		}
		clear(trial.Key)
		trial.Key = next
	default:
		return 0, nil, fmt.Errorf("%w: unknown ratchet epoch", ErrDecrypt)
	}
	if err := advance(m.Seq); err != nil {
		return 0, nil, err
	}
	key, nonce := trial.step()
	pt, err := gcm(key).Open(nil, nonce, ct, aad)
	if err != nil {
		return 0, nil, ErrDecrypt
	}
	ctype, body, err = split(pt)
	if err != nil {
		return 0, nil, err
	}
	clear(s.Recv.Key)
	s.Recv = trial
	if len(skipped) > 0 {
		if s.Skipped == nil {
			s.Skipped = map[uint32][]byte{}
		}
		for k, v := range skipped {
			s.Skipped[k] = v
		}
	}
	if h != nil {
		if newEpoch || s.RecvPub == nil {
			s.RecvEpoch, s.RecvPub = h.Epoch, append([]byte{}, h.Pub[:]...)
		}
		s.learn(h)
	}
	return ctype, body, nil
}

// learn records how far the peer has decrypted this side's epochs.
func (s *Session) learn(h *header) {
	if h.Seen > s.PeerSeen && h.Seen <= s.SendEpoch {
		s.PeerSeen = h.Seen
		s.prune()
	}
}

func split(pt []byte) (byte, []byte, error) {
	if len(pt) < 1 {
		return 0, nil, ErrDecrypt
	}
	ctype, body := pt[0], pt[1:]
	if ctype == TypeText && !utf8.Valid(body) {
		return 0, nil, ErrDecrypt
	}
	if ctype != TypeText && ctype != TypeJSON {
		return 0, nil, ErrDecrypt
	}
	return ctype, body, nil
}
