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
// used once and deleted, so per-message cost is a few HMACs plus AES-GCM and
// per-message overhead is 16 bytes of tag (no per-message public keys).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
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

func introInfo(in *wire.Intro) []byte  { return append([]byte("silk/v2 intro\x00"), in.Header()...) }
func grantInfo(g *wire.Grant) []byte   { return append([]byte("silk/v2 grant\x00"), g.Header()...) }

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
// chain, and a bounded set of skipped (out-of-order) receive keys.
type Session struct {
	GrantID string            `json:"grant"`
	SendDir uint8             `json:"dir"`
	Send    Chain             `json:"send"`
	Recv    Chain             `json:"recv"`
	Skipped map[uint32][]byte `json:"skipped,omitempty"` // seq -> key||nonce
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
	return s, nil
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

// Encrypt assigns the next sequence number to m, sets its direction, and
// fills m.CT. The caller must persist the session before transmitting.
func (s *Session) Encrypt(m *wire.Msg, ctype byte, body []byte) error {
	if len(body) > wire.MaxPlaintext {
		return fmt.Errorf("message body exceeds %d bytes", wire.MaxPlaintext)
	}
	if ctype == TypeText && !utf8.Valid(body) {
		return errors.New("text must be valid UTF-8")
	}
	m.Dir = s.SendDir
	m.Seq = s.Send.N
	key, nonce := s.Send.step()
	pt := make([]byte, 0, 1+len(body))
	pt = append(append(pt, ctype), body...)
	m.CT = gcm(key).Seal(nil, nonce, pt, m.Header())
	clear(key)
	return nil
}

// Decrypt opens a message in the receive direction. Each key works once.
func (s *Session) Decrypt(m *wire.Msg) (ctype byte, body []byte, err error) {
	if m.Dir == s.SendDir {
		return 0, nil, fmt.Errorf("%w: message is in this session's send direction", ErrDecrypt)
	}
	var key, nonce []byte
	switch {
	case m.Seq < s.Recv.N:
		kn, ok := s.Skipped[m.Seq]
		if !ok {
			return 0, nil, fmt.Errorf("%w: key for seq %d already used", ErrDecrypt, m.Seq)
		}
		key, nonce = kn[:32], kn[32:]
		pt, err := gcm(key).Open(nil, nonce, m.CT, m.Header())
		if err != nil {
			return 0, nil, ErrDecrypt
		}
		delete(s.Skipped, m.Seq)
		return split(pt)
	default:
		if m.Seq-s.Recv.N > MaxSkip || len(s.Skipped)+int(m.Seq-s.Recv.N) > MaxSkip {
			return 0, nil, fmt.Errorf("%w: too many skipped messages", ErrDecrypt)
		}
		// Derive on a copy so a forged message cannot advance the real chain.
		trial := Chain{Key: append([]byte{}, s.Recv.Key...), N: s.Recv.N}
		var skipped map[uint32][]byte
		for trial.N < m.Seq {
			n := trial.N
			k, nn := trial.step()
			if skipped == nil {
				skipped = map[uint32][]byte{}
			}
			skipped[n] = append(k, nn...)
		}
		key, nonce = trial.step()
		pt, err := gcm(key).Open(nil, nonce, m.CT, m.Header())
		if err != nil {
			return 0, nil, ErrDecrypt
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
		return split(pt)
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
