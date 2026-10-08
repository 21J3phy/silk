package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

// Config is the per-home configuration.
type Config struct {
	Relay        string `json:"relay"`
	LedgerKey    string `json:"ledger_key,omitempty"` // pinned on first contact (TOFU)
	Origin       string `json:"origin,omitempty"`
	DefaultAgent string `json:"default_agent,omitempty"`
}

// DefaultHome is $SILK_HOME or ~/.silk.
func DefaultHome() string {
	if h := os.Getenv("SILK_HOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".silk"
	}
	return filepath.Join(home, ".silk")
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeFileAtomic writes via a synced temp file and rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, perm)
}

// ---------------------------------------------------------------------------
// Owner key: the human's root of authority. Optionally passphrase-encrypted.

type ownerFile struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"` // "none" or "pbkdf2-sha256"
	Iter    int    `json:"iter,omitempty"`
	Salt    []byte `json:"salt,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
	Seed    []byte `json:"seed"` // plaintext seed, or AES-256-GCM ciphertext
	Public  []byte `json:"public"`
}

const ownerIter = 600_000

// ErrPassphrase means the owner key needs a (correct) passphrase.
var ErrPassphrase = errors.New("owner key passphrase required or incorrect (set SILK_PASSPHRASE or enter it when prompted)")

func passKey(pass string, salt []byte, iter int) []byte {
	k, err := pbkdf2.Key(sha256.New, pass, salt, iter, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func saveOwner(path string, priv ed25519.PrivateKey, passphrase string) error {
	f := ownerFile{Version: 1, KDF: "none", Seed: priv.Seed(), Public: priv.Public().(ed25519.PublicKey)}
	if passphrase != "" {
		f.KDF, f.Iter = "pbkdf2-sha256", ownerIter
		f.Salt = make([]byte, 16)
		f.Nonce = make([]byte, 12)
		rand.Read(f.Salt)
		rand.Read(f.Nonce)
		block, _ := aes.NewCipher(passKey(passphrase, f.Salt, f.Iter))
		g, _ := cipher.NewGCM(block)
		f.Seed = g.Seal(nil, f.Nonce, priv.Seed(), f.Public)
	}
	return writeJSON(path, f, 0o600)
}

func ownerPublic(path string) (ed25519.PublicKey, error) {
	var f ownerFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	if len(f.Public) != ed25519.PublicKeySize {
		return nil, errors.New("owner key file is corrupt")
	}
	return ed25519.PublicKey(f.Public), nil
}

func loadOwner(path string, passphrase func() (string, error)) (ed25519.PrivateKey, error) {
	var f ownerFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	seed := f.Seed
	if f.KDF == "pbkdf2-sha256" {
		pass, err := passphrase()
		if err != nil {
			return nil, err
		}
		if pass == "" {
			return nil, ErrPassphrase
		}
		block, _ := aes.NewCipher(passKey(pass, f.Salt, f.Iter))
		g, _ := cipher.NewGCM(block)
		seed, err = g.Open(nil, f.Nonce, f.Seed, f.Public)
		if err != nil {
			return nil, ErrPassphrase
		}
	} else if f.KDF != "none" {
		return nil, fmt.Errorf("unsupported owner key format %q", f.KDF)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("owner key file is corrupt")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(f.Public)) {
		return nil, errors.New("owner key file is corrupt")
	}
	return priv, nil
}

// ---------------------------------------------------------------------------
// Agent keys

type keyFile struct {
	Serial   uint32             `json:"serial"`
	SignSeed []byte             `json:"sign_seed"`
	KEM      []byte             `json:"kem"`
	Legacy   map[uint32][]byte  `json:"previous_kem,omitempty"` // older format, read only
	Previous map[uint32]oldKey  `json:"previous,omitempty"`     // serial -> retired KEM key
}

type oldKey struct {
	KEM     []byte `json:"kem"`
	Retired int64  `json:"retired_ms"`
}

type agentKeys struct {
	serial  uint32
	sign    ed25519.PrivateKey
	kem     *seal.KEMKey
	prev    map[uint32]*seal.KEMKey
	retired map[uint32]int64
}

// retire keeps a replaced encryption key only as long as a contact request
// sent to it can still be pending, then forgets it.
func (k *agentKeys) retire(serial uint32, kem *seal.KEMKey, now int64) {
	k.prev[serial] = kem
	k.retired[serial] = now
	for s, t := range k.retired {
		if now-t > (wire.MaxIntroTTL + 24*time.Hour).Milliseconds() {
			delete(k.prev, s)
			delete(k.retired, s)
		}
	}
}

func loadKeys(path string) (*agentKeys, error) {
	var f keyFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	if len(f.SignSeed) != ed25519.SeedSize {
		return nil, errors.New("agent key file is corrupt")
	}
	k := &agentKeys{serial: f.Serial, sign: ed25519.NewKeyFromSeed(f.SignSeed), prev: map[uint32]*seal.KEMKey{}, retired: map[uint32]int64{}}
	var err error
	if k.kem, err = seal.LoadKEMKey(f.KEM); err != nil {
		return nil, fmt.Errorf("agent kem key: %w", err)
	}
	for s, b := range f.Legacy {
		if pk, err := seal.LoadKEMKey(b); err == nil {
			k.prev[s], k.retired[s] = pk, time.Now().UnixMilli()
		}
	}
	for s, o := range f.Previous {
		if pk, err := seal.LoadKEMKey(o.KEM); err == nil {
			k.prev[s], k.retired[s] = pk, o.Retired
		}
	}
	return k, nil
}

func (k *agentKeys) save(path string) error {
	f := keyFile{Serial: k.serial, SignSeed: k.sign.Seed(), KEM: k.kem.Bytes()}
	if len(k.prev) > 0 {
		f.Previous = map[uint32]oldKey{}
		for s, pk := range k.prev {
			f.Previous[s] = oldKey{KEM: pk.Bytes(), Retired: k.retired[s]}
		}
	}
	return writeJSON(path, f, 0o600)
}

func (k *agentKeys) kemFor(serial uint32) *seal.KEMKey {
	if serial == k.serial {
		return k.kem
	}
	return k.prev[serial]
}

// ---------------------------------------------------------------------------
// Agent state (protected by the agent lock; re-read for every operation).

// Message is a decrypted inbound message.
type Message struct {
	ID         string `json:"id"`
	Grant      string `json:"grant"`
	From       string `json:"from"`
	FromHandle string `json:"from_handle,omitempty"`
	Seq        uint32 `json:"seq"`
	SentMs     int64  `json:"sent_ms"`
	ReceivedMs int64  `json:"received_ms"`
	Type       string `json:"type"`
	Body       string `json:"body"`
	ReplyTo    string `json:"reply_to,omitempty"`
	LedgerIdx  int64  `json:"ledger_index"`
	Acked      string `json:"acked,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Sent tracks an outbound message until it is acknowledged.
type Sent struct {
	ID         string `json:"id"`
	Grant      string `json:"grant"`
	To         string `json:"to"`
	Seq        uint32 `json:"seq"`
	SentMs     int64  `json:"sent_ms"`
	LedgerIdx  int64  `json:"ledger_index"`
	Frame      []byte `json:"frame,omitempty"` // kept until the relay accepts it (outbox)
	Status     string `json:"status"`          // "queued", "accepted", outcome name, or "failed: code"
	AckIdx     int64  `json:"ack_ledger_index,omitempty"`
	Preview    string `json:"preview,omitempty"`
	Hash       []byte `json:"hash,omitempty"` // SHA-256 of the frame, for ledger audits
}

// GrantInfo is a conversation the agent can use.
type GrantInfo struct {
	ID         string `json:"id"`
	Peer       string `json:"peer"`
	PeerHandle string `json:"peer_handle,omitempty"`
	Initiator  bool   `json:"initiator"`
	Scope      string `json:"scope"`
	SendBudget uint32 `json:"send_budget"`
	RecvBudget uint32 `json:"recv_budget"`
	Received   uint32 `json:"received"`
	Rate       uint16 `json:"rate_per_minute"`
	ExpiresMs  int64  `json:"expires_ms"`
	Status     string `json:"status"`
	LedgerIdx  int64  `json:"ledger_index"`
	// KeyTurns counts fresh key exchanges in this conversation (both
	// directions); each one locks out anyone holding older session keys.
	KeyTurns uint32 `json:"key_turns,omitempty"`
}

// OutIntro is a contact request this agent sent.
type OutIntro struct {
	ID        string `json:"id"`
	To        string `json:"to"`
	ToHandle  string `json:"to_handle,omitempty"`
	Scope     string `json:"scope"`
	Note      string `json:"note"`
	EphKEM    []byte `json:"eph_kem,omitempty"`
	K1        []byte `json:"k1,omitempty"`
	IntroHash []byte `json:"intro_hash"`
	ExpiresMs int64  `json:"expires_ms"`
	Status    string `json:"status"`
	LedgerIdx int64  `json:"ledger_index"`
	PoWBits   uint8  `json:"pow_bits"`
	PoWMs     int64  `json:"pow_ms"`
	Budget    uint32 `json:"budget,omitempty"`
	GrantTTL  uint32 `json:"grant_ttl_s,omitempty"`
	Frame     []byte `json:"frame,omitempty"` // kept until the relay confirms it
}

// InIntro is a contact request awaiting the owner's decision.
type InIntro struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	FromHandle string `json:"from_handle,omitempty"`
	Scope      string `json:"scope"`
	Note       string `json:"note"`
	Budget     uint32 `json:"budget"`
	GrantTTL   uint32 `json:"grant_ttl_s"`
	ExpiresMs  int64  `json:"expires_ms"`
	Frame      []byte `json:"frame"`
	LedgerIdx  int64  `json:"ledger_index"`
	PoWBits    uint8  `json:"pow_bits"`
	Status     string `json:"status"`
	GrantFrame []byte `json:"grant_frame,omitempty"` // an approval awaiting relay confirmation
}

// Contact caches a verified peer certificate.
type Contact struct {
	Handle    string `json:"handle,omitempty"`
	Cert      []byte `json:"cert"`
	FetchedMs int64  `json:"fetched_ms"`
}

type agentState struct {
	Cursor     uint64                   `json:"cursor"`
	Checkpoint []byte                   `json:"checkpoint,omitempty"`
	Sessions   map[string]*seal.Session `json:"sessions"`
	Grants     map[string]*GrantInfo    `json:"grants"`
	OutIntros  map[string]*OutIntro     `json:"out_intros"`
	InIntros   map[string]*InIntro      `json:"in_intros"`
	Inbox      []*Message               `json:"inbox"`
	Sent       []*Sent                  `json:"sent"`
	Contacts   map[string]*Contact      `json:"contacts"`
	Handles    map[string]string        `json:"handles,omitempty"` // @handle -> agent ID pinned on first use
}

func newState() *agentState {
	return &agentState{Sessions: map[string]*seal.Session{}, Grants: map[string]*GrantInfo{}, OutIntros: map[string]*OutIntro{},
		InIntros: map[string]*InIntro{}, Contacts: map[string]*Contact{}}
}

const (
	maxInbox = 1000
	maxSent  = 1000
	keepMs   = int64(7 * 24 * time.Hour / time.Millisecond)
)

// trim bounds local history: keeps unacknowledged items and the newest records.
func (s *agentState) trim(now int64) {
	if len(s.Inbox) > maxInbox {
		var keep []*Message
		drop := len(s.Inbox) - maxInbox
		for _, m := range s.Inbox {
			if drop > 0 && (m.Acked != "" || m.Error != "") {
				drop--
				continue
			}
			keep = append(keep, m)
		}
		s.Inbox = keep
	}
	if len(s.Sent) > maxSent {
		var keep []*Sent
		drop := len(s.Sent) - maxSent
		for _, m := range s.Sent {
			if drop > 0 && m.Frame == nil && now-m.SentMs > 0 {
				drop--
				continue
			}
			keep = append(keep, m)
		}
		s.Sent = keep
	}
	for id, in := range s.OutIntros {
		if in.Status != "pending" && now-in.ExpiresMs > keepMs {
			delete(s.OutIntros, id)
		}
	}
	for id, in := range s.InIntros {
		if in.Status != "pending" && now-in.ExpiresMs > keepMs {
			delete(s.InIntros, id)
		}
	}
}
