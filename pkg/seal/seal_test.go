package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"testing"

	"github.com/21J3phy/silk/pkg/wire"
)

func pair(t testing.TB) (a, b *Session, grant wire.ID) {
	t.Helper()
	rand.Read(grant[:])
	root := make([]byte, 32)
	rand.Read(root)
	a, err := NewSession(grant, root, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err = NewSession(grant, root, false)
	if err != nil {
		t.Fatal(err)
	}
	return a, b, grant
}

func enc(t testing.TB, s *Session, grant wire.ID, body string) *wire.Msg {
	t.Helper()
	m := &wire.Msg{GrantID: grant, Created: 1791400001000, TTL: 3600}
	if err := s.Encrypt(m, TypeText, []byte(body)); err != nil {
		t.Fatal(err)
	}
	return m
}

func clone(t testing.TB, s *Session) *Session {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var c Session
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func open(t testing.TB, s *Session, m *wire.Msg, want string) {
	t.Helper()
	_, body, err := s.Decrypt(m)
	if err != nil {
		t.Fatalf("decrypt seq %d: %v", m.Seq, err)
	}
	if string(body) != want {
		t.Fatalf("got %q, want %q", body, want)
	}
}

// legacyEncrypt is the 2.0 message format: no ratchet header, header-only AAD.
func legacyEncrypt(s *Session, m *wire.Msg, body string) {
	m.Dir, m.Seq = s.SendDir, s.Send.N
	key, nonce := s.Send.step()
	m.CT = gcm(key).Seal(nil, nonce, append([]byte{TypeText}, body...), m.Header())
}

func TestFramesSurviveTheWire(t *testing.T) {
	a, b, grant := pair(t)
	_, agent, _ := ed25519.GenerateKey(rand.Reader)
	for i := range 4 {
		from, to := a, b
		if i%2 == 1 {
			from, to = b, a
		}
		m := enc(t, from, grant, "hello")
		if got, want := len(m.CT), wire.RatchetHeaderLen+1+5+wire.AEADTagLen; got != want {
			t.Fatalf("ciphertext is %d bytes, want %d", got, want)
		}
		m.Sign(agent)
		d, err := wire.DecodeMsg(m.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Ratchet {
			t.Fatal("ratchet flag lost in encoding")
		}
		open(t, to, d, "hello")
	}
	if a.SendEpoch == 0 || b.SendEpoch == 0 {
		t.Fatalf("no ratchet step after two round trips (epochs %d, %d)", a.SendEpoch, b.SendEpoch)
	}
}

// Random interleaving: both sides send while messages are delivered in random
// order. Every message must decrypt exactly once, and keys must keep turning.
func TestConversationWithReordering(t *testing.T) {
	for seed := range uint64(20) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := mrand.New(mrand.NewPCG(seed, 7))
			a, b, grant := pair(t)
			type flight struct {
				m    *wire.Msg
				to   *Session
				body string
			}
			var inflight []flight
			sent, delivered := 0, 0
			for sent < 600 || len(inflight) > 0 {
				if sent < 600 && (len(inflight) == 0 || (len(inflight) < 40 && r.IntN(2) == 0)) {
					from, to := a, b
					if r.IntN(2) == 0 {
						from, to = b, a
					}
					body := fmt.Sprintf("m%d", sent)
					inflight = append(inflight, flight{enc(t, from, grant, body), to, body})
					sent++
					continue
				}
				// Mostly in order, sometimes far out of order.
				j := 0
				if r.IntN(4) == 0 {
					j = r.IntN(len(inflight))
				}
				f := inflight[j]
				inflight = append(inflight[:j], inflight[j+1:]...)
				open(t, f.to, f.m, f.body)
				if _, _, err := f.to.Decrypt(f.m); err == nil {
					t.Fatal("replayed message decrypted twice")
				}
				delivered++
			}
			if delivered != 600 {
				t.Fatalf("delivered %d of 600", delivered)
			}
			if a.SendEpoch < 5 || b.SendEpoch < 5 {
				t.Fatalf("keys barely turned: epochs %d and %d", a.SendEpoch, b.SendEpoch)
			}
			if len(a.Mine) > 2 || len(b.Mine) > 2 {
				t.Fatalf("old ratchet keys kept: %d and %d", len(a.Mine), len(b.Mine))
			}
		})
	}
}

// An attacker who copies A's whole session can read along at first, but once
// both sides have exchanged fresh keys, every later message is closed to it.
func TestHealsAfterSessionTheft(t *testing.T) {
	a, b, grant := pair(t)
	turn := func(from, to *Session, body string) *wire.Msg {
		m := enc(t, from, grant, body)
		open(t, to, m, body)
		return m
	}
	for i := range 6 {
		turn(a, b, fmt.Sprint("warmup a", i))
		turn(b, a, fmt.Sprint("warmup b", i))
	}

	// The theft happens mid-turn: A has just sent and will send again before B replies.
	turn(a, b, "before the theft")
	stolen := clone(t, a) // everything A's device holds
	// The attacker reads A->B with A's send chain and B->A with A's receive state.
	readAB := &Session{GrantID: stolen.GrantID, SendDir: wire.DirBA, Recv: Chain{Key: append([]byte{}, stolen.Send.Key...), N: stolen.Send.N},
		RecvEpoch: stolen.SendEpoch, Mine: map[uint32][]byte{}}
	readBA := stolen

	var readable []bool
	read := func(r *Session, m *wire.Msg) {
		_, _, err := r.Decrypt(m)
		readable = append(readable, err == nil)
	}
	read(readAB, turn(a, b, "secret a, same turn"))
	for i := range 10 {
		read(readBA, turn(b, a, fmt.Sprint("secret b", i)))
		read(readAB, turn(a, b, fmt.Sprint("secret a", i)))
	}
	healedAt := len(readable)
	for i := len(readable) - 1; i >= 0 && !readable[i]; i-- {
		healedAt = i
	}
	if healedAt == 0 {
		t.Fatal("test is not exercising a real compromise: nothing readable after the theft")
	}
	if healedAt > 3 {
		t.Fatalf("attacker still reads messages %v", readable)
	}
	t.Logf("attacker read %d messages after the theft, none from message %d on (of %d)", healedAt, healedAt+1, len(readable))
}

func TestTamperingLeavesStateUnchanged(t *testing.T) {
	a, b, grant := pair(t)
	open(t, b, enc(t, a, grant, "one"), "one")
	open(t, a, enc(t, b, grant, "two"), "two")
	m := enc(t, a, grant, "three") // starts a new epoch
	before, _ := json.Marshal(b)
	for _, i := range []int{1, 5, 9, 13, 20, wire.RatchetHeaderLen + 2} {
		bad := *m
		bad.CT = append([]byte{}, m.CT...)
		bad.CT[i] ^= 1
		if _, _, err := b.Decrypt(&bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("byte %d: tampered message accepted (%v)", i, err)
		}
	}
	if after, _ := json.Marshal(b); !bytes.Equal(before, after) {
		t.Fatal("rejected message changed the session")
	}
	open(t, b, m, "three")
}

func TestMessagesFrom20ClientsStillOpen(t *testing.T) {
	a, b, grant := pair(t)
	// A session stored by a 2.0 client has none of the ratchet fields.
	old := &Session{GrantID: a.GrantID, SendDir: a.SendDir, Send: a.Send, Recv: a.Recv}
	raw, _ := json.Marshal(old)
	var a20 Session
	json.Unmarshal(raw, &a20)
	for i := range 3 {
		m := &wire.Msg{GrantID: grant, Created: 1791400001000, TTL: 3600}
		legacyEncrypt(&a20, m, fmt.Sprint("legacy", i))
		open(t, b, m, fmt.Sprint("legacy", i))
	}
	// After upgrading, the same session continues and starts turning keys.
	for i := range 4 {
		open(t, b, enc(t, &a20, grant, fmt.Sprint("new a", i)), fmt.Sprint("new a", i))
		open(t, &a20, enc(t, b, grant, fmt.Sprint("new b", i)), fmt.Sprint("new b", i))
	}
	if a20.SendEpoch == 0 || b.SendEpoch == 0 {
		t.Fatal("upgraded session never stepped")
	}
}

func TestSkipLimit(t *testing.T) {
	a, b, grant := pair(t)
	var last *wire.Msg
	for range MaxSkip + 2 {
		last = enc(t, a, grant, "x")
	}
	if _, _, err := b.Decrypt(last); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("message beyond the skip window accepted: %v", err)
	}
}

func BenchmarkMessageOneWay(b *testing.B) {
	x, y, grant := pair(b)
	body := bytes.Repeat([]byte("a"), 200)
	for b.Loop() {
		m := &wire.Msg{GrantID: grant, Created: 1791400001000, TTL: 3600}
		x.Encrypt(m, TypeText, body)
		if _, _, err := y.Decrypt(m); err != nil {
			b.Fatal(err)
		}
	}
}

// Alternating turns: every message starts a new epoch (worst case).
func BenchmarkMessageAlternating(b *testing.B) {
	x, y, grant := pair(b)
	body := bytes.Repeat([]byte("a"), 200)
	for b.Loop() {
		m := &wire.Msg{GrantID: grant, Created: 1791400001000, TTL: 3600}
		x.Encrypt(m, TypeText, body)
		if _, _, err := y.Decrypt(m); err != nil {
			b.Fatal(err)
		}
		x, y = y, x
	}
}

// Arbitrary ciphertexts must never panic or change the session.
func FuzzDecrypt(f *testing.F) {
	a, b, grant := pair(f)
	open(f, b, enc(f, a, grant, "one"), "one")
	open(f, a, enc(f, b, grant, "two"), "two")
	for _, body := range []string{"three", "four"} {
		m := enc(f, a, grant, body)
		f.Add(m.CT, m.Seq, true)
	}
	f.Add(make([]byte, 20), uint32(0), false)
	before, _ := json.Marshal(b)
	f.Fuzz(func(t *testing.T, ct []byte, seq uint32, ratchet bool) {
		s := clone(t, b)
		m := &wire.Msg{GrantID: grant, Dir: wire.DirAB, Seq: seq, Created: 1791400001000, TTL: 3600, Ratchet: ratchet, CT: ct}
		if _, _, err := s.Decrypt(m); err == nil {
			return // a genuine seed message
		}
		if after, _ := json.Marshal(s); !bytes.Equal(before, after) {
			t.Fatal("failed decrypt changed the session")
		}
	})
}
