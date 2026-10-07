package wire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// Every decoder must reject or round-trip arbitrary input without panicking,
// and anything it accepts must re-encode to exactly the same bytes
// (one canonical encoding per object).
func seedFrames(f *testing.F) {
	_, k, _ := ed25519.GenerateKey(nil)
	var id ID
	id[0] = 1
	m := &Msg{GrantID: id, Seq: 3, Created: 1791400000000, TTL: 60, CT: bytes.Repeat([]byte{7}, 40)}
	m.Sign(k)
	f.Add(m.Raw)
	a := &Ack{MsgID: id, GrantID: id, Outcome: AckHandled, Created: 1791400000000}
	a.Sign(k)
	f.Add(a.Raw)
	v := &Revoke{GrantID: id, By: id, Created: 1791400000000}
	v.Sign(k)
	f.Add(v.Raw)
	t := &Ticket{Recipient: id, TicketID: id, Expires: 1791400000000}
	t.Sign(k)
	f.Add(t.Raw)
	p := &Policy{Agent: id, Serial: 1, Created: 1791400000000, Flags: PolicyTrustSameOwner, Agents: []ID{id}}
	p.Sign(k)
	f.Add(p.Raw)
	f.Add([]byte{2, 5})
	f.Add([]byte{})
}

func FuzzDecodeMsg(f *testing.F) {
	seedFrames(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeMsg(b)
		if err != nil {
			return
		}
		re := (&Msg{GrantID: m.GrantID, Dir: m.Dir, Seq: m.Seq, Created: m.Created, TTL: m.TTL, ReplyTo: m.ReplyTo, CT: m.CT}).body()
		if !bytes.Equal(append(re, m.Sig[:]...), b) {
			t.Fatalf("non-canonical message accepted")
		}
	})
}

func FuzzDecodeAny(f *testing.F) {
	seedFrames(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeCert(b)
		DecodeIntro(b)
		DecodeGrant(b)
		DecodeDecline(b)
		DecodeAck(b)
		DecodeRevoke(b)
		DecodeRelease(b)
		if p, err := DecodePolicy(b); err == nil && !bytes.Equal(append(p.body(), p.Sig[:]...), b) {
			t.Fatalf("non-canonical policy accepted")
		}
		if tk, err := DecodeTicket(b); err == nil && !bytes.Equal(append(tk.body(), tk.Sig[:]...), b) {
			t.Fatalf("non-canonical ticket accepted")
		}
	})
}

func FuzzParseAuth(f *testing.F) {
	f.Add("v2h aaaaaaaaaaaaaaaaaaaaaaaaaa 1791400000000 " + string(bytes.Repeat([]byte{'A'}, 86)))
	f.Fuzz(func(t *testing.T, s string) { ParseAuth(s) })
}
