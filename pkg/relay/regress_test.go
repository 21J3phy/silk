package relay_test

// Regression tests for the October 2026 security review. Each test encodes an
// attack that used to work.

import (
	"bytes"
	"context"
	"fmt"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

func (f *fixture) introAt(from, to *ag, created, expires int64, bits uint8) *wire.Intro {
	in := &wire.Intro{From: from.id, To: to.id, ToSerial: 1, Created: created, Expires: expires, Scope: "chat", Budget: 5, GrantTTL: 3600}
	rand.Read(in.IntroID[:])
	eph, _ := seal.NewKEMKey()
	in.EphPub = eph.Public()
	if _, err := seal.SealIntro(in, to.kem.Public(), "x"); err != nil {
		f.t.Fatal(err)
	}
	in.PoWBits = bits
	in.PoWNonce, _ = pow.Solve(f.ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), bits, 0)
	in.Sign(from.sign)
	return in
}

// Timestamps far in the future used to overflow the skew and lifetime checks,
// creating contact requests that never expired.
func TestRegressTimeOverflow(t *testing.T) {
	f := newFixture(t, relay.Config{})
	x, y, z := f.agent(nil), f.agent(nil), f.agent(nil)
	now := f.clk.now().UnixMilli()
	created := now + 18446744073710
	if _, err := f.r.Submit(f.ctx, f.introAt(x, y, created, created+3600_000, 8).Raw); err == nil {
		t.Fatal("future-dated intro admitted")
	}
	if _, err := f.r.Submit(f.ctx, f.introAt(z, y, now, now+9223372036855, 8).Raw); err == nil {
		t.Fatal("292-year intro admitted")
	}
}

// A granter could allow itself far more messages toward the requester than requested.
func TestRegressGrantTermsBounded(t *testing.T) {
	f := newFixture(t, relay.Config{})
	x, y := f.agent(nil), f.agent(nil)
	in, _, _ := f.intro(x, y, 4)
	if _, err := f.r.Submit(f.ctx, in.Raw); err != nil {
		t.Fatal(err)
	}
	g := f.grant(in, y, y.owner, 600)
	g.BudgetBA = wire.MaxBudget
	if _, err := seal.SealGrant(g, in.EphPub); err != nil {
		t.Fatal(err)
	}
	g.Sign(y.owner)
	_, err := f.r.Submit(f.ctx, g.Raw)
	f.expect(err, "terms_exceed_request")
	long := f.grant(in, y, y.owner, 60)
	long.Expires = long.Created + int64(in.GrantTTL)*1000 + 1
	seal.SealGrant(long, in.EphPub)
	long.Sign(y.owner)
	_, err = f.r.Submit(f.ctx, long.Raw)
	f.expect(err, "terms_exceed_request")
}

// One peer could fill the recipient's whole inbox; now each conversation has its own backlog cap.
func TestRegressPerGrantBacklog(t *testing.T) {
	f := newFixture(t, relay.Config{MaxPendingPerGrant: 2})
	c := f.connect(600)
	for i := 0; i < 2; i++ {
		_, err := f.r.Submit(f.ctx, f.msg(c, "x").Raw)
		f.expect(err, "")
	}
	_, err := f.r.Submit(f.ctx, f.msg(c, "x").Raw)
	f.expect(err, "backlog_full")
}

// Another agent's ticket with the same ID could burn a victim's invite.
func TestRegressTicketScopedToRecipient(t *testing.T) {
	f := newFixture(t, relay.Config{IntroBaseBits: 12})
	victim, attacker, attackerAlt, guest := f.agent(nil), f.agent(nil), f.agent(nil), f.agent(nil)
	ticket := &wire.Ticket{Recipient: victim.id, Expires: f.clk.now().Add(time.Hour).UnixMilli()}
	rand.Read(ticket.TicketID[:])
	ticket.Sign(victim.owner)
	// Attacker signs its own ticket with the victim's ticket ID and redeems it with itself.
	fake := &wire.Ticket{Recipient: attacker.id, TicketID: ticket.TicketID, Expires: ticket.Expires}
	fake.Sign(attacker.owner)
	in := f.introAt(attackerAlt, attacker, f.clk.now().UnixMilli(), f.clk.now().Add(time.Hour).UnixMilli(), 0)
	in.Ticket = fake.Raw
	in.Sign(attackerAlt.sign)
	if _, err := f.r.Submit(f.ctx, in.Raw); err != nil {
		t.Fatal(err)
	}
	// The victim's real invite still works.
	gin := f.introAt(guest, victim, f.clk.now().UnixMilli(), f.clk.now().Add(time.Hour).UnixMilli(), 0)
	gin.Ticket = ticket.Raw
	gin.Sign(guest.sign)
	_, err := f.r.Submit(f.ctx, gin.Raw)
	f.expect(err, "")
}

func serve(t *testing.T, r *relay.Relay, o relay.HTTPOptions) *httptest.Server {
	srv := httptest.NewServer(relay.Handler(r, o))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path, auth, host string) int {
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	if auth != "" {
		req.Header.Set(wire.AuthHeader, auth)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// After a rotation through one instance, another instance kept honoring the old key.
func TestRegressRotationAcrossInstances(t *testing.T) {
	store, err := sqlitekv.Open(filepath.Join(t.TempDir(), "r.db"), sqlitekv.SQLiteOptions{Synchronous: "NORMAL"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	skey, _, _ := ledger.GenerateKey("test.relay")
	signer, _ := ledger.NewSigner(skey)
	cfg := relay.Config{RegisterBits: 4, IntroBaseBits: 4}
	rA, rB := relay.New(store, signer, cfg, nil), relay.New(store, signer, cfg, nil)
	ctx := context.Background()
	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	_, sign1, _ := ed25519.GenerateKey(rand.Reader)
	kem, _ := seal.NewKEMKey()
	now := time.Now()
	c := &wire.Cert{Label: "victim", Serial: 1, Suite: wire.Suite1, KEMPub: kem.Public(), Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli()}
	copy(c.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	copy(c.SignPub[:], sign1.Public().(ed25519.PublicKey))
	c.Sign(owner, sign1)
	n, _ := pow.Solve(ctx, pow.Digest(pow.DomainRegister, c.Raw), 4, 1)
	if _, err := rB.Register(ctx, relay.EncodeRegistration(c.Raw, 4, n)); err != nil {
		t.Fatal(err)
	}
	id := c.ID()
	srvA := serve(t, rA, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1})
	host := srvA.Listener.Addr().String()
	p := "/v2/inbox?after=0"
	if code := get(t, srvA, p, wire.SignAuth(id, sign1, time.Now().UnixMilli(), "GET", host, p), ""); code != 200 {
		t.Fatalf("warm-up read: %d", code)
	}
	_, sign2, _ := ed25519.GenerateKey(rand.Reader)
	c2 := *c
	c2.Serial = 2
	copy(c2.SignPub[:], sign2.Public().(ed25519.PublicKey))
	c2.Sign(owner, sign2)
	if _, err := rB.Register(ctx, relay.EncodeRegistration(c2.Raw, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if code := get(t, srvA, p, wire.SignAuth(id, sign1, time.Now().UnixMilli(), "GET", host, p), ""); code != 401 {
		t.Fatalf("rotated-out key still accepted on another instance: HTTP %d", code)
	}
	if code := get(t, srvA, p, wire.SignAuth(id, sign2, time.Now().UnixMilli(), "GET", host, p), ""); code != 200 {
		t.Fatalf("new key rejected on another instance: HTTP %d", code)
	}
}

// A signed read for one relay host must not work against another.
func TestRegressAuthBoundToHost(t *testing.T) {
	f := newFixture(t, relay.Config{})
	a := f.agent(nil)
	srv := serve(t, f.r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1})
	p := "/v2/inbox?after=0"
	auth := wire.SignAuth(a.id, a.sign, time.Now().UnixMilli(), "GET", "relay-one.example", p)
	if code := get(t, srv, p, auth, "relay-one.example"); code != 200 {
		t.Fatalf("correct host rejected: %d", code)
	}
	if code := get(t, srv, p, auth, "relay-two.example"); code != 401 {
		t.Fatalf("replay against another host accepted: %d", code)
	}
}

// Anyone could ask for another sender's price and learn whether it is trusted.
func TestRegressSenderPriceRequiresAuth(t *testing.T) {
	f := newFixture(t, relay.Config{})
	a, b := f.agent(nil), f.agent(nil)
	srv := serve(t, f.r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1})
	p := "/v2/agents/" + b.id.String() + "?from=" + a.id.String()
	if code := get(t, srv, p, "", ""); code != 401 {
		t.Fatalf("unsigned sender-specific lookup: %d", code)
	}
	host := srv.Listener.Addr().String()
	if code := get(t, srv, p, wire.SignAuth(a.id, a.sign, time.Now().UnixMilli(), "GET", host, p), ""); code != 200 {
		t.Fatalf("signed lookup by the sender: %d", code)
	}
	if code := get(t, srv, p, wire.SignAuth(b.id, b.sign, time.Now().UnixMilli(), "GET", host, p), ""); code != 403 {
		t.Fatalf("lookup signed by someone else: %d", code)
	}
}

// A batch cost one rate-limit token for up to 64 frames.
func TestRegressBatchChargedPerFrame(t *testing.T) {
	f := newFixture(t, relay.Config{})
	srv := serve(t, f.r, relay.HTTPOptions{PostRate: 2, GetRate: -1, RegisterRate: -1}) // burst 8
	var frames [][]byte
	for i := 0; i < 20; i++ {
		frames = append(frames, []byte{2, 99})
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v2/frames/batch", bytesReader(relay.EncodeBatch(frames)))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("20-frame batch within a burst of 8: HTTP %d", resp.StatusCode)
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Behind a self-hosted proxy, clients could pick their own rate-limit bucket
// by sending a header the proxy passes through unchanged.
func TestRegressSpoofedClientIP(t *testing.T) {
	f := newFixture(t, relay.Config{})
	srv := serve(t, f.r, relay.HTTPOptions{TrustProxy: true, PostRate: -1, GetRate: 1, RegisterRate: -1}) // burst 4
	limited := 0
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/v2/info", nil)
		req.Header.Set("X-Vercel-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		req.Header.Set("X-Real-Ip", fmt.Sprintf("10.0.1.%d", i))
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.2.%d, 192.0.2.7", i)) // the proxy's own hop is last
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("spoofed client-IP headers escaped the per-IP limit")
	}
}

// Expired messages no longer pin a conversation's backlog until the sweep runs.
func TestRegressBacklogClearsExpired(t *testing.T) {
	f := newFixture(t, relay.Config{MaxPendingPerGrant: 2})
	c := f.connect(600)
	for i := 0; i < 2; i++ {
		m := &wire.Msg{GrantID: c.grant.GrantID, Created: f.clk.now().UnixMilli(), TTL: 1}
		c.sa.Encrypt(m, seal.TypeText, []byte("short"))
		m.Sign(c.x.sign)
		_, err := f.r.Submit(f.ctx, m.Raw)
		f.expect(err, "")
	}
	f.clk.add(2 * time.Second)
	_, err := f.r.Submit(f.ctx, f.msg(c, "after expiry").Raw)
	f.expect(err, "")
}
