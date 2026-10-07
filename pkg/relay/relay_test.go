package relay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/21J3phy/silk/pkg/kv/pgkv"

	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	t     *testing.T
	r     *relay.Relay
	clk   *clock
	vkey  string
	ctx   context.Context
	count int
}

func newFixture(t *testing.T, cfg relay.Config) *fixture {
	store, err := sqlitekv.Open(filepath.Join(t.TempDir(), "r.db"), sqlitekv.SQLiteOptions{Synchronous: "NORMAL"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	skey, vkey, _ := ledger.GenerateKey("test.relay")
	signer, _ := ledger.NewSigner(skey)
	if cfg.RegisterBits == 0 {
		cfg.RegisterBits = 4
	}
	if cfg.IntroBaseBits == 0 {
		cfg.IntroBaseBits = 4
	}
	if cfg.PolicyEvery == 0 {
		cfg.PolicyEvery = time.Millisecond
	}
	clk := &clock{t: time.Now()}
	return &fixture{t: t, r: relay.New(store, signer, cfg, clk.now), clk: clk, vkey: vkey, ctx: context.Background()}
}

type ag struct {
	owner, sign ed25519.PrivateKey
	kem         *seal.KEMKey
	cert        *wire.Cert
	id          wire.ID
}

func (f *fixture) agent(owner ed25519.PrivateKey) *ag {
	f.t.Helper()
	if owner == nil {
		_, owner, _ = ed25519.GenerateKey(rand.Reader)
	}
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	kem, _ := seal.NewKEMKey()
	f.count++
	now := f.clk.now()
	c := &wire.Cert{Label: "a" + string(rune('a'+f.count%26)) + string(rune('a'+f.count/26)), Serial: 1, Suite: wire.Suite1, KEMPub: kem.Public(),
		Created: now.UnixMilli(), Expires: now.Add(24 * time.Hour).UnixMilli(), Flags: wire.CertAcceptsIntros}
	copy(c.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	copy(c.SignPub[:], sign.Public().(ed25519.PublicKey))
	c.Sign(owner, sign)
	bits := f.r.Config().RegisterBits
	n, _ := pow.Solve(f.ctx, pow.Digest(pow.DomainRegister, c.Raw), bits, 1)
	if _, err := f.r.Register(f.ctx, relay.EncodeRegistration(c.Raw, bits, n)); err != nil {
		f.t.Fatal(err)
	}
	return &ag{owner, sign, kem, c, c.ID()}
}

func (f *fixture) intro(x, y *ag, bits uint8) (*wire.Intro, *seal.KEMKey, []byte) {
	now := f.clk.now()
	in := &wire.Intro{From: x.id, To: y.id, ToSerial: 1, Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(), Scope: "chat", Budget: 5, GrantTTL: 3600}
	rand.Read(in.IntroID[:])
	eph, _ := seal.NewKEMKey()
	in.EphPub = eph.Public()
	k1, err := seal.SealIntro(in, y.kem.Public(), "hello")
	if err != nil {
		f.t.Fatal(err)
	}
	in.PoWBits = bits
	in.PoWNonce, _ = pow.Solve(f.ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), bits, 0)
	in.Sign(x.sign)
	return in, eph, k1
}

func (f *fixture) grant(in *wire.Intro, y *ag, owner ed25519.PrivateKey, rate uint16) *wire.Grant {
	now := f.clk.now()
	g := &wire.Grant{GrantID: in.IntroID, IntroHash: wire.Hash(in.Raw), From: in.From, To: in.To, Created: now.UnixMilli(),
		Expires: now.Add(time.Hour).UnixMilli(), BudgetAB: in.Budget, BudgetBA: in.Budget, Rate: rate}
	copy(g.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	if _, err := seal.SealGrant(g, in.EphPub); err != nil {
		f.t.Fatal(err)
	}
	g.Sign(owner)
	return g
}

func code(err error) string {
	var e *relay.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

func (f *fixture) expect(err error, want string) {
	f.t.Helper()
	if got := code(err); got != want {
		f.t.Fatalf("got %q (%v), want %q", got, err, want)
	}
}

type conv struct {
	x, y  *ag
	grant *wire.Grant
	sa    *seal.Session
	sb    *seal.Session
}

func (f *fixture) connect(rate uint16) *conv {
	x, y := f.agent(nil), f.agent(nil)
	in, eph, k1 := f.intro(x, y, 4)
	_, err := f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	g := f.grant(in, y, y.owner, rate)
	_, err = f.r.Submit(f.ctx, g.Raw)
	f.expect(err, "")
	_, k1b, _ := seal.OpenIntro(in, y.kem)
	k2b, _ := seal.SealGrant(&wire.Grant{}, eph.Public()) // unused; real k2 below
	_ = k2b
	k2, err := seal.OpenGrant(g, eph)
	if err != nil {
		f.t.Fatal(err)
	}
	root, _ := seal.Root(k1, k2, g.IntroHash, g)
	rootB, _ := seal.Root(k1b, k2, g.IntroHash, g)
	sa, _ := seal.NewSession(g.GrantID, root, true)
	sb, _ := seal.NewSession(g.GrantID, rootB, false)
	return &conv{x, y, g, sa, sb}
}

func (f *fixture) msg(c *conv, body string) *wire.Msg {
	m := &wire.Msg{GrantID: c.grant.GrantID, Created: f.clk.now().UnixMilli(), TTL: 600}
	if err := c.sa.Encrypt(m, seal.TypeText, []byte(body)); err != nil {
		f.t.Fatal(err)
	}
	m.Sign(c.x.sign)
	return m
}

func TestMessageAdmission(t *testing.T) {
	f := newFixture(t, relay.Config{})
	c := f.connect(600)
	m := f.msg(c, "one")
	r1, err := f.r.Submit(f.ctx, m.Raw)
	f.expect(err, "")
	// Exact replay is idempotent and returns the original ledger index.
	r2, err := f.r.Submit(f.ctx, m.Raw)
	f.expect(err, "")
	if !r2.Duplicate || r2.LedgerIdx != r1.LedgerIdx {
		t.Fatalf("replay not idempotent: %+v vs %+v", r2, r1)
	}
	// Same sequence number, different content: rejected.
	m2 := &wire.Msg{GrantID: c.grant.GrantID, Created: f.clk.now().UnixMilli() + 1, TTL: 600, Seq: m.Seq, CT: append([]byte{}, m.CT...)}
	m2.Sign(c.x.sign)
	_, err = f.r.Submit(f.ctx, m2.Raw)
	f.expect(err, "seq_reused")
	// Tampered ciphertext breaks the signature.
	bad := append([]byte{}, f.msg(c, "two").Raw...)
	bad[len(bad)-70] ^= 1
	_, err = f.r.Submit(f.ctx, bad)
	f.expect(err, "invalid_signature")
	// A third party cannot inject into the conversation.
	eve := f.agent(nil)
	m3 := f.msg(c, "three")
	m3.Sign(eve.sign)
	_, err = f.r.Submit(f.ctx, m3.Raw)
	f.expect(err, "invalid_signature")
	// Recipient cannot send in the sender's direction.
	m4 := f.msg(c, "four")
	m4.Sign(c.y.sign)
	_, err = f.r.Submit(f.ctx, m4.Raw)
	f.expect(err, "invalid_signature")
	// Budget is 5 per direction: seqs 0..4. We used 0 (accepted), 1-3 rejected locally above but consumed seqs.
	for {
		m := f.msg(c, "fill")
		_, err := f.r.Submit(f.ctx, m.Raw)
		if code(err) == "budget_exhausted" {
			break
		}
		f.expect(err, "")
	}
	// Clock skew is rejected.
	c2 := f.connect(600)
	mm := &wire.Msg{GrantID: c2.grant.GrantID, Created: f.clk.now().Add(10 * time.Minute).UnixMilli(), TTL: 600}
	c2.sa.Encrypt(mm, seal.TypeText, []byte("future"))
	mm.Sign(c2.x.sign)
	_, err = f.r.Submit(f.ctx, mm.Raw)
	f.expect(err, "clock_skew")
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, relay.Config{})
	x, y := f.agent(nil), f.agent(nil)
	now := f.clk.now()
	in := &wire.Intro{From: x.id, To: y.id, ToSerial: 1, Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(), Scope: "chat", Budget: 100, GrantTTL: 3600}
	rand.Read(in.IntroID[:])
	eph, _ := seal.NewKEMKey()
	in.EphPub = eph.Public()
	k1, _ := seal.SealIntro(in, y.kem.Public(), "")
	in.PoWBits = 4
	in.PoWNonce, _ = pow.Solve(f.ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), 4, 1)
	in.Sign(x.sign)
	_, err := f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	g := f.grant(in, y, y.owner, 3)
	_, err = f.r.Submit(f.ctx, g.Raw)
	f.expect(err, "")
	k2, _ := seal.OpenGrant(g, eph)
	root, _ := seal.Root(k1, k2, g.IntroHash, g)
	sa, _ := seal.NewSession(g.GrantID, root, true)
	c := &conv{x: x, y: y, grant: g, sa: sa}
	for i := 0; i < 3; i++ {
		_, err := f.r.Submit(f.ctx, f.msg(c, "x").Raw)
		f.expect(err, "")
	}
	_, err = f.r.Submit(f.ctx, f.msg(c, "x").Raw)
	f.expect(err, "rate_limited")
	f.clk.add(61 * time.Second)
	_, err = f.r.Submit(f.ctx, f.msg(c, "x").Raw)
	f.expect(err, "")
}

func TestConsentRules(t *testing.T) {
	f := newFixture(t, relay.Config{IntroBaseBits: 8})
	x, y := f.agent(nil), f.agent(nil)
	// Bad or missing postage.
	in, _, _ := f.intro(x, y, 4)
	_, err := f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "pow_required")
	in, _, _ = f.intro(x, y, 8)
	in.PoWNonce++
	in.Sign(x.sign)
	if pow.Check(pow.Digest(pow.DomainIntro, in.PoWPrefix()), 8, in.PoWNonce) {
		t.Skip("nonce+1 happened to be valid")
	}
	_, err = f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "pow_required")
	in, _, _ = f.intro(x, y, 8)
	_, err = f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	// A second pending request to the same agent is refused.
	in2, _, _ := f.intro(x, y, 8)
	_, err = f.r.Submit(f.ctx, in2.Raw)
	f.expect(err, "intro_pending")
	// Only the recipient's owner can grant; the requester's owner cannot.
	_, err = f.r.Submit(f.ctx, f.grant(in, y, x.owner, 60).Raw)
	f.expect(err, "not_owner")
	// Nor can the recipient agent's own signing key stand in for its owner.
	_, err = f.r.Submit(f.ctx, f.grant(in, y, y.sign, 60).Raw)
	f.expect(err, "not_owner")
	_, err = f.r.Submit(f.ctx, f.grant(in, y, y.owner, 60).Raw)
	f.expect(err, "")
	// A decision is final.
	_, err = f.r.Submit(f.ctx, f.grant(in, y, y.owner, 30).Raw)
	f.expect(err, "already_decided")
}

func TestSameOwnerAndPolicyTrust(t *testing.T) {
	f := newFixture(t, relay.Config{IntroBaseBits: 12})
	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	mine1, mine2 := f.agent(owner), f.agent(owner)
	stranger, target := f.agent(nil), f.agent(nil)
	// Same owner: no postage needed.
	in, _, _ := f.intro(mine1, mine2, 0)
	_, err := f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	info, err := f.r.LookupAgent(f.ctx, mine2.id.String(), mine1.id)
	if err != nil || info.IntroPoWBits != 0 {
		t.Fatalf("same-owner price %v %v", info, err)
	}
	// Strangers must pay.
	in, _, _ = f.intro(stranger, target, 0)
	_, err = f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "pow_required")
	// The target's owner allowlists the stranger's owner key.
	pol := &wire.Policy{Agent: target.id, Serial: 1, Created: f.clk.now().UnixMilli(), Flags: wire.PolicyTrustSameOwner}
	var so [32]byte
	copy(so[:], stranger.cert.OwnerPub[:])
	pol.Owners = append(pol.Owners, so)
	// Signed by the wrong key: rejected.
	bad := *pol
	bad.Sign(stranger.owner)
	_, err = f.r.Submit(f.ctx, bad.Raw)
	f.expect(err, "not_owner")
	pol.Sign(target.owner)
	_, err = f.r.Submit(f.ctx, pol.Raw)
	f.expect(err, "")
	in, _, _ = f.intro(stranger, target, 0)
	_, err = f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	// Stale serials cannot roll a policy back.
	old := &wire.Policy{Agent: target.id, Serial: 1, Created: f.clk.now().UnixMilli(), Flags: 0}
	old.Sign(target.owner)
	_, err = f.r.Submit(f.ctx, old.Raw)
	f.expect(err, "stale_serial")
}

func TestStrangerQueueEviction(t *testing.T) {
	f := newFixture(t, relay.Config{IntroBaseBits: 4, MaxPendingPerRecipient: 4, MaxSurgeBits: 1})
	target := f.agent(nil)
	var cheap []*ag
	for i := 0; i < 4; i++ {
		s := f.agent(nil)
		cheap = append(cheap, s)
		in, _, _ := f.intro(s, target, 5)
		_, err := f.r.Submit(f.ctx, in.Raw)
		f.expect(err, "")
	}
	late := f.agent(nil)
	info, _ := f.r.LookupAgent(f.ctx, target.id.String(), late.id)
	if info.IntroPoWBits < 6 {
		t.Fatalf("full queue should price above the cheapest pending stamp, got %d", info.IntroPoWBits)
	}
	in, _, _ := f.intro(late, target, 5)
	_, err := f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "outbid")
	in, _, _ = f.intro(late, target, 7)
	_, err = f.r.Submit(f.ctx, in.Raw)
	f.expect(err, "")
	// Exactly one cheap sender was told it was evicted.
	evicted := 0
	for _, s := range cheap {
		evs, _ := f.r.Inbox(f.ctx, s.id, 0, 10)
		for _, ev := range evs {
			if ev.Kind == wire.KindEvicted {
				evicted++
			}
		}
	}
	if evicted != 1 {
		t.Fatalf("evicted notices = %d, want 1", evicted)
	}
}

func TestRevocationAndAcks(t *testing.T) {
	f := newFixture(t, relay.Config{})
	c := f.connect(600)
	m := f.msg(c, "hi")
	_, err := f.r.Submit(f.ctx, m.Raw)
	f.expect(err, "")
	// Only the recipient can ack.
	ack := &wire.Ack{MsgID: m.ID(), GrantID: c.grant.GrantID, Outcome: wire.AckReceived, Created: f.clk.now().UnixMilli()}
	ack.Sign(c.x.sign)
	_, err = f.r.Submit(f.ctx, ack.Raw)
	f.expect(err, "not_recipient")
	ack.Sign(c.y.sign)
	_, err = f.r.Submit(f.ctx, ack.Raw)
	f.expect(err, "")
	ack2 := &wire.Ack{MsgID: m.ID(), GrantID: c.grant.GrantID, Outcome: wire.AckDeclined, Created: f.clk.now().UnixMilli()}
	ack2.Sign(c.y.sign)
	_, err = f.r.Submit(f.ctx, ack2.Raw)
	f.expect(err, "already_acked")
	// Acked content is gone from the inbox.
	evs, _ := f.r.Inbox(f.ctx, c.y.id, 0, 10)
	for _, ev := range evs {
		if ev.Kind == wire.KindMsg {
			t.Fatal("acknowledged message still in inbox")
		}
	}
	// Outsiders cannot revoke.
	eve := f.agent(nil)
	v := &wire.Revoke{GrantID: c.grant.GrantID, By: eve.id, Created: f.clk.now().UnixMilli()}
	v.Sign(eve.sign)
	_, err = f.r.Submit(f.ctx, v.Raw)
	f.expect(err, "not_participant")
	// Pending messages are purged on revocation.
	p := f.msg(c, "pending")
	_, err = f.r.Submit(f.ctx, p.Raw)
	f.expect(err, "")
	v = &wire.Revoke{GrantID: c.grant.GrantID, By: c.y.id, Created: f.clk.now().UnixMilli(), Role: wire.RoleOwner}
	v.Sign(c.y.owner)
	_, err = f.r.Submit(f.ctx, v.Raw)
	f.expect(err, "")
	evs, _ = f.r.Inbox(f.ctx, c.y.id, 0, 10)
	for _, ev := range evs {
		if ev.Kind == wire.KindMsg {
			t.Fatal("pending message survived revocation")
		}
	}
	_, err = f.r.Submit(f.ctx, f.msg(c, "after").Raw)
	f.expect(err, "grant_inactive")
	st, err := f.r.MessageStatus(f.ctx, c.x.id, p.ID())
	if err != nil || st.Status != "revoked" {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestExpirySweep(t *testing.T) {
	f := newFixture(t, relay.Config{})
	c := f.connect(600)
	m := f.msg(c, "short-lived")
	_, err := f.r.Submit(f.ctx, m.Raw)
	f.expect(err, "")
	f.clk.add(11 * time.Minute)
	evs, _ := f.r.Inbox(f.ctx, c.y.id, 0, 10)
	for _, ev := range evs {
		if ev.Kind == wire.KindMsg {
			t.Fatal("expired message visible")
		}
	}
	if n, err := f.r.Sweep(f.ctx, 100); err != nil || n == 0 {
		t.Fatalf("sweep %d %v", n, err)
	}
	st, _ := f.r.MessageStatus(f.ctx, c.x.id, m.ID())
	if st.Status != "expired" {
		t.Fatalf("status %q", st.Status)
	}
}

func TestLedgerProofsForEveryEntry(t *testing.T) {
	f := newFixture(t, relay.Config{})
	var frames [][]byte
	for i := 0; i < 3; i++ {
		c := f.connect(600)
		frames = append(frames, c.x.cert.Raw, c.y.cert.Raw, c.grant.Raw)
		for j := 0; j < 3; j++ {
			m := f.msg(c, "m")
			if _, err := f.r.Submit(f.ctx, m.Raw); err != nil {
				t.Fatal(err)
			}
			frames = append(frames, m.Raw)
		}
	}
	raw, size, err := f.r.Checkpoint(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := ledger.OpenCheckpoint(raw, f.vkey)
	if err != nil || cp.Size != size {
		t.Fatalf("checkpoint %v %v", cp, err)
	}
	for _, fr := range frames {
		sum := wire.Hash(fr)
		idx, err := f.r.Find(f.ctx, sum[:])
		if err != nil || idx < 0 {
			t.Fatalf("frame not on ledger: %v", err)
		}
		p, err := f.r.InclusionProof(f.ctx, idx, cp.Size)
		if err != nil {
			t.Fatal(err)
		}
		proof := make(tlog.RecordProof, len(p.Hashes))
		for i, h := range p.Hashes {
			copy(proof[i][:], h)
		}
		if err := ledger.VerifyInclusion(proof, cp.Size, cp.Root, idx, p.Leaf); err != nil {
			t.Fatalf("inclusion %d: %v", idx, err)
		}
		leaf, _ := ledger.ParseLeaf(p.Leaf)
		if leaf.Commitment != sum {
			t.Fatal("leaf does not commit to frame")
		}
	}
	// Consistency from every earlier size to the current one.
	for old := int64(1); old < cp.Size; old++ {
		p, err := f.r.ConsistencyProof(f.ctx, old, cp.Size)
		if err != nil {
			t.Fatal(err)
		}
		var oldRoot tlog.Hash
		store := f.r
		_ = store
		proof := make(tlog.TreeProof, len(p.Hashes))
		for i, h := range p.Hashes {
			copy(proof[i][:], h)
		}
		// Recompute the old root from the public leaves.
		leaves, _ := f.r.Leaves(f.ctx, 0, old)
		hashes := make([]tlog.Hash, 0)
		for i, l := range leaves {
			hs, _ := tlog.StoredHashes(int64(i), l, tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
				out := make([]tlog.Hash, len(idx))
				for j, x := range idx {
					out[j] = hashes[x]
				}
				return out, nil
			}))
			hashes = append(hashes, hs...)
		}
		oldRoot, _ = tlog.TreeHash(old, tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
			out := make([]tlog.Hash, len(idx))
			for j, x := range idx {
				out[j] = hashes[x]
			}
			return out, nil
		}))
		if err := ledger.VerifyConsistency(proof, cp.Size, cp.Root, old, oldRoot); err != nil {
			t.Fatalf("consistency %d->%d: %v", old, cp.Size, err)
		}
	}
}

func TestNotifierCountsAndWakes(t *testing.T) {
	f := newFixture(t, relay.Config{})
	c := f.connect(600)
	cur, _ := f.r.Inbox(f.ctx, c.y.id, 0, 100)
	var cursor uint64
	if len(cur) > 0 {
		cursor = cur[len(cur)-1].Seq
	}
	done := make(chan []*relay.Event, 1)
	go func() {
		evs, _ := f.r.WaitInbox(f.ctx, c.y.id, cursor, 10, 5*time.Second)
		done <- evs
	}()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if _, err := f.r.Submit(f.ctx, f.msg(c, "wake").Raw); err != nil {
		t.Fatal(err)
	}
	select {
	case evs := <-done:
		if len(evs) != 1 {
			t.Fatalf("got %d events", len(evs))
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("in-process wakeup took %v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter was not woken")
	}
}

// TestCrossInstanceWake runs two relay instances over one PostgreSQL database
// (as serverless functions do) and checks a waiter on one is woken promptly by
// a write on the other, via LISTEN/NOTIFY rather than the backoff poll.
func TestCrossInstanceWake(t *testing.T) {
	dsn := os.Getenv("SILK_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SILK_TEST_POSTGRES to a disposable database to run")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	conn.Exec(ctx, "DROP TABLE IF EXISTS silk_kv")
	conn.Close(ctx)
	skey, _, _ := ledger.GenerateKey("x.relay")
	signer, _ := ledger.NewSigner(skey)
	var relays []*relay.Relay
	for i := 0; i < 2; i++ {
		store, err := pgkv.Open(ctx, dsn, pgkv.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		relays = append(relays, relay.New(store, signer, relay.Config{RegisterBits: 4, IntroBaseBits: 4, PollInterval: 4 * time.Second}, nil))
	}
	f := &fixture{t: t, r: relays[0], clk: &clock{t: time.Now()}, ctx: ctx}
	c := f.connect(600)
	for round := 0; round < 5; round++ {
		cur, _ := relays[1].Inbox(ctx, c.y.id, 0, 1000)
		var cursor uint64
		if len(cur) > 0 {
			cursor = cur[len(cur)-1].Seq
		}
		done := make(chan time.Time, 1)
		go func() {
			relays[1].WaitInbox(ctx, c.y.id, cursor, 10, 10*time.Second)
			done <- time.Now()
		}()
		time.Sleep(300 * time.Millisecond) // past the first fast re-checks; only a push wakes it soon
		f.clk.t = time.Now()
		start := time.Now()
		if _, err := relays[0].Submit(ctx, f.msg(c, "cross").Raw); err != nil {
			t.Fatal(err)
		}
		end := <-done
		if d := end.Sub(start); d > 400*time.Millisecond {
			t.Fatalf("round %d: cross-instance wake took %v", round, d)
		} else {
			t.Logf("round %d: woken %v after the write started", round, d)
		}
	}
}
