package relay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

type tAgent struct {
	owner, sign ed25519.PrivateKey
	kem         *seal.KEMKey
	cert        *wire.Cert
}

func mkAgent(tb testing.TB, r *relay.Relay, label string) *tAgent {
	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	kem, _ := seal.NewKEMKey()
	now := time.Now()
	c := &wire.Cert{Label: label, Serial: 1, Suite: wire.Suite1, KEMPub: kem.Public(), Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(), Flags: wire.CertAcceptsIntros}
	copy(c.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	copy(c.SignPub[:], sign.Public().(ed25519.PublicKey))
	c.Sign(owner, sign)
	n, _ := pow.Solve(context.Background(), pow.Digest(pow.DomainRegister, c.Raw), 4, 1)
	if _, err := r.Register(context.Background(), relay.EncodeRegistration(c.Raw, 4, n)); err != nil {
		tb.Fatal(err)
	}
	return &tAgent{owner, sign, kem, c}
}

type tPair struct {
	a, b  *tAgent
	grant wire.ID
	sa    *seal.Session
}

func mkPair(tb testing.TB, r *relay.Relay, i int) *tPair {
	ctx := context.Background()
	x, y := mkAgent(tb, r, "x"+string(rune('a'+i%26))+string(rune('a'+i/26))), mkAgent(tb, r, "y"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	now := time.Now()
	in := &wire.Intro{From: x.cert.ID(), To: y.cert.ID(), ToSerial: 1, Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(), Scope: "b", Budget: 1000000, GrantTTL: 3600}
	rand.Read(in.IntroID[:])
	eph, _ := seal.NewKEMKey()
	in.EphPub = eph.Public()
	k1, _ := seal.SealIntro(in, y.kem.Public(), "")
	in.PoWBits = 4
	in.PoWNonce, _ = pow.Solve(ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), 4, 1)
	in.Sign(x.sign)
	if _, err := r.Submit(ctx, in.Raw); err != nil {
		tb.Fatal(err)
	}
	g := &wire.Grant{GrantID: in.IntroID, IntroHash: wire.Hash(in.Raw), From: in.From, To: in.To, Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(), BudgetAB: 1000000, BudgetBA: 1000000, Rate: 600}
	k2, _ := seal.SealGrant(g, in.EphPub)
	g.Sign(y.owner)
	if _, err := r.Submit(ctx, g.Raw); err != nil {
		tb.Fatal(err)
	}
	root, _ := seal.Root(k1, k2, g.IntroHash, g)
	sa, _ := seal.NewSession(g.GrantID, root, true)
	return &tPair{x, y, g.GrantID, sa}
}

func newRelay(tb testing.TB) *relay.Relay {
	store, err := sqlitekv.Open(filepath.Join(tb.TempDir(), "r.db"), sqlitekv.SQLiteOptions{})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { store.Close() })
	skey, _, _ := ledger.GenerateKey("bench")
	signer, _ := ledger.NewSigner(skey)
	return relay.New(store, signer, relay.Config{RegisterBits: 4, IntroBaseBits: 4, IgnoreGrantRate: true}, nil)
}

func BenchmarkSubmitMsgParallel(b *testing.B) {
	r := newRelay(b)
	const P = 16
	pairs := make([]*tPair, P)
	for i := range pairs {
		pairs[i] = mkPair(b, r, i)
	}
	frames := make([][][]byte, P)
	per := b.N/P + 1
	for i, p := range pairs {
		for j := 0; j < per; j++ {
			m := &wire.Msg{GrantID: p.grant, Created: time.Now().UnixMilli(), TTL: 3600}
			p.sa.Encrypt(m, seal.TypeText, []byte("Can we coordinate a time? This is untrusted message data."))
			m.Sign(p.a.sign)
			frames[i] = append(frames[i], m.Raw)
		}
	}
	var w atomic.Int64
	b.ResetTimer()
	b.SetParallelism(P / 12 + 1)
	b.RunParallel(func(pb *testing.PB) {
		i := int(w.Add(1)-1) % P
		j := 0
		for pb.Next() {
			if j >= len(frames[i]) {
				i = (i + 1) % P
				j = 0
			}
			if _, err := r.Submit(context.Background(), frames[i][j]); err != nil {
				b.Error(err)
				return
			}
			j++
		}
	})
}
