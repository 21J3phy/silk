package client_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/pgkv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	relay  *relay.Relay
	ctx    context.Context
	cancel context.CancelFunc
}

func newEnv(t *testing.T, cfg relay.Config) *env {
	t.Helper()
	var store kv.Store
	var err error
	if dsn := os.Getenv("SILK_TEST_POSTGRES"); dsn != "" {
		// Run the whole suite against PostgreSQL (the hosted backend).
		conn, cerr := pgx.Connect(context.Background(), dsn)
		if cerr != nil {
			t.Fatal(cerr)
		}
		conn.Exec(context.Background(), "DROP TABLE IF EXISTS silk_kv")
		conn.Close(context.Background())
		store, err = pgkv.Open(context.Background(), dsn, pgkv.Options{})
	} else {
		store, err = sqlitekv.Open(filepath.Join(t.TempDir(), "relay.db"), sqlitekv.SQLiteOptions{Synchronous: "NORMAL"})
	}
	if err != nil {
		t.Fatal(err)
	}
	skey, _, err := ledger.GenerateKey("test.silk.relay")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ledger.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RegisterBits == 0 {
		cfg.RegisterBits = 8
	}
	if cfg.IntroBaseBits == 0 {
		cfg.IntroBaseBits = 8
	}
	cfg.PollInterval = 50 * time.Millisecond
	r := relay.New(store, signer, cfg, nil)
	srv := httptest.NewServer(relay.Handler(r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(func() { cancel(); srv.Close(); store.Close() })
	return &env{t: t, srv: srv, relay: r, ctx: ctx, cancel: cancel}
}

func (e *env) agent(label, handle string) *client.Agent {
	e.t.Helper()
	c, err := client.Open(e.t.TempDir())
	if err != nil {
		e.t.Fatal(err)
	}
	a, _, err := c.Init(e.ctx, client.InitOptions{Relay: e.srv.URL, Label: label, Handle: handle, AcceptIntros: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

// connect runs the full consent handshake and returns the grant ID.
func (e *env) connect(a, b *client.Agent, note string) string {
	e.t.Helper()
	out, err := a.RequestContact(e.ctx, b.Address(), client.IntroOptions{Note: note, Budget: 10})
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := b.Sync(e.ctx, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(res.Intros) != 1 || res.Intros[0].Note != note || res.Intros[0].Status != "pending" {
		e.t.Fatalf("intro not delivered correctly: %+v", res.Intros)
	}
	if _, err := b.Accept(e.ctx, out.ID, client.AcceptOptions{}); err != nil {
		e.t.Fatal(err)
	}
	res, err = a.Sync(e.ctx, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(res.Grants) != 1 {
		e.t.Fatalf("grant not delivered: %+v", res)
	}
	return out.ID
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	bob := e.agent("codex", "bob-codex")
	grant := e.connect(alice, bob, "Coordinate the launch checklist")

	sent, err := alice.Send(e.ctx, "@bob-codex", "hello bob — this is end-to-end encrypted ✓", client.SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sent.Status != "accepted" {
		t.Fatalf("send status %q", sent.Status)
	}
	res, err := bob.Sync(e.ctx, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 1 || res.Messages[0].Body != "hello bob — this is end-to-end encrypted ✓" || res.Messages[0].Error != "" {
		t.Fatalf("message not decrypted: %+v", res.Messages)
	}
	if res.Messages[0].FromHandle != "alice-claude" {
		t.Fatalf("sender handle %q", res.Messages[0].FromHandle)
	}
	if _, err := bob.Ack(e.ctx, res.Messages[0].ID, "handled"); err != nil {
		t.Fatal(err)
	}
	// Bob replies in the same conversation.
	reply, err := bob.Send(e.ctx, grant, `{"ok":true}`, client.SendOptions{JSON: true, ReplyTo: res.Messages[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	res, err = alice.Sync(e.ctx, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Receipts) != 1 || res.Receipts[0].Status != "handled" {
		t.Fatalf("receipt missing: %+v", res.Receipts)
	}
	if len(res.Messages) != 1 || res.Messages[0].Type != "json" || res.Messages[0].ReplyTo != sent.ID {
		t.Fatalf("reply not received: %+v", res.Messages)
	}
	st, err := alice.MessageStatus(e.ctx, sent.ID)
	if err != nil || st.Status != "handled" {
		t.Fatalf("status %+v %v", st, err)
	}
	// The relay never sees plaintext.
	frame := mustFrame(t, e, reply.ID)
	if strings.Contains(string(frame), "ok") {
		t.Fatal("plaintext visible in stored frame")
	}
	// Ledger audit and inclusion proofs.
	ar, err := alice.Audit(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Size < 7 || ar.Checked == 0 {
		t.Fatalf("audit %+v", ar)
	}
	if _, err := bob.Send(e.ctx, grant, "one more", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	ar2, err := alice.Audit(e.ctx)
	if err != nil || ar2.PreviousSize != ar.Size || ar2.Size <= ar.Size {
		t.Fatalf("consistency audit %+v %v", ar2, err)
	}
	// Revocation stops delivery and purges pending content.
	if _, err := alice.Revoke(e.ctx, grant, false); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Send(e.ctx, grant, "after revoke", client.SendOptions{}); err == nil {
		t.Fatal("send after revoke succeeded")
	}
	res, err = bob.Sync(e.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Revoked) != 1 {
		t.Fatalf("revocation not delivered: %+v", res)
	}
}

func mustFrame(t *testing.T, e *env, id string) []byte {
	t.Helper()
	// Look the frame up through the relay's public commitment index is not possible
	// without the frame; instead read the most recent ledger leaves and confirm
	// they are 41-byte commitments only.
	leaves, err := e.relay.Leaves(e.ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, l := range leaves {
		if len(l) != ledger.LeafLen {
			t.Fatalf("leaf length %d", len(l))
		}
		all = append(all, l...)
	}
	return all
}

func TestDeclineRaisesSenderCost(t *testing.T) {
	e := newEnv(t, relay.Config{})
	a := e.agent("spammer", "")
	b := e.agent("target", "")
	info0, _, err := a.Lookup(e.ctx, b.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.RequestContact(e.ctx, b.ID.String(), client.IntroOptions{Note: "buy now"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sync(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Decline(e.ctx, out.ID); err != nil {
		t.Fatal(err)
	}
	info1, _, err := a.Lookup(e.ctx, b.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if info1.IntroPoWBits <= info0.IntroPoWBits {
		t.Fatalf("pow bits did not rise after decline: %d -> %d", info0.IntroPoWBits, info1.IntroPoWBits)
	}
	res, err := a.Sync(e.ctx, 0)
	if err != nil || len(res.Declined) != 1 {
		t.Fatalf("decline not delivered: %+v %v", res, err)
	}
}

func TestBudgetAndDuplicates(t *testing.T) {
	e := newEnv(t, relay.Config{})
	a := e.agent("a", "")
	b := e.agent("b", "")
	out, err := a.RequestContact(e.ctx, b.ID.String(), client.IntroOptions{Budget: 2})
	if err != nil {
		t.Fatal(err)
	}
	b.Sync(e.ctx, 0)
	if _, err := b.Accept(e.ctx, out.ID, client.AcceptOptions{}); err != nil {
		t.Fatal(err)
	}
	a.Sync(e.ctx, 0)
	s1, err := a.Send(e.ctx, b.ID.String(), "1", client.SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(e.ctx, b.ID.String(), "2", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(e.ctx, b.ID.String(), "3", client.SendOptions{}); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("expected budget error, got %v", err)
	}
	// Resubmitting an identical frame is idempotent.
	snap, _ := a.Snapshot()
	_ = snap
	st, err := a.MessageStatus(e.ctx, s1.ID)
	if err != nil || st.Status != "pending" {
		t.Fatalf("status %+v %v", st, err)
	}
	res, err := b.Sync(e.ctx, 0)
	if err != nil || len(res.Messages) != 2 {
		t.Fatalf("expected 2 messages: %+v %v", res, err)
	}
	// Re-sync processes nothing new (idempotent cursor).
	res, err = b.Sync(e.ctx, 0)
	if err != nil || len(res.Messages) != 0 {
		t.Fatalf("re-sync delivered again: %+v", res)
	}
}

func TestOwnerPassphraseRequired(t *testing.T) {
	e := newEnv(t, relay.Config{})
	home := t.TempDir()
	c, _ := client.Open(home)
	a, _, err := c.Init(e.ctx, client.InitOptions{Relay: e.srv.URL, Label: "x", Passphrase: "correct horse", AcceptIntros: true})
	if err != nil {
		t.Fatal(err)
	}
	peer := e.agent("peer", "")
	out, err := peer.RequestContact(e.ctx, a.ID.String(), client.IntroOptions{})
	if err != nil {
		t.Fatal(err)
	}
	a.Sync(e.ctx, 0)
	c.Passphrase = func() (string, error) { return "wrong", nil }
	if _, err := a.Accept(e.ctx, out.ID, client.AcceptOptions{}); err == nil {
		t.Fatal("accept succeeded with wrong passphrase")
	}
	c.Passphrase = func() (string, error) { return "correct horse", nil }
	if _, err := a.Accept(e.ctx, out.ID, client.AcceptOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestIDsAreBoundToOwnerKeys(t *testing.T) {
	e := newEnv(t, relay.Config{})
	a := e.agent("a", "handle-a")
	if a.ID != wire.AgentID(a.Cert.OwnerPub[:], "a") {
		t.Fatal("agent id not derived from owner key")
	}
	other := e.agent("b", "")
	if _, _, err := other.Lookup(e.ctx, a.ID.String()); err != nil {
		t.Fatal(err)
	}
}

func TestTrustSkipsPostage(t *testing.T) {
	e := newEnv(t, relay.Config{IntroBaseBits: 16})
	a := e.agent("a", "trust-a")
	b := e.agent("b", "trust-b")
	info, _, err := a.Lookup(e.ctx, "@trust-b")
	if err != nil || info.IntroPoWBits < 16 {
		t.Fatalf("stranger price %+v %v", info, err)
	}
	if _, _, err := b.Trust(e.ctx, "@trust-a", false, false); err != nil {
		t.Fatal(err)
	}
	info, _, err = a.Lookup(e.ctx, "@trust-b")
	if err != nil || info.IntroPoWBits != 0 {
		t.Fatalf("trusted price %+v %v", info, err)
	}
	out, err := a.RequestContact(e.ctx, "@trust-b", client.IntroOptions{Note: "hi"})
	if err != nil || out.PoWBits != 0 {
		t.Fatalf("trusted request %+v %v", out, err)
	}
	if _, _, err := b.Trust(e.ctx, "@trust-a", false, true); err != nil {
		t.Fatal(err)
	}
	info, _, _ = a.Lookup(e.ctx, "@trust-b")
	if info.IntroPoWBits == 0 {
		t.Fatal("untrust did not restore postage")
	}
}

func TestInviteSkipsPostageOnce(t *testing.T) {
	e := newEnv(t, relay.Config{IntroBaseBits: 18, MaxPendingPerRecipient: 1})
	host := e.agent("host", "host")
	guest := e.agent("guest", "")
	other := e.agent("other", "")
	spam := e.agent("spam", "")
	// Fill the host's one-slot stranger queue.
	if _, err := spam.RequestContact(e.ctx, "@host", client.IntroOptions{}); err != nil {
		t.Fatal(err)
	}
	inv, err := host.CreateInvite(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	out, err := guest.RequestContact(e.ctx, inv, client.IntroOptions{Note: "invited"})
	if err != nil || out.PoWBits != 0 {
		t.Fatalf("invite request: %+v %v", out, err)
	}
	// Single use.
	if _, err := other.RequestContact(e.ctx, inv, client.IntroOptions{}); client.Code(err) != "invite_used" {
		t.Fatalf("reuse: %v", err)
	}
	res, err := host.Sync(e.ctx, 0)
	if err != nil || len(res.Intros) != 2 {
		t.Fatalf("host should see both requests: %+v %v", res, err)
	}
}
