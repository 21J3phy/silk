package client_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

// ownerSign plays the owner on their own device: it signs a request and
// returns the signature the agent finishes with.
func ownerSign(t *testing.T, owner *client.Client, err error) string {
	t.Helper()
	var need *client.OwnerSignatureNeeded
	if !errors.As(err, &need) {
		t.Fatalf("want an owner signature request, got %v", err)
	}
	sig, serr := owner.SignRequest(need.Request)
	if serr != nil {
		t.Fatal(serr)
	}
	return sig
}

func complete(t *testing.T, a *client.Agent, sig string) *client.OwnerResult {
	t.Helper()
	res, found, err := a.CompleteOwner(t.Context(), sig)
	if err != nil || !found {
		t.Fatalf("complete: found=%v %v", found, err)
	}
	return res
}

// An agent on its own computer holds only agent keys. Every owner operation
// waits for a signature made where the owner key is, and then works exactly
// as if the owner key were local.
func TestOwnerOnAnotherDevice(t *testing.T) {
	e := newEnv(t, relay.Config{IntroBaseBits: 12})
	owner, err := client.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, created, err := owner.CreateOwner("")
	if err != nil || !created {
		t.Fatalf("create owner: %v %v", created, err)
	}

	// The cloud computer: init stops for the owner, then registers.
	cloud, err := client.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := client.InitOptions{Relay: e.srv.URL, Label: "dot", Handle: "nirav-dot", AcceptIntros: true, Owner: pub}
	_, _, err = cloud.Init(e.ctx, opts)
	var first *client.OwnerSignatureNeeded
	if !errors.As(err, &first) || first.Op != "init" {
		t.Fatalf("init should wait for the owner: %v", err)
	}
	_, _, again := cloud.Init(e.ctx, opts)
	var second *client.OwnerSignatureNeeded
	if !errors.As(again, &second) || second.Request != first.Request {
		t.Fatal("running init again should repeat the same request")
	}
	if _, _, found, err := cloud.CompleteInit(e.ctx, "silk-sig:"+base64.RawURLEncoding.EncodeToString(make([]byte, 64))); found || err != nil {
		t.Fatalf("a wrong signature must not match: found=%v %v", found, err)
	}
	dot, _, found, err := cloud.CompleteInit(e.ctx, ownerSign(t, owner, err))
	if err != nil || !found {
		t.Fatalf("complete init: %v %v", found, err)
	}
	if string(dot.Cert.OwnerPub[:]) != string(pub) {
		t.Fatal("agent is not delegated by the owner key")
	}
	if _, err := cloud.OwnerKey(); err == nil {
		t.Fatal("the cloud computer must not hold the owner key")
	}

	// Accept: the session waits with the request; messages flow after signing.
	peer := e.agent("peer", "peer")
	out, err := peer.RequestContact(e.ctx, "@nirav-dot", client.IntroOptions{Note: "hello", Budget: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dot.Sync(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	_, err = dot.Accept(e.ctx, out.ID, client.AcceptOptions{})
	sig := ownerSign(t, owner, err)
	if _, err := dot.Send(e.ctx, "@peer", "too early", client.SendOptions{}); err == nil {
		t.Fatal("no conversation should exist before the owner signs")
	}
	if res := complete(t, dot, sig); res.Op != "accept" || res.Grant == nil || res.Grant.Status != "active" {
		t.Fatalf("accept result %+v", res)
	}
	if _, found, err := dot.CompleteOwner(e.ctx, sig); found || err != nil {
		t.Fatalf("a used signature must not match again: %v %v", found, err)
	}
	if _, err := peer.Sync(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := dot.Send(e.ctx, "@peer", "hi from the cloud", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := peer.Sync(e.ctx, 2*time.Second)
	if err != nil || len(got.Messages) != 1 || got.Messages[0].Body != "hi from the cloud" {
		t.Fatalf("message: %+v %v", got, err)
	}

	// Decline.
	other := e.agent("other", "")
	out2, err := other.RequestContact(e.ctx, "@nirav-dot", client.IntroOptions{Note: "spam"})
	if err != nil {
		t.Fatal(err)
	}
	dot.Sync(e.ctx, 0)
	err = dot.Decline(e.ctx, out2.ID)
	if res := complete(t, dot, ownerSign(t, owner, err)); res.Op != "decline" {
		t.Fatalf("decline result %+v", res)
	}
	if res, err := other.Sync(e.ctx, 0); err != nil || len(res.Declined) != 1 {
		t.Fatalf("decline not delivered: %+v %v", res, err)
	}

	// Invite.
	_, err = dot.CreateInvite(time.Hour)
	inv := complete(t, dot, ownerSign(t, owner, err)).Invite
	if !strings.HasPrefix(inv, wire.TicketPrefix) {
		t.Fatalf("invite %q", inv)
	}
	if o, err := e.agent("guest", "").RequestContact(e.ctx, inv, client.IntroOptions{}); err != nil || o.PoWBits != 0 {
		t.Fatalf("invite request: %+v %v", o, err)
	}

	// Trust.
	_, _, err = dot.Trust(e.ctx, "@peer", false, false)
	if res := complete(t, dot, ownerSign(t, owner, err)); res.Policy == nil || res.Policy.Serial != 1 || len(res.Policy.Agents) != 1 {
		t.Fatalf("trust result %+v", res)
	}
	if info, _, err := peer.Lookup(e.ctx, "@nirav-dot"); err != nil || info.IntroPoWBits != 0 {
		t.Fatalf("trusted price %+v %v", info, err)
	}

	// Rotate, then keep talking.
	_, err = dot.Rotate(e.ctx)
	if res := complete(t, dot, ownerSign(t, owner, err)); res.Op != "rotate" || dot.Cert.Serial != 2 {
		t.Fatalf("rotate result %+v serial %d", res, dot.Cert.Serial)
	}
	if _, err := dot.Send(e.ctx, "@peer", "new keys", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}

	// Owner revocation.
	_, err = dot.Revoke(e.ctx, out.ID, true)
	if res := complete(t, dot, ownerSign(t, owner, err)); res.Op != "revoke" {
		t.Fatalf("revoke result %+v", res)
	}
	if _, err := dot.Send(e.ctx, "@peer", "after revoke", client.SendOptions{}); err == nil {
		t.Fatal("send after owner revocation should fail")
	}
}

// The owner's device refuses requests for another owner key and anything
// that is not an owner frame.
func TestSignRequestRefusesOthers(t *testing.T) {
	e := newEnv(t, relay.Config{})
	mine, _ := client.Open(t.TempDir())
	if _, _, err := mine.CreateOwner(""); err != nil {
		t.Fatal(err)
	}
	theirs, _ := client.Open(t.TempDir())
	theirPub, _, _ := theirs.CreateOwner("")
	cloud, _ := client.Open(t.TempDir())
	_, _, err := cloud.Init(e.ctx, client.InitOptions{Relay: e.srv.URL, Label: "x", Owner: theirPub})
	var need *client.OwnerSignatureNeeded
	if !errors.As(err, &need) {
		t.Fatal(err)
	}
	if _, err := mine.SignRequest(need.Request); err == nil || !strings.Contains(err.Error(), "different owner") {
		t.Fatalf("signed another owner's request: %v", err)
	}
	// A message frame dressed up as a request.
	body := append([]byte{wire.Version, byte(wire.KindMsg)}, make([]byte, 64)...)
	if _, err := mine.SignRequest(client.SignRequestPrefix + base64.RawURLEncoding.EncodeToString(body)); err == nil {
		t.Fatal("signed a non-owner frame")
	}
}
