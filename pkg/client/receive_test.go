package client_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/relay"
)

// Monitoring must not retry an earlier failed send or contact request. Exercise
// real encrypted messages and relay processing, not a fake SyncResult.
func TestReceiveLeavesOutboxQueued(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("alice", "receive-alice")
	bob := e.agent("bob", "receive-bob")
	carol := e.agent("carol", "receive-carol")
	e.connect(alice, bob, "receive test")
	var posts atomic.Int64
	var block atomic.Bool
	block.Store(true)
	alice.Client().Config.Relay = proxy(t, e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost {
			posts.Add(1)
			if block.Load() {
				http.Error(w, "test-only unavailable", http.StatusServiceUnavailable)
				return true
			}
		}
		return false
	})
	sent, err := alice.Send(e.ctx, bob.Address(), "queued outgoing", client.SendOptions{})
	if err == nil || sent == nil {
		t.Fatalf("send should remain queued: %v, %v", sent, err)
	}
	intro, err := alice.RequestContact(e.ctx, carol.Address(), client.IntroOptions{Note: "queued introduction"})
	if err == nil || intro == nil {
		t.Fatalf("intro should remain queued: %v, %v", intro, err)
	}
	if _, err := bob.Send(e.ctx, alice.Address(), "incoming while queued", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	block.Store(false)
	posts.Store(0)
	res, err := alice.Receive(e.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 {
		t.Fatalf("Receive made %d POSTs", posts.Load())
	}
	if len(res.Messages) != 1 || res.Messages[0].Body != "incoming while queued" || res.Messages[0].Error != "" {
		t.Fatalf("incoming message: %+v", res.Messages)
	}
	snap, err := alice.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Sent) != 1 || snap.Sent[0].Status != "queued" || len(snap.Sent[0].Frame) == 0 {
		t.Fatalf("outgoing message changed: %+v", snap.Sent)
	}
	found := false
	for _, out := range snap.OutIntros {
		if out.ID == intro.ID {
			found = out.Status == "queued" && len(out.Frame) > 0
		}
	}
	if !found {
		t.Fatal("queued introduction changed")
	}
	again, err := alice.Receive(e.ctx, 0)
	if err != nil || len(again.Messages) != 0 || again.Cursor != res.Cursor {
		t.Fatalf("receive replay: %+v, %v", again, err)
	}
	if posts.Load() != 0 {
		t.Fatalf("repeated Receive made %d POSTs", posts.Load())
	}
	// Reopen from disk: the cursor and receive ratchet must survive a restart.
	reopened, err := alice.Client().Agent("alice")
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.Snapshot()
	if err != nil || len(persisted.Inbox) != 1 || persisted.Inbox[0].Body != "incoming while queued" {
		t.Fatalf("persisted inbox: %+v, %v", persisted, err)
	}
	if _, err := bob.Send(e.ctx, alice.Address(), "incoming after restart", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	afterRestart, err := reopened.Receive(e.ctx, 0)
	if err != nil || len(afterRestart.Messages) != 1 || afterRestart.Messages[0].Body != "incoming after restart" || afterRestart.Messages[0].Error != "" {
		t.Fatalf("receive after restart: %+v, %v", afterRestart, err)
	}
	if posts.Load() != 0 {
		t.Fatalf("Receive after restart made %d POSTs", posts.Load())
	}
	// Existing Sync behavior remains available and retries both kinds of frames.
	if _, err := alice.Sync(e.ctx, 0); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 2 {
		t.Fatalf("Sync made %d POSTs, want intro and message batch", posts.Load())
	}
	snap, err = alice.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Sent[0].Status == "queued" {
		t.Fatal("Sync did not flush message")
	}
}
