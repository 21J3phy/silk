package relay_test

import (
	"context"
	"testing"

	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/wire"
)

func FuzzDecodeEvents(f *testing.F) {
	f.Add(relay.EncodeEvents([]*relay.Event{{Seq: 1, Kind: wire.KindMsg, Millis: 5, LedgerIdx: 9, Frame: []byte{2, 5, 1}}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, err := relay.DecodeEvents(b)
		if err != nil {
			return
		}
		if string(relay.EncodeEvents(evs)) != string(b) {
			t.Fatal("events did not round-trip")
		}
	})
}

// Arbitrary bytes into the relay's registration and frame admission must never
// panic or be accepted without valid signatures and postage.
func FuzzAdmission(f *testing.F) {
	f.Add([]byte{2, 5, 0, 0})
	f.Add(relay.EncodeRegistration([]byte{2, 1, 0}, 4, 7))
	f.Fuzz(func(t *testing.T, b []byte) {
		fx := newFixture(t, relay.Config{})
		if _, err := fx.r.Submit(context.Background(), b); err == nil {
			t.Fatalf("random frame accepted: %x", b)
		}
		if _, err := fx.r.Register(context.Background(), b); err == nil {
			t.Fatalf("random registration accepted: %x", b)
		}
	})
}
