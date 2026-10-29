package client

import (
	"encoding/json"
	"github.com/21J3phy/silk/pkg/seal"
	"testing"
)

func TestRestoreDropsOldProtocolState(t *testing.T) {
	st := newState()
	st.Cursor = 123
	st.Sessions["old"] = &seal.Session{}
	st.Grants["old"] = &GrantInfo{ID: "old", Status: "active"}
	st.Grants["revoked"] = &GrantInfo{ID: "revoked", Status: "revoked"}
	st.OutIntros["pending"] = &OutIntro{Status: "pending", K1: []byte("synthetic")}
	st.InIntros["pending"] = &InIntro{Status: "accepting", GrantFrame: []byte("synthetic")}
	st.OwnerRequests = map[string]*OwnerRequest{"pending": {Op: "accept"}}
	st.Sent = []*Sent{{Status: "queued", Frame: []byte("synthetic")}, {Status: "accepted", ID: "history"}}
	st.Inbox = []*Message{{Body: "history"}}
	data, _ := json.Marshal(st)
	b := backupBundle{Files: map[string][]byte{"agents/a/state.json": data}}
	if err := invalidateRestoredSessions(&b); err != nil {
		t.Fatal(err)
	}
	var got agentState
	if err := json.Unmarshal(b.Files["agents/a/state.json"], &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Sessions)+len(got.OutIntros)+len(got.InIntros)+len(got.OwnerRequests) != 0 {
		t.Fatal("restored active protocol state")
	}
	if got.Grants["old"].Status == "active" || got.Grants["revoked"].Status != "revoked" {
		t.Fatal("incorrect grant state")
	}
	if got.Sent[0].Frame != nil || got.Sent[0].Status == "queued" {
		t.Fatal("restored live outbox")
	}
	if got.Cursor != 123 || got.Sent[1].ID != "history" || got.Inbox[0].Body != "history" {
		t.Fatal("lost historical records")
	}
}
