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
	impact, err := invalidateRestoredSessions(&b)
	if err != nil {
		t.Fatal(err)
	}
	if impact.ConversationsRequiringApproval != 1 || impact.CanceledQueuedMessages != 1 {
		t.Fatalf("incorrect impact: %+v", impact)
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

func TestImportReportsRecoveryImpact(t *testing.T) {
	const pass = "test-only backup passphrase"
	files := map[string][]byte{}
	for _, name := range []string{"a", "b"} {
		st := newState()
		st.Grants["active"] = &GrantInfo{Status: "active"}
		st.Grants["revoked"] = &GrantInfo{Status: "revoked"}
		st.Grants["nil"] = nil
		st.Sent = []*Sent{{Status: "queued", Frame: []byte("synthetic")}, {Status: "accepted"}, nil}
		data, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		files["agents/"+name+"/state.json"] = data
	}
	res, err := Import(t.TempDir(), sealBundle(t, pass, files), pass, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Recovery.ConversationsRequiringApproval != 2 || res.Recovery.CanceledQueuedMessages != 2 {
		t.Fatalf("impact: %+v", res.Recovery)
	}
	if len(res.Agents) != 2 || len(res.Files) != 2 {
		t.Fatalf("result: %+v", res)
	}
}

func TestRestoreImpactEmptyAndMalformed(t *testing.T) {
	b := backupBundle{Files: map[string][]byte{"config.json": []byte(`{}`)}}
	impact, err := invalidateRestoredSessions(&b)
	if err != nil || impact != (RestoreImpact{}) {
		t.Fatalf("empty impact: %+v, %v", impact, err)
	}
	b.Files["agents/a/state.json"] = []byte(`not json`)
	impact, err = invalidateRestoredSessions(&b)
	if err == nil || impact != (RestoreImpact{}) {
		t.Fatalf("malformed state: %+v, %v", impact, err)
	}
}
