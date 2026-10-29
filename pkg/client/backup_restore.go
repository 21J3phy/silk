package client

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/21J3phy/silk/pkg/seal"
)

// invalidateRestoredSessions keeps identity and historical records, never live
// cryptographic protocol state. Even the newest available backup may predate a
// send that reached the network: resuming its deterministic chain would reuse
// an AES-GCM key/nonce. Fresh owner-approved handshakes are required after every
// restore. Replaying pending handshakes can recreate the old root too.
func invalidateRestoredSessions(b *backupBundle) error {
	for name, data := range b.Files {
		if agentOf(name) == "" || path.Base(name) != "state.json" {
			continue
		}
		var st agentState
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("invalid backed-up agent state %s: %w", name, err)
		}
		st.Sessions = map[string]*seal.Session{}
		for _, g := range st.Grants {
			if g != nil && g.Status == "active" {
				g.Status = "restored: fresh owner-approved conversation required"
			}
		}
		st.OutIntros = map[string]*OutIntro{}
		st.InIntros = map[string]*InIntro{}
		st.OwnerRequests = nil
		for _, s := range st.Sent {
			if s != nil && s.Status == "queued" {
				s.Status = "canceled by restore"
				s.Frame = nil
			}
		}
		out, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		b.Files[name] = out
	}
	return nil
}
