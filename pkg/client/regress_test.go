package client_test

// Regression tests for the October 2026 security review.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/relay"
)

func proxy(t *testing.T, e *env, intercept func(w http.ResponseWriter, r *http.Request) bool) string {
	target, _ := url.Parse(e.srv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept(w, r) {
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// A relay could answer an @handle lookup with someone else's certificate.
func TestRegressHandleSubstitution(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	e.agent("codex", "bob-codex")
	mallory := e.agent("evil", "mallory")
	alice.Client().Config.Relay = proxy(t, e, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "bob-codex") {
			r.URL.Path, r.URL.RawPath = "/v2/agents/"+mallory.ID.String(), ""
		}
		return false
	})
	if out, err := alice.RequestContact(e.ctx, "@bob-codex", client.IntroOptions{Note: "secret"}); err == nil {
		t.Fatalf("intro for @bob-codex was sent to %s", out.To)
	}
}

// A pinned handle that later resolves to a different agent is refused.
func TestRegressHandlePinned(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	e.agent("codex", "bob-codex")
	if _, err := alice.RequestContact(e.ctx, "@bob-codex", client.IntroOptions{}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(alice.Client().Home, "agents", "claude", "state.json")
	b, _ := os.ReadFile(p)
	var st map[string]any
	json.Unmarshal(b, &st)
	st["handles"].(map[string]any)["bob-codex"] = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	b, _ = json.Marshal(st)
	os.WriteFile(p, b, 0o600)
	if _, err := alice.RequestContact(e.ctx, "@bob-codex", client.IntroOptions{}); err == nil || !strings.Contains(err.Error(), "now resolves") {
		t.Fatalf("remapped handle accepted: %v", err)
	}
}

// Audit "proved" whatever leaf sat at a stored index, not the agent's own frame.
func TestRegressAuditBoundToOwnFrames(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	bob := e.agent("codex", "bob-codex")
	e.connect(alice, bob, "hi")
	if _, err := alice.Send(e.ctx, "@bob-codex", "first", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Audit(e.ctx); err != nil {
		t.Fatalf("honest audit failed: %v", err)
	}
	p := filepath.Join(alice.Client().Home, "agents", "claude", "state.json")
	b, _ := os.ReadFile(p)
	var st map[string]any
	json.Unmarshal(b, &st)
	st["sent"].([]any)[0].(map[string]any)["ledger_index"] = 1 // bob's registration
	b, _ = json.Marshal(st)
	os.WriteFile(p, b, 0o600)
	if _, err := alice.Audit(e.ctx); err == nil {
		t.Fatal("audit accepted someone else's ledger entry as this agent's message")
	}
}

// After a peer rotated keys, its new contact requests were rejected as bad signatures.
func TestRegressPeerRotation(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	bob := e.agent("codex", "bob-codex")
	e.connect(alice, bob, "hi")
	if _, err := alice.Rotate(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.RequestContact(e.ctx, "@bob-codex", client.IntroOptions{Note: "again"}); err != nil {
		t.Fatal(err)
	}
	res, err := bob.Sync(e.ctx, 0)
	if err != nil || len(res.Intros) != 1 || res.Intros[0].Status != "pending" {
		t.Fatalf("intro after rotation: %+v %v", res.Intros, err)
	}
}

// A malformed batch response crashed Send (and with it the MCP server).
func TestRegressMalformedBatchResponse(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	bob := e.agent("codex", "bob-codex")
	e.connect(alice, bob, "hi")
	if _, err := alice.Send(e.ctx, "@bob-codex", "first", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := bob.Sync(e.ctx, 0)
	if err != nil || len(res.Messages) != 1 {
		t.Fatal(err)
	}
	bob.Client().Config.Relay = proxy(t, e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v2/frames/batch" {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{},{}]`))
			return true
		}
		return false
	})
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("Send panicked: %v", p)
		}
	}()
	if _, err := bob.Send(e.ctx, res.Messages[0].From, "reply", client.SendOptions{ReplyTo: res.Messages[0].ID}); err == nil {
		t.Fatal("empty batch result treated as success")
	}
}

// An approval whose response was lost could never be completed.
func TestRegressAcceptResumes(t *testing.T) {
	e := newEnv(t, relay.Config{})
	alice := e.agent("claude", "alice-claude")
	bob := e.agent("codex", "bob-codex")
	out, err := alice.RequestContact(e.ctx, "@bob-codex", client.IntroOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bob.Sync(e.ctx, 0)
	real := bob.Client().Config.Relay
	// The relay commits the grant but the response is lost.
	bob.Client().Config.Relay = proxy(t, e, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v2/frames" {
			body, _ := io.ReadAll(r.Body)
			resp, err := http.Post(real+"/v2/frames", "application/octet-stream", strings.NewReader(string(body)))
			if err == nil {
				resp.Body.Close()
			}
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		return false
	})
	if _, err := bob.Accept(e.ctx, out.ID, client.AcceptOptions{}); err == nil {
		t.Fatal("expected the lost response to surface as an error")
	}
	bob.Client().Config.Relay = real
	gi, err := bob.Accept(e.ctx, out.ID, client.AcceptOptions{})
	if err != nil || gi == nil || gi.Status != "active" {
		t.Fatalf("resumed accept: %+v %v", gi, err)
	}
	alice.Sync(e.ctx, 0)
	if _, err := alice.Send(e.ctx, "@bob-codex", "works", client.SendOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := bob.Sync(e.ctx, 0)
	if err != nil || len(r.Messages) != 1 || r.Messages[0].Body != "works" {
		t.Fatalf("conversation after resumed accept: %+v %v", r, err)
	}
}
