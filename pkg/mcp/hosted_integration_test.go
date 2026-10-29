package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/21J3phy/silk/pkg/client"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/relay"
)

// TestHostedMCPRelayRoundTrip exercises real HTTP tool calls, OAuth/PKCE and
// the encrypted relay protocol together. Everything is synthetic and loopback;
// it does not use a production identity, external service or Claude account.
func TestHostedMCPRelayRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := sqlitekv.Open(filepath.Join(t.TempDir(), "relay.db"), sqlitekv.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, _, err := ledger.GenerateKey("synthetic.mcp.test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ledger.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	r := relay.New(store, signer, relay.Config{RegisterBits: 8, IntroBaseBits: 8, PollInterval: time.Millisecond, PolicyEvery: time.Millisecond}, nil)
	rs := httptest.NewServer(relay.Handler(r, relay.HTTPOptions{PostRate: -1, GetRate: -1, RegisterRate: -1}))
	defer rs.Close()
	agent := func(label string) *client.Agent {
		c, e := client.Open(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		a, _, e := c.Init(ctx, client.InitOptions{Relay: rs.URL, Label: label, Handle: label, AcceptIntros: true})
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	a, b := agent("synthetic-opy"), agent("synthetic-duet")
	endpoint := func(a *client.Agent) (*HTTP, *httptest.Server) {
		h := &HTTP{Server: &Server{Agent: a, Version: "test"}, StatePath: filepath.Join(t.TempDir(), "oauth.json"), Agent: a.Address()}
		if err := h.Load(false); err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(h)
		t.Cleanup(ts.Close)
		return h, ts
	}
	ah, as := endpoint(a)
	bh, bs := endpoint(b)
	at := hostedOAuthToken(t, ah, as.URL)
	bt := hostedOAuthToken(t, bh, bs.URL)
	call := func(base, token, name string, args map[string]any, wantErr bool) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		resp, body := post(t, base+"/mcp", token, string(raw))
		var got struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError bool           `json:"isError"`
				Data    map[string]any `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil || resp.StatusCode != 200 || len(got.Error) > 0 || got.Result.IsError != wantErr {
			t.Fatalf("%s failed: HTTP%d, err=%v, toolError=%v (want%v)", name, resp.StatusCode, err, got.Result.IsError, wantErr)
		}
		return got.Result.Data
	}
	for _, side := range []struct{ base, token string }{{as.URL, at}, {bs.URL, bt}} {
		resp, _ := post(t, side.base+"/mcp", side.token, initBody)
		if resp.StatusCode != 200 {
			t.Fatal("MCP initialize failed")
		}
	}
	if got := call(as.URL, at, "silk_whoami", map[string]any{}, false); got["address"] != a.Address() {
		t.Fatal("wrong MCP identity")
	}
	// A connected OAuth client has no authority to send before owner consent.
	call(as.URL, at, "silk_send", map[string]any{"to": b.Address(), "text": "must not send"}, true)
	request := call(as.URL, at, "silk_request_contact", map[string]any{"to": b.Address(), "note": "synthetic integration", "budget": 4}, false)
	requestID, ok := request["request_id"].(string)
	if !ok {
		t.Fatal("missing request id")
	}
	inbox := call(bs.URL, bt, "silk_inbox", map[string]any{}, false)
	requests, ok := inbox["pending_contact_requests"].([]any)
	if !ok || len(requests) != 1 {
		t.Fatal("owner request not delivered")
	}
	// Only the synthetic owner-side SDK approves; no MCP tool does so.
	if _, err := b.Accept(ctx, requestID, client.AcceptOptions{}); err != nil {
		t.Fatal(err)
	}
	call(as.URL, at, "silk_inbox", map[string]any{}, false)
	sent := call(as.URL, at, "silk_send", map[string]any{"to": b.Address(), "text": "synthetic ping"}, false)
	if sent["status"] != "accepted" {
		t.Fatal("ping not accepted")
	}
	inbox = call(bs.URL, bt, "silk_inbox", map[string]any{}, false)
	messages, ok := inbox["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatal("ping not received")
	}
	ping := messages[0].(map[string]any)
	if ping["untrusted_peer_content"] != "synthetic ping" || ping["error"] != nil {
		t.Fatal("ping not decrypted and marked untrusted")
	}
	call(bs.URL, bt, "silk_send", map[string]any{"to": a.Address(), "text": "synthetic pong", "reply_to": ping["id"]}, false)
	inbox = call(as.URL, at, "silk_inbox", map[string]any{}, false)
	messages, ok = inbox["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatal("pong not received")
	}
	pong := messages[0].(map[string]any)
	if pong["untrusted_peer_content"] != "synthetic pong" || pong["reply_to"] != sent["message_id"] || pong["error"] != nil {
		t.Fatal("invalid pong")
	}
	call(as.URL, at, "silk_ack", map[string]any{"message_id": pong["id"], "outcome": "handled"}, false)
	if got := call(as.URL, at, "silk_inbox", map[string]any{}, false); len(got["messages"].([]any)) != 0 {
		t.Fatal("handled pong still unread")
	}
	// Revoking HTTP access must not allow another authorized tool call.
	if err := ah.Load(true); err != nil {
		t.Fatal(err)
	}
	resp, _ := post(t, as.URL+"/mcp", at, initBody)
	if resp.StatusCode != 401 {
		t.Fatal("old OAuth token survived reset")
	}
}

func hostedOAuthToken(t *testing.T, h *HTTP, base string) string {
	t.Helper()
	callback := "https://synthetic.example/callback"
	resp, body := post(t, base+"/register", "", `{"redirect_uris":["`+callback+`"],"client_name":"Synthetic hosted test"}`)
	var reg struct {
		ID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(body), &reg); err != nil || resp.StatusCode != 201 || reg.ID == "" {
		t.Fatal("OAuth registration failed")
	}
	verifier, challenge := pkce()
	resp, _ = form(t, base+"/authorize", url.Values{"response_type": {"code"}, "client_id": {reg.ID}, "redirect_uri": {callback}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {base + "/mcp"}, "decision": {"approve"}, "pairing_code": {h.PairingCode()}})
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != 302 || loc.Query().Get("code") == "" {
		t.Fatal("OAuth authorization failed")
	}
	resp, body = form(t, base+"/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {reg.ID}, "redirect_uri": {callback}, "code": {loc.Query().Get("code")}, "code_verifier": {verifier}})
	var tok struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || resp.StatusCode != http.StatusOK || tok.Access == "" {
		t.Fatal("OAuth exchange failed")
	}
	return tok.Access
}
