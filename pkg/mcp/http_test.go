package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/21J3phy/silk/pkg/client"
)

func newTestHTTP(t *testing.T) (*HTTP, *httptest.Server) {
	t.Helper()
	s := &Server{Version: "test", Open: func() (*client.Agent, error) { return nil, errors.New("no agent") }}
	h := &HTTP{Server: s, StatePath: filepath.Join(t.TempDir(), "mcp-remote.json"), Agent: "test-agent"}
	if err := h.Load(false); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return h, ts
}

func post(t *testing.T, url, bearer, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`

func TestHTTPRequiresAuth(t *testing.T) {
	h, ts := newTestHTTP(t)
	resp, _ := post(t, ts.URL+"/mcp", "", initBody)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), ts.URL+"/.well-known/oauth-protected-resource") {
		t.Fatalf("unauthenticated: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp, _ := post(t, ts.URL+"/mcp", "silk_wrong", initBody); resp.StatusCode != 401 {
		t.Fatalf("wrong bearer: %d", resp.StatusCode)
	}
	if resp, _ := post(t, ts.URL+"/mcp/silk_wrong", "", initBody); resp.StatusCode != 404 {
		t.Fatalf("wrong URL token: %d", resp.StatusCode)
	}
	bare, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(initBody))
	bare.Header.Set("Authorization", h.Token()) // xAI's `authorization` field may omit "Bearer"
	if r, err := http.DefaultClient.Do(bare); err != nil || r.StatusCode != 200 {
		t.Fatalf("bare token: %v %v", r.StatusCode, err)
	}
	// The connect token works as a header and as a secret URL.
	for _, c := range []struct{ url, bearer string }{{ts.URL + "/mcp", h.Token()}, {ts.URL + "/mcp/" + h.Token(), ""}} {
		resp, body := post(t, c.url, c.bearer, initBody)
		if resp.StatusCode != 200 || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
			t.Fatalf("initialize: %d %s", resp.StatusCode, body)
		}
	}
}

func TestHTTPStreamableTransport(t *testing.T) {
	h, ts := newTestHTTP(t)
	tok := h.Token()
	if resp, body := post(t, ts.URL+"/mcp", tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); resp.StatusCode != 202 || body != "" {
		t.Fatalf("notification: %d %q", resp.StatusCode, body)
	}
	resp, body := post(t, ts.URL+"/mcp", tok, `{"jsonrpc":"2.0","id":"a","method":"tools/list"}`)
	var one struct {
		ID     string `json:"id"`
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &one); err != nil || resp.StatusCode != 200 || one.ID != "a" || len(one.Result.Tools) != 9 {
		t.Fatalf("tools/list: %d %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	// Batches (protocol 2025-03-26) get an array of responses, notifications omitted.
	_, body = post(t, ts.URL+"/mcp", tok, `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"silk_whoami","arguments":{}}}]`)
	var batch []map[string]any
	if err := json.Unmarshal([]byte(body), &batch); err != nil || len(batch) != 2 {
		t.Fatalf("batch: %s", body)
	}
	if !strings.Contains(body, "silk init") {
		t.Fatalf("tool call without identity should explain setup: %s", body)
	}
	if resp, _ := post(t, ts.URL+"/mcp", tok, `{not json`); resp.StatusCode != 400 {
		t.Fatalf("parse error: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 405 {
		t.Fatalf("GET /mcp: %d", r.StatusCode)
	}
}

func pkce() (verifier, challenge string) {
	verifier = randToken("", 32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func getJSON(t *testing.T, u string) map[string]any {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func form(t *testing.T, u string, v url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := noRedirect.PostForm(u, v)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// The sign-in a cloud connector (grok.com, Muse, ChatGPT, claude.ai) runs:
// discovery, dynamic registration, consent with the pairing code, PKCE code
// exchange, then refresh-token rotation.
func TestHTTPOAuthFlow(t *testing.T) {
	h, ts := newTestHTTP(t)
	prm := getJSON(t, ts.URL+"/.well-known/oauth-protected-resource/mcp")
	if prm["resource"] != ts.URL+"/mcp" || prm["authorization_servers"].([]any)[0] != ts.URL {
		t.Fatalf("protected resource metadata: %v", prm)
	}
	asm := getJSON(t, ts.URL+"/.well-known/oauth-authorization-server")
	if asm["registration_endpoint"] != ts.URL+"/register" || asm["code_challenge_methods_supported"].([]any)[0] != "S256" {
		t.Fatalf("authorization server metadata: %v", asm)
	}

	if resp, _ := post(t, ts.URL+"/register", "", `{"redirect_uris":["javascript:alert(1)"]}`); resp.StatusCode != 400 {
		t.Fatalf("script redirect accepted: %d", resp.StatusCode)
	}
	cb := "https://grok.example/oauth/callback"
	resp, body := post(t, ts.URL+"/register", "", `{"redirect_uris":["`+cb+`"],"client_name":"Grok <b>","token_endpoint_auth_method":"none"}`)
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if json.Unmarshal([]byte(body), &reg); resp.StatusCode != 201 || reg.ClientID == "" {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}

	verifier, challenge := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {cb}, "state": {"st8"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {ts.URL + "/mcp"}}
	page, err := http.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != 200 || !strings.Contains(string(html), "Grok &lt;b&gt;") || page.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("consent page: %d %s", page.StatusCode, html)
	}
	if strings.Contains(string(html), h.PairingCode()) {
		t.Fatal("consent page leaks the pairing code")
	}

	// Wrong code: no redirect, no authorization code.
	v := url.Values{}
	for k, vs := range q {
		v[k] = vs
	}
	v.Set("decision", "approve")
	v.Set("pairing_code", "AAAA-AAAA")
	if resp, _ := form(t, ts.URL+"/authorize", v); resp.StatusCode != 401 {
		t.Fatalf("wrong pairing code: %d", resp.StatusCode)
	}
	v.Set("pairing_code", strings.ToLower(h.PairingCode())) // typed casually
	resp, _ = form(t, ts.URL+"/authorize", v)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc.String(), cb) || code == "" || loc.Query().Get("state") != "st8" || loc.Query().Get("iss") != ts.URL {
		t.Fatalf("approve: %d %s", resp.StatusCode, loc)
	}

	exchange := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}, "client_id": {reg.ClientID}, "code_verifier": {"wrong-verifier-wrong-verifier-wrong-verifier"}}
	if resp, _ := form(t, ts.URL+"/token", exchange); resp.StatusCode != 400 {
		t.Fatalf("bad verifier accepted: %d", resp.StatusCode)
	}
	exchange.Set("code_verifier", verifier)
	if resp, _ := form(t, ts.URL+"/token", exchange); resp.StatusCode != 400 {
		t.Fatalf("authorization code reused after a failed exchange: %d", resp.StatusCode)
	}

	// The pairing code is single use.
	if resp, _ := form(t, ts.URL+"/authorize", v); resp.StatusCode != 401 {
		t.Fatalf("pairing code reused: %d", resp.StatusCode)
	}
	// Fresh code, correct verifier.
	v.Set("pairing_code", h.PairingCode())
	resp, _ = form(t, ts.URL+"/authorize", v)
	loc, _ = url.Parse(resp.Header.Get("Location"))
	exchange.Set("code", loc.Query().Get("code"))
	resp, body = form(t, ts.URL+"/token", exchange)
	var tok struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Type    string `json:"token_type"`
	}
	if json.Unmarshal([]byte(body), &tok); resp.StatusCode != 200 || tok.Access == "" || tok.Refresh == "" || tok.Type != "Bearer" {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	if resp, _ := form(t, ts.URL+"/token", exchange); resp.StatusCode != 400 {
		t.Fatal("authorization code was accepted twice")
	}
	if resp, body := post(t, ts.URL+"/mcp", tok.Access, initBody); resp.StatusCode != 200 {
		t.Fatalf("MCP with access token: %d %s", resp.StatusCode, body)
	}
	if got := h.Clients(); len(got) != 1 || got[0] != "Grok <b>" {
		t.Fatalf("connected clients: %v", got)
	}

	// Refresh rotates: the new token works, the old one is spent.
	ref := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh}, "client_id": {reg.ClientID}}
	resp, body = form(t, ts.URL+"/token", ref)
	var tok2 struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if json.Unmarshal([]byte(body), &tok2); resp.StatusCode != 200 || tok2.Access == "" || tok2.Refresh == tok.Refresh {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	if resp, _ := form(t, ts.URL+"/token", ref); resp.StatusCode != 400 {
		t.Fatal("spent refresh token accepted")
	}

	// Tokens survive a restart; --reset revokes them all and replaces the connect token.
	h2 := &HTTP{Server: h.Server, StatePath: h.StatePath}
	if err := h2.Load(false); err != nil {
		t.Fatal(err)
	}
	ts2 := httptest.NewServer(h2)
	defer ts2.Close()
	if resp, _ := post(t, ts2.URL+"/mcp", tok2.Access, initBody); resp.StatusCode != 200 || h2.Token() != h.Token() {
		t.Fatalf("after restart: %d", resp.StatusCode)
	}
	old := h2.Token()
	if err := h2.Load(true); err != nil {
		t.Fatal(err)
	}
	if resp, _ := post(t, ts2.URL+"/mcp", tok2.Access, initBody); resp.StatusCode != 401 || h2.Token() == old {
		t.Fatalf("after reset: %d", resp.StatusCode)
	}
}

func TestHTTPDenyAndPairingLockout(t *testing.T) {
	h, ts := newTestHTTP(t)
	cb := "http://127.0.0.1:33418/callback"
	_, body := post(t, ts.URL+"/register", "", `{"redirect_uris":["`+cb+`"],"client_name":"Muse"}`)
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal([]byte(body), &reg)
	_, challenge := pkce()
	v := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {cb}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "decision": {"deny"}}
	resp, _ := form(t, ts.URL+"/authorize", v)
	if loc, _ := url.Parse(resp.Header.Get("Location")); resp.StatusCode != 302 || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny: %d %v", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Unregistered redirect URIs are refused outright, never redirected to.
	v.Set("redirect_uri", "https://evil.example/cb")
	if resp, _ := form(t, ts.URL+"/authorize", v); resp.StatusCode != 400 {
		t.Fatalf("unregistered redirect: %d", resp.StatusCode)
	}
	v.Set("redirect_uri", cb)
	v.Set("decision", "approve")
	first := h.PairingCode()
	for i := 0; i < maxPairFails; i++ {
		v.Set("pairing_code", "WRONG-CODE")
		form(t, ts.URL+"/authorize", v)
	}
	if h.PairingCode() == first {
		t.Fatal("pairing code did not change after repeated wrong guesses")
	}
	v.Set("pairing_code", first)
	if resp, _ := form(t, ts.URL+"/authorize", v); resp.StatusCode != 401 {
		t.Fatalf("old pairing code still accepted: %d", resp.StatusCode)
	}
}
