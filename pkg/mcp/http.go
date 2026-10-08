package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HTTP serves the MCP server over Streamable HTTP, for agents that run in
// someone else's cloud and cannot start a process on this machine: grok.com
// and Grok Bot, Meta Muse, OpenAI Dots and ChatGPT, claude.ai. The agent's
// keys never leave this machine; the cloud agent only gets the tools.
//
// Three ways in, all equivalent:
//   - OAuth 2.1 sign-in (authorization code + PKCE, dynamic client
//     registration), which is what most cloud connectors expect. The consent
//     page asks for a pairing code that is only shown in this machine's
//     terminal, so only the owner can connect an agent.
//   - Authorization: Bearer <token>, for clients that take a header.
//   - <base>/mcp/<token>, for clients that only take a URL.
//
// Tokens and registered clients persist in StatePath (mode 0600).
type HTTP struct {
	Server    *Server
	StatePath string
	// PublicURL is the external base URL (e.g. a tunnel); when empty it is
	// derived from each request.
	PublicURL string
	// Agent names the agent on the consent page.
	Agent string
	// Logf reports connections and pairing codes to the owner's terminal.
	Logf func(format string, args ...any)

	mu    sync.Mutex
	st    *httpState
	pair  string
	fails int
	codes map[string]*authCode
}

const (
	accessTTL    = 24 * time.Hour
	refreshTTL   = 180 * 24 * time.Hour
	codeTTL      = 2 * time.Minute
	maxClients   = 64
	maxPairFails = 5
	maxBody      = 4 << 20
)

type httpState struct {
	Token   string                  `json:"token"`
	Clients map[string]*oauthClient `json:"clients"`
	// Tokens are stored as SHA-256 hashes.
	Access  map[string]*issued `json:"access"`
	Refresh map[string]*issued `json:"refresh"`
}

type oauthClient struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedMs    int64    `json:"created_ms"`
}

type issued struct {
	Client    string `json:"client"`
	ExpiresMs int64  `json:"expires_ms"`
}

type authCode struct {
	client, redirect, challenge string
	expires                     time.Time
}

func randToken(prefix string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func hashTok(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// pairingAlphabet avoids look-alike characters (no 0/O, 1/I/L).
const pairingAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

func newPairingCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	var s strings.Builder
	for i, c := range b {
		if i == 4 {
			s.WriteByte('-')
		}
		s.WriteByte(pairingAlphabet[int(c)%len(pairingAlphabet)])
	}
	return s.String()
}

func normPairing(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		return r
	}, strings.TrimSpace(s))
}

// Load reads or creates the state file and a fresh pairing code. Reset
// revokes every connected client and issues a new connect token.
func (h *HTTP) Load(reset bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := &httpState{}
	if b, err := os.ReadFile(h.StatePath); err == nil && !reset {
		if err := json.Unmarshal(b, st); err != nil {
			return fmt.Errorf("%s: %w", h.StatePath, err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if st.Token == "" {
		st.Token = randToken("silk_", 32)
	}
	if st.Clients == nil {
		st.Clients = map[string]*oauthClient{}
	}
	if st.Access == nil {
		st.Access = map[string]*issued{}
	}
	if st.Refresh == nil {
		st.Refresh = map[string]*issued{}
	}
	h.st = st
	h.pair = newPairingCode()
	h.codes = map[string]*authCode{}
	return h.saveLocked()
}

func (h *HTTP) saveLocked() error {
	now := time.Now().UnixMilli()
	for k, v := range h.st.Access {
		if v.ExpiresMs < now {
			delete(h.st.Access, k)
		}
	}
	for k, v := range h.st.Refresh {
		if v.ExpiresMs < now {
			delete(h.st.Refresh, k)
		}
	}
	b, err := json.MarshalIndent(h.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.StatePath), 0o700); err != nil {
		return err
	}
	tmp := h.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.StatePath)
}

// Token is the connect token for header and URL access.
func (h *HTTP) Token() string { h.mu.Lock(); defer h.mu.Unlock(); return h.st.Token }

// PairingCode is what the owner types on the sign-in page.
func (h *HTTP) PairingCode() string { h.mu.Lock(); defer h.mu.Unlock(); return h.pair }

// Clients lists the names of connected OAuth clients.
func (h *HTTP) Clients() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	live := map[string]bool{}
	for _, v := range h.st.Refresh {
		live[v.Client] = true
	}
	var out []string
	for id, c := range h.st.Clients {
		if live[id] {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (h *HTTP) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}

func (h *HTTP) base(r *http.Request) string {
	if h.PublicURL != "" {
		return strings.TrimRight(h.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	path := r.URL.Path
	if path != "/authorize" {
		// Bearer tokens, not cookies, carry authority here, so cross-origin
		// browser clients (e.g. MCP Inspector) are safe to allow.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID")
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	switch {
	case path == "/mcp" || path == "/":
		if path == "/" && r.Method == http.MethodGet {
			h.home(w, r)
			return
		}
		if !h.bearerOK(r) {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+h.base(r)+`/.well-known/oauth-protected-resource", scope="silk"`)
			httpErr(w, http.StatusUnauthorized, "invalid_token", "sign in, or send Authorization: Bearer <token>")
			return
		}
		h.rpc(w, r)
	case strings.HasPrefix(path, "/mcp/"):
		if !equal(strings.TrimPrefix(path, "/mcp/"), h.Token()) {
			http.NotFound(w, r)
			return
		}
		h.rpc(w, r)
	case strings.HasPrefix(path, "/.well-known/oauth-protected-resource"):
		b := h.base(r)
		writeJSON(w, http.StatusOK, map[string]any{"resource": b + "/mcp", "authorization_servers": []string{b},
			"bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"silk"}, "resource_name": "Silk agent " + h.Agent})
	case strings.HasPrefix(path, "/.well-known/oauth-authorization-server"), strings.HasPrefix(path, "/.well-known/openid-configuration"):
		b := h.base(r)
		writeJSON(w, http.StatusOK, map[string]any{"issuer": b, "authorization_endpoint": b + "/authorize", "token_endpoint": b + "/token",
			"registration_endpoint": b + "/register", "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
			"grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"}, "scopes_supported": []string{"silk"},
			"authorization_response_iss_parameter_supported": true})
	case path == "/register":
		h.register(w, r)
	case path == "/authorize":
		h.authorize(w, r)
	case path == "/token":
		h.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, kind, desc string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": desc})
}

func (h *HTTP) bearerOK(r *http.Request) bool {
	tok := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(tok) > 7 && strings.EqualFold(tok[:7], "bearer ") {
		tok = strings.TrimSpace(tok[7:]) // some API clients send the bare token
	}
	if tok == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if equal(tok, h.st.Token) {
		return true
	}
	a, ok := h.st.Access[hashTok(tok)]
	return ok && a.ExpiresMs > time.Now().UnixMilli()
}

// rpc handles one Streamable HTTP POST: a JSON-RPC request, notification,
// or (protocol 2025-03-26) a batch. Responses are plain JSON; this server
// never initiates messages, so GET has no stream to offer.
func (h *HTTP) rpc(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent) // stateless: no session to end
		return
	default:
		w.Header().Set("Allow", "POST, DELETE")
		httpErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST JSON-RPC messages to this endpoint")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		httpErr(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
		return
	}
	body = bytes.TrimSpace(body)
	batch := len(body) > 0 && body[0] == '['
	var reqs []rpcRequest
	if batch {
		err = json.Unmarshal(body, &reqs)
	} else {
		var one rpcRequest
		err = json.Unmarshal(body, &one)
		reqs = []rpcRequest{one}
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	resps := make([]rpcResponse, len(reqs))
	var wg sync.WaitGroup
	for i := range reqs {
		if len(reqs[i].ID) == 0 || reqs[i].Method == "" {
			continue // notification, or a response to a request we never send
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i] = h.Server.respond(r.Context(), &reqs[i])
		}(i)
	}
	wg.Wait()
	var out []rpcResponse
	for i := range reqs {
		if resps[i].JSONRPC != "" {
			out = append(out, resps[i])
		}
	}
	switch {
	case len(out) == 0:
		w.WriteHeader(http.StatusAccepted)
	case batch:
		writeJSON(w, http.StatusOK, out)
	default:
		writeJSON(w, http.StatusOK, out[0])
	}
}

func (h *HTTP) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Silk MCP server for agent %s.\nAdd %s/mcp to your AI agent as a custom MCP connector and sign in with the pairing code shown in the owner's terminal.\n", h.Agent, h.base(r))
}

// validRedirect accepts https URLs, http on loopback (local apps), and
// private-use schemes of native apps; never script or file URLs.
func validRedirect(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Fragment != "" || u.Scheme == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	case "javascript", "data", "file", "vbscript", "blob", "about":
		return false
	}
	return true
}

func (h *HTTP) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST client metadata")
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid_client_metadata", "body must be JSON client metadata")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		httpErr(w, http.StatusBadRequest, "invalid_redirect_uri", "1 to 10 redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if len(u) > 2048 || !validRedirect(u) {
			httpErr(w, http.StatusBadRequest, "invalid_redirect_uri", "unsupported redirect_uri: "+u)
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "an AI agent"
	}
	if len(name) > 100 {
		name = name[:100]
	}
	id := randToken("silkc_", 16)
	now := time.Now()
	h.mu.Lock()
	h.evictClientsLocked()
	h.st.Clients[id] = &oauthClient{Name: name, RedirectURIs: req.RedirectURIs, CreatedMs: now.UnixMilli()}
	err := h.saveLocked()
	h.mu.Unlock()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": id, "client_id_issued_at": now.Unix(), "client_name": name,
		"redirect_uris": req.RedirectURIs, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
}

// evictClientsLocked keeps registration (which needs no credentials) from
// growing without bound: the oldest clients that hold no tokens go first.
func (h *HTTP) evictClientsLocked() {
	if len(h.st.Clients) < maxClients {
		return
	}
	live := map[string]bool{}
	for _, v := range h.st.Refresh {
		live[v.Client] = true
	}
	var idle []string
	for id := range h.st.Clients {
		if !live[id] {
			idle = append(idle, id)
		}
	}
	sort.Slice(idle, func(i, j int) bool { return h.st.Clients[idle[i]].CreatedMs < h.st.Clients[idle[j]].CreatedMs })
	for _, id := range idle {
		if len(h.st.Clients) < maxClients {
			break
		}
		delete(h.st.Clients, id)
	}
}

// consentPage is the sign-in page. It is built with html.EscapeString rather
// than html/template: the template packages' reflection keeps the linker
// from dropping unused methods anywhere in the binary (+3 MB).
func consentPage(w io.Writer, client, agent, host, errMsg string, params map[string]string) {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect to Silk</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1.25rem;color:#111}
h1{font-size:1.4rem;margin:0 0 1rem}p{margin:.6rem 0}code{background:#f2f2f2;padding:.1rem .3rem;border-radius:4px}
input{font:inherit;font-size:1.3rem;letter-spacing:.15em;text-transform:uppercase;width:100%;box-sizing:border-box;padding:.6rem;margin:.4rem 0 1rem;border:1px solid #999;border-radius:6px}
button{font:inherit;padding:.6rem 1.2rem;border-radius:6px;border:1px solid #111;background:#111;color:#fff;cursor:pointer}
button.deny{background:#fff;color:#111;margin-left:.5rem}.err{color:#b00020}.small{color:#555;font-size:.9rem}
</style></head><body>
`)
	fmt.Fprintf(&b, "<h1>Connect %s to Silk</h1>\n", e(client))
	fmt.Fprintf(&b, "<p><b>%s</b> wants to use your Silk agent <b>%s</b>: read its inbox and send messages in conversations you approved. It cannot approve new contacts; that stays with you.</p>\n", e(client), e(agent))
	fmt.Fprintf(&b, "<p class=\"small\">After approving, you return to <code>%s</code>.</p>\n", e(host))
	if errMsg != "" {
		fmt.Fprintf(&b, "<p class=\"err\">%s</p>\n", e(errMsg))
	}
	b.WriteString("<form method=\"post\" action=\"/authorize\">\n")
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "<input type=\"hidden\" name=\"%s\" value=\"%s\">", e(k), e(params[k]))
	}
	b.WriteString(`
<label for="code">Pairing code from the terminal running <code>silk mcp --http</code></label>
<input id="code" name="pairing_code" autocomplete="off" autofocus required maxlength="12" placeholder="XXXX-XXXX">
<button type="submit" name="decision" value="approve">Approve</button><button class="deny" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</form></body></html>`)
	io.WriteString(w, b.String())
}

func (h *HTTP) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	// No form-action directive: approving redirects to the client's own URI,
	// which may be a native app scheme that CSP cannot express.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	q := r.Form
	clientID, redirect, state := q.Get("client_id"), q.Get("redirect_uri"), q.Get("state")
	h.mu.Lock()
	c := h.st.Clients[clientID]
	h.mu.Unlock()
	if c == nil {
		http.Error(w, "unknown client_id: register the client first", http.StatusBadRequest)
		return
	}
	if redirect == "" && len(c.RedirectURIs) == 1 {
		redirect = c.RedirectURIs[0]
	}
	known := false
	for _, u := range c.RedirectURIs {
		known = known || u == redirect
	}
	if !known {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	// From here on, errors go back to the client's redirect URI.
	back := func(params url.Values) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		for k, vs := range params {
			v[k] = vs
		}
		if state != "" {
			v.Set("state", state)
		}
		v.Set("iss", h.base(r))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		back(url.Values{"error": {"invalid_request"}, "error_description": {"PKCE with S256 is required"}})
		return
	}
	u, _ := url.Parse(redirect)
	host := u.Host
	if host == "" {
		host = u.Scheme + ":"
	}
	params := map[string]string{}
	for _, k := range []string{"response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"} {
		if v := q.Get(k); v != "" {
			params[k] = v
		}
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		consentPage(w, c.Name, h.Agent, host, "", params)
		return
	}
	if q.Get("decision") != "approve" {
		back(url.Values{"error": {"access_denied"}})
		return
	}
	h.mu.Lock()
	ok := equal(normPairing(q.Get("pairing_code")), normPairing(h.pair))
	if !ok {
		h.fails++
		if h.fails >= maxPairFails {
			h.fails = 0
			h.pair = newPairingCode()
			h.logf("silk: %d wrong pairing codes; new pairing code: %s", maxPairFails, h.pair)
		}
	} else {
		// Single use: the next agent needs a new code from the terminal.
		h.fails = 0
		h.pair = newPairingCode()
	}
	next := h.pair
	h.mu.Unlock()
	if !ok {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		consentPage(w, c.Name, h.Agent, host, "That pairing code is not right. Use the newest code shown in the terminal running silk mcp --http (each code works once, and 5 wrong tries replace it).", params)
		return
	}
	code := randToken("", 32)
	h.mu.Lock()
	for k, v := range h.codes {
		if time.Now().After(v.expires) {
			delete(h.codes, k)
		}
	}
	h.codes[hashTok(code)] = &authCode{client: clientID, redirect: redirect, challenge: challenge, expires: time.Now().Add(codeTTL)}
	h.mu.Unlock()
	h.logf("silk: approved a connection from %s. Pairing code for the next one: %s", c.Name, next)
	back(url.Values{"code": {code}})
}

func (h *HTTP) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "invalid_request", "POST to the token endpoint")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid_request", "form body required")
		return
	}
	f := r.PostForm
	clientID := f.Get("client_id")
	h.mu.Lock()
	defer h.mu.Unlock()
	switch f.Get("grant_type") {
	case "authorization_code":
		key := hashTok(f.Get("code"))
		c := h.codes[key]
		delete(h.codes, key) // single use, even when the exchange fails
		if c == nil || time.Now().After(c.expires) || c.client != clientID || (f.Get("redirect_uri") != "" && f.Get("redirect_uri") != c.redirect) {
			httpErr(w, http.StatusBadRequest, "invalid_grant", "unknown, expired, or mismatched authorization code")
			return
		}
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !equal(base64.RawURLEncoding.EncodeToString(sum[:]), c.challenge) {
			httpErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	case "refresh_token":
		key := hashTok(f.Get("refresh_token"))
		old := h.st.Refresh[key]
		if old == nil || old.ExpiresMs < time.Now().UnixMilli() || (clientID != "" && old.Client != clientID) {
			httpErr(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh token")
			return
		}
		delete(h.st.Refresh, key) // rotate
		clientID = old.Client
	default:
		httpErr(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	if h.st.Clients[clientID] == nil {
		httpErr(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	access, refresh := randToken("silk_at_", 32), randToken("silk_rt_", 32)
	now := time.Now()
	h.st.Access[hashTok(access)] = &issued{Client: clientID, ExpiresMs: now.Add(accessTTL).UnixMilli()}
	h.st.Refresh[hashTok(refresh)] = &issued{Client: clientID, ExpiresMs: now.Add(refreshTTL).UnixMilli()}
	if err := h.saveLocked(); err != nil {
		httpErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()),
		"refresh_token": refresh, "scope": "silk"})
}

// Serve serves on ln until ctx ends.
func (h *HTTP) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}
