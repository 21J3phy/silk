package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/21J3phy/silk/pkg/wire"
)

// Protocol identifies the wire protocol served under /v2.
const Protocol = "silk/2"

// MinClient is the oldest client version this relay accepts frames from.
const MinClient = "2.0.0"

// HTTPOptions configures the HTTP front end.
type HTTPOptions struct {
	// TrustProxy uses the first X-Forwarded-For address for rate limiting (set behind a trusted proxy such as Vercel).
	TrustProxy bool
	// PostRate and GetRate are per-IP requests/second (defaults 30 and 60; negative disables).
	PostRate, GetRate float64
	// RegisterRate is per-IP new identities/second (default 1/60 with a burst of 10; negative disables).
	RegisterRate float64
	// MaxWait bounds inbox long-polls (default 25s).
	MaxWait time.Duration
	Logger  *slog.Logger
}

// Handler serves the relay API.
func Handler(r *Relay, o HTTPOptions) http.Handler {
	if o.PostRate == 0 {
		o.PostRate = 30
	}
	if o.GetRate == 0 {
		o.GetRate = 60
	}
	if o.MaxWait == 0 {
		o.MaxWait = 25 * time.Second
	}
	if o.RegisterRate == 0 {
		o.RegisterRate = 1.0 / 60
	}
	h := &httpAPI{r: r, o: o, post: newLimiter(o.PostRate), get: newLimiter(o.GetRate), reg: newLimiter(o.RegisterRate)}
	if o.RegisterRate > 0 {
		h.reg.burst = 10
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /v2/info", h.public(h.info))
	mux.HandleFunc("GET /.well-known/silk", h.public(h.wellKnown))
	mux.HandleFunc("GET /v2/stats", h.public(h.stats))
	mux.HandleFunc("POST /v2/agents", h.register)
	mux.HandleFunc("GET /v2/agents/{ref}", h.public(h.agent))
	mux.HandleFunc("POST /v2/frames", h.submit)
	mux.HandleFunc("POST /v2/frames/batch", h.batch)
	mux.HandleFunc("GET /v2/inbox", h.inbox)
	mux.HandleFunc("GET /v2/messages/{id}", h.message)
	mux.HandleFunc("GET /v2/ledger/checkpoint", h.public(h.checkpoint))
	mux.HandleFunc("GET /v2/ledger/leaves", h.public(h.leaves))
	mux.HandleFunc("GET /v2/ledger/proof", h.public(h.proof))
	mux.HandleFunc("GET /v2/ledger/consistency", h.public(h.consistency))
	mux.HandleFunc("GET /v2/ledger/find", h.public(h.find))
	mux.HandleFunc("GET /v2/release", h.public(h.release))
	mux.HandleFunc("GET /v2/release/manifest", h.public(h.manifest))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		writeErr(w, errf(404, "not_found", "no route %s %s", req.Method, req.URL.Path))
	})
	return h.wrap(mux)
}

type httpAPI struct {
	r              *Relay
	o              HTTPOptions
	post, get, reg *limiter
}

func (h *httpAPI) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Silk-Protocol", Protocol)
		if req.Method == http.MethodOptions {
			hd.Set("Access-Control-Allow-Origin", "*")
			hd.Set("Access-Control-Allow-Methods", "GET")
			hd.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		lim := h.get
		if req.Method == http.MethodPost {
			lim = h.post
		}
		if !lim.allow(h.clientIP(req)) {
			hd.Set("Retry-After", "1")
			writeErr(w, errf(429, "slow_down", "too many requests from this address"))
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (h *httpAPI) clientIP(req *http.Request) string {
	if h.o.TrustProxy {
		// Vercel sets this itself; clients cannot forge it.
		if v := req.Header.Get("X-Vercel-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
		if ip := req.Header.Get("X-Real-Ip"); ip != "" {
			return ip
		}
		// Otherwise trust only the address our own proxy appended (the last entry).
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func (h *httpAPI) public(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fn(w, req)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			e = errf(503, "timeout", "request deadline passed; retry with the same frame")
		} else {
			slog.Error("relay internal error", "err", err)
			e = errf(500, "internal", "the relay could not complete the request; retrying the identical frame is safe")
		}
	}
	writeJSON(w, e.Status, map[string]any{"error": e})
}

func readBody(w http.ResponseWriter, req *http.Request, max int64) ([]byte, error) {
	ct := req.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/octet-stream") && !strings.HasPrefix(ct, "application/vnd.silk") {
		return nil, errf(415, "content_type", "send frames as application/octet-stream")
	}
	buf := bodyPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bodyPool.Put(buf)
	if _, err := buf.ReadFrom(http.MaxBytesReader(w, req.Body, max)); err != nil {
		return nil, errf(413, "too_large", "request body exceeds %d bytes", max)
	}
	return bytes.Clone(buf.Bytes()), nil
}

var bodyPool = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 2048)) }}

func (h *httpAPI) health(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "protocol": Protocol})
}

func (h *httpAPI) info(w http.ResponseWriter, req *http.Request) {
	cfg := h.r.cfg
	writeJSON(w, 200, map[string]any{
		"protocol":   Protocol,
		"software":   h.r.Version,
		"min_client": MinClient,
		"origin":     h.r.Origin(),
		"ledger_key": h.r.VerifierKey(),
		"suite":      "MLKEM768-X25519 HPKE + HKDF-SHA256 + AES-256-GCM; Ed25519 signatures; RFC 6962 ledger",
		"time_ms":    time.Now().UnixMilli(),
		"pow": map[string]any{
			"algorithm":       "sha256-hashcash",
			"register_bits":   cfg.RegisterBits,
			"intro_base_bits": cfg.IntroBaseBits,
			"max_surge_bits":  cfg.MaxSurgeBits,
		},
		"limits": map[string]any{
			"max_frame_bytes":       wire.MaxFrame,
			"max_plaintext_bytes":   wire.MaxPlaintext,
			"max_note_bytes":        wire.MaxNote,
			"max_clock_skew_ms":     wire.MaxClockSkew.Milliseconds(),
			"max_message_ttl_s":     int(wire.MaxMsgTTL.Seconds()),
			"max_pending_intros":    cfg.MaxPendingPerRecipient,
			"max_outstanding_intro": cfg.MaxOutstandingPerSender,
		},
	})
}

func (h *httpAPI) stats(w http.ResponseWriter, req *http.Request) {
	s, err := h.r.Stats(req.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (h *httpAPI) register(w http.ResponseWriter, req *http.Request) {
	if !h.reg.allow(h.clientIP(req)) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, errf(429, "slow_down", "too many new identities from this address; try again later"))
		return
	}
	body, err := readBody(w, req, wire.MaxFrame+16)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := h.r.Register(req.Context(), body)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (h *httpAPI) agent(w http.ResponseWriter, req *http.Request) {
	var from wire.ID
	if f := req.URL.Query().Get("from"); f != "" {
		// A sender-specific price reveals whether the sender is trusted and its
		// penalty, so only the sender itself may ask (signed request).
		id, err := wire.ParseID(f)
		if err != nil {
			writeErr(w, errf(400, "invalid_ref", "from must be an agent id"))
			return
		}
		authed, err := h.authenticate(req)
		if err != nil {
			writeErr(w, err)
			return
		}
		if authed != id {
			writeErr(w, errf(403, "not_you", "a sender-specific price can only be requested by that sender"))
			return
		}
		from = id
	}
	info, err := h.r.LookupAgent(req.Context(), req.PathValue("ref"), from)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, info)
}

func (h *httpAPI) submit(w http.ResponseWriter, req *http.Request) {
	body, err := readBody(w, req, wire.MaxFrame)
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := h.r.Submit(req.Context(), body)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

// MaxBatch is the number of frames accepted in one batch request.
const MaxBatch = 64

// BatchItem is one frame's outcome in a batch.
type BatchItem struct {
	*Result
	Error *Error `json:"error,omitempty"`
}

// EncodeBatch frames a batch body: repeated u32 length | frame.
func EncodeBatch(frames [][]byte) []byte {
	var b []byte
	for _, f := range frames {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func (h *httpAPI) batch(w http.ResponseWriter, req *http.Request) {
	body, err := readBody(w, req, 1<<20)
	if err != nil {
		writeErr(w, err)
		return
	}
	var frames [][]byte
	for len(body) > 0 {
		if len(body) < 4 {
			writeErr(w, errf(400, "malformed", "truncated batch"))
			return
		}
		n := binary.BigEndian.Uint32(body)
		if uint64(n) > uint64(len(body)-4) || n > wire.MaxFrame {
			writeErr(w, errf(400, "malformed", "invalid batch frame length"))
			return
		}
		frames = append(frames, body[4:4+n])
		body = body[4+n:]
		if len(frames) > MaxBatch {
			writeErr(w, errf(413, "too_large", "batches are limited to %d frames", MaxBatch))
			return
		}
	}
	if len(frames) > 1 && !h.post.allowN(h.clientIP(req), float64(len(frames)-1)) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, errf(429, "slow_down", "too many frames from this address"))
		return
	}
	out := make([]BatchItem, len(frames))
	var wg sync.WaitGroup
	for i, f := range frames {
		wg.Add(1)
		go func(i int, f []byte) {
			defer wg.Done()
			res, err := h.r.Submit(req.Context(), f)
			if err != nil {
				var e *Error
				if !errors.As(err, &e) {
					slog.Error("relay batch item error", "err", err)
					e = errf(500, "internal", "retry this frame")
				}
				out[i] = BatchItem{Error: e}
				return
			}
			out[i] = BatchItem{Result: res}
		}(i, f)
	}
	wg.Wait()
	writeJSON(w, 200, out)
}

// authenticate verifies the Silk-Auth header for a read.
func (h *httpAPI) authenticate(req *http.Request) (wire.ID, error) {
	v := req.Header.Get(wire.AuthHeader)
	if v == "" {
		return wire.ID{}, errf(401, "auth_required", "sign this request with a %s header", wire.AuthHeader)
	}
	p, err := wire.ParseAuth(v)
	if err != nil {
		return wire.ID{}, errf(401, "auth_invalid", "%v", err)
	}
	if d := time.Since(time.UnixMilli(p.TS)); d > 2*time.Minute || d < -2*time.Minute {
		return wire.ID{}, errf(401, "auth_expired", "request signature is outside the 2 minute window")
	}
	pub, err := h.r.AuthKey(req.Context(), p.Agent)
	if err != nil {
		return wire.ID{}, err
	}
	if !p.Verify(pub, req.Method, req.Host, req.URL.RequestURI()) {
		return wire.ID{}, errf(401, "auth_invalid", "request signature does not verify")
	}
	return p.Agent, nil
}

func queryInt(req *http.Request, name string, def int64) (int64, error) {
	s := req.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, errf(400, "invalid_query", "%s must be a non-negative integer", name)
	}
	return v, nil
}

// EncodeEvents is the binary inbox format: repeated
// u64 seq | u8 kind | i64 ms | i64 ledgerIdx | 16 ref | u32 len | frame.
func EncodeEvents(evs []*Event) []byte {
	n := 0
	for _, ev := range evs {
		n += 45 + len(ev.Frame)
	}
	b := make([]byte, 0, n)
	for _, ev := range evs {
		b = binary.BigEndian.AppendUint64(b, ev.Seq)
		b = append(b, byte(ev.Kind))
		b = binary.BigEndian.AppendUint64(b, uint64(ev.Millis))
		b = binary.BigEndian.AppendUint64(b, uint64(ev.LedgerIdx))
		b = append(b, ev.Ref[:]...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(ev.Frame)))
		b = append(b, ev.Frame...)
	}
	return b
}

// DecodeEvents parses EncodeEvents output.
func DecodeEvents(b []byte) ([]*Event, error) {
	var out []*Event
	for len(b) > 0 {
		if len(b) < 45 {
			return nil, errors.New("truncated event")
		}
		ev := &Event{Seq: binary.BigEndian.Uint64(b), Kind: wire.Kind(b[8]), Millis: int64(binary.BigEndian.Uint64(b[9:])),
			LedgerIdx: int64(binary.BigEndian.Uint64(b[17:]))}
		copy(ev.Ref[:], b[25:41])
		n := binary.BigEndian.Uint32(b[41:])
		if uint64(n) > uint64(len(b)-45) {
			return nil, errors.New("truncated event frame")
		}
		ev.Frame = b[45 : 45+n]
		b = b[45+n:]
		out = append(out, ev)
	}
	return out, nil
}

func (h *httpAPI) inbox(w http.ResponseWriter, req *http.Request) {
	agent, err := h.authenticate(req)
	if err != nil {
		writeErr(w, err)
		return
	}
	after, err := queryInt(req, "after", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	limit, err := queryInt(req, "limit", 100)
	if err != nil {
		writeErr(w, err)
		return
	}
	waitS, err := queryInt(req, "wait", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	wait := time.Duration(waitS) * time.Second
	if wait > h.o.MaxWait {
		wait = h.o.MaxWait
	}
	evs, err := h.r.WaitInbox(req.Context(), agent, uint64(after), int(limit), wait)
	if err != nil {
		writeErr(w, err)
		return
	}
	cursor := uint64(after)
	if len(evs) > 0 {
		cursor = evs[len(evs)-1].Seq
	}
	w.Header().Set("Content-Type", "application/vnd.silk.events")
	w.Header().Set("Silk-Cursor", strconv.FormatUint(cursor, 10))
	w.WriteHeader(200)
	w.Write(EncodeEvents(evs))
}

func (h *httpAPI) message(w http.ResponseWriter, req *http.Request) {
	agent, err := h.authenticate(req)
	if err != nil {
		writeErr(w, err)
		return
	}
	id, err := wire.ParseID(req.PathValue("id"))
	if err != nil {
		writeErr(w, errf(400, "invalid_id", "invalid message id"))
		return
	}
	st, err := h.r.MessageStatus(req.Context(), agent, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (h *httpAPI) checkpoint(w http.ResponseWriter, req *http.Request) {
	raw, _, err := h.r.Checkpoint(req.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write(raw)
}

func (h *httpAPI) leaves(w http.ResponseWriter, req *http.Request) {
	start, err := queryInt(req, "start", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	count, err := queryInt(req, "count", 1000)
	if err != nil {
		writeErr(w, err)
		return
	}
	leaves, err := h.r.Leaves(req.Context(), start, count)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	for _, l := range leaves {
		w.Write(l)
	}
}

func (h *httpAPI) proof(w http.ResponseWriter, req *http.Request) {
	index, err := queryInt(req, "index", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	size, err := queryInt(req, "size", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	p, err := h.r.InclusionProof(req.Context(), index, size)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *httpAPI) consistency(w http.ResponseWriter, req *http.Request) {
	old, err := queryInt(req, "old", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	size, err := queryInt(req, "size", 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	p, err := h.r.ConsistencyProof(req.Context(), old, size)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (h *httpAPI) find(w http.ResponseWriter, req *http.Request) {
	c, err := hex.DecodeString(req.URL.Query().Get("commitment"))
	if err != nil || len(c) != 32 {
		writeErr(w, errf(400, "invalid_query", "commitment must be 64 hex characters (SHA-256 of a frame)"))
		return
	}
	idx, err := h.r.Find(req.Context(), c)
	if err != nil {
		writeErr(w, err)
		return
	}
	if idx < 0 {
		writeErr(w, errf(404, "not_found", "no ledger entry for that commitment"))
		return
	}
	writeJSON(w, 200, map[string]int64{"index": idx})
}

// ---------------------------------------------------------------------------
// Per-IP token bucket (per process; a first line of defense, not the only one).

type limiter struct {
	rate  float64
	burst float64 // 0 = 4 seconds' worth
	mu    sync.Mutex
	b     map[string]*bucket
	sweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate float64) *limiter { return &limiter{rate: rate, b: map[string]*bucket{}} }

func (l *limiter) allow(key string) bool { return l.allowN(key, 1) }

// allowN takes n tokens at once (all or nothing).
func (l *limiter) allowN(key string, n float64) bool {
	if l.rate < 0 {
		return true
	}
	now := time.Now()
	burst := l.burst
	if burst == 0 {
		burst = l.rate * 4
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.sweep) > time.Minute {
		idle := time.Duration(burst/l.rate) * time.Second // time to refill completely
		for k, b := range l.b {
			if now.Sub(b.last) > idle {
				delete(l.b, k)
			}
		}
		l.sweep = now
	}
	b := l.b[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		l.b[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func (h *httpAPI) release(w http.ResponseWriter, req *http.Request) {
	info, err := h.r.LatestRelease(req.Context(), req.URL.Query().Get("version"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, info)
}

// manifest serves the latest release's manifest JSON for installers. Clients
// that can, verify the signed frame from /v2/release instead.
func (h *httpAPI) manifest(w http.ResponseWriter, req *http.Request) {
	info, err := h.r.LatestRelease(req.Context(), "")
	if err != nil {
		writeErr(w, err)
		return
	}
	rel, err := wire.DecodeRelease(info.Frame)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !h.r.VerifyRelease(rel) {
		writeErr(w, errf(500, "release_unverified", "the stored release does not verify against this relay's release keys"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(rel.Manifest)
}

// wellKnown is a machine-readable description for agents and tools discovering
// this relay: what it is, how to install a client, and how to connect it to an
// AI agent over MCP.
func (h *httpAPI) wellKnown(w http.ResponseWriter, req *http.Request) {
	base := "https://" + req.Host
	writeJSON(w, 200, map[string]any{
		"name":        "Silk",
		"description": "Consent-first, end-to-end encrypted messaging between AI agents, with a public transparency ledger and proof-of-work postage against spam.",
		"protocol":    Protocol,
		"relay":       base,
		"api":         base + "/v2",
		"ledger":      map[string]any{"origin": h.r.Origin(), "key": h.r.VerifierKey(), "checkpoint": base + "/v2/ledger/checkpoint"},
		"install":     map[string]any{"script": base + "/install.sh", "manifest": base + "/v2/release/manifest", "verify": "silk self-verify"},
		"mcp": map[string]any{
			"transport": "stdio",
			"command":   "silk",
			"args":      []string{"mcp"},
			"setup":     map[string]string{"claude_code": "claude mcp add silk -- silk mcp", "codex": "[mcp_servers.silk]\ncommand = \"silk\"\nargs = [\"mcp\"]"},
			"tools":     []string{"silk_whoami", "silk_inbox", "silk_send", "silk_ack", "silk_request_contact", "silk_conversations", "silk_message_status", "silk_revoke", "silk_audit"},
		},
		"docs":       "https://github.com/21J3phy/silk",
		"benchmarks": base + "/benchmarks",
		"llms_txt":   base + "/llms.txt",
	})
}
