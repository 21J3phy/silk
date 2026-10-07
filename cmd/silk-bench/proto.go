package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/relay"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

// countingConn counts bytes written to and read from the network.
type countingConn struct {
	net.Conn
	r, w *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.r.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.w.Add(int64(n))
	return n, err
}

// api is a minimal HTTP client for the relay with byte accounting.
type api struct {
	base     string
	http     *http.Client
	sent, rx atomic.Int64
}

func newAPI(base string, conns int) *api {
	a := &api{base: base}
	d := &net.Dialer{Timeout: 5 * time.Second}
	a.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		MaxIdleConns: conns * 2, MaxIdleConnsPerHost: conns * 2, MaxConnsPerHost: conns * 2, IdleConnTimeout: time.Minute,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &countingConn{Conn: c, r: &a.rx, w: &a.sent}, nil
		},
	}}
	return a
}

type apiErr struct {
	status int
	body   string
}

func (e *apiErr) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }

func (a *api) do(ctx context.Context, method, path string, body []byte, auth string) ([]byte, http.Header, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if auth != "" {
		req.Header.Set("Silk-Auth", auth)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, nil, &apiErr{resp.StatusCode, string(data)}
	}
	return data, resp.Header, nil
}

func (a *api) submit(ctx context.Context, frame []byte) (*relay.Result, error) {
	data, _, err := a.do(ctx, "POST", "/v2/frames", frame, "")
	if err != nil {
		return nil, err
	}
	var r relay.Result
	return &r, json.Unmarshal(data, &r)
}

// agent is a protocol-level identity held in memory.
type agent struct {
	owner, sign ed25519.PrivateKey
	kem         *seal.KEMKey
	cert        *wire.Cert
	id          wire.ID
}

func newAgent(ctx context.Context, a *api, label string, regBits uint8) (*agent, error) {
	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	kem, err := seal.NewKEMKey()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c := &wire.Cert{Label: label, Serial: 1, Suite: wire.Suite1, KEMPub: kem.Public(), Created: now.UnixMilli(),
		Expires: now.Add(24 * time.Hour).UnixMilli(), Flags: wire.CertAcceptsIntros}
	copy(c.OwnerPub[:], owner.Public().(ed25519.PublicKey))
	copy(c.SignPub[:], sign.Public().(ed25519.PublicKey))
	c.Sign(owner, sign)
	nonce, err := pow.Solve(ctx, pow.Digest(pow.DomainRegister, c.Raw), regBits, 0)
	if err != nil {
		return nil, err
	}
	if _, _, err := a.do(ctx, "POST", "/v2/agents", relay.EncodeRegistration(c.Raw, regBits, nonce), ""); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return &agent{owner: owner, sign: sign, kem: kem, cert: c, id: c.ID()}, nil
}

func (ag *agent) auth(method, path string) string {
	return wire.SignAuth(ag.id, ag.sign, time.Now().UnixMilli(), method, path)
}

// pair is an established conversation with both sides' ratchets in memory.
type pair struct {
	a, b       *agent
	grant      wire.ID
	sessA      *seal.Session
	sessB      *seal.Session
	budget     uint32
	cursorB    uint64
	cursorA    uint64
}

func handshake(ctx context.Context, a *api, x, y *agent, budget uint32) (*pair, error) {
	var info relay.AgentInfo
	data, _, err := a.do(ctx, "GET", "/v2/agents/"+y.id.String()+"?from="+x.id.String(), nil, "")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	now := time.Now()
	in := &wire.Intro{From: x.id, To: y.id, ToSerial: 1, Created: now.UnixMilli(), Expires: now.Add(time.Hour).UnixMilli(),
		Scope: "bench", Budget: budget, GrantTTL: 86400}
	rand.Read(in.IntroID[:])
	eph, _ := seal.NewKEMKey()
	in.EphPub = eph.Public()
	k1, err := seal.SealIntro(in, y.cert.KEMPub, "benchmark")
	if err != nil {
		return nil, err
	}
	nonce, err := pow.Solve(ctx, pow.Digest(pow.DomainIntro, in.PoWPrefix()), info.IntroPoWBits, 0)
	if err != nil {
		return nil, err
	}
	in.PoWBits, in.PoWNonce = info.IntroPoWBits, nonce
	in.Sign(x.sign)
	if _, err := a.submit(ctx, in.Raw); err != nil {
		return nil, fmt.Errorf("intro: %w", err)
	}
	_, k1b, err := seal.OpenIntro(in, y.kem)
	if err != nil {
		return nil, err
	}
	g := &wire.Grant{GrantID: in.IntroID, IntroHash: wire.Hash(in.Raw), From: x.id, To: y.id, Created: now.UnixMilli(),
		Expires: now.Add(24 * time.Hour).UnixMilli(), BudgetAB: budget, BudgetBA: budget, Rate: wire.MaxRate}
	copy(g.OwnerPub[:], y.owner.Public().(ed25519.PublicKey))
	k2, err := seal.SealGrant(g, in.EphPub)
	if err != nil {
		return nil, err
	}
	g.Sign(y.owner)
	if _, err := a.submit(ctx, g.Raw); err != nil {
		return nil, fmt.Errorf("grant: %w", err)
	}
	rootB, _ := seal.Root(k1b, k2, g.IntroHash, g)
	k2a, err := seal.OpenGrant(g, eph)
	if err != nil {
		return nil, err
	}
	rootA, _ := seal.Root(k1, k2a, g.IntroHash, g)
	sa, _ := seal.NewSession(g.GrantID, rootA, true)
	sb, _ := seal.NewSession(g.GrantID, rootB, false)
	return &pair{a: x, b: y, grant: g.GrantID, sessA: sa, sessB: sb, budget: budget}, nil
}

// sealAB builds a signed, encrypted A->B message frame.
func (p *pair) sealAB(body []byte) (*wire.Msg, error) {
	m := &wire.Msg{GrantID: p.grant, Created: time.Now().UnixMilli(), TTL: 3600}
	if err := p.sessA.Encrypt(m, seal.TypeText, body); err != nil {
		return nil, err
	}
	m.Sign(p.a.sign)
	return m, nil
}

func (p *pair) ackFrame(m *wire.Msg) []byte {
	a := &wire.Ack{MsgID: m.ID(), GrantID: p.grant, Outcome: wire.AckReceived, Created: time.Now().UnixMilli()}
	return a.Sign(p.b.sign)
}
