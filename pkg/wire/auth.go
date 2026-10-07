package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// AuthHeader is the HTTP header carrying a signed read request.
const AuthHeader = "Silk-Auth"

func authBody(agent ID, ts int64, method, pathQuery string) []byte {
	b := make([]byte, 0, IDLen+8+len(method)+1+len(pathQuery))
	b = append(b, agent[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(ts))
	b = append(b, method...)
	b = append(b, '\n')
	b = append(b, pathQuery...)
	return b
}

// SignAuth produces a Silk-Auth header value binding the agent, time, method, and exact path+query.
func SignAuth(agent ID, key ed25519.PrivateKey, ts int64, method, pathQuery string) string {
	sig := Sign(key, DomainAuth, authBody(agent, ts, method, pathQuery))
	return "v2 " + agent.String() + " " + strconv.FormatInt(ts, 10) + " " + base64.RawURLEncoding.EncodeToString(sig)
}

// ParsedAuth is a decoded Silk-Auth header awaiting signature verification.
type ParsedAuth struct {
	Agent ID
	TS    int64
	sig   []byte
}

// ParseAuth decodes a Silk-Auth header value.
func ParseAuth(v string) (*ParsedAuth, error) {
	parts := strings.Split(v, " ")
	if len(parts) != 4 || parts[0] != "v2" || len(v) > 200 {
		return nil, fmt.Errorf("malformed %s header", AuthHeader)
	}
	id, err := ParseID(parts[1])
	if err != nil {
		return nil, err
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || ts <= 0 {
		return nil, fmt.Errorf("malformed %s timestamp", AuthHeader)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(sig) != SigLen {
		return nil, fmt.Errorf("malformed %s signature", AuthHeader)
	}
	return &ParsedAuth{Agent: id, TS: ts, sig: sig}, nil
}

// Verify checks the header signature against the agent's signing key.
func (p *ParsedAuth) Verify(pub []byte, method, pathQuery string) bool {
	return Verify(pub, DomainAuth, authBody(p.Agent, p.TS, method, pathQuery), p.sig)
}
