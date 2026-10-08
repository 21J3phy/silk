package wire

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrOwnerSig means an owner signature does not match the request it answers.
var ErrOwnerSig = errors.New("the signature is not the owner's signature on this request")

// Owner signatures made on another device. An agent that runs away from its
// owner (on its own cloud computer, say) builds a frame without the owner's
// signature, the owner signs those exact bytes where the owner key lives, and
// the agent attaches the signature. Only kinds an owner signs qualify, so a
// request can never get the owner to sign a message, an ack or a release.

// Unsigned returns the bytes the owner signs to delegate this certificate.
func (c *Cert) Unsigned() []byte { return c.body() }

// Unsigned returns the bytes the owner signs to approve this grant.
func (g *Grant) Unsigned(owner ed25519.PublicKey) []byte {
	copy(g.OwnerPub[:], owner)
	return g.body()
}

// Unsigned returns the bytes the owner signs to decline the intro.
func (d *Decline) Unsigned(owner ed25519.PublicKey) []byte {
	copy(d.OwnerPub[:], owner)
	return d.body()
}

// Unsigned returns the bytes the owner signs to revoke as owner.
func (v *Revoke) Unsigned() []byte { return v.body() }

// Unsigned returns the bytes the owner signs to publish this policy.
func (p *Policy) Unsigned(owner ed25519.PublicKey) []byte {
	copy(p.OwnerPub[:], owner)
	return p.body()
}

// Unsigned returns the bytes the owner signs to issue this invite.
func (t *Ticket) Unsigned(owner ed25519.PublicKey) []byte {
	copy(t.OwnerPub[:], owner)
	return t.body()
}

// DecodeUnsigned parses an unsigned owner frame body. It returns a *Cert,
// *Grant, *Decline, *Revoke (owner role only), *Policy or *Ticket whose
// signatures are zero.
func DecodeUnsigned(body []byte) (any, error) {
	if len(body) < 2 || body[0] != Version {
		return nil, fmt.Errorf("%w: not a v%d frame", ErrMalformed, Version)
	}
	sigs := make([]byte, SigLen)
	if Kind(body[1]) == KindCert {
		sigs = make([]byte, 2*SigLen)
	}
	b := append(append([]byte{}, body...), sigs...)
	switch Kind(body[1]) {
	case KindCert:
		return DecodeCert(b)
	case KindGrant:
		return DecodeGrant(b)
	case KindDecline:
		return DecodeDecline(b)
	case KindRevoke:
		v, err := DecodeRevoke(b)
		if err == nil && v.Role != RoleOwner {
			return nil, fmt.Errorf("%w: an agent revocation is not signed by the owner", ErrMalformed)
		}
		return v, err
	case KindPolicy:
		return DecodePolicy(b)
	case KindTicket:
		return DecodeTicket(b)
	}
	return nil, fmt.Errorf("%w: %v frames are not signed by an owner", ErrMalformed, Kind(body[1]))
}

// ownerDomain is the domain of the owner signature over an unsigned body.
func ownerDomain(body []byte) (string, error) {
	if _, err := DecodeUnsigned(body); err != nil {
		return "", err
	}
	switch Kind(body[1]) {
	case KindCert:
		return DomainCertOwner, nil
	case KindGrant:
		return DomainGrant, nil
	case KindDecline:
		return DomainDecline, nil
	case KindRevoke:
		return DomainRevoke, nil
	case KindPolicy:
		return DomainPolicy, nil
	}
	return DomainTicket, nil
}

// SignOwner signs an unsigned owner frame body with the owner key.
func SignOwner(owner ed25519.PrivateKey, body []byte) ([]byte, error) {
	domain, err := ownerDomain(body)
	if err != nil {
		return nil, err
	}
	return signWith(owner, domain, body), nil
}

// AttachOwner completes an unsigned body with the owner's signature after
// checking it against owner, and returns the frame. A certificate also needs
// the agent's signing key, which adds the agent's proof of possession.
func AttachOwner(body, sig []byte, owner ed25519.PublicKey, agent ed25519.PrivateKey) ([]byte, error) {
	domain, err := ownerDomain(body)
	if err != nil {
		return nil, err
	}
	if len(sig) != SigLen || !Verify(owner, domain, body, sig) {
		return nil, ErrOwnerSig
	}
	raw := append(append([]byte{}, body...), sig...)
	if Kind(body[1]) == KindCert {
		raw = append(raw, signWith(agent, DomainCertAgent, body)...)
	}
	return raw, nil
}
