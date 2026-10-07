// Package vectors pins Silk v2's byte-level behavior in docs/v2/test-vectors.json
// so other implementations can check compatibility. Run with -update to regenerate.
package vectors

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/21J3phy/silk/pkg/ledger"
	"github.com/21J3phy/silk/pkg/pow"
	"github.com/21J3phy/silk/pkg/seal"
	"github.com/21J3phy/silk/pkg/wire"
)

var update = flag.Bool("update", false, "rewrite docs/v2/test-vectors.json")

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func h(b []byte) string { return hex.EncodeToString(b) }

func mac(key []byte, label byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte{label})
	return m.Sum(nil)
}

func build(t *testing.T) map[string]any {
	owner := ed25519.NewKeyFromSeed(seed(1))
	agent := ed25519.NewKeyFromSeed(seed(2))
	ownerPub := owner.Public().(ed25519.PublicKey)
	v := map[string]any{"description": "Silk v2 test vectors. All byte strings are hex. Seeds are 32 repeated bytes."}

	id := wire.AgentID(ownerPub, "claude")
	v["identity"] = map[string]any{
		"owner_seed": h(seed(1)), "owner_pub": h(ownerPub), "agent_seed": h(seed(2)), "agent_pub": h(agent.Public().(ed25519.PublicKey)),
		"label": "claude", "agent_id": h(id[:]), "agent_id_text": id.String(),
	}

	// Certificate with a fixed (non-functional) KEM public key: tests encoding and signatures only.
	c := &wire.Cert{Label: "claude", Handle: "alice-claude", Serial: 1, Suite: wire.Suite1, KEMPub: bytes.Repeat([]byte{0xab}, wire.KEMPublicLen),
		Created: 1791400000000, Expires: 1822936000000, MinPoW: 0, Flags: wire.CertAcceptsIntros}
	copy(c.OwnerPub[:], ownerPub)
	copy(c.SignPub[:], agent.Public().(ed25519.PublicKey))
	c.Sign(owner, agent)
	certHash := wire.Hash(c.Raw)
	v["cert"] = map[string]any{"frame": h(c.Raw), "sha256": h(certHash[:])}

	// A message frame with fixed ciphertext bytes.
	var grant wire.ID
	copy(grant[:], bytes.Repeat([]byte{0x11}, 16))
	m := &wire.Msg{GrantID: grant, Dir: wire.DirAB, Seq: 0, Created: 1791400001000, TTL: 3600, CT: bytes.Repeat([]byte{0x22}, 33)}
	m.Sign(agent)
	mid := m.ID()
	v["msg_frame"] = map[string]any{"frame": h(m.Raw), "id": h(mid[:]), "header": h(m.Header())}

	// Ratchet from a fixed root.
	root := seed(9)
	ab, _ := hkdf.Expand(sha256.New, root, "silk/v2 chain a>b", 32)
	ba, _ := hkdf.Expand(sha256.New, root, "silk/v2 chain b>a", 32)
	var steps []map[string]string
	ck := ab
	for n := 0; n < 3; n++ {
		steps = append(steps, map[string]string{"chain_key": h(ck), "message_key": h(mac(ck, 1)), "nonce": h(mac(ck, 3)[:12])})
		ck = mac(ck, 2)
	}
	// Encrypt "hello" as text at position 0 with the message header as AAD.
	s, _ := seal.NewSession(grant, root, true)
	em := &wire.Msg{GrantID: grant, Created: 1791400001000, TTL: 3600}
	if err := s.Encrypt(em, seal.TypeText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(mac(ab, 1))
	g, _ := cipher.NewGCM(blk)
	want := g.Seal(nil, mac(ab, 3)[:12], append([]byte{seal.TypeText}, "hello"...), em.Header())
	if !bytes.Equal(want, em.CT) {
		t.Fatal("ratchet encryption disagrees with the specification")
	}
	v["ratchet"] = map[string]any{"root": h(root), "chain_ab": h(ab), "chain_ba": h(ba), "steps_ab": steps,
		"encrypt_text_hello_at_seq0": map[string]string{"header": h(em.Header()), "ciphertext": h(em.CT)}}

	// Proof of work: smallest valid nonce at 8 bits for a fixed prefix.
	d := pow.Digest(pow.DomainIntro, []byte("silk test prefix"))
	var nonce uint64
	for !pow.Check(d, 8, nonce) {
		nonce++
	}
	v["pow"] = map[string]any{"domain": pow.DomainIntro, "prefix": h([]byte("silk test prefix")), "digest": h(d[:]), "bits": 8, "smallest_nonce": nonce}

	// Ledger: three leaves and the RFC 6962 root.
	leaves := [][]byte{ledger.Leaf(wire.KindCert, 1791400000000, c.Raw), ledger.Leaf(wire.KindMsg, 1791400001000, m.Raw), ledger.Leaf(wire.KindMsg, 1791400002000, []byte("x"))}
	var hashes []tlog.Hash
	reader := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = hashes[x]
		}
		return out, nil
	})
	for i, l := range leaves {
		hs, err := tlog.StoredHashes(int64(i), l, reader)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, hs...)
	}
	rootHash, _ := tlog.TreeHash(3, reader)
	var lh []string
	for _, l := range leaves {
		lh = append(lh, h(l))
	}
	v["ledger"] = map[string]any{"leaves": lh, "root_size_3": h(rootHash[:]), "checkpoint_body": ledger.FormatCheckpoint("example.silk.relay", 3, rootHash)}

	// Signed read header.
	v["auth"] = map[string]any{"header": wire.SignAuth(id, agent, 1791400003000, "GET", "silk-relay.vercel.app", "/v2/inbox?after=0&limit=200&wait=25")}
	return v
}

func TestVectors(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "docs", "v2", "test-vectors.json")
	got, err := json.MarshalIndent(build(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("implementation no longer matches docs/v2/test-vectors.json (an encoding changed; if intended, run with -update and bump the protocol version)")
	}
	_ = context.Background
}
