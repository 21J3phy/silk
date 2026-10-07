// Package ledger is Silk's append-only transparency log. Every protocol event
// (agent registration, intro, grant, decline, message, ack, revoke) appends a
// 41-byte leaf: kind || unix-ms || SHA-256(frame). Leaves reveal no identities
// or content; participants hold the frames and can prove inclusion.
//
// The tree is an RFC 6962 Merkle tree (via golang.org/x/mod/sumdb/tlog, the
// Go checksum database's implementation). Signed tree heads use the C2SP
// tlog-checkpoint format with signed-note Ed25519 signatures, so standard
// transparency tooling and witnesses can verify them.
package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/wire"
)

const (
	bucketLeaf  = 'L'
	bucketHash  = 'H'
	bucketState = 'S'
	LeafLen     = 1 + 8 + 32
)

var stateKey = kv.Key(bucketState, []byte("ledger.size"))

// Leaf builds the leaf for an event.
func Leaf(kind wire.Kind, ms int64, frame []byte) []byte {
	sum := sha256.Sum256(frame)
	b := make([]byte, 0, LeafLen)
	b = append(b, byte(kind))
	b = binary.BigEndian.AppendUint64(b, uint64(ms))
	return append(b, sum[:]...)
}

// ParsedLeaf is a decoded leaf.
type ParsedLeaf struct {
	Kind       wire.Kind
	Millis     int64
	Commitment [32]byte
}

func ParseLeaf(b []byte) (ParsedLeaf, error) {
	var p ParsedLeaf
	if len(b) != LeafLen {
		return p, errors.New("invalid leaf length")
	}
	p.Kind = wire.Kind(b[0])
	p.Millis = int64(binary.BigEndian.Uint64(b[1:9]))
	copy(p.Commitment[:], b[9:])
	return p, nil
}

func reader(tx kv.Tx) tlog.HashReader {
	return tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		keys := make([][]byte, len(idx))
		for i, x := range idx {
			keys[i] = kv.Key(bucketHash, kv.U64(uint64(x)))
		}
		vals, err := tx.GetMany(keys)
		if err != nil {
			return nil, err
		}
		out := make([]tlog.Hash, len(idx))
		for i, v := range vals {
			if len(v) != tlog.HashSize {
				return nil, fmt.Errorf("ledger: missing stored hash %d", idx[i])
			}
			copy(out[i][:], v)
		}
		return out, nil
	})
}

// Size returns the number of leaves.
func Size(tx kv.Tx) (int64, error) {
	v, err := tx.Get(stateKey)
	if err != nil || v == nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(v)), nil
}

// Append adds a leaf and returns its index.
func Append(tx kv.Tx, leaf []byte) (int64, error) {
	n, err := Size(tx)
	if err != nil {
		return 0, err
	}
	hashes, err := tlog.StoredHashes(n, leaf, reader(tx))
	if err != nil {
		return 0, err
	}
	base := tlog.StoredHashIndex(0, n)
	for i, h := range hashes {
		if err := tx.Put(kv.Key(bucketHash, kv.U64(uint64(base+int64(i)))), h[:]); err != nil {
			return 0, err
		}
	}
	if err := tx.Put(kv.Key(bucketLeaf, kv.U64(uint64(n))), leaf); err != nil {
		return 0, err
	}
	return n, tx.Put(stateKey, kv.U64(uint64(n+1)))
}

// Root returns the tree hash at size n.
func Root(tx kv.Tx, n int64) (tlog.Hash, error) {
	if n == 0 {
		return tlog.Hash{}, nil
	}
	return tlog.TreeHash(n, reader(tx))
}

// Leaves returns leaves [start, start+count).
func Leaves(tx kv.Tx, start, count int64) ([][]byte, error) {
	var out [][]byte
	err := tx.Scan(kv.Key(bucketLeaf, kv.U64(uint64(start))), kv.Key(bucketLeaf, kv.U64(uint64(start+count))), int(count), func(_, v []byte) bool {
		out = append(out, append([]byte{}, v...))
		return true
	})
	return out, err
}

// ProveInclusion proves leaf index is in the tree of size n.
func ProveInclusion(tx kv.Tx, index, n int64) (tlog.RecordProof, error) {
	return tlog.ProveRecord(n, index, reader(tx))
}

// ProveConsistency proves the tree of size old is a prefix of the tree of size n.
func ProveConsistency(tx kv.Tx, old, n int64) (tlog.TreeProof, error) {
	return tlog.ProveTree(n, old, reader(tx))
}

// LeafHash is the RFC 6962 leaf hash.
func LeafHash(leaf []byte) tlog.Hash { return tlog.RecordHash(leaf) }

// VerifyInclusion checks a proof that leaf is at index in a tree with the given root.
func VerifyInclusion(proof tlog.RecordProof, size int64, root tlog.Hash, index int64, leaf []byte) error {
	return tlog.CheckRecord(proof, size, root, index, tlog.RecordHash(leaf))
}

// VerifyConsistency checks that oldRoot (size old) is a prefix of newRoot (size n).
func VerifyConsistency(proof tlog.TreeProof, n int64, newRoot tlog.Hash, old int64, oldRoot tlog.Hash) error {
	return tlog.CheckTree(proof, n, newRoot, old, oldRoot)
}

// ---------------------------------------------------------------------------
// Checkpoints (C2SP tlog-checkpoint, signed note).

// Checkpoint is a verified tree head.
type Checkpoint struct {
	Origin string
	Size   int64
	Root   tlog.Hash
	Raw    []byte // full signed note
}

// FormatCheckpoint renders the unsigned checkpoint body.
func FormatCheckpoint(origin string, size int64, root tlog.Hash) string {
	return fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
}

// Signer signs checkpoints with an Ed25519 note key.
type Signer struct {
	Origin   string
	signer   note.Signer
	Verifier note.Verifier
	VKey     string
}

// NewSigner loads a note private key ("PRIVATE+KEY+origin+hash+data").
func NewSigner(skey string) (*Signer, error) {
	s, err := note.NewSigner(skey)
	if err != nil {
		return nil, err
	}
	vkey, err := verifierKeyFor(skey)
	if err != nil {
		return nil, err
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, err
	}
	return &Signer{Origin: s.Name(), signer: s, Verifier: v, VKey: vkey}, nil
}

// GenerateKey creates a new note key pair named origin.
func GenerateKey(origin string) (skey, vkey string, err error) {
	return note.GenerateKey(nil, origin)
}

// verifierKeyFor derives the public verifier key from a private note key.
func verifierKeyFor(skey string) (string, error) {
	// PRIVATE+KEY+<name>+<hash>+<base64(alg||priv)>
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return "", errors.New("malformed note private key")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(raw) != 33 || raw[0] != 1 {
		return "", errors.New("malformed note private key data")
	}
	return note.NewEd25519VerifierKey(parts[2], ed25519FromSeed(raw[1:]))
}

// Sign produces a signed checkpoint for size/root.
func (s *Signer) Sign(size int64, root tlog.Hash) ([]byte, error) {
	return note.Sign(&note.Note{Text: FormatCheckpoint(s.Origin, size, root)}, s.signer)
}

// OpenCheckpoint verifies a signed checkpoint against a verifier key and parses it.
func OpenCheckpoint(raw []byte, vkey string) (*Checkpoint, error) {
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, err
	}
	n, err := note.Open(raw, note.VerifierList(v))
	if err != nil {
		return nil, fmt.Errorf("checkpoint signature: %w", err)
	}
	lines := strings.SplitN(n.Text, "\n", 4)
	if len(lines) < 4 || lines[0] != v.Name() {
		return nil, errors.New("checkpoint origin mismatch")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return nil, errors.New("checkpoint size malformed")
	}
	rootRaw, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rootRaw) != tlog.HashSize {
		return nil, errors.New("checkpoint root malformed")
	}
	cp := &Checkpoint{Origin: lines[0], Size: size, Raw: raw}
	copy(cp.Root[:], rootRaw)
	return cp, nil
}

// SameTree reports whether two checkpoints describe identical trees.
func SameTree(a, b *Checkpoint) bool { return a.Size == b.Size && bytes.Equal(a.Root[:], b.Root[:]) }

func ed25519FromSeed(seed []byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}
