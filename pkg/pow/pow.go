// Package pow implements Silk's proof-of-work postage: a Hashcash-style stamp
// that makes unsolicited contact (and identity creation) cost the sender CPU
// time while costing the relay a single SHA-256 to verify.
//
// stamp hash = SHA-256( SHA-256(domain || 0x00 || prefix) || bits || nonce )
// A stamp is valid when the hash has at least `bits` leading zero bits.
// The inner digest binds the stamp to the exact request, so a stamp cannot be
// reused for a different intro or certificate.
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	DomainIntro    = "silk/v2/pow/intro"
	DomainRegister = "silk/v2/pow/register"
)

// Digest commits to the request a stamp is for.
func Digest(domain string, prefix []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(prefix)
	var d [32]byte
	h.Sum(d[:0])
	return d
}

func stampHash(buf *[41]byte, nonce uint64) uint64 {
	binary.BigEndian.PutUint64(buf[33:], nonce)
	sum := sha256.Sum256(buf[:])
	return binary.BigEndian.Uint64(sum[:8])
}

func seed(d [32]byte, b uint8) *[41]byte {
	var buf [41]byte
	copy(buf[:32], d[:])
	buf[32] = b
	return &buf
}

// Check verifies a stamp. Cost: one SHA-256 compression.
func Check(d [32]byte, b uint8, nonce uint64) bool {
	if b == 0 {
		return true
	}
	if b > 64 {
		return false
	}
	return bits.LeadingZeros64(stampHash(seed(d, b), nonce)) >= int(b)
}

// Solve searches for a nonce using `workers` goroutines (0 = all CPUs).
// Expected work is 2^bits hashes.
func Solve(ctx context.Context, d [32]byte, b uint8, workers int) (uint64, error) {
	if b == 0 {
		return 0, nil
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var start [8]byte
	rand.Read(start[:])
	base := binary.BigEndian.Uint64(start[:])
	var found atomic.Bool
	var result atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			buf := seed(d, b)
			n := base + uint64(w)
			for i := 0; ; i++ {
				if i&0xfff == 0 && (found.Load() || ctx.Err() != nil) {
					return
				}
				if bits.LeadingZeros64(stampHash(buf, n)) >= int(b) {
					if found.CompareAndSwap(false, true) {
						result.Store(n)
					}
					return
				}
				n += uint64(workers)
			}
		}(w)
	}
	wg.Wait()
	if !found.Load() {
		return 0, ctx.Err()
	}
	return result.Load(), nil
}

// ExpectedHashes is the mean number of hashes needed for a stamp of `b` bits.
func ExpectedHashes(b uint8) float64 { return float64(uint64(1) << b) }
