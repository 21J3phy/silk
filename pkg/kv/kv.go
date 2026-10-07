// Package kv is the storage contract for the Silk relay: ordered byte keys,
// serializable write transactions, and snapshot reads. Domain logic is written
// once against this interface; SQLite and PostgreSQL implement it.
package kv

import (
	"context"
	"encoding/binary"
	"errors"
)

// Tx is a transaction. Writes are visible to later reads in the same Tx.
type Tx interface {
	// Get returns nil, nil when the key is absent.
	Get(key []byte) ([]byte, error)
	// GetMany returns values in key order; missing keys yield nil entries.
	GetMany(keys [][]byte) ([][]byte, error)
	Put(key, val []byte) error
	Delete(key []byte) error
	// Scan visits keys in [start, end) in ascending order until fn returns false or limit is hit (0 = no limit).
	Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error
}

// Store runs transactions.
type Store interface {
	// Update runs fn in a serialized write transaction. Implementations may
	// group several Updates into one durable commit; each fn is isolated by a
	// savepoint, so one failing fn does not affect the others.
	Update(ctx context.Context, fn func(Tx) error) error
	// View runs fn in a read-only snapshot.
	View(ctx context.Context, fn func(Tx) error) error
	Close() error
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("store closed")

// Key builds a key from a one-byte bucket and parts.
func Key(bucket byte, parts ...[]byte) []byte {
	n := 1
	for _, p := range parts {
		n += len(p)
	}
	k := make([]byte, 0, n)
	k = append(k, bucket)
	for _, p := range parts {
		k = append(k, p...)
	}
	return k
}

// U64 encodes an integer so byte order equals numeric order.
func U64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// U32 encodes an integer so byte order equals numeric order.
func U32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// PrefixEnd returns the smallest key greater than every key with this prefix.
func PrefixEnd(prefix []byte) []byte {
	end := append([]byte{}, prefix...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] < 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}
