// Package boltkv implements kv.Store on bbolt, a pure-Go copy-on-write B+tree
// (the storage engine of etcd). Reads are zero-copy lookups in a memory map;
// writes are group-committed by one goroutine with one fsync per batch.
package boltkv

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/21J3phy/silk/pkg/kv"
)

var bucket = []byte("kv")

// Options tunes the store.
type Options struct {
	// NoSync skips fsync on commit (benchmarks/tests only; not crash-safe).
	NoSync bool
	// MaxBatch caps Updates per commit (default 512; 1 disables grouping).
	MaxBatch int
}

// Store is a bbolt-backed kv.Store.
type Store struct {
	db       *bolt.DB
	reqs     chan *request
	stop     chan struct{}
	wg       sync.WaitGroup
	closed   atomic.Bool
	maxBatch int

	Batches atomic.Int64
	Updates atomic.Int64
	Rows    atomic.Int64
}

type request struct {
	ctx context.Context
	fn  func(kv.Tx) error
	err chan error
}

// Open opens or creates the database file.
func Open(path string, o Options) (*Store, error) {
	if o.MaxBatch <= 0 {
		o.MaxBatch = 512
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout:         5 * time.Second,
		NoFreelistSync:  true, // freelist is rebuilt on open; commits write less
		FreelistType:    bolt.FreelistMapType,
		InitialMmapSize: 1 << 30, // address space only; avoids remaps blocking readers
		NoSync:          o.NoSync,
	})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, reqs: make(chan *request, 4096), stop: make(chan struct{}), maxBatch: o.MaxBatch}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *Store) Update(ctx context.Context, fn func(kv.Tx) error) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}
	req := &request{ctx: ctx, fn: fn, err: make(chan error, 1)}
	select {
	case s.reqs <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stop:
		return kv.ErrClosed
	}
	return <-req.err
}

func (s *Store) writer() {
	defer s.wg.Done()
	batch := make([]*request, 0, s.maxBatch)
	for {
		var first *request
		select {
		case first = <-s.reqs:
		case <-s.stop:
			for {
				select {
				case r := <-s.reqs:
					r.err <- kv.ErrClosed
				default:
					return
				}
			}
		}
		batch = append(batch[:0], first)
	drain:
		for len(batch) < s.maxBatch {
			select {
			case r := <-s.reqs:
				batch = append(batch, r)
			default:
				break drain
			}
		}
		s.commit(batch)
	}
}

func (s *Store) commit(batch []*request) {
	results := make([]error, len(batch))
	kept, rows := 0, 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		ov := kv.NewOverlay(&boltTx{b: b})
		for i, r := range batch {
			if err := r.ctx.Err(); err != nil {
				results[i] = err
				continue
			}
			ov.Begin()
			if results[i] = safeRun(r.fn, ov); results[i] != nil {
				ov.Discard()
			} else {
				ov.Keep()
				kept++
			}
		}
		if kept == 0 {
			return errNothing
		}
		return ov.Writes(func(k, v []byte, deleted bool) error {
			rows++
			if deleted {
				return b.Delete(k)
			}
			return b.Put(k, v)
		})
	})
	if err == errNothing {
		err = nil
	}
	if err != nil {
		for _, r := range batch {
			r.err <- err
		}
		return
	}
	s.Batches.Add(1)
	s.Updates.Add(int64(kept))
	s.Rows.Add(int64(rows))
	for i, r := range batch {
		r.err <- results[i]
	}
}

var errNothing = fmt.Errorf("boltkv: nothing to commit")

func safeRun(fn func(kv.Tx) error, t kv.Tx) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("transaction panic: %v", p)
		}
	}()
	return fn(t)
}

func (s *Store) View(ctx context.Context, fn func(kv.Tx) error) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}
	return s.db.View(func(tx *bolt.Tx) error {
		return safeRun(fn, &boltTx{b: tx.Bucket(bucket), readOnly: true})
	})
}

func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.stop)
	s.wg.Wait()
	return s.db.Close()
}

// boltTx adapts a bucket. Values returned by Get are copied (bbolt's are only
// valid inside the transaction); Scan values are valid only during the callback.
type boltTx struct {
	b        *bolt.Bucket
	readOnly bool
}

func (t *boltTx) Get(key []byte) ([]byte, error) {
	v := t.b.Get(key)
	if v == nil {
		return nil, nil
	}
	return append([]byte{}, v...), nil
}

func (t *boltTx) GetMany(keys [][]byte) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		if v := t.b.Get(k); v != nil {
			out[i] = append([]byte{}, v...)
		}
	}
	return out, nil
}

func (t *boltTx) Put(key, val []byte) error {
	if t.readOnly {
		return fmt.Errorf("write in read-only transaction")
	}
	return t.b.Put(key, val)
}

func (t *boltTx) Delete(key []byte) error {
	if t.readOnly {
		return fmt.Errorf("write in read-only transaction")
	}
	return t.b.Delete(key)
}

func (t *boltTx) Scan(start, end []byte, limit int, fn func(k, v []byte) bool) error {
	c := t.b.Cursor()
	n := 0
	for k, v := c.Seek(start); k != nil; k, v = c.Next() {
		if end != nil && bytes.Compare(k, end) >= 0 {
			break
		}
		if limit > 0 && n >= limit {
			break
		}
		n++
		if !fn(k, v) {
			break
		}
	}
	return nil
}
