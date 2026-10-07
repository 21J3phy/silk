// Package kvtest is a conformance suite for kv.Store implementations.
package kvtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"

	"github.com/21J3phy/silk/pkg/kv"
)

// Run exercises a fresh store returned by open.
func Run(t *testing.T, open func(t *testing.T) kv.Store) {
	ctx := context.Background()
	t.Run("ReadYourWritesAndScan", func(t *testing.T) {
		s := open(t)
		err := s.Update(ctx, func(tx kv.Tx) error {
			for i := 0; i < 10; i++ {
				tx.Put(kv.Key('a', kv.U64(uint64(i))), []byte{byte(i)})
			}
			v, err := tx.Get(kv.Key('a', kv.U64(3)))
			if err != nil || !bytes.Equal(v, []byte{3}) {
				return fmt.Errorf("read-your-write: %v %v", v, err)
			}
			tx.Delete(kv.Key('a', kv.U64(4)))
			var got []byte
			tx.Scan(kv.Key('a', kv.U64(2)), kv.Key('a', kv.U64(7)), 0, func(k, v []byte) bool { got = append(got, v[0]); return true })
			if !bytes.Equal(got, []byte{2, 3, 5, 6}) {
				return fmt.Errorf("scan in tx: %v", got)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		s.View(ctx, func(tx kv.Tx) error {
			var got []byte
			tx.Scan([]byte{'a'}, kv.PrefixEnd([]byte{'a'}), 3, func(k, v []byte) bool { got = append(got, v[0]); return true })
			if !bytes.Equal(got, []byte{0, 1, 2}) {
				t.Errorf("scan limit: %v", got)
			}
			vals, _ := tx.GetMany([][]byte{kv.Key('a', kv.U64(9)), kv.Key('a', kv.U64(4)), kv.Key('a', kv.U64(1)), kv.Key('a', kv.U64(9))})
			if !bytes.Equal(vals[0], []byte{9}) || vals[1] != nil || !bytes.Equal(vals[2], []byte{1}) || !bytes.Equal(vals[3], []byte{9}) {
				t.Errorf("GetMany: %v", vals)
			}
			return nil
		})
	})
	t.Run("EmptyValuesArePresent", func(t *testing.T) {
		s := open(t)
		if err := s.Update(ctx, func(tx kv.Tx) error {
			if err := tx.Put([]byte("e1"), nil); err != nil {
				return err
			}
			return tx.Put([]byte("e2"), []byte{})
		}); err != nil {
			t.Fatal(err)
		}
		s.View(ctx, func(tx kv.Tx) error {
			for _, k := range []string{"e1", "e2"} {
				v, err := tx.Get([]byte(k))
				if err != nil || v == nil || len(v) != 0 {
					t.Errorf("%s: got %v, %v; want present empty value", k, v, err)
				}
			}
			n := 0
			tx.Scan([]byte("e"), []byte("f"), 0, func(k, v []byte) bool { n++; return true })
			if n != 2 {
				t.Errorf("scan saw %d empty-valued keys, want 2", n)
			}
			return nil
		})
	})
	t.Run("FailedUpdateIsIsolated", func(t *testing.T) {
		s := open(t)
		boom := errors.New("boom")
		var wg sync.WaitGroup
		errs := make([]error, 64)
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = s.Update(ctx, func(tx kv.Tx) error {
					tx.Put(kv.Key('b', kv.U64(uint64(i))), []byte("x"))
					if i%3 == 0 {
						return boom
					}
					return nil
				})
			}(i)
		}
		wg.Wait()
		s.View(ctx, func(tx kv.Tx) error {
			for i := 0; i < 64; i++ {
				v, _ := tx.Get(kv.Key('b', kv.U64(uint64(i))))
				if i%3 == 0 && (v != nil || !errors.Is(errs[i], boom)) {
					t.Errorf("failed update %d leaked (%v, %v)", i, v, errs[i])
				}
				if i%3 != 0 && (v == nil || errs[i] != nil) {
					t.Errorf("update %d lost (%v)", i, errs[i])
				}
			}
			return nil
		})
	})
	t.Run("ConcurrentCountersAreSerialized", func(t *testing.T) {
		s := open(t)
		var wg sync.WaitGroup
		for i := 0; i < 200; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.Update(ctx, func(tx kv.Tx) error {
					v, _ := tx.Get([]byte("ctr"))
					n := uint64(0)
					if len(v) == 8 {
						n = uint64(v[0])<<56 | uint64(v[1])<<48 | uint64(v[2])<<40 | uint64(v[3])<<32 | uint64(v[4])<<24 | uint64(v[5])<<16 | uint64(v[6])<<8 | uint64(v[7])
					}
					return tx.Put([]byte("ctr"), kv.U64(n+1))
				})
			}()
		}
		wg.Wait()
		s.View(ctx, func(tx kv.Tx) error {
			v, _ := tx.Get([]byte("ctr"))
			if !bytes.Equal(v, kv.U64(200)) {
				t.Errorf("counter = %x, want 200", v)
			}
			return nil
		})
	})
	t.Run("RandomizedModel", func(t *testing.T) {
		s := open(t)
		model := map[string][]byte{}
		r := rand.New(rand.NewPCG(1, 2))
		for round := 0; round < 200; round++ {
			pending := map[string][]byte{}
			fail := r.IntN(5) == 0
			err := s.Update(ctx, func(tx kv.Tx) error {
				for j := 0; j < 1+r.IntN(8); j++ {
					k := []byte{'r', byte(r.IntN(40))}
					if r.IntN(3) == 0 {
						tx.Delete(k)
						pending[string(k)] = nil
					} else {
						v := []byte{byte(round), byte(j)}
						tx.Put(k, v)
						pending[string(k)] = v
					}
				}
				if fail {
					return errors.New("abort")
				}
				return nil
			})
			if fail != (err != nil) {
				t.Fatalf("round %d err=%v", round, err)
			}
			if !fail {
				for k, v := range pending {
					if v == nil {
						delete(model, k)
					} else {
						model[k] = v
					}
				}
			}
		}
		var keys []string
		for k := range model {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		s.View(ctx, func(tx kv.Tx) error {
			var got []string
			tx.Scan([]byte{'r'}, []byte{'s'}, 0, func(k, v []byte) bool {
				got = append(got, string(k))
				if !bytes.Equal(model[string(k)], v) {
					t.Errorf("value mismatch for %x", k)
				}
				return true
			})
			if fmt.Sprint(got) != fmt.Sprint(keys) {
				t.Errorf("keys mismatch:\n got %x\nwant %x", got, keys)
			}
			return nil
		})
	})
}
