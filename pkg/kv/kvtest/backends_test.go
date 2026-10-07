package kvtest_test

import (
	"context"
	"encoding/binary"
	"sync"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/kvtest"
	"github.com/21J3phy/silk/pkg/kv/pgkv"
	"github.com/21J3phy/silk/pkg/kv/sqlitekv"
)

func TestSQLite(t *testing.T) {
	kvtest.Run(t, func(t *testing.T) kv.Store {
		s, err := sqlitekv.Open(filepath.Join(t.TempDir(), "s.db"), sqlitekv.SQLiteOptions{Synchronous: "NORMAL"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

func TestBolt(t *testing.T) {
	kvtest.Run(t, func(t *testing.T) kv.Store {
		s, err := boltkv.Open(filepath.Join(t.TempDir(), "b.db"), boltkv.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

// TestPostgres runs when SILK_TEST_POSTGRES is a DSN for a disposable database.
func TestPostgres(t *testing.T) {
	dsn := os.Getenv("SILK_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SILK_TEST_POSTGRES to a disposable database to run")
	}
	kvtest.Run(t, func(t *testing.T) kv.Store {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		conn.Exec(ctx, "DROP TABLE IF EXISTS silk_kv")
		conn.Close(ctx)
		s, err := pgkv.Open(ctx, dsn, pgkv.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

// TestPostgresMultiInstance checks that writers in separate instances (separate
// pools, as in separate serverless functions) are serialized.
func TestPostgresMultiInstance(t *testing.T) {
	dsn := os.Getenv("SILK_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SILK_TEST_POSTGRES to a disposable database to run")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	conn.Exec(ctx, "DROP TABLE IF EXISTS silk_kv")
	conn.Close(ctx)
	var stores []kv.Store
	for i := 0; i < 3; i++ {
		s, err := pgkv.Open(ctx, dsn, pgkv.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		stores = append(stores, s)
	}
	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(s kv.Store) {
			defer wg.Done()
			err := s.Update(ctx, func(tx kv.Tx) error {
				v, err := tx.Get([]byte("ctr"))
				if err != nil {
					return err
				}
				var n uint64
				if len(v) == 8 {
					n = binary.BigEndian.Uint64(v)
				}
				return tx.Put([]byte("ctr"), kv.U64(n+1))
			})
			if err != nil {
				t.Error(err)
			}
		}(stores[i%3])
	}
	wg.Wait()
	stores[0].View(ctx, func(tx kv.Tx) error {
		v, _ := tx.Get([]byte("ctr"))
		if binary.BigEndian.Uint64(v) != 300 {
			t.Errorf("counter = %d, want 300 (lost updates across instances)", binary.BigEndian.Uint64(v))
		}
		return nil
	})
}
