package kvtest_test

import (
	"path/filepath"
	"testing"

	"github.com/21J3phy/silk/pkg/kv"
	"github.com/21J3phy/silk/pkg/kv/boltkv"
	"github.com/21J3phy/silk/pkg/kv/kvtest"
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
