package pgkv

import (
	"strings"
	"testing"
)

func TestExistingOnlyBootstrapNeverCreatesSchema(t *testing.T) {
	sql := bootstrapStatement(true)
	if sql != "SELECT k, v FROM silk_kv LIMIT 0" || strings.Contains(strings.ToUpper(sql), "CREATE") {
		t.Fatalf("unexpected migration bootstrap: %s", sql)
	}
	if bootstrapStatement(false) != schema {
		t.Fatal("normal bootstrap changed")
	}
}
