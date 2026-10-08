package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/21J3phy/silk/pkg/client"
)

// Without an identity the server still starts, lists its tools, and every
// tool explains the one-time setup instead of the client seeing a crash.
func TestServesSetupHelpBeforeInit(t *testing.T) {
	opens := 0
	s := &Server{Version: "test", Open: func() (*client.Agent, error) { opens++; return nil, errors.New("no agent selected") }}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"silk_whoami","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"silk_nope","arguments":{}}}
`)
	var out bytes.Buffer
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	resps := map[int]map[string]any{} // by request id: responses may arrive in any order
	dec := json.NewDecoder(&out)
	for dec.More() {
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		resps[int(r["id"].(float64))-1] = r
	}
	if len(resps) != 4 {
		t.Fatalf("got %d responses", len(resps))
	}
	if tools := resps[1]["result"].(map[string]any)["tools"].([]any); len(tools) != 9 {
		t.Fatalf("tools/list returned %d tools", len(tools))
	}
	res := resps[2]["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != true || !strings.Contains(text, "silk init") {
		t.Fatalf("whoami before init: %v", res)
	}
	if resps[3]["error"] == nil {
		t.Fatal("unknown tool did not return a JSON-RPC error")
	}
	if opens != 1 {
		t.Fatalf("Open called %d times, want once per known tool call", opens)
	}
}
