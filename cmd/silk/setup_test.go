package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testBin = "/opt/silk/bin/silk"

var testSpec = serverSpec{Command: testBin, Args: []string{"mcp"}}

// fakeMachine has a temporary home, no agent CLIs on PATH and an empty
// environment, so tests never touch the real machine.
func fakeMachine(t *testing.T) *machine {
	t.Helper()
	return &machine{
		home:     t.TempDir(),
		goos:     "linux",
		getenv:   func(string) string { return "" },
		lookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			t.Fatalf("unexpected CLI run: %s %v", name, args)
			return nil, nil
		},
	}
}

func setupT(t *testing.T, m *machine, s serverSpec, mode setupMode, ids ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := setupMain(context.Background(), m, &globals{}, s, mode, ids, &out); err != nil {
		t.Fatalf("setup %v %v: %v\n%s", mode, ids, err, out.String())
	}
	return out.String()
}

func setupJSON(t *testing.T, m *machine, s serverSpec, mode setupMode, ids ...string) []setupResult {
	t.Helper()
	var out bytes.Buffer
	if err := setupMain(context.Background(), m, &globals{json: true}, s, mode, ids, &out); err != nil {
		t.Fatalf("setup %v %v: %v\n%s", mode, ids, err, out.String())
	}
	var rs []setupResult
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil {
		t.Fatalf("--json output is not a JSON array: %v\n%s", err, out.String())
	}
	return rs
}

func one(t *testing.T, m *machine, s serverSpec, mode setupMode, id string) setupResult {
	t.Helper()
	rs := setupJSON(t, m, s, mode, id)
	if len(rs) != 1 {
		t.Fatalf("want 1 result, got %+v", rs)
	}
	return rs[0]
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func wantFile(t *testing.T, path, want string) {
	t.Helper()
	if got := readFile(t, path); got != want {
		t.Fatalf("%s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func noFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s should not exist (err %v)", path, err)
	}
}

func TestSetupCreatesNewFile(t *testing.T) {
	m := fakeMachine(t)
	r := one(t, m, testSpec, modeInstall, "cursor")
	p := filepath.Join(m.home, ".cursor", "mcp.json")
	if r.Status != statusAdded || r.Path != p || r.Method != "file" || r.Backup != "" {
		t.Fatalf("result %+v", r)
	}
	wantFile(t, p, `{
  "mcpServers": {
    "silk": {
      "type": "stdio",
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ]
    }
  }
}
`)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode %v, want 0600", fi.Mode().Perm())
	}
	noFile(t, p+backupSuffix)
}

const desktopBefore = `{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "zeta": {"command": "z", "args": ["--x"]},
    "alpha": {
      "command": "a",
      "env": {"K": "1.50", "N": 1e3, "U": "\u00e9<&>"}
    }
  },
  "preferences": {"b": 2, "a": 1},
  "num": 1.0
}
`

func TestSetupMergePreservesOrderAndBytes(t *testing.T) {
	m := fakeMachine(t)
	p := filepath.Join(m.home, ".config", "Claude", "claude_desktop_config.json")
	writeFile(t, p, desktopBefore, 0o640)

	if r := one(t, m, testSpec, modeInstall, "claude-desktop"); r.Status != statusAdded || r.Backup != p+backupSuffix {
		t.Fatalf("result %+v", r)
	}
	wantFile(t, p, `{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "zeta": {"command": "z", "args": ["--x"]},
    "alpha": {
      "command": "a",
      "env": {"K": "1.50", "N": 1e3, "U": "\u00e9<&>"}
    },
    "silk": {
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ]
    }
  },
  "preferences": {"b": 2, "a": 1},
  "num": 1.0
}
`)
	wantFile(t, p+backupSuffix, desktopBefore)
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640 kept", fi.Mode().Perm())
	}

	// Removing gives back the original file exactly.
	if r := one(t, m, testSpec, modeRemove, "claude-desktop"); r.Status != statusRemoved {
		t.Fatalf("remove %+v", r)
	}
	wantFile(t, p, desktopBefore)
	wantFile(t, p+backupSuffix, desktopBefore)
}

// Indentation, line endings, a byte order mark and a missing final newline
// all survive an add followed by a remove.
func TestSetupRoundTripKeepsFormatting(t *testing.T) {
	for name, before := range map[string]string{
		"tabs":       "{\n\t\"mcpServers\": {\n\t\t\"a\": {\n\t\t\t\"command\": \"a\"\n\t\t}\n\t},\n\t\"x\": [1, 2]\n}\n",
		"four":       "{\n    \"mcpServers\": {\n        \"a\": {\"command\": \"a\"}\n    }\n}",
		"crlf":       "{\r\n  \"mcpServers\": {\r\n    \"a\": {\r\n      \"command\": \"a\"\r\n    }\r\n  }\r\n}\r\n",
		"bom":        "\ufeff{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"a\"}\n  }\n}\n",
		"escapedKey": "{\n  \"caf\\u00e9\": {},\n  \"mcpServers\": {\n    \"\\u0061\": {\"command\": \"a\"}\n  }\n}\n"} {
		t.Run(name, func(t *testing.T) {
			m := fakeMachine(t)
			p := filepath.Join(m.home, ".cursor", "mcp.json")
			writeFile(t, p, before, 0o600)
			if r := one(t, m, testSpec, modeInstall, "cursor"); r.Status != statusAdded {
				t.Fatalf("add %+v", r)
			}
			mid := readFile(t, p)
			var v map[string]any
			if err := json.Unmarshal(bytes.TrimPrefix([]byte(mid), utf8BOM), &v); err != nil {
				t.Fatalf("result is not JSON: %v\n%s", err, mid)
			}
			if name == "crlf" && strings.Count(mid, "\n") != strings.Count(mid, "\r\n") {
				t.Fatalf("mixed line endings:\n%q", mid)
			}
			if name == "tabs" && !strings.Contains(mid, "\n\t\t\"silk\": {\n\t\t\t\"type\"") {
				t.Fatalf("silk entry not tab-indented:\n%s", mid)
			}
			if r := one(t, m, testSpec, modeRemove, "cursor"); r.Status != statusRemoved {
				t.Fatalf("remove %+v", r)
			}
			wantFile(t, p, before)
		})
	}
}

func TestSetupIdempotent(t *testing.T) {
	m := fakeMachine(t)
	p := filepath.Join(m.home, ".config", "Claude", "claude_desktop_config.json")
	writeFile(t, p, desktopBefore, 0o600)
	one(t, m, testSpec, modeInstall, "claude-desktop")
	after := readFile(t, p)
	fi1, _ := os.Stat(p)
	for range 2 {
		if r := one(t, m, testSpec, modeInstall, "claude-desktop"); r.Status != statusSet || r.Backup != "" {
			t.Fatalf("second run %+v", r)
		}
	}
	wantFile(t, p, after)
	if fi2, _ := os.Stat(p); !fi2.ModTime().Equal(fi1.ModTime()) {
		t.Fatal("an unchanged config was rewritten")
	}
	out := setupT(t, m, testSpec, modeInstall, "claude-desktop")
	if !strings.Contains(out, "already set") || strings.Contains(out, "Restart") {
		t.Fatalf("human output:\n%s", out)
	}
	// The list reports it as configured.
	var list bytes.Buffer
	if err := setupMain(context.Background(), m, &globals{json: true}, testSpec, modeList, nil, &list); err != nil {
		t.Fatal(err)
	}
	var rows []agentInfo
	json.Unmarshal(list.Bytes(), &rows)
	for _, r := range rows {
		if r.Agent == "claude-desktop" && (r.Silk != "configured" || !r.Detected) {
			t.Fatalf("list row %+v", r)
		}
	}
}

func TestSetupUpdatesStaleEntry(t *testing.T) {
	m := fakeMachine(t)
	p := filepath.Join(m.home, ".cline", "data", "settings", "cline_mcp_settings.json")
	writeFile(t, p, `{
  "mcpServers": {
    "silk": {
      "autoApprove": ["silk_inbox"],
      "command": "/usr/local/Cellar/silk/2.0.0/bin/silk",
      "args": ["mcp"],
      "env": {"SILK_HOME": "/old"},
      "disabled": false
    },
    "other": {"command": "o"}
  }
}
`, 0o600)
	if r := one(t, m, testSpec, modeInstall, "cline"); r.Status != statusUpdated || r.Backup == "" {
		t.Fatalf("result %+v", r)
	}
	// Setup's keys are rewritten in place, the stale env is dropped, and the
	// user's autoApprove and disabled settings are kept.
	wantFile(t, p, `{
  "mcpServers": {
    "silk": {
      "autoApprove": ["silk_inbox"],
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ],
      "disabled": false
    },
    "other": {"command": "o"}
  }
}
`)
	if r := one(t, m, testSpec, modeInstall, "cline"); r.Status != statusSet {
		t.Fatalf("after update %+v", r)
	}
	// A later change does not overwrite the backup of the original.
	s2 := testSpec
	s2.Args = []string{"mcp", "--agent", "work"}
	if r := one(t, m, s2, modeInstall, "cline"); r.Status != statusUpdated || r.Backup != "" {
		t.Fatalf("second update %+v", r)
	}
	if !strings.Contains(readFile(t, p+backupSuffix), "/usr/local/Cellar/silk/2.0.0/bin/silk") {
		t.Fatal("backup of the original was overwritten")
	}
}

func TestSetupRemove(t *testing.T) {
	m := fakeMachine(t)
	cursor := filepath.Join(m.home, ".cursor", "mcp.json")
	kiro := filepath.Join(m.home, ".kiro", "settings", "mcp.json")
	writeFile(t, kiro, `{"mcpServers": {"other": {"command": "o"}}}`, 0o600)
	setupT(t, m, testSpec, modeInstall, "cursor", "kiro")
	wantFile(t, kiro, `{
  "mcpServers": {
    "other": {"command": "o"},
    "silk": {
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ]
    }
  }
}`)

	// With no agents named, --remove visits only the configured ones.
	rs := setupJSON(t, m, testSpec, modeRemove)
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.Agent+"="+r.Status)
	}
	if !slices.Equal(ids, []string{"cursor=removed", "kiro=removed"}) {
		t.Fatalf("remove results %v", ids)
	}
	wantFile(t, cursor, "{\n  \"mcpServers\": {}\n}\n")
	wantFile(t, kiro, "{\n  \"mcpServers\": {\n    \"other\": {\"command\": \"o\"}\n  }\n}")

	if r := one(t, m, testSpec, modeRemove, "kiro"); r.Status != statusAbsent {
		t.Fatalf("second remove %+v", r)
	}
	if r := one(t, m, testSpec, modeRemove, "gemini"); r.Status != statusAbsent {
		t.Fatalf("remove from a missing file %+v", r)
	}
	noFile(t, filepath.Join(m.home, ".gemini", "settings.json"))
	if out := setupT(t, m, testSpec, modeRemove); !strings.Contains(out, "No agent has Silk configured") {
		t.Fatalf("remove with nothing configured:\n%s", out)
	}
}

func TestSetupRefusesJSONC(t *testing.T) {
	for name, content := range map[string]string{
		"comment":        "// Zed settings\n{\n  \"theme\": \"One Dark\"\n}\n",
		"block comment":  "{\n  /* mine */ \"theme\": \"One Dark\"\n}\n",
		"trailing comma": "{\n  \"theme\": \"One Dark\",\n}\n",
		"two objects":    "{}\n{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := fakeMachine(t)
			p := filepath.Join(m.home, ".config", "zed", "settings.json")
			writeFile(t, p, content, 0o600)
			r := one(t, m, testSpec, modeInstall, "zed")
			if r.Status != statusManual || !strings.Contains(r.Detail, "not strict JSON") || !strings.Contains(r.Snippet, `"context_servers"`) {
				t.Fatalf("result %+v", r)
			}
			wantFile(t, p, content)
			noFile(t, p+backupSuffix)
			out := setupT(t, m, testSpec, modeInstall, "zed")
			if !strings.Contains(out, `"context_servers": {`) || !strings.Contains(out, testBin) {
				t.Fatalf("human output lacks the snippet:\n%s", out)
			}
			if r := one(t, m, testSpec, modeRemove, "zed"); r.Status != statusManual {
				t.Fatalf("remove %+v", r)
			}
			wantFile(t, p, content)
		})
	}
}

func TestSetupRefusesAmbiguousJSON(t *testing.T) {
	for name, content := range map[string]string{
		"duplicate container": `{"mcpServers": {}, "mcpServers": {}}`,
		"duplicate silk":      `{"mcpServers": {"silk": {}, "silk": {}}}`,
		"container not obj":   `{"mcpServers": []}`,
		"not an object":       `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			m := fakeMachine(t)
			p := filepath.Join(m.home, ".cursor", "mcp.json")
			writeFile(t, p, content, 0o600)
			if r := one(t, m, testSpec, modeInstall, "cursor"); r.Status != statusManual {
				t.Fatalf("result %+v", r)
			}
			wantFile(t, p, content)
		})
	}
}

const codexBefore = `# my Codex settings
model = "gpt-5"

[mcp_servers.other]
command = "npx"
args = ["-y", "other"]

[profiles.fast]
model = "mini"
`

func TestSetupCodexTOML(t *testing.T) {
	m := fakeMachine(t)
	p := filepath.Join(m.home, ".codex", "config.toml")
	writeFile(t, p, codexBefore, 0o600)
	if r := one(t, m, testSpec, modeInstall, "codex"); r.Status != statusAdded || r.Method != "file" {
		t.Fatalf("result %+v", r)
	}
	wantFile(t, p, codexBefore+`
[mcp_servers.silk]
command = "/opt/silk/bin/silk"
args = ["mcp"]
`)
	if r := one(t, m, testSpec, modeInstall, "codex"); r.Status != statusSet {
		t.Fatalf("second run %+v", r)
	}
	if r := one(t, m, testSpec, modeRemove, "codex"); r.Status != statusRemoved {
		t.Fatalf("remove %+v", r)
	}
	wantFile(t, p, codexBefore)
	wantFile(t, p+backupSuffix, codexBefore)
}

func TestSetupCodexTOMLWrittenByCodex(t *testing.T) {
	// The layout `codex mcp add` writes: an env subtable, between other tables.
	before := `model = "gpt-5"

[mcp_servers.silk]
command = "/opt/silk/bin/silk"
args = ["mcp"]

[mcp_servers.silk.env]
SILK_HOME = "/srv/silk"

[profiles.fast]
model = "mini"
`
	m := fakeMachine(t)
	m.getenv = func(k string) string {
		if k == "CODEX_HOME" {
			return filepath.Join(m.home, "codex-home")
		}
		return ""
	}
	p := filepath.Join(m.home, "codex-home", "config.toml")
	writeFile(t, p, before, 0o600)
	withEnv := serverSpec{Command: testBin, Args: []string{"mcp"}, Env: map[string]string{"SILK_HOME": "/srv/silk"}}
	if r := one(t, m, withEnv, modeInstall, "codex"); r.Status != statusSet {
		t.Fatalf("identical entry: %+v", r)
	}
	if r := one(t, m, testSpec, modeInstall, "codex"); r.Status != statusUpdated {
		t.Fatalf("update %+v", r)
	}
	wantFile(t, p, `model = "gpt-5"

[mcp_servers.silk]
command = "/opt/silk/bin/silk"
args = ["mcp"]

[profiles.fast]
model = "mini"
`)
	if r := one(t, m, testSpec, modeRemove, "codex"); r.Status != statusRemoved {
		t.Fatalf("remove %+v", r)
	}
	wantFile(t, p, "model = \"gpt-5\"\n\n[profiles.fast]\nmodel = \"mini\"\n")
}

func TestSetupTOMLRefusesOtherLayouts(t *testing.T) {
	for name, content := range map[string]string{
		"dotted keys":  "[mcp_servers]\nsilk.command = \"x\"\n",
		"inline table": "mcp_servers.silk = { command = \"x\" }\n",
		"inline all":   "mcp_servers = { silk = { command = \"x\" } }\n",
		"twice":        "[mcp_servers.silk]\ncommand = \"a\"\n[mcp_servers.silk]\ncommand = \"b\"\n",
		"orphan sub":   "[mcp_servers.silk.env]\nA = \"b\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := fakeMachine(t)
			p := filepath.Join(m.home, ".grok", "config.toml")
			writeFile(t, p, content, 0o600)
			if r := one(t, m, testSpec, modeInstall, "grok"); r.Status != statusManual || !strings.Contains(r.Snippet, "[mcp_servers.silk]") {
				t.Fatalf("result %+v", r)
			}
			wantFile(t, p, content)
		})
	}
}

func TestSetupGrokTOML(t *testing.T) {
	m := fakeMachine(t)
	m.getenv = func(k string) string {
		if k == "GROK_HOME" {
			return filepath.Join(m.home, "g")
		}
		return ""
	}
	p := filepath.Join(m.home, "g", "config.toml")
	before := "[ui]\ntheme = \"dark\"" // no final newline
	writeFile(t, p, before, 0o600)
	s := serverSpec{Command: `C:\Program Files\silk\silk.exe`, Args: []string{"mcp", "--agent", "grok"}, Env: map[string]string{"SILK_HOME": `D:\silk "home"`}}
	if r := one(t, m, s, modeInstall, "grok"); r.Status != statusAdded {
		t.Fatalf("result %+v", r)
	}
	wantFile(t, p, `[ui]
theme = "dark"

[mcp_servers.silk]
command = "C:\\Program Files\\silk\\silk.exe"
args = ["mcp", "--agent", "grok"]
env = { SILK_HOME = "D:\\silk \"home\"" }
`)
	if r := one(t, m, s, modeInstall, "grok"); r.Status != statusSet {
		t.Fatalf("escaped values do not round-trip: %+v", r)
	}
	if r := one(t, m, s, modeRemove, "grok"); r.Status != statusRemoved {
		t.Fatalf("remove %+v", r)
	}
	wantFile(t, p, "[ui]\ntheme = \"dark\"\n")
}

func TestParseTOMLBody(t *testing.T) {
	v := map[string]any{}
	err := parseTOMLBody(`command = 'C:\silk.exe' # literal
args = [
  "mcp", # first
  "--agent",
  "a\u00e9",
]
env.SILK_HOME = "/x"
"quoted key" = { a = "b", c = true }
startup_timeout_sec = 20`, v)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"command":             `C:\silk.exe`,
		"args":                []any{"mcp", "--agent", "aé"},
		"env":                 map[string]any{"SILK_HOME": "/x"},
		"quoted key":          map[string]any{"a": "b", "c": true},
		"startup_timeout_sec": "20",
	}
	got, _ := json.Marshal(v)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("got %s\nwant %s", got, exp)
	}
	for _, bad := range []string{`command = """x"""`, `command = "x" extra`, `args = ["a" "b"]`} {
		if err := parseTOMLBody(bad, map[string]any{}); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestSetupMuseSchemaVersion(t *testing.T) {
	m := fakeMachine(t)
	p := filepath.Join(m.home, ".config", "muse", "settings.json")
	if r := one(t, m, testSpec, modeInstall, "muse"); r.Status != statusAdded {
		t.Fatalf("result %+v", r)
	}
	wantFile(t, p, `{
  "schema_version": 1,
  "mcp_servers": {
    "silk": {
      "transport": "stdio",
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ],
      "mode": "optional"
    }
  }
}
`)

	// An existing file keeps its keys; the user's "mode" choice is respected.
	writeFile(t, p, `{
  "schema_version": 1,
  "model": "muse-large",
  "mcp_servers": {
    "silk": {"transport": "stdio", "command": "/opt/silk/bin/silk", "args": ["mcp"], "mode": "required"}
  }
}
`, 0o600)
	if r := one(t, m, testSpec, modeInstall, "muse"); r.Status != statusSet {
		t.Fatalf("user-chosen mode should count as set: %+v", r)
	}

	for name, content := range map[string]string{
		"missing":    `{"model": "muse-large"}`,
		"other":      `{"schema_version": 2}`,
		"mcpServers": `{"schema_version": 1, "mcpServers": {"silk": {"command": "x"}}}`,
	} {
		writeFile(t, p, content, 0o600)
		if r := one(t, m, testSpec, modeInstall, "muse"); r.Status != statusManual {
			t.Fatalf("%s: %+v", name, r)
		}
		wantFile(t, p, content)
	}
}

func TestSetupVSCodeShape(t *testing.T) {
	m := fakeMachine(t)
	m.goos = "darwin"
	p := filepath.Join(m.home, "Library", "Application Support", "Code", "User", "mcp.json")
	writeFile(t, p, "{\n\t\"inputs\": [],\n\t\"servers\": {}\n}", 0o600)
	setupT(t, m, testSpec, modeInstall, "vscode")
	wantFile(t, p, "{\n\t\"inputs\": [],\n\t\"servers\": {\n\t\t\"silk\": {\n\t\t\t\"type\": \"stdio\",\n\t\t\t\"command\": \"/opt/silk/bin/silk\",\n\t\t\t\"args\": [\n\t\t\t\t\"mcp\"\n\t\t\t]\n\t\t}\n\t}\n}")
}

func TestSetupOpencodeShape(t *testing.T) {
	m := fakeMachine(t)
	dir := filepath.Join(m.home, ".config", "opencode")
	s := serverSpec{Command: testBin, Args: []string{"mcp"}, Env: map[string]string{"SILK_HOME": "/x"}}
	setupT(t, m, s, modeInstall, "opencode")
	wantFile(t, filepath.Join(dir, "opencode.json"), `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "silk": {
      "type": "local",
      "command": [
        "/opt/silk/bin/silk",
        "mcp"
      ],
      "enabled": true,
      "environment": {
        "SILK_HOME": "/x"
      }
    }
  }
}
`)
	// A user who switched Silk off keeps it off.
	writeFile(t, filepath.Join(dir, "opencode.jsonc"), `{"mcp": {"silk": {"type": "local", "command": ["/opt/silk/bin/silk", "mcp"], "enabled": false, "environment": {"SILK_HOME": "/x"}}}}`, 0o600)
	if r := one(t, m, s, modeInstall, "opencode"); r.Status != statusSet || filepath.Base(r.Path) != "opencode.jsonc" {
		t.Fatalf("result %+v", r)
	}
}

func TestSetupCopilotCLIShape(t *testing.T) {
	m := fakeMachine(t)
	setupT(t, m, testSpec, modeInstall, "copilot-cli")
	var v struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(m.home, ".copilot", "mcp-config.json"))), &v); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(v.MCPServers["silk"])
	if string(got) != `{"args":["mcp"],"command":"/opt/silk/bin/silk","tools":["*"],"type":"local"}` {
		t.Fatalf("entry %s", got)
	}
}

func TestSetupFollowsSymlinkedConfig(t *testing.T) {
	m := fakeMachine(t)
	real := filepath.Join(m.home, "dotfiles", "mcp.json")
	writeFile(t, real, `{"mcpServers": {}}`, 0o600)
	link := filepath.Join(m.home, ".cursor", "mcp.json")
	os.MkdirAll(filepath.Dir(link), 0o755)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	setupT(t, m, testSpec, modeInstall, "cursor")
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
	if !strings.Contains(readFile(t, real), testBin) {
		t.Fatal("the link target was not updated")
	}
}

func TestSetupDetectsInstalledAgents(t *testing.T) {
	m := fakeMachine(t)
	os.MkdirAll(filepath.Join(m.home, ".cursor"), 0o755)
	os.MkdirAll(filepath.Join(m.home, ".config", "goose"), 0o755)
	rs := setupJSON(t, m, testSpec, modeInstall)
	var got []string
	for _, r := range rs {
		got = append(got, r.Agent+"="+r.Status)
	}
	if !slices.Equal(got, []string{"cursor=added", "goose=manual"}) {
		t.Fatalf("results %v", got)
	}
	if !strings.Contains(rs[1].Snippet, "cmd: \"/opt/silk/bin/silk\"") {
		t.Fatalf("goose snippet:\n%s", rs[1].Snippet)
	}
	noFile(t, filepath.Join(m.home, ".config", "goose", "config.yaml"))

	if out := setupT(t, fakeMachine(t), testSpec, modeInstall); !strings.Contains(out, "No supported agents found") {
		t.Fatalf("nothing installed:\n%s", out)
	}
}

func TestSetupJSONOutput(t *testing.T) {
	m := fakeMachine(t)
	var out bytes.Buffer
	if err := setupMain(context.Background(), m, &globals{json: true}, testSpec, modeInstall, []string{"gemini", "goose"}, &out); err != nil {
		t.Fatal(err)
	}
	var rs []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(rs) != 2 || rs[0]["agent"] != "gemini" || rs[0]["status"] != "added" || rs[0]["method"] != "file" ||
		rs[0]["path"] != filepath.Join(m.home, ".gemini", "settings.json") || rs[1]["status"] != "manual" || rs[1]["snippet"] == "" {
		t.Fatalf("json %s", out.String())
	}

	out.Reset()
	if err := setupMain(context.Background(), m, &globals{json: true}, testSpec, modeRemove, []string{"cursor"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "[") {
		t.Fatalf("remove json %s", out.String())
	}

	out.Reset()
	if err := setupMain(context.Background(), m, &globals{json: true}, testSpec, modePrint, []string{"codex"}, &out); err != nil {
		t.Fatal(err)
	}
	var ps []agentSnippet
	if err := json.Unmarshal(out.Bytes(), &ps); err != nil || len(ps) != 1 ||
		ps[0].Command != "codex mcp add silk -- /opt/silk/bin/silk mcp" || !strings.HasPrefix(ps[0].Snippet, "[mcp_servers.silk]\n") {
		t.Fatalf("print json %v %s", err, out.String())
	}

	out.Reset()
	if err := setupMain(context.Background(), m, &globals{json: true}, testSpec, modeList, nil, &out); err != nil {
		t.Fatal(err)
	}
	var rows []agentInfo
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != len(setupAgents()) {
		t.Fatalf("list json %v %s", err, out.String())
	}
}

// fakeCLI puts one agent CLI on PATH and records its invocations.
func fakeCLI(m *machine, bin string, fail error) *[][]string {
	var calls [][]string
	m.lookPath = func(name string) (string, error) {
		if name == bin {
			return "/usr/local/bin/" + bin, nil
		}
		return "", exec.ErrNotFound
	}
	m.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if fail != nil {
			return []byte("Error: " + fail.Error() + "\nmore detail"), fail
		}
		return nil, nil
	}
	return &calls
}

func TestSetupClaudeCodeCLI(t *testing.T) {
	m := fakeMachine(t)
	calls := fakeCLI(m, "claude", nil)
	r := one(t, m, testSpec, modeInstall, "claude-code")
	if r.Status != statusAdded || r.Method != "cli" || r.Command != "claude mcp add --scope user silk -- /opt/silk/bin/silk mcp" {
		t.Fatalf("result %+v", r)
	}
	want := [][]string{{"/usr/local/bin/claude", "mcp", "add", "--scope", "user", "silk", "--", testBin, "mcp"}}
	if !slices.EqualFunc(*calls, want, slices.Equal) {
		t.Fatalf("calls %q", *calls)
	}
	noFile(t, filepath.Join(m.home, ".claude.json"))

	// --env goes after the server name, or claude reads the name as another pair.
	*calls = nil
	withEnv := serverSpec{Command: testBin, Args: []string{"mcp", "--agent", "cc"}, Env: map[string]string{"SILK_HOME": "/x"}}
	one(t, m, withEnv, modeInstall, "claude-code")
	want = [][]string{{"/usr/local/bin/claude", "mcp", "add", "--scope", "user", "silk", "--env", "SILK_HOME=/x", "--", testBin, "mcp", "--agent", "cc"}}
	if !slices.EqualFunc(*calls, want, slices.Equal) {
		t.Fatalf("calls %q", *calls)
	}

	// Already registered (as the CLI writes it): nothing runs.
	p := filepath.Join(m.home, ".claude.json")
	writeFile(t, p, `{"numStartups": 3, "mcpServers": {"silk": {"type": "stdio", "command": "/opt/silk/bin/silk", "args": ["mcp"], "env": {}}}, "projects": {}}`, 0o600)
	*calls = nil
	if r := one(t, m, testSpec, modeInstall, "claude-code"); r.Status != statusSet || len(*calls) != 0 {
		t.Fatalf("result %+v calls %q", r, *calls)
	}

	// A stale entry is removed, then added again.
	if r := one(t, m, withEnv, modeInstall, "claude-code"); r.Status != statusUpdated {
		t.Fatalf("update %+v", r)
	}
	if len(*calls) != 2 || !slices.Equal((*calls)[0], []string{"/usr/local/bin/claude", "mcp", "remove", "silk", "--scope", "user"}) {
		t.Fatalf("calls %q", *calls)
	}

	*calls = nil
	if r := one(t, m, testSpec, modeRemove, "claude-code"); r.Status != statusRemoved || r.Method != "cli" || len(*calls) != 1 {
		t.Fatalf("remove %+v calls %q", r, *calls)
	}
}

func TestSetupCLIFailureFallsBackToFile(t *testing.T) {
	m := fakeMachine(t)
	m.getenv = func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return filepath.Join(m.home, "cc")
		}
		return ""
	}
	calls := fakeCLI(m, "claude", errors.New("boom"))
	r := one(t, m, testSpec, modeInstall, "claude-code")
	p := filepath.Join(m.home, "cc", ".claude.json")
	if r.Status != statusAdded || r.Method != "file" || r.Path != p || !strings.Contains(r.Detail, "failed (Error: boom)") || len(*calls) != 1 {
		t.Fatalf("result %+v calls %q", r, *calls)
	}
	wantFile(t, p, `{
  "mcpServers": {
    "silk": {
      "type": "stdio",
      "command": "/opt/silk/bin/silk",
      "args": [
        "mcp"
      ]
    }
  }
}
`)
	if r := one(t, m, testSpec, modeRemove, "claude-code"); r.Status != statusRemoved || r.Method != "file" {
		t.Fatalf("remove %+v", r)
	}
}

// Codex's and Grok Build's CLIs are only suggested: setup edits their TOML
// itself, even with the CLI installed, because `codex mcp add` rewrites the
// whole file. --print still offers the command.
func TestSetupCodexAndGrokEditFileDespiteCLI(t *testing.T) {
	s := serverSpec{Command: testBin, Args: []string{"mcp"}, Env: map[string]string{"SILK_HOME": "/x"}}
	for _, tc := range []struct {
		id, dir string
		cmd     string
	}{
		{"codex", ".codex", "codex mcp add silk --env SILK_HOME=/x -- " + testBin + " mcp"},
		{"grok", ".grok", "grok mcp add silk -e SILK_HOME=/x -- " + testBin + " mcp"},
	} {
		m := fakeMachine(t)
		calls := fakeCLI(m, tc.id, nil)
		if r := one(t, m, s, modeInstall, tc.id); r.Status != statusAdded || r.Method != "file" {
			t.Fatalf("%s: %+v", tc.id, r)
		}
		if r := one(t, m, s, modeRemove, tc.id); r.Status != statusRemoved || r.Method != "file" {
			t.Fatalf("%s remove: %+v", tc.id, r)
		}
		if len(*calls) != 0 {
			t.Fatalf("%s: setup ran the agent's CLI: %q", tc.id, *calls)
		}
		if p := findAgent(tc.id).printable(m, s); p.Command != tc.cmd {
			t.Fatalf("%s --print command %q", tc.id, p.Command)
		}
	}
}

func TestSilkSpec(t *testing.T) {
	m := fakeMachine(t)
	if s := silkSpec(m, testBin, &globals{home: filepath.Join(m.home, ".silk")}); s.Env != nil || !slices.Equal(s.Args, []string{"mcp"}) {
		t.Fatalf("default home: %+v", s)
	}
	// A home chosen any other way (--home or $SILK_HOME in this shell) must be
	// passed on: GUI apps do not inherit the shell's environment.
	s := silkSpec(m, testBin, &globals{home: "/srv/silk", agent: "work"})
	if s.Env["SILK_HOME"] != "/srv/silk" || !slices.Equal(s.Args, []string{"mcp", "--agent", "work"}) || s.Command != testBin {
		t.Fatalf("custom: %+v", s)
	}
}

func TestSetupUsageErrors(t *testing.T) {
	m := fakeMachine(t)
	var out bytes.Buffer
	if err := setupMain(context.Background(), m, &globals{}, testSpec, modeInstall, []string{"nope"}, &out); err == nil || !strings.Contains(err.Error(), "claude-code") {
		t.Fatalf("unknown agent: %v", err)
	}
	if err := setupMain(context.Background(), m, &globals{}, testSpec, modePrint, nil, &out); err == nil {
		t.Fatal("--print without an agent should fail")
	}
}

// Every agent's snippet must be what setup itself would write, and every
// key it writes must be one setup owns or deliberately leaves to the user.
func TestSetupAgentTable(t *testing.T) {
	m := fakeMachine(t)
	seen := map[string]bool{}
	s := serverSpec{Command: testBin, Args: []string{"mcp"}, Env: map[string]string{"SILK_HOME": "/x"}}
	for _, a := range setupAgents() {
		if seen[a.id] {
			t.Fatalf("duplicate id %s", a.id)
		}
		seen[a.id] = true
		if a.file(m) == "" {
			t.Errorf("%s: no config file", a.id)
		}
		p := a.printable(m, s)
		if !strings.Contains(p.Snippet, testBin) {
			t.Errorf("%s: snippet lacks the command:\n%s", a.id, p.Snippet)
		}
		switch a.format {
		case formatJSON:
			var v map[string]map[string]any
			if err := json.Unmarshal([]byte(p.Snippet), &map[string]any{}); err != nil {
				t.Errorf("%s: snippet is not JSON: %v", a.id, err)
			}
			json.Unmarshal([]byte(p.Snippet), &v)
			if _, ok := v[a.container]["silk"]; !ok {
				t.Errorf("%s: snippet has no %s.silk", a.id, a.container)
			}
			for _, f := range a.entry(s) {
				if !a.owns(f.k) && !slices.Contains(a.soft, f.k) {
					t.Errorf("%s: entry key %q is neither owned nor soft", a.id, f.k)
				}
			}
		case formatManual:
			if a.hint == "" || a.snippet == nil {
				t.Errorf("%s: manual agent needs a hint and a snippet", a.id)
			}
		}
	}
}
