package main

// `silk setup` registers Silk's MCP server (`silk mcp`) with the AI agents
// installed on this machine.
//
// These are the user's own config files, so setup is deliberately careful:
// it touches only the "silk" entry; other servers and settings keep their
// order and their exact bytes; a file that is not strict JSON (comments,
// trailing commas) is never written (the snippet is printed instead); the
// first edit of an existing file leaves a <file>.silk-backup copy; and every
// write is atomic and keeps the file's mode.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	silkServer      = "silk"
	setupCLITimeout = 15 * time.Second
	backupSuffix    = ".silk-backup"
)

// Results of setting up (or removing) one agent.
const (
	statusAdded   = "added"
	statusUpdated = "updated"
	statusSet     = "already set"
	statusRemoved = "removed"
	statusAbsent  = "not configured"
	statusManual  = "manual"
	statusFailed  = "failed"
)

// serverSpec is the MCP server entry setup writes for every agent.
type serverSpec struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// silkSpec builds the server entry. The command is an absolute path because
// GUI apps (Claude Desktop, Cursor, ...) do not inherit the shell's PATH, and
// a non-default home is passed as SILK_HOME because they do not inherit the
// shell's environment either.
func silkSpec(m *machine, exe string, g *globals) serverSpec {
	s := serverSpec{Command: exe, Args: []string{"mcp"}}
	if g.agent != "" {
		s.Args = append(s.Args, "--agent", g.agent)
	}
	home := g.home
	if abs, err := filepath.Abs(home); err == nil {
		home = abs
	}
	if home != filepath.Join(m.home, ".silk") {
		s.Env = map[string]string{"SILK_HOME": home}
	}
	return s
}

// machine is everything setup reads from the computer; tests use a fake one.
type machine struct {
	home     string
	goos     string
	getenv   func(string) string
	lookPath func(string) (string, error)
	run      func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func realMachine() (*machine, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &machine{home: home, goos: runtime.GOOS, getenv: os.Getenv, lookPath: exec.LookPath, run: runAgentCLI}, nil
}

// runAgentCLI runs an agent's own CLI directly (no shell), with a timeout and
// no stdin, and returns its combined output.
func runAgentCLI(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, setupCLITimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %v", setupCLITimeout)
	}
	return out, err
}

func (m *machine) path(elem ...string) string {
	return filepath.Join(append([]string{m.home}, elem...)...)
}

func (m *machine) exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (m *machine) onPath(bin string) (string, bool) {
	p, err := m.lookPath(bin)
	return p, err == nil && p != ""
}

// envDir is the directory named by an environment variable when it is set
// to an absolute path, otherwise def.
func (m *machine) envDir(name, def string) string {
	if d := m.getenv(name); filepath.IsAbs(d) {
		return d
	}
	return def
}

// xdgConfig is $XDG_CONFIG_HOME or ~/.config.
func (m *machine) xdgConfig() string { return m.envDir("XDG_CONFIG_HOME", m.path(".config")) }

// appData is where desktop (Electron) apps keep per-user data: ~/Library/
// Application Support on macOS, %APPDATA% on Windows, ~/.config on Linux.
func (m *machine) appData(elem ...string) string {
	var base string
	switch m.goos {
	case "darwin":
		base = m.path("Library", "Application Support")
	case "windows":
		base = m.envDir("APPDATA", m.path("AppData", "Roaming"))
	default:
		base = m.xdgConfig()
	}
	return filepath.Join(append([]string{base}, elem...)...)
}

// tilde shortens a path under the home directory for display.
func (m *machine) tilde(p string) string {
	if m.home != "" && strings.HasPrefix(p, m.home+string(filepath.Separator)) {
		return "~" + p[len(m.home):]
	}
	return p
}

// ---------------------------------------------------------------------------
// Agents

type configFormat int

const (
	formatJSON   configFormat = iota
	formatTOML                // [mcp_servers.silk] table (Codex, Grok Build)
	formatManual              // a format setup does not edit (YAML); it prints the snippet
)

type agentDef struct {
	id, name string
	detect   func(m *machine) bool
	file     func(m *machine) string
	format   configFormat

	// JSON: servers live in the top-level object named container.
	container string
	entry     func(s serverSpec) ordered
	// soft entry keys are written into a new entry but afterwards belong to
	// the user (e.g. "enabled": they may switch Silk off).
	soft []string
	// prepare checks (and may extend) the top-level members before an edit;
	// created is true when the file is new or empty.
	prepare func(top []jsonMember, created bool) ([]jsonMember, error)

	// Agents with their own CLI: preferred whenever it is on PATH, unless
	// cliPrintOnly, when the CLI is only suggested by --print because it
	// rewrites the whole file (Codex 0.161 reformats every table and drops
	// empty values of other servers) and setup's own edit changes only silk's lines.
	cli          string
	cliAdd       func(s serverSpec) []string
	cliRemove    []string
	cliPrintOnly bool

	snippet func(s serverSpec) string // formatManual
	hint    string                    // formatManual: where the snippet goes (%s is the file)
}

// stdio returns the common {"command", "args", "env"} entry, optionally
// preceded by a "type" member.
func stdio(typ string) func(s serverSpec) ordered {
	return func(s serverSpec) ordered {
		var o ordered
		if typ != "" {
			o = append(o, pair{"type", typ})
		}
		o = append(o, pair{"command", s.Command}, pair{"args", s.Args})
		if len(s.Env) > 0 {
			o = append(o, pair{"env", s.Env})
		}
		return o
	}
}

// envFlags renders env vars as repeated CLI flags, sorted for stable output.
func envFlags(flag string, env map[string]string) []string {
	var out []string
	for _, k := range sortedKeys(env) {
		out = append(out, flag, k+"="+env[k])
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// setupAgents lists the supported agents. Every format was checked against
// the vendor's documentation (October 2026), linked above each entry.
func setupAgents() []*agentDef {
	return []*agentDef{
		// https://code.claude.com/docs/en/mcp (user scope lives in the top-level
		// "mcpServers" of ~/.claude.json; `--env` goes after the name, see
		// "Pass any environment variables ... after the server name and before --").
		{
			id: "claude-code", name: "Claude Code",
			detect: func(m *machine) bool { return m.onPathOK("claude") || m.exists(claudeCodeFile(m)) },
			file:   claudeCodeFile, container: "mcpServers", entry: stdio("stdio"),
			cli: "claude",
			cliAdd: func(s serverSpec) []string {
				args := append([]string{"mcp", "add", "--scope", "user", silkServer}, envFlags("--env", s.Env)...)
				return append(append(args, "--", s.Command), s.Args...)
			},
			cliRemove: []string{"mcp", "remove", silkServer, "--scope", "user"},
		},
		// https://modelcontextprotocol.io/docs/develop/connect-local-servers
		{
			id: "claude-desktop", name: "Claude Desktop",
			detect: func(m *machine) bool { return m.exists(filepath.Dir(claudeDesktopFile(m))) },
			file:   claudeDesktopFile, container: "mcpServers", entry: stdio(""),
		},
		// https://learn.chatgpt.com/docs/extend/mcp (the CLI, IDE extension and
		// desktop app share $CODEX_HOME/config.toml) and
		// https://learn.chatgpt.com/docs/config-file/config-reference
		{
			id: "codex", name: "OpenAI Codex", format: formatTOML,
			detect: func(m *machine) bool { return m.onPathOK("codex") || m.exists(codexHome(m)) },
			file:   func(m *machine) string { return filepath.Join(codexHome(m), "config.toml") },
			cli:    "codex", cliPrintOnly: true,
			cliAdd: func(s serverSpec) []string {
				args := append([]string{"mcp", "add", silkServer}, envFlags("--env", s.Env)...)
				return append(append(args, "--", s.Command), s.Args...)
			},
			cliRemove: []string{"mcp", "remove", silkServer},
		},
		// https://cursor.com/docs/context/mcp ("~/.cursor/mcp.json ... for tools
		// available everywhere"; STDIO servers take type "stdio").
		{
			id: "cursor", name: "Cursor",
			detect:    func(m *machine) bool { return m.exists(m.path(".cursor")) },
			file:      func(m *machine) string { return m.path(".cursor", "mcp.json") },
			container: "mcpServers", entry: stdio("stdio"),
		},
		// https://docs.devin.ai/desktop/cascade/mcp — Windsurf became Devin Desktop
		// on 2026-06-02 (https://docs.devin.ai/desktop/devin-desktop-faq) and reads
		// $XDG_CONFIG_HOME/devin/mcp_config.json (%APPDATA%\devin on Windows), as
		// does the Devin CLI. Installs from before the rename read
		// ~/.codeium/windsurf/mcp_config.json, which Devin also still reads.
		{
			id: "windsurf", name: "Windsurf / Devin",
			detect: func(m *machine) bool { return m.exists(devinDir(m)) || m.exists(m.path(".codeium", "windsurf")) },
			file:   windsurfFile, container: "mcpServers", entry: stdio(""),
		},
		// https://code.visualstudio.com/docs/agents/reference/mcp-configuration
		// (user mcp.json sits next to settings.json in the profile folder:
		// https://code.visualstudio.com/docs/configure/settings).
		{
			id: "vscode", name: "VS Code (Copilot)",
			detect:    func(m *machine) bool { return m.exists(m.appData("Code", "User")) },
			file:      func(m *machine) string { return m.appData("Code", "User", "mcp.json") },
			container: "servers", entry: stdio("stdio"),
		},
		// https://geminicli.com/docs/tools/mcp-server/ and
		// https://geminicli.com/docs/reference/configuration/ ($GEMINI_CLI_HOME
		// replaces the home directory: $GEMINI_CLI_HOME/.gemini/settings.json).
		{
			id: "gemini", name: "Gemini CLI",
			detect:    func(m *machine) bool { return m.onPathOK("gemini") || m.exists(geminiDir(m)) },
			file:      func(m *machine) string { return filepath.Join(geminiDir(m), "settings.json") },
			container: "mcpServers", entry: stdio(""),
		},
		// https://docs.x.ai/build/features/mcp-servers and
		// https://docs.x.ai/build/settings ($GROK_HOME, default ~/.grok).
		// `grok mcp add` writes user scope and stdio by default.
		{
			id: "grok", name: "Grok Build", format: formatTOML,
			detect: func(m *machine) bool { return m.onPathOK("grok") || m.exists(grokHome(m)) },
			file:   func(m *machine) string { return filepath.Join(grokHome(m), "config.toml") },
			cli:    "grok", cliPrintOnly: true,
			cliAdd: func(s serverSpec) []string {
				args := append([]string{"mcp", "add", silkServer}, envFlags("-e", s.Env)...)
				return append(append(args, "--", s.Command), s.Args...)
			},
			cliRemove: []string{"mcp", "remove", silkServer},
		},
		// https://dev.meta.ai/docs/muse-code/configuration ("settings.json must set
		// "schema_version": 1") and https://dev.meta.ai/docs/muse-code/extending
		// (mcp_servers; "optional" servers are skipped with a warning when they
		// cannot start instead of aborting the run).
		{
			id: "muse", name: "Muse Code",
			detect:    func(m *machine) bool { return m.onPathOK("muse") || m.exists(m.path(".config", "muse")) },
			file:      func(m *machine) string { return m.path(".config", "muse", "settings.json") },
			container: "mcp_servers", soft: []string{"mode"}, prepare: museSettings,
			entry: func(s serverSpec) ordered {
				o := ordered{{"transport", "stdio"}, {"command", s.Command}, {"args", s.Args}}
				if len(s.Env) > 0 {
					o = append(o, pair{"env", s.Env})
				}
				return append(o, pair{"mode", "optional"})
			},
		},
		// https://opencode.ai/docs/mcp-servers/ and https://opencode.ai/docs/config/
		// (global config in $XDG_CONFIG_HOME/opencode via xdg-basedir).
		{
			id: "opencode", name: "opencode",
			detect: func(m *machine) bool {
				return m.onPathOK("opencode") || m.exists(filepath.Join(m.xdgConfig(), "opencode"))
			},
			file: opencodeFile, container: "mcp", soft: []string{"enabled"}, prepare: opencodeSettings,
			entry: func(s serverSpec) ordered {
				o := ordered{{"type", "local"}, {"command", append([]string{s.Command}, s.Args...)}, {"enabled", true}}
				if len(s.Env) > 0 {
					o = append(o, pair{"environment", s.Env})
				}
				return o
			},
		},
		// https://docs.cline.bot/mcp/mcp-overview and
		// https://docs.cline.bot/getting-started/config: since Cline 4.0 the
		// extension, CLI and SDK share ~/.cline/data/settings/cline_mcp_settings.json.
		// Older extensions used VS Code's globalStorage.
		{
			id: "cline", name: "Cline",
			detect: func(m *machine) bool { return m.exists(clineDir(m)) || m.exists(filepath.Dir(clineLegacyFile(m))) },
			file:   clineFile, container: "mcpServers", entry: stdio(""),
		},
		// https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers,
		// https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference
		// ("Local server configuration fields") and .../cli-config-dir-reference ($COPILOT_HOME).
		{
			id: "copilot-cli", name: "GitHub Copilot CLI",
			detect:    func(m *machine) bool { return m.onPathOK("copilot") || m.exists(copilotHome(m)) },
			file:      func(m *machine) string { return filepath.Join(copilotHome(m), "mcp-config.json") },
			container: "mcpServers", soft: []string{"tools"},
			entry: func(s serverSpec) ordered { return append(stdio("local")(s), pair{"tools", []string{"*"}}) },
		},
		// https://kiro.dev/docs/mcp/configuration/ (IDE and CLI share the user
		// file) and https://kiro.dev/docs/reference/cli-commands/ ($KIRO_HOME).
		{
			id: "kiro", name: "Kiro",
			detect:    func(m *machine) bool { return m.onPathOK("kiro-cli") || m.exists(kiroHome(m)) },
			file:      func(m *machine) string { return filepath.Join(kiroHome(m), "settings", "mcp.json") },
			container: "mcpServers", entry: stdio(""),
		},
		// https://lmstudio.ai/blog/mcp ("~/.lmstudio/mcp.json ... follows Cursor's
		// mcp.json notation"); the home directory is resolved like LM Studio's own
		// findLMStudioHome (https://lmstudio.ai/lmstudio/js-code-sandbox/files/src/findLMStudioHome.ts).
		{
			id: "lmstudio", name: "LM Studio",
			detect:    func(m *machine) bool { return m.exists(lmstudioHome(m)) },
			file:      func(m *machine) string { return filepath.Join(lmstudioHome(m), "mcp.json") },
			container: "mcpServers", entry: stdio(""),
		},
		// https://zed.dev/docs/ai/mcp and
		// https://github.com/zed-industries/zed/blob/main/docs/src/configuring-zed.md.
		// settings.json allows // comments; setup edits it only when it is strict
		// JSON and otherwise prints the snippet.
		{
			id: "zed", name: "Zed",
			detect: func(m *machine) bool { return m.exists(filepath.Dir(zedFile(m))) },
			file:   zedFile, container: "context_servers", entry: stdio(""),
		},
		// https://goose-docs.ai/docs/guides/config-files (YAML, not edited by
		// setup) and https://goose-docs.ai/docs/guides/environment-variables
		// ($GOOSE_PATH_ROOT).
		{
			id: "goose", name: "Goose", format: formatManual,
			detect:  func(m *machine) bool { return m.onPathOK("goose") || m.exists(filepath.Dir(gooseFile(m))) },
			file:    gooseFile,
			hint:    "merge into the extensions: section of %s",
			snippet: gooseSnippet,
		},
	}
}

func copilotHome(m *machine) string { return m.envDir("COPILOT_HOME", m.path(".copilot")) }

func kiroHome(m *machine) string { return m.envDir("KIRO_HOME", m.path(".kiro")) }

// lmstudioHome: the path in ~/.lmstudio-home-pointer, else ~/.cache/lm-studio
// (older installs) when it exists, else ~/.lmstudio.
func lmstudioHome(m *machine) string {
	if b, err := os.ReadFile(m.path(".lmstudio-home-pointer")); err == nil {
		if p := strings.TrimSpace(string(b)); filepath.IsAbs(p) {
			return p
		}
	}
	if old := m.path(".cache", "lm-studio"); m.exists(old) {
		return old
	}
	return m.path(".lmstudio")
}

func zedFile(m *machine) string {
	switch m.goos {
	case "windows":
		return filepath.Join(m.envDir("APPDATA", m.path("AppData", "Roaming")), "Zed", "settings.json")
	case "linux":
		return filepath.Join(m.xdgConfig(), "zed", "settings.json")
	}
	return m.path(".config", "zed", "settings.json")
}

func gooseFile(m *machine) string {
	if root := m.getenv("GOOSE_PATH_ROOT"); filepath.IsAbs(root) {
		return filepath.Join(root, "config", "config.yaml")
	}
	if m.goos == "windows" {
		return filepath.Join(m.envDir("APPDATA", m.path("AppData", "Roaming")), "Block", "goose", "config", "config.yaml")
	}
	return filepath.Join(m.xdgConfig(), "goose", "config.yaml")
}

// gooseSnippet writes YAML using JSON-style flow values, which YAML reads as
// the same strings without any escaping surprises.
func gooseSnippet(s serverSpec) string {
	q := func(v any) string {
		b, _ := marshalIndent(v, "", 0)
		return string(b)
	}
	env := ordered{}
	for _, k := range sortedKeys(s.Env) {
		env = append(env, pair{k, s.Env[k]})
	}
	return strings.Join([]string{
		"extensions:",
		"  silk:",
		"    type: stdio",
		"    name: silk",
		"    enabled: true",
		"    cmd: " + q(s.Command),
		"    args: " + strings.ReplaceAll(q(s.Args), `","`, `", "`),
		"    envs: " + q(env),
		"    timeout: 300",
	}, "\n")
}

// onPathOK reports whether an agent's CLI is installed.
func (m *machine) onPathOK(bin string) bool {
	_, ok := m.onPath(bin)
	return ok
}

// claudeCodeFile is ~/.claude.json, or .claude.json in $CLAUDE_CONFIG_DIR.
func claudeCodeFile(m *machine) string {
	if d := m.getenv("CLAUDE_CONFIG_DIR"); filepath.IsAbs(d) {
		return filepath.Join(d, ".claude.json")
	}
	return m.path(".claude.json")
}

// claudeDesktopFile also handles the Windows MSIX install, whose file
// reads are redirected to a per-package copy of %APPDATA% when it exists
// (https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes).
func claudeDesktopFile(m *machine) string {
	if m.goos == "windows" {
		local := m.envDir("LOCALAPPDATA", m.path("AppData", "Local"))
		dirs, _ := filepath.Glob(filepath.Join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude"))
		if len(dirs) == 1 {
			return filepath.Join(dirs[0], "claude_desktop_config.json")
		}
	}
	return m.appData("Claude", "claude_desktop_config.json")
}

func codexHome(m *machine) string { return m.envDir("CODEX_HOME", m.path(".codex")) }

func grokHome(m *machine) string { return m.envDir("GROK_HOME", m.path(".grok")) }

func geminiDir(m *machine) string {
	return filepath.Join(m.envDir("GEMINI_CLI_HOME", m.home), ".gemini")
}

func devinDir(m *machine) string {
	if m.goos == "windows" {
		return filepath.Join(m.envDir("APPDATA", m.path("AppData", "Roaming")), "devin")
	}
	return filepath.Join(m.xdgConfig(), "devin")
}

// windsurfFile picks one file so Silk is not defined twice: Devin's own
// file once it exists, else a pre-rename Windsurf's.
func windsurfFile(m *machine) string {
	devin := filepath.Join(devinDir(m), "mcp_config.json")
	legacy := m.path(".codeium", "windsurf", "mcp_config.json")
	if !m.exists(devin) && m.exists(filepath.Dir(legacy)) {
		return legacy
	}
	return devin
}

// opencodeFile is the global file opencode itself updates: the first of
// opencode.jsonc, opencode.json and config.json that exists.
func opencodeFile(m *machine) string {
	dir := filepath.Join(m.xdgConfig(), "opencode")
	for _, name := range []string{"opencode.jsonc", "opencode.json", "config.json"} {
		if p := filepath.Join(dir, name); m.exists(p) {
			return p
		}
	}
	return filepath.Join(dir, "opencode.json")
}

func clineDir(m *machine) string { return m.envDir("CLINE_DIR", m.path(".cline")) }

func clineLegacyFile(m *machine) string {
	return m.appData("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
}

// clineFile follows Cline's own lookup order: $CLINE_MCP_SETTINGS_PATH,
// $CLINE_DATA_DIR/settings, then ~/.cline/data/settings. An extension older
// than 4.0 (globalStorage file present, no ~/.cline) keeps its own file.
func clineFile(m *machine) string {
	if p := m.getenv("CLINE_MCP_SETTINGS_PATH"); filepath.IsAbs(p) {
		return p
	}
	if d := m.getenv("CLINE_DATA_DIR"); filepath.IsAbs(d) {
		return filepath.Join(d, "settings", "cline_mcp_settings.json")
	}
	if legacy := clineLegacyFile(m); !m.exists(clineDir(m)) && m.exists(legacy) {
		return legacy
	}
	return filepath.Join(clineDir(m), "data", "settings", "cline_mcp_settings.json")
}

// museSettings: Muse Code refuses a settings.json without "schema_version": 1.
func museSettings(top []jsonMember, created bool) ([]jsonMember, error) {
	if created {
		return append([]jsonMember{newMember("schema_version", []byte("1"))}, top...), nil
	}
	i, err := findMember(top, "schema_version")
	switch {
	case err != nil:
		return nil, err
	case i < 0:
		return nil, &manualError{`has no "schema_version": 1, which Muse Code requires`}
	case string(top[i].val) != "1":
		return nil, &manualError{fmt.Sprintf("has schema_version %s; setup knows version 1", top[i].val)}
	}
	// Muse also reads the common "mcpServers" key; do not define silk twice.
	if j, _ := findMember(top, "mcpServers"); j >= 0 {
		if ms, err := parseObject(top[j].val); err == nil {
			if k, _ := findMember(ms, silkServer); k >= 0 {
				return nil, &manualError{`already defines silk under "mcpServers"`}
			}
		}
	}
	return top, nil
}

// opencodeSettings starts a new file the way opencode does, with its schema.
func opencodeSettings(top []jsonMember, created bool) ([]jsonMember, error) {
	if created {
		return append([]jsonMember{newMember("$schema", []byte(`"https://opencode.ai/config.json"`))}, top...), nil
	}
	return top, nil
}

func findAgent(id string) *agentDef {
	for _, a := range setupAgents() {
		if a.id == id {
			return a
		}
	}
	return nil
}

func agentIDs() string {
	var ids []string
	for _, a := range setupAgents() {
		ids = append(ids, a.id)
	}
	return strings.Join(ids, ", ")
}

// ---------------------------------------------------------------------------
// Command

type setupMode int

const (
	modeInstall setupMode = iota
	modeRemove
	modeList
	modePrint
)

type setupResult struct {
	Agent   string `json:"agent"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Method  string `json:"method,omitempty"` // "cli", "file" or "manual"
	Path    string `json:"path,omitempty"`
	Command string `json:"command,omitempty"` // the agent CLI command that was run
	Backup  string `json:"backup,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

type agentInfo struct {
	Agent    string `json:"agent"`
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	Silk     string `json:"silk"` // "configured", "not configured", "differs", "unknown"
	Method   string `json:"method"`
	Path     string `json:"path,omitempty"`
}

type agentSnippet struct {
	Agent   string `json:"agent"`
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Where   string `json:"where"`
	Command string `json:"command,omitempty"`
	Snippet string `json:"snippet"`
}

func runSetup(ctx context.Context, g *globals, args []string) error {
	fset := newFlags("setup", g)
	list := fset.Bool("list", false, "show supported agents, whether each is installed and has Silk (writes nothing)")
	show := fset.Bool("print", false, "print the config snippet or command to set an agent up by hand (writes nothing)")
	remove := fset.Bool("remove", false, "unregister Silk (from every configured agent when none is named)")
	ids, err := parse(fset, args)
	if err != nil {
		return err
	}
	mode := modeInstall
	n := 0
	for _, f := range []struct {
		set  bool
		mode setupMode
	}{{*list, modeList}, {*show, modePrint}, {*remove, modeRemove}} {
		if f.set {
			mode, n = f.mode, n+1
		}
	}
	if n > 1 {
		return errors.New("use only one of --list, --print and --remove")
	}
	m, err := realMachine()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.Contains(exe, "go-build") && mode != modeList {
		fmt.Fprintf(os.Stderr, "silk setup: warning: %s is a temporary `go run` build; install silk and run setup from the installed binary\n", exe)
	}
	return setupMain(ctx, m, g, silkSpec(m, exe, g), mode, ids, os.Stdout)
}

func setupMain(ctx context.Context, m *machine, g *globals, s serverSpec, mode setupMode, ids []string, w io.Writer) error {
	var named []*agentDef
	for _, id := range ids {
		a := findAgent(strings.ToLower(id))
		if a == nil {
			return fmt.Errorf("unknown agent %q (supported: %s)", id, agentIDs())
		}
		if !slices.Contains(named, a) {
			named = append(named, a)
		}
	}
	all := setupAgents()

	switch mode {
	case modeList:
		var rows []agentInfo
		for _, a := range all {
			rows = append(rows, a.info(m, s))
		}
		if g.json {
			return writeJSON(w, rows)
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tID\tINSTALLED\tSILK\tHOW\tCONFIG")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Agent, yesNo(r.Detected), r.Silk, r.Method, m.tilde(r.Path))
		}
		tw.Flush()
		fmt.Fprintln(w, "\n`silk setup` sets up every installed agent; `silk setup <id>...` sets up the ones named, installed or not.")
		return nil

	case modePrint:
		if len(named) == 0 {
			return fmt.Errorf("usage: silk setup --print <agent>... (agents: %s)", agentIDs())
		}
		var out []agentSnippet
		for _, a := range named {
			out = append(out, a.printable(m, s))
		}
		if g.json {
			return writeJSON(w, out)
		}
		for i, p := range out {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "# %s (%s)\n", p.Name, p.Agent)
			if p.Command != "" {
				fmt.Fprintf(w, "# Run:\n%s\n# or %s:\n", p.Command, p.Where)
			} else {
				fmt.Fprintf(w, "# %s:\n", capitalize(p.Where))
			}
			fmt.Fprintln(w, p.Snippet)
		}
		return nil
	}

	targets := named
	if len(targets) == 0 {
		for _, a := range all {
			if mode == modeInstall && a.detect(m) {
				targets = append(targets, a)
			}
			if mode == modeRemove && a.mayHaveSilk(m, s) {
				targets = append(targets, a)
			}
		}
	}
	var results []setupResult
	for _, a := range targets {
		if mode == modeRemove {
			results = append(results, a.uninstall(ctx, m, s))
		} else {
			results = append(results, a.install(ctx, m, s))
		}
	}
	if g.json {
		if results == nil {
			results = []setupResult{}
		}
		if err := writeJSON(w, results); err != nil {
			return err
		}
	} else {
		printResults(w, m, mode, s, results)
	}
	failed := 0
	for _, r := range results {
		if r.Status == statusFailed {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d agent(s) could not be updated", failed)
	}
	return nil
}

func printResults(w io.Writer, m *machine, mode setupMode, s serverSpec, rs []setupResult) {
	if len(rs) == 0 {
		if mode == modeRemove {
			fmt.Fprintln(w, "No agent has Silk configured.")
		} else {
			fmt.Fprintf(w, "No supported agents found. `silk setup --list` shows what is supported; `silk setup <id>` sets one up anyway.\n")
		}
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tRESULT\tWHERE")
	for _, r := range rs {
		where := m.tilde(r.Path)
		if r.Method == "cli" {
			where = r.Command
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, r.Status, where)
	}
	tw.Flush()
	changed := false
	for _, r := range rs {
		switch r.Status {
		case statusAdded, statusUpdated, statusRemoved:
			changed = true
		}
		if r.Detail != "" && r.Status != statusManual {
			fmt.Fprintf(w, "  %s: %s\n", r.Name, r.Detail)
		}
		if r.Backup != "" {
			fmt.Fprintf(w, "  %s: previous config saved to %s\n", r.Name, m.tilde(r.Backup))
		}
	}
	for _, r := range rs {
		if r.Status != statusManual {
			continue
		}
		fmt.Fprintf(w, "\n%s: %s.\n", r.Name, r.Detail)
		if r.Snippet != "" {
			fmt.Fprintln(w, r.Snippet)
		}
	}
	if changed && mode == modeInstall {
		fmt.Fprintf(w, "\nSilk's MCP server: %s\nRestart running agents (or start a new session) to load it.\n", strings.Join(append([]string{s.Command}, s.Args...), " "))
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------------------
// Per-agent operations

type silkState int

const (
	stateAbsent silkState = iota
	stateConfigured
	stateDiffers
	stateUnknown // the config could not be read or parsed
)

func (st silkState) String() string {
	return [...]string{"not configured", "configured", "differs", "unknown"}[st]
}

// state reports whether the agent's config already has Silk.
func (a *agentDef) state(m *machine, s serverSpec) silkState {
	if a.format == formatManual {
		return stateUnknown
	}
	b, err := os.ReadFile(a.file(m))
	if errors.Is(err, os.ErrNotExist) {
		return stateAbsent
	}
	if err != nil {
		return stateUnknown
	}
	if a.format == formatTOML {
		return tomlState(b, s)
	}
	return a.jsonState(b, s)
}

// mayHaveSilk decides which agents `silk setup --remove` visits by default.
func (a *agentDef) mayHaveSilk(m *machine, s serverSpec) bool {
	switch a.state(m, s) {
	case stateConfigured, stateDiffers:
		return true
	case stateUnknown:
		// Unparsable or hand-edited formats: only bother the user when the
		// file mentions silk at all.
		b, err := os.ReadFile(a.file(m))
		return err == nil && bytes.Contains(b, []byte(silkServer))
	}
	return false
}

func (a *agentDef) info(m *machine, s serverSpec) agentInfo {
	method := "file"
	switch {
	case a.format == formatManual:
		method = "manual"
	case a.cli != "" && !a.cliPrintOnly:
		if _, ok := m.onPath(a.cli); ok {
			method = "cli"
		}
	}
	return agentInfo{Agent: a.id, Name: a.name, Detected: a.detect(m), Silk: a.state(m, s).String(), Method: method, Path: a.file(m)}
}

func (a *agentDef) printable(m *machine, s serverSpec) agentSnippet {
	p := agentSnippet{Agent: a.id, Name: a.name, Path: a.file(m), Snippet: a.snippetFor(s)}
	switch a.format {
	case formatJSON:
		p.Where = fmt.Sprintf("merge into %s (keep your other %q entries)", m.tilde(p.Path), a.container)
	case formatTOML:
		p.Where = "append to " + m.tilde(p.Path)
	default:
		p.Where = fmt.Sprintf(a.hint, m.tilde(p.Path))
	}
	if a.cli != "" {
		p.Command = shellJoin(append([]string{a.cli}, a.cliAdd(s)...))
	}
	return p
}

// snippetFor is the text a user would paste by hand.
func (a *agentDef) snippetFor(s serverSpec) string {
	switch a.format {
	case formatJSON:
		var top ordered
		if a.prepare != nil {
			members, _ := a.prepare(nil, true)
			for _, mb := range members {
				top = append(top, pair{mb.key, mb.val})
			}
		}
		top = append(top, pair{a.container, ordered{{silkServer, a.entry(s)}}})
		b, _ := marshalIndent(top, "  ", 0)
		return string(b)
	case formatTOML:
		return strings.Join(tomlBlock(s), "\n")
	}
	return a.snippet(s)
}

func (a *agentDef) manual(m *machine, s serverSpec, remove bool) setupResult {
	r := setupResult{Agent: a.id, Name: a.name, Status: statusManual, Method: "manual", Path: a.file(m)}
	if remove {
		r.Detail = fmt.Sprintf("remove the %q entry from %s by hand", silkServer, m.tilde(r.Path))
		return r
	}
	r.Detail = fmt.Sprintf(a.hint, m.tilde(r.Path)) + " (setup does not edit YAML)"
	r.Snippet = a.snippetFor(s)
	return r
}

func (a *agentDef) install(ctx context.Context, m *machine, s serverSpec) setupResult {
	if a.format == formatManual {
		return a.manual(m, s, false)
	}
	if a.cli == "" || a.cliPrintOnly {
		return a.edit(m, s, false)
	}
	st := a.state(m, s)
	if st == stateConfigured {
		return setupResult{Agent: a.id, Name: a.name, Status: statusSet, Method: "file", Path: a.file(m)}
	}
	bin, ok := m.onPath(a.cli)
	if !ok {
		return a.edit(m, s, false)
	}
	if st != stateAbsent {
		// Replace rather than fail with "already exists"; add reports any real problem.
		m.run(ctx, bin, a.cliRemove...)
	}
	args := a.cliAdd(s)
	out, err := m.run(ctx, bin, args...)
	cmd := shellJoin(append([]string{a.cli}, args...))
	if err == nil {
		status := statusAdded
		if st == stateDiffers {
			status = statusUpdated
		}
		return setupResult{Agent: a.id, Name: a.name, Status: status, Method: "cli", Path: a.file(m), Command: cmd}
	}
	r := a.edit(m, s, false)
	r.Detail = joinDetail(fmt.Sprintf("`%s` failed (%s); edited the config file instead", cmd, cliError(out, err)), r.Detail)
	return r
}

func (a *agentDef) uninstall(ctx context.Context, m *machine, s serverSpec) setupResult {
	if a.format == formatManual {
		return a.manual(m, s, true)
	}
	if a.cli != "" && !a.cliPrintOnly {
		if st := a.state(m, s); st == stateAbsent {
			return setupResult{Agent: a.id, Name: a.name, Status: statusAbsent, Method: "file", Path: a.file(m)}
		}
		if bin, ok := m.onPath(a.cli); ok {
			out, err := m.run(ctx, bin, a.cliRemove...)
			cmd := shellJoin(append([]string{a.cli}, a.cliRemove...))
			if err == nil {
				return setupResult{Agent: a.id, Name: a.name, Status: statusRemoved, Method: "cli", Path: a.file(m), Command: cmd}
			}
			r := a.edit(m, s, true)
			r.Detail = joinDetail(fmt.Sprintf("`%s` failed (%s); edited the config file instead", cmd, cliError(out, err)), r.Detail)
			return r
		}
	}
	return a.edit(m, s, true)
}

// edit adds (or removes) the silk entry in the agent's config file.
func (a *agentDef) edit(m *machine, s serverSpec, remove bool) setupResult {
	r := setupResult{Agent: a.id, Name: a.name, Method: "file", Path: a.file(m)}
	var status string
	_, backup, err := editFile(r.Path, func(old []byte, exists bool) ([]byte, error) {
		var out []byte
		var err error
		switch {
		case remove && !exists:
			status = statusAbsent
		case remove && a.format == formatTOML:
			out, status, err = tomlRemove(old)
		case remove:
			out, status, err = a.jsonRemove(old)
		case a.format == formatTOML:
			out, status, err = tomlInstall(old, s)
		default:
			out, status, err = a.jsonInstall(old, s)
		}
		return out, err
	})
	var me *manualError
	switch {
	case errors.As(err, &me):
		r.Status, r.Method = statusManual, "manual"
		if remove {
			r.Detail = fmt.Sprintf("%s %s; remove the %q entry by hand", m.tilde(r.Path), me.why, silkServer)
		} else {
			r.Detail = fmt.Sprintf("%s %s; add this by hand", m.tilde(r.Path), me.why)
			r.Snippet = a.snippetFor(s)
		}
	case err != nil:
		r.Status, r.Detail = statusFailed, err.Error()
	default:
		r.Status, r.Backup = status, backup
	}
	return r
}

// manualError means the file is in a shape setup will not edit; the user is
// shown the snippet instead.
type manualError struct{ why string }

func (e *manualError) Error() string { return e.why }

func cliError(out []byte, err error) string {
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if line == "" {
		return err.Error()
	}
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
}

func joinDetail(a, b string) string {
	if b == "" {
		return a
	}
	return a + "; " + b
}

// shellJoin renders a command for display, quoting where a POSIX shell would need it.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = shellQuote(a)
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// ---------------------------------------------------------------------------
// Files

// editFile applies edit to the file at path (following symlinks) and writes
// the result atomically. edit returns nil to leave the file as it is. Before
// the first change to an existing file it saves <file>.silk-backup. If the
// file changes on disk while being edited (a running app rewriting it), the
// edit is redone on the new contents.
func editFile(path string, edit func(old []byte, exists bool) ([]byte, error)) (wrote bool, backup string, err error) {
	target := path
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		// A config kept in a dotfiles repo: edit the file the link points to
		// rather than replacing the link.
		if target, err = filepath.EvalSymlinks(path); err != nil {
			return false, "", fmt.Errorf("%s is a broken symlink", path)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		old, err := os.ReadFile(target)
		exists := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, backup, err
		}
		upd, err := edit(old, exists)
		if err != nil || upd == nil || (exists && bytes.Equal(upd, old)) {
			return false, backup, err
		}
		mode := os.FileMode(0o600)
		if exists {
			if fi, err := os.Stat(target); err == nil {
				mode = fi.Mode().Perm()
			}
			if b, err := backupOnce(target, old, mode); err != nil {
				return false, backup, fmt.Errorf("backing up %s: %w", target, err)
			} else if b != "" {
				backup = b
			}
		}
		unchanged := func() bool {
			cur, err := os.ReadFile(target)
			if exists {
				return err == nil && bytes.Equal(cur, old)
			}
			return errors.Is(err, os.ErrNotExist)
		}
		err = writeAtomic(target, upd, mode, unchanged)
		if errors.Is(err, errChanged) {
			continue
		}
		return err == nil, backup, err
	}
	return false, backup, fmt.Errorf("%s kept changing while being edited; quit the app and run setup again", path)
}

var errChanged = errors.New("file changed during edit")

func backupOnce(target string, old []byte, mode os.FileMode) (string, error) {
	p := target + backupSuffix
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if _, err := f.Write(old); err != nil {
		f.Close()
		os.Remove(p)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return "", err
	}
	return p, nil
}

// writeAtomic writes data to a temporary file next to target and renames it
// into place, unless unchanged reports that target was modified meanwhile.
func writeAtomic(target string, data []byte, mode os.FileMode, unchanged func() bool) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(target)+".silk-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if !unchanged() {
		return errChanged
	}
	return os.Rename(tmp, target)
}

// ---------------------------------------------------------------------------
// Order- and byte-preserving JSON

// pair and ordered build JSON objects whose keys keep their order.
type pair struct {
	k string
	v any
}

type ordered []pair

func (o ordered) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := marshalIndent(f.k, "", 0)
		if err != nil {
			return nil, err
		}
		v, err := marshalIndent(f.v, "", 0)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (o ordered) get(k string) (any, bool) {
	for _, f := range o {
		if f.k == k {
			return f.v, true
		}
	}
	return nil, false
}

// marshalIndent encodes v (without HTML escaping) as a value whose first line
// sits at nesting level `level`.
func marshalIndent(v any, indent string, level int) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent(strings.Repeat(indent, level), indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// jsonMember is one member of a JSON object exactly as written in the file.
type jsonMember struct {
	rawKey []byte // the key's original bytes, quotes included
	key    string
	val    json.RawMessage // the value's original bytes
}

func newMember(key string, val []byte) jsonMember {
	k, _ := marshalIndent(key, "", 0)
	return jsonMember{rawKey: k, key: key, val: val}
}

// parseObject splits a strict JSON object into its members, keeping the
// original bytes of every key and value. Comments, trailing commas and
// anything after the object are errors.
func parseObject(b []byte) ([]jsonMember, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	ms := []jsonMember{}
	for dec.More() {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("malformed object key")
		}
		rawKey := bytes.TrimLeft(b[start:dec.InputOffset()], " \t\r\n,")
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		ms = append(ms, jsonMember{rawKey: rawKey, key: key, val: bytes.TrimSpace(val)})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the top-level object")
	}
	return ms, nil
}

// findMember returns the index of key in ms, or -1. A key that appears more
// than once is an error: it is ambiguous which one the app reads.
func findMember(ms []jsonMember, key string) (int, error) {
	at := -1
	for i, mb := range ms {
		if mb.key == key {
			if at >= 0 {
				return -1, &manualError{fmt.Sprintf("has %q more than once", key)}
			}
			at = i
		}
	}
	return at, nil
}

// encodeObject writes members one per line, indented for nesting level
// `level`, with each value's original bytes.
func encodeObject(ms []jsonMember, indent string, level int) []byte {
	if len(ms) == 0 {
		return []byte("{}")
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	pad := strings.Repeat(indent, level+1)
	for i, mb := range ms {
		b.WriteString(pad)
		b.Write(mb.rawKey)
		b.WriteString(": ")
		b.Write(mb.val)
		if i < len(ms)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString(strings.Repeat(indent, level))
	b.WriteByte('}')
	return b.Bytes()
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// jsonDoc is a JSON config file split into top-level members, plus the
// details needed to write it back the way it was: byte order mark, line
// endings, final newline and indentation.
type jsonDoc struct {
	top                []jsonMember
	bom, crlf, newline bool
	indent             string
}

// parseDoc reads a config file; an empty (or whitespace-only) file is an
// empty object.
func parseDoc(b []byte) (*jsonDoc, error) {
	d := &jsonDoc{indent: "  ", newline: true}
	if bytes.HasPrefix(b, utf8BOM) {
		d.bom, b = true, b[len(utf8BOM):]
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return d, nil
	}
	top, err := parseObject(b)
	if err != nil {
		return nil, err
	}
	d.top = top
	d.crlf = bytes.Contains(b, []byte("\r\n"))
	d.newline = bytes.HasSuffix(b, []byte("\n"))
	d.indent = detectIndent(b)
	return d, nil
}

func (d *jsonDoc) bytes() []byte {
	out := encodeObject(d.top, d.indent, 0)
	if d.newline {
		out = append(out, '\n')
	}
	if d.crlf {
		out = toCRLF(out)
	}
	if d.bom {
		out = append(append([]byte{}, utf8BOM...), out...)
	}
	return out
}

// detectIndent returns the indentation of the first top-level member when
// the object is written one member per line (all spaces or all tabs), and
// two spaces otherwise.
func detectIndent(b []byte) string {
	i := bytes.IndexByte(b, '{')
	if i < 0 {
		return "  "
	}
	rest := b[i+1:]
	j := bytes.IndexByte(rest, '\n')
	if j < 0 || len(bytes.TrimSpace(rest[:j])) != 0 {
		return "  "
	}
	line := rest[j+1:]
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	ws := string(line[:n])
	if ws == "" || (strings.Trim(ws, " ") != "" && strings.Trim(ws, "\t") != "") {
		return "  "
	}
	return ws
}

func toCRLF(b []byte) []byte {
	var out bytes.Buffer
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out.WriteByte('\r')
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}

// locate finds the servers container and the silk entry in it (index -1
// when absent).
func (a *agentDef) locate(d *jsonDoc) (ci int, servers []jsonMember, si int, err error) {
	if ci, err = findMember(d.top, a.container); err != nil || ci < 0 {
		return ci, nil, -1, err
	}
	if servers, err = parseObject(d.top[ci].val); err != nil {
		return ci, nil, -1, &manualError{fmt.Sprintf("has a %q that is not a JSON object", a.container)}
	}
	si, err = findMember(servers, silkServer)
	return ci, servers, si, err
}

func notStrict(err error) error {
	return &manualError{"is not strict JSON (comments or trailing commas? " + err.Error() + "), so setup will not edit it"}
}

func (a *agentDef) jsonState(b []byte, s serverSpec) silkState {
	d, err := parseDoc(b)
	if err != nil {
		return stateUnknown
	}
	_, servers, si, err := a.locate(d)
	switch {
	case err != nil:
		return stateUnknown
	case si < 0:
		return stateAbsent
	case a.same(servers[si].val, a.entry(s)):
		return stateConfigured
	}
	return stateDiffers
}

func (a *agentDef) jsonInstall(old []byte, s serverSpec) ([]byte, string, error) {
	d, err := parseDoc(old)
	if err != nil {
		return nil, "", notStrict(err)
	}
	if a.prepare != nil {
		if d.top, err = a.prepare(d.top, len(d.top) == 0); err != nil {
			return nil, "", err
		}
	}
	ci, servers, si, err := a.locate(d)
	if err != nil {
		return nil, "", err
	}
	ours := a.entry(s)
	status := statusAdded
	if si >= 0 {
		if a.same(servers[si].val, ours) {
			return nil, statusSet, nil
		}
		servers[si].val = a.merge(servers[si].val, ours, d.indent)
		status = statusUpdated
	} else {
		v, err := marshalIndent(ours, d.indent, 2)
		if err != nil {
			return nil, "", err
		}
		servers = append(servers, newMember(silkServer, v))
	}
	cv := encodeObject(servers, d.indent, 1)
	if ci >= 0 {
		d.top[ci].val = cv
	} else {
		d.top = append(d.top, newMember(a.container, cv))
	}
	return d.bytes(), status, nil
}

func (a *agentDef) jsonRemove(old []byte) ([]byte, string, error) {
	d, err := parseDoc(old)
	if err != nil {
		return nil, "", notStrict(err)
	}
	ci, servers, si, err := a.locate(d)
	if err != nil {
		return nil, "", err
	}
	if si < 0 {
		return nil, statusAbsent, nil
	}
	servers = append(servers[:si], servers[si+1:]...)
	d.top[ci].val = encodeObject(servers, d.indent, 1)
	return d.bytes(), statusRemoved, nil
}

// transportKeys decide how a server is started. Setup owns them in the silk
// entry even when its own entry does not use them, so a leftover "url" or
// "type" cannot contradict the command it writes.
var transportKeys = []string{"type", "transport", "command", "args", "env", "url", "httpUrl", "serverUrl", "headers"}

// owns reports whether setup manages key in the silk entry. Everything
// else in an existing entry (autoApprove lists, timeouts, trust, soft keys)
// is the user's and is kept as written.
func (a *agentDef) owns(key string) bool {
	if slices.Contains(a.soft, key) {
		return false
	}
	if slices.Contains(transportKeys, key) {
		return true
	}
	_, ok := a.entry(serverSpec{Command: "silk", Args: []string{"mcp"}, Env: map[string]string{"SILK_HOME": "x"}}).get(key)
	return ok
}

// same reports whether an existing entry already matches ours in every key
// setup owns (a missing key equals an empty one).
func (a *agentDef) same(existing json.RawMessage, ours ordered) bool {
	var ex, want map[string]any
	if json.Unmarshal(existing, &ex) != nil {
		return false
	}
	b, err := json.Marshal(ours)
	if err != nil || json.Unmarshal(b, &want) != nil {
		return false
	}
	for k := range ex {
		if a.owns(k) && !reflect.DeepEqual(nonEmpty(ex[k]), nonEmpty(want[k])) {
			return false
		}
	}
	for k := range want {
		if a.owns(k) && !reflect.DeepEqual(nonEmpty(ex[k]), nonEmpty(want[k])) {
			return false
		}
	}
	return true
}

func nonEmpty(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			return nil
		}
	case []any:
		if len(t) == 0 {
			return nil
		}
	}
	return v
}

// merge rewrites the keys setup owns and keeps the rest of an existing
// entry (the user's autoApprove lists, timeouts, ...) as written.
func (a *agentDef) merge(existing json.RawMessage, ours ordered, indent string) json.RawMessage {
	old, err := parseObject(existing)
	if err != nil {
		v, _ := marshalIndent(ours, indent, 2)
		return v
	}
	var out []jsonMember
	seen := map[string]bool{}
	for _, mb := range old {
		first := !seen[mb.key]
		seen[mb.key] = true
		if !a.owns(mb.key) {
			out = append(out, mb)
			continue
		}
		if v, ok := ours.get(mb.key); ok && first {
			b, _ := marshalIndent(v, indent, 3)
			out = append(out, jsonMember{rawKey: mb.rawKey, key: mb.key, val: b})
		}
	}
	for _, f := range ours {
		if !seen[f.k] {
			b, _ := marshalIndent(f.v, indent, 3)
			out = append(out, newMember(f.k, b))
		}
	}
	return encodeObject(out, indent, 2)
}

// ---------------------------------------------------------------------------
// TOML: the [mcp_servers.silk] table (Codex, Grok Build)
//
// Setup does not rewrite TOML documents. It finds the lines of the
// [mcp_servers.silk] table (and its [mcp_servers.silk.*] subtables) and
// replaces or deletes exactly those lines, or appends a new table at the end.
// Any other way of defining silk (dotted keys, inline tables) is left to the
// user.

var silkTable = []string{"mcp_servers", silkServer}

type tomlFile struct {
	lines   []string // split on "\n"; a final "" means the text ends with a newline
	crlf    bool
	ranges  [][2]int // [start, end) lines of [mcp_servers.silk] and its subtables
	main    int      // index in ranges of [mcp_servers.silk], or -1
	problem string   // silk is defined in a way setup does not edit
}

func scanTOML(text string) *tomlFile {
	t := &tomlFile{lines: strings.Split(text, "\n"), crlf: strings.Contains(text, "\r\n"), main: -1}
	var table []string
	open, last := -1, -1 // range being extended; last line with content
	multi := ""          // inside a multi-line string with this delimiter
	closeRange := func() {
		if open >= 0 {
			t.ranges[open][1] = last + 1
			open = -1
		}
	}
	for i, raw := range t.lines {
		line := strings.TrimSpace(raw)
		if multi != "" {
			if strings.Count(line, multi)%2 == 1 {
				multi = ""
			}
			last = i
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			closeRange()
			path, array, ok := parseTOMLHeader(line)
			table, last = path, i
			if !ok {
				table = []string{"\x00"} // unparsable header: some other table
				continue
			}
			if hasPrefix(path, silkTable) {
				switch {
				case array:
					t.problem = "defines [[mcp_servers.silk]] as an array of tables"
				case len(path) == 2 && t.main >= 0:
					t.problem = "has [mcp_servers.silk] more than once"
				case len(path) == 2:
					t.main = len(t.ranges)
				}
				t.ranges = append(t.ranges, [2]int{i, i + 1})
				open = len(t.ranges) - 1
			}
			continue
		}
		last = i
		if key, rest, ok := tomlKey(line); ok && strings.HasPrefix(rest, "=") && open < 0 {
			full := append(slices.Clone(table), key...)
			if hasPrefix(full, silkTable) || slices.Equal(full, silkTable[:1]) {
				t.problem = "defines silk with dotted keys or an inline table"
			}
		}
		for _, delim := range []string{`"""`, `'''`} {
			if strings.Count(line, delim)%2 == 1 {
				multi = delim
				break
			}
		}
	}
	closeRange()
	if t.main < 0 && len(t.ranges) > 0 && t.problem == "" {
		t.problem = "has a [mcp_servers.silk.*] subtable but no [mcp_servers.silk] table"
	}
	return t
}

func hasPrefix(path, prefix []string) bool {
	return len(path) >= len(prefix) && slices.Equal(path[:len(prefix)], prefix)
}

// values parses the silk table and its subtables into nested maps.
func (t *tomlFile) values() (map[string]any, error) {
	root := map[string]any{}
	for _, r := range t.ranges {
		path, _, _ := parseTOMLHeader(strings.TrimSpace(t.lines[r[0]]))
		target := root
		for _, k := range path[len(silkTable):] {
			next, ok := target[k].(map[string]any)
			if !ok {
				next = map[string]any{}
				target[k] = next
			}
			target = next
		}
		if err := parseTOMLBody(strings.Join(t.lines[r[0]+1:r[1]], "\n"), target); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// without returns the text with the silk table removed. When block is not
// nil it takes the place of [mcp_servers.silk]. Blank lines that only
// separated a removed table are removed with it.
func (t *tomlFile) without(block []string) string {
	nl := "\n"
	if t.crlf {
		nl = "\r\n"
	}
	blank := func(i int) bool { return strings.TrimSpace(t.lines[i]) == "" }
	del := make([]bool, len(t.lines))
	for n, r := range t.ranges {
		for i := r[0]; i < r[1]; i++ {
			del[i] = true
		}
		if block != nil && n == t.main {
			continue
		}
		atEnd := true
		for i := r[1]; i < len(t.lines); i++ {
			if !blank(i) && !del[i] {
				atEnd = false
				break
			}
		}
		switch {
		case atEnd:
			for i := r[0] - 1; i >= 0 && blank(i) && !del[i]; i-- {
				del[i] = true
			}
		case r[1] < len(t.lines)-1 && blank(r[1]):
			del[r[1]] = true
		}
	}
	var out []string
	for i, line := range t.lines {
		if block != nil && i == t.ranges[t.main][0] {
			for _, b := range block {
				out = append(out, b+strings.TrimSuffix(nl, "\n"))
			}
		}
		if !del[i] {
			out = append(out, line)
		}
	}
	// Keep the final newline (the trailing "" element) if the text had one.
	if n := len(t.lines); n > 0 && t.lines[n-1] == "" && (len(out) == 0 || out[len(out)-1] != "") {
		out = append(out, "")
	}
	text := strings.Join(out, "\n")
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return text
}

func (t *tomlFile) appendBlock(block []string) string {
	nl := "\n"
	if t.crlf {
		nl = "\r\n"
	}
	text := strings.Join(t.lines, "\n")
	add := strings.Join(block, nl) + nl
	if strings.TrimSpace(text) == "" {
		return add
	}
	if !strings.HasSuffix(text, "\n") {
		text += nl
	}
	if !strings.HasSuffix(strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r"), "\n") {
		text += nl // a blank line between the previous table and ours
	}
	return text + add
}

func tomlBlock(s serverSpec) []string {
	args := make([]string, len(s.Args))
	for i, a := range s.Args {
		args[i] = tomlQuote(a)
	}
	lines := []string{
		"[" + strings.Join(silkTable, ".") + "]",
		"command = " + tomlQuote(s.Command),
		"args = [" + strings.Join(args, ", ") + "]",
	}
	if len(s.Env) > 0 {
		var env []string
		for _, k := range sortedKeys(s.Env) {
			env = append(env, tomlKeyName(k)+" = "+tomlQuote(s.Env[k]))
		}
		lines = append(lines, "env = { "+strings.Join(env, ", ")+" }")
	}
	return lines
}

func tomlState(b []byte, s serverSpec) silkState {
	t := scanTOML(string(b))
	switch {
	case t.problem != "":
		return stateUnknown
	case t.main < 0:
		return stateAbsent
	}
	v, err := t.values()
	if err == nil && sameTOMLServer(v, s) {
		return stateConfigured
	}
	return stateDiffers
}

func tomlInstall(old []byte, s serverSpec) ([]byte, string, error) {
	t := scanTOML(string(old))
	if t.problem != "" {
		return nil, "", &manualError{t.problem}
	}
	block := tomlBlock(s)
	if t.main < 0 {
		return []byte(t.appendBlock(block)), statusAdded, nil
	}
	if v, err := t.values(); err == nil && sameTOMLServer(v, s) {
		return nil, statusSet, nil
	}
	return []byte(t.without(block)), statusUpdated, nil
}

func tomlRemove(old []byte) ([]byte, string, error) {
	t := scanTOML(string(old))
	if t.problem != "" {
		return nil, "", &manualError{t.problem}
	}
	if t.main < 0 {
		return nil, statusAbsent, nil
	}
	return []byte(t.without(nil)), statusRemoved, nil
}

func sameTOMLServer(v map[string]any, s serverSpec) bool {
	if v["command"] != s.Command {
		return false
	}
	args, _ := v["args"].([]any)
	if len(args) != len(s.Args) {
		return false
	}
	for i, a := range args {
		if a != s.Args[i] {
			return false
		}
	}
	env, _ := v["env"].(map[string]any)
	if len(env) != len(s.Env) {
		return false
	}
	for k, val := range env {
		if want, ok := s.Env[k]; !ok || val != want {
			return false
		}
	}
	return true
}

func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlKeyName(k string) string {
	for i := 0; i < len(k); i++ {
		if !isBareKeyChar(k[i]) {
			return tomlQuote(k)
		}
	}
	if k == "" {
		return `""`
	}
	return k
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// tomlKey parses a (dotted) key at the start of s and returns its parts and
// what follows it, with leading spaces removed.
func tomlKey(s string) ([]string, string, bool) {
	var parts []string
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil, "", false
		}
		switch s[0] {
		case '"':
			v, rest, ok := tomlBasic(s)
			if !ok {
				return nil, "", false
			}
			parts, s = append(parts, v), rest
		case '\'':
			end := strings.IndexByte(s[1:], '\'')
			if end < 0 {
				return nil, "", false
			}
			parts, s = append(parts, s[1:1+end]), s[2+end:]
		default:
			n := 0
			for n < len(s) && isBareKeyChar(s[n]) {
				n++
			}
			if n == 0 {
				return nil, "", false
			}
			parts, s = append(parts, s[:n]), s[n:]
		}
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ".") {
			return parts, s, true
		}
		s = s[1:]
	}
}

func parseTOMLHeader(line string) (path []string, array, ok bool) {
	s := strings.TrimPrefix(line, "[")
	closer := "]"
	if strings.HasPrefix(s, "[") {
		s, closer, array = s[1:], "]]", true
	}
	path, rest, ok := tomlKey(s)
	if !ok || !strings.HasPrefix(rest, closer) {
		return nil, array, false
	}
	rest = strings.TrimSpace(rest[len(closer):])
	return path, array, rest == "" || rest[0] == '#'
}

// tomlBasic parses a basic (double-quoted, single-line) string at the start of s.
func tomlBasic(s string) (string, string, bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), s[i+1:], true
		case '\n':
			return "", "", false
		case '\\':
			i++
			if i >= len(s) {
				return "", "", false
			}
			switch e := s[i]; e {
			case 'b':
				b.WriteByte('\b')
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			case 'f':
				b.WriteByte('\f')
			case 'r':
				b.WriteByte('\r')
			case 'e':
				b.WriteByte(0x1b)
			case '"', '\\':
				b.WriteByte(e)
			case 'x', 'u', 'U':
				n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
				if i+n >= len(s) {
					return "", "", false
				}
				r, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
				if err != nil {
					return "", "", false
				}
				b.WriteRune(rune(r))
				i += n
			default:
				return "", "", false
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// parseTOMLBody parses the key/value lines of one table: enough TOML
// (strings, arrays, inline tables, booleans, bare numbers) to compare a
// server entry. Multi-line strings are not supported.
func parseTOMLBody(text string, into map[string]any) error {
	p := &tomlParser{s: text}
	for {
		p.skip(true)
		if p.s == "" {
			return nil
		}
		key, rest, ok := tomlKey(p.s)
		if !ok || !strings.HasPrefix(rest, "=") {
			return fmt.Errorf("unsupported TOML near %q", firstLine(p.s))
		}
		p.s = rest[1:]
		v, err := p.value()
		if err != nil {
			return err
		}
		setTOML(into, key, v)
		p.skip(false)
		if p.s != "" && p.s[0] != '\n' && p.s[0] != '\r' {
			return fmt.Errorf("unsupported TOML near %q", firstLine(p.s))
		}
	}
}

func setTOML(into map[string]any, key []string, v any) {
	for _, k := range key[:len(key)-1] {
		next, ok := into[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			into[k] = next
		}
		into = next
	}
	into[key[len(key)-1]] = v
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

type tomlParser struct{ s string }

// skip skips spaces and comments, and newlines too when lines is true.
func (p *tomlParser) skip(lines bool) {
	for p.s != "" {
		switch c := p.s[0]; {
		case c == ' ' || c == '\t':
			p.s = p.s[1:]
		case (c == '\n' || c == '\r') && lines:
			p.s = p.s[1:]
		case c == '#':
			i := strings.IndexByte(p.s, '\n')
			if i < 0 {
				i = len(p.s)
			}
			p.s = p.s[i:]
		default:
			return
		}
	}
}

func (p *tomlParser) value() (any, error) {
	p.skip(false)
	if p.s == "" {
		return nil, errors.New("missing TOML value")
	}
	switch p.s[0] {
	case '"':
		if strings.HasPrefix(p.s, `"""`) {
			return nil, errors.New("multi-line strings are not supported")
		}
		v, rest, ok := tomlBasic(p.s)
		if !ok {
			return nil, errors.New("bad TOML string")
		}
		p.s = rest
		return v, nil
	case '\'':
		if strings.HasPrefix(p.s, "'''") {
			return nil, errors.New("multi-line strings are not supported")
		}
		end := strings.IndexByte(p.s[1:], '\'')
		if end < 0 || strings.ContainsAny(p.s[1:1+end], "\n") {
			return nil, errors.New("bad TOML string")
		}
		v := p.s[1 : 1+end]
		p.s = p.s[2+end:]
		return v, nil
	case '[':
		p.s = p.s[1:]
		arr := []any{}
		for {
			p.skip(true)
			if strings.HasPrefix(p.s, "]") {
				p.s = p.s[1:]
				return arr, nil
			}
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
			p.skip(true)
			switch {
			case strings.HasPrefix(p.s, ","):
				p.s = p.s[1:]
			case strings.HasPrefix(p.s, "]"):
			default:
				return nil, errors.New("bad TOML array")
			}
		}
	case '{':
		p.s = p.s[1:]
		tbl := map[string]any{}
		for {
			p.skip(true)
			if strings.HasPrefix(p.s, "}") {
				p.s = p.s[1:]
				return tbl, nil
			}
			key, rest, ok := tomlKey(p.s)
			if !ok || !strings.HasPrefix(rest, "=") {
				return nil, errors.New("bad TOML inline table")
			}
			p.s = rest[1:]
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			setTOML(tbl, key, v)
			p.skip(true)
			switch {
			case strings.HasPrefix(p.s, ","):
				p.s = p.s[1:]
			case strings.HasPrefix(p.s, "}"):
			default:
				return nil, errors.New("bad TOML inline table")
			}
		}
	}
	n := strings.IndexAny(p.s, " \t\r\n,]}#")
	if n < 0 {
		n = len(p.s)
	}
	tok := p.s[:n]
	p.s = p.s[n:]
	switch tok {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "":
		return nil, errors.New("missing TOML value")
	}
	return tok, nil // numbers and dates: compared as text
}
