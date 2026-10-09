package manifest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "tool.clad.toml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTmp: %v", err)
	}
	return p
}

func TestCallbackDispatchAllowsNoBackendOrOutput(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "store_knowledge"
version = "1.0.0"
binary = "callback"
description = "Validator-only embedding"
risk_tier = "low"
dispatch = "callback"

[args.confidence]
position = 1
required = true
type = "number"
min_float = 0.0
max_float = 1.0
description = "Confidence 0-1"
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Tool.Dispatch != "callback" {
		t.Errorf("expected dispatch=callback, got %q", m.Tool.Dispatch)
	}
	if m.Output != nil {
		t.Errorf("expected Output to be nil, got %+v", m.Output)
	}
	conf, ok := m.Args["confidence"]
	if !ok {
		t.Fatal("missing confidence arg")
	}
	if conf.MinFloat == nil || *conf.MinFloat != 0.0 {
		t.Errorf("expected MinFloat=0.0, got %v", conf.MinFloat)
	}
	if conf.MaxFloat == nil || *conf.MaxFloat != 1.0 {
		t.Errorf("expected MaxFloat=1.0, got %v", conf.MaxFloat)
	}
}

func TestExecDispatchRequiresBackendAndOutput(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "missing_backend"
version = "1.0.0"
binary = ""
description = "x"
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected error for manifest with no backend / no output")
	}
	if !strings.Contains(err.Error(), "execution backend") {
		t.Errorf("expected 'execution backend' in error, got: %v", err)
	}
}

func TestInvalidDispatchRejected(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "x"
dispatch = "rocket"

[command]
exec = ["true"]

[output]
format = "text"
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected error for invalid dispatch")
	}
	if !strings.Contains(err.Error(), "invalid dispatch") {
		t.Errorf("expected 'invalid dispatch' in error, got: %v", err)
	}
}

func TestTokenizeTemplate(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr string
	}{
		{name: "plain", in: "a b  c", want: []string{"a", "b", "c"}},
		{name: "single quotes", in: "a 'b c' d", want: []string{"a", "b c", "d"}},
		{name: "double quotes", in: `a "b c"`, want: []string{"a", "b c"}},
		{name: "backslash escape", in: `a\ b`, want: []string{"a b"}},
		{name: "tabs and newlines", in: "a\tb\nc", want: []string{"a", "b", "c"}},
		{name: "empty quoted token", in: "''", want: []string{""}},
		{name: "empty", in: "", want: nil},
		{name: "brace escape inside quotes", in: `-w '%{{http_code}}'`, want: []string{"-w", "%{{http_code}}"}},
		{name: "placeholder outside quotes", in: "echo {msg}", want: []string{"echo", "{msg}"}},
		{name: "placeholder in single quotes", in: "echo '{msg}'", wantErr: "placeholder inside quotes"},
		{name: "placeholder in double quotes", in: `echo "{msg}"`, wantErr: "placeholder inside quotes"},
		{name: "placeholder after escape in quotes", in: `'{{{msg}'`, wantErr: "placeholder inside quotes"},
		{name: "unbalanced single", in: "echo 'abc", wantErr: "unbalanced quote"},
		{name: "unbalanced double", in: `echo "abc`, wantErr: "unbalanced quote"},
		{name: "trailing backslash", in: `echo abc\`, wantErr: "trailing backslash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TokenizeTemplate(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got tokens %q", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestExpandTokenBraceEscapes(t *testing.T) {
	resolve := func(name string) (string, bool) {
		if name == "msg" {
			return "hi", true
		}
		return "", false
	}
	cases := map[string]string{
		"%{{http_code}}": "%{http_code}",
		"{{":             "{",
		"}}":             "}",
		"a{msg}b":        "ahib",
		"{{{msg}}}":      "{hi}",
	}
	for in, want := range cases {
		got, err := ExpandToken(in, resolve)
		if err != nil {
			t.Fatalf("ExpandToken(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ExpandToken(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ExpandToken("{nope}", resolve); err == nil || !strings.Contains(err.Error(), "unresolved placeholder '{nope}'") {
		t.Errorf("expected unresolved placeholder error, got %v", err)
	}
	if names := Placeholders("%{{http_code}} {msg} {{x}}"); len(names) != 1 || names[0] != "msg" {
		t.Errorf("Placeholders: got %q, want [msg]", names)
	}
}

const manifestHeader = `
[tool]
name = "echo_tool"
version = "1.0.0"
binary = "echo"
description = "x"

[output]
format = "text"
`

func TestTemplateCompiledToExecWithWarning(t *testing.T) {
	var buf bytes.Buffer
	prev := WarningOutput
	WarningOutput = &buf
	defer func() { WarningOutput = prev }()

	p := writeTmp(t, manifestHeader+`
[args.msg]
position = 1
required = true
type = "string"

[command]
template = "echo -n {msg}"
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"echo", "-n", "{msg}"}
	if strings.Join(m.Command.Exec, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("Exec = %q, want %q", m.Command.Exec, want)
	}
	if m.Command.ExecWasDeclared {
		t.Error("ExecWasDeclared should be false for a compiled template")
	}
	if m.Command.Template == "" {
		t.Error("Template should be kept for display")
	}
	if !strings.Contains(buf.String(), TemplateDeprecationWarning) {
		t.Errorf("expected deprecation warning, got %q", buf.String())
	}
}

func TestExecDeclaredNoWarning(t *testing.T) {
	var buf bytes.Buffer
	prev := WarningOutput
	WarningOutput = &buf
	defer func() { WarningOutput = prev }()

	p := writeTmp(t, manifestHeader+`
[args.msg]
position = 1
required = true
type = "string"

[command]
exec = ["echo", "{msg}"]
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Command.ExecWasDeclared {
		t.Error("ExecWasDeclared should be true")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected warning output: %q", buf.String())
	}
}

func TestPlaceholderInQuotesRefusedAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.msg]
position = 1
required = true
type = "string"

[command]
template = "echo '{msg}'"
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "placeholder inside quotes") {
		t.Fatalf("expected in-quotes rejection, got %v", err)
	}
}

func TestConditionalPlaceholderInQuotesRefusedAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.headers]
position = 1
required = false
type = "string"

[command]
exec = ["echo", "{_header_flags}"]

[command.conditionals.header_flags]
when = "headers != ''"
template = "-H '{headers}'"
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "placeholder inside quotes") {
		t.Fatalf("expected in-quotes rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "conditionals.header_flags") {
		t.Errorf("error should name the conditional, got %v", err)
	}
}

func TestConditionalTokenizedAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.headers]
position = 1
required = false
type = "string"

[command]
exec = ["echo", "{_header_flags}"]

[command.conditionals.header_flags]
when = "headers != ''"
template = "-H {headers}"
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	toks := m.Command.Conditionals["header_flags"].Tokens
	if len(toks) != 2 || toks[0] != "-H" || toks[1] != "{headers}" {
		t.Errorf("Tokens = %q, want [-H {headers}]", toks)
	}
}

func TestUnresolvedPlaceholderRefusedAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[command]
exec = ["echo", "{nope}"]
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "unresolved placeholder '{nope}'") {
		t.Fatalf("expected unresolved placeholder error, got %v", err)
	}

	p = writeTmp(t, manifestHeader+`
[command]
exec = ["echo", "{_cond}"]

[command.conditionals.cond]
when = "x != ''"
template = "{missing}"
`)
	_, err = LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "unresolved placeholder '{missing}'") {
		t.Fatalf("expected unresolved placeholder error in conditional, got %v", err)
	}
}

func TestKnownPlaceholdersAcceptedAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.target]
position = 1
required = true
type = "scope_target"

[args.mode]
position = 2
required = true
type = "enum"
allowed = ["a", "b"]

[command]
exec = ["echo", "{_mode_flags}", "--rate", "{rate}", "{_extra}", "{_scan_id}", "{_evidence_dir}", "{_output_file}", "{target}"]

[command.defaults]
rate = 10

[command.mappings.mode]
a = "-A"
b = "-B -b"

[command.conditionals.extra]
when = "mode == 'a'"
template = "--extra"
`)
	if _, err := LoadManifest(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBraceEscapeIsNotPlaceholderAtLoad(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[command]
exec = ["echo", "-w", "%{{http_code}}"]
`)
	if _, err := LoadManifest(p); err != nil {
		t.Fatalf("brace escape must not trip the placeholder check: %v", err)
	}
}

func TestEndOfOptionsValidation(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[command]
exec = ["echo"]
end_of_options = "--"
`)
	if _, err := LoadManifest(p); err != nil {
		t.Fatalf("end_of_options = \"--\" must load: %v", err)
	}
	p = writeTmp(t, manifestHeader+`
[command]
exec = ["echo"]
end_of_options = "-"
`)
	if _, err := LoadManifest(p); err == nil || !strings.Contains(err.Error(), "end_of_options") {
		t.Fatalf("expected end_of_options rejection, got %v", err)
	}
}

func TestNewArgDefFieldsParsed(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.flag]
position = 1
required = true
type = "string"
allow_leading_dash = true
allow_whitespace = true

[command]
exec = ["echo", "{flag}"]
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Args["flag"].AllowLeadingDash || !m.Args["flag"].AllowWhitespace {
		t.Errorf("allow_leading_dash / allow_whitespace not parsed: %+v", m.Args["flag"])
	}
}

func TestEnumMappingMustCoverAllowedValues(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.mode]
position = 1
required = true
type = "enum"
allowed = ["fast", "plain", "slow"]

[command]
exec = ["echo", "{_mode_flags}"]

[command.mappings.mode]
fast = "-T4"
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "command.mappings.mode") {
		t.Fatalf("expected enum coverage error, got %v", err)
	}
	for _, missing := range []string{"plain", "slow"} {
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error should name missing value %q: %v", missing, err)
		}
	}
	if strings.Contains(err.Error(), `"fast"`) {
		t.Errorf("error must not list the covered value: %v", err)
	}

	// Mapping a value to "" means "no flags" and satisfies coverage.
	p = writeTmp(t, manifestHeader+`
[args.mode]
position = 1
required = true
type = "enum"
allowed = ["fast", "plain"]

[command]
exec = ["echo", "{_mode_flags}"]

[command.mappings.mode]
fast = "-T4"
plain = ""
`)
	if _, err := LoadManifest(p); err != nil {
		t.Fatalf("complete mapping must load: %v", err)
	}
}

func TestTrustedVarGluedToLiteralRefusedAtLoad(t *testing.T) {
	want := "expands to multiple tokens and must be a whole token in command"
	p := writeTmp(t, manifestHeader+`
[args.mode]
position = 1
required = true
type = "enum"
allowed = ["fast"]

[command]
exec = ["echo", "--f={_mode_flags}"]

[command.mappings.mode]
fast = "-T4"
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "'{_mode_flags}' "+want) {
		t.Fatalf("expected glued mapping var rejection, got %v", err)
	}

	p = writeTmp(t, manifestHeader+`
[args.headers]
position = 1
required = false
type = "string"

[command]
exec = ["echo", "x{_hf}"]

[command.conditionals.hf]
when = "headers != ''"
template = "-H {headers}"
`)
	_, err = LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "'{_hf}' "+want) {
		t.Fatalf("expected glued conditional var rejection, got %v", err)
	}
}

// --- Unknown manifest keys (SEMANTICS.md W2) ---

func TestUnknownToolKeyRefused(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
tiemout_seconds = 5

[command]
exec = ["echo"]

[output]
format = "text"
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected misspelled tool key to be refused")
	}
	if !strings.Contains(err.Error(), "unknown key 'tool.tiemout_seconds' in manifest") {
		t.Errorf("error must name the key: %v", err)
	}
}

func TestUnknownArgKeyRefused(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[args.target]
position = 1
required = true
type = "scope_target"
block_internal_typo = true

[command]
exec = ["echo", "{target}"]
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "unknown key 'args.target.block_internal_typo' in manifest") {
		t.Fatalf("expected args.target.block_internal_typo to be refused, got %v", err)
	}
}

func TestUnknownSectionKeysRefused(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "command",
			body: `
[command]
exec = ["echo"]
shell = true
`,
			want: "unknown key 'command.shell' in manifest",
		},
		{
			name: "output",
			body: `
[command]
exec = ["echo"]

[output]
formatt = "text"
`,
			want: "unknown key 'output.formatt' in manifest",
		},
		{
			name: "http",
			body: `
[http]
method = "GET"
url = "https://example.com/"
verify_tls = false

[output]
format = "json"
`,
			want: "unknown key 'http.verify_tls' in manifest",
		},
		{
			name: "conditional",
			body: `
[args.rate]
position = 1
required = false
type = "integer"

[command]
exec = ["echo", "{_rate_flag}"]

[command.conditionals.rate_flag]
whenn = "rate != ''"
template = "--rate {rate}"

[output]
format = "text"
`,
			want: "unknown key 'command.conditionals.rate_flag.whenn' in manifest",
		},
		{
			name: "session",
			body: `
[session]
startup_command = "sh"
ready_patern = "> "

[output]
format = "text"
`,
			want: "unknown key 'session.ready_patern' in manifest",
		},
		{
			name: "browser",
			body: `
[browser]
engine = "chromium"
headles = true

[output]
format = "text"
`,
			want: "unknown key 'browser.headles' in manifest",
		},
	}
	header := `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeTmp(t, header+c.body)
			_, err := LoadManifest(p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q in error, got %v", c.want, err)
			}
		})
	}
}

func TestUnknownKeysReportedTogetherSorted(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
zzz_last = 1
tiemout_seconds = 5

[args.target]
position = 1
required = true
type = "scope_target"
block_internal_typo = true

[command]
exec = ["echo", "{target}"]
shell = true

[output]
format = "text"
formatt = "text"
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	want := []string{
		"unknown key 'args.target.block_internal_typo' in manifest",
		"unknown key 'command.shell' in manifest",
		"unknown key 'output.formatt' in manifest",
		"unknown key 'tool.tiemout_seconds' in manifest",
		"unknown key 'tool.zzz_last' in manifest",
	}
	last := -1
	for _, w := range want {
		idx := strings.Index(msg, w)
		if idx < 0 {
			t.Errorf("error must name %q: %s", w, msg)
			continue
		}
		if idx < last {
			t.Errorf("unknown keys must be sorted; %q out of order in: %s", w, msg)
		}
		if strings.Count(msg, w) != 1 {
			t.Errorf("%q must be reported exactly once: %s", w, msg)
		}
		last = idx
	}
}

func TestUnknownTableReportedByItsOwnPath(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[command]
exec = ["echo"]

[sandbox]
enabled = true
level = 2
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected unknown table to be refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown key 'sandbox' in manifest") {
		t.Errorf("unknown table must be reported by its own path: %s", msg)
	}
	if strings.Contains(msg, "sandbox.enabled") || strings.Contains(msg, "sandbox.level") {
		t.Errorf("entries beneath an unknown table must not be reported separately: %s", msg)
	}
}

func TestAllowUnknownKeysDowngradesToWarning(t *testing.T) {
	src := `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
tiemout_seconds = 5

[command]
exec = ["echo"]
shell = true

[output]
format = "text"
`
	p := writeTmp(t, src)

	// The strict entry points stay strict.
	if _, err := LoadManifest(p); err == nil {
		t.Fatal("LoadManifest must stay strict")
	}
	if _, err := LoadManifestWithOptions(p, LoadOptions{}); err == nil {
		t.Fatal("zero LoadOptions must be strict")
	}

	var buf bytes.Buffer
	old := WarningOutput
	WarningOutput = &buf
	defer func() { WarningOutput = old }()

	m, err := LoadManifestWithOptions(p, LoadOptions{AllowUnknownKeys: true})
	if err != nil {
		t.Fatalf("AllowUnknownKeys must load: %v", err)
	}
	if m.Tool.Name != "x" {
		t.Errorf("manifest not loaded: %+v", m.Tool)
	}
	out := buf.String()
	for _, w := range []string{
		"warning: unknown key 'command.shell' in manifest\n",
		"warning: unknown key 'tool.tiemout_seconds' in manifest\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("expected %q on WarningOutput, got %q", w, out)
		}
	}
}

func TestOpenMapKeysNotReported(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"

[args.mode]
position = 1
required = true
type = "enum"
allowed = ["fast"]

[command]
exec = ["echo", "{anything}", "{_mode_flags}"]

[command.defaults]
anything = "goes"
other = 5

[command.defaults.nested]
deeper = true

[command.mappings.mode]
fast = "-T4"

[output]
format = "json"

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "nested schema tables are author-defined"

[output.schema.properties.hosts.items.properties.port]
type = "integer"

[http]
method = "GET"
url = "https://example.com/"

[http.headers]
Accept = "application/json"
X-Anything = "allowed"

[mcp]
server = "mcp://example.com"
tool = "scan"

[mcp.field_map]
mode = "speed"
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("author-chosen keys under open maps must load: %v", err)
	}
	if m.Command.Defaults["anything"] != "goes" {
		t.Errorf("command.defaults not decoded: %v", m.Command.Defaults)
	}
	if m.Http.Headers["X-Anything"] != "allowed" {
		t.Errorf("http.headers not decoded: %v", m.Http.Headers)
	}
	if m.Mcp.FieldMap["mode"] != "speed" {
		t.Errorf("mcp.field_map not decoded: %v", m.Mcp.FieldMap)
	}
	if _, ok := m.Output.Schema["properties"]; !ok {
		t.Errorf("output.schema not decoded: %v", m.Output.Schema)
	}
}

// TestEveryAllowlistedKeyAccepted exercises every key in the SEMANTICS.md W2
// allowlist so the Go struct tags cannot drift from the other runtimes.
func TestEveryAllowlistedKeyAccepted(t *testing.T) {
	oneshot := writeTmp(t, `
[tool]
name = "all_keys"
version = "1.0.0"
binary = "echo"
description = "exercises every oneshot key"
timeout_seconds = 30
risk_tier = "low"
human_approval = false
dispatch = "exec"
mode = "oneshot"
network_egress = true
allow_interpreter = false

[tool.cedar]
resource = "Tool::AllKeys"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}"
capture = true
hash = "sha256"
screenshots = false

[tool.limits]
nproc = 64
nofile = 256
fsize_bytes = 1048576
address_space_bytes = 536870912
cpu_seconds = 30

[args.target]
position = 1
required = true
type = "scope_target"
description = "target"
default = "example.com"
allowed = []
pattern = "^[a-z.]+$"
sanitize = ["injection"]
min = 1
max = 10
min_float = 0.5
max_float = 9.5
clamp = true
schemes = ["https"]
scope_check = false
block_internal = true
allow_leading_dash = false
allow_whitespace = false

[args.mode]
position = 2
required = false
type = "enum"
allowed = ["fast", "slow"]
default = "fast"

[command]
template = "echo {target}"
exec = ["echo", "{target}", "{_mode_flags}", "{_rate}", "{maxtime}"]
executor = ""
end_of_options = "--"

[command.defaults]
maxtime = "600s"

[command.mappings.mode]
fast = "-T4"
slow = "-T1"

[command.conditionals.rate]
when = "target != ''"
template = "--rate 10"

[output]
format = "json"
parser = "builtin:json"
envelope = true
max_bytes = 1024

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"

[http]
method = "POST"
url = "https://api.example.com/scan"
body_template = "{\"target\": \"{target}\"}"
success_status = [200]
error_status = [500]

[http.headers]
Accept = "application/json"

[mcp]
server = "mcp://example.com"
tool = "remote_scan"

[mcp.field_map]
target = "host"
`)
	m, err := LoadManifest(oneshot)
	if err != nil {
		t.Fatalf("every allowlisted oneshot key must load: %v", err)
	}
	if !m.Tool.NetworkEgress || m.Tool.AllowInterpreter || m.Tool.Mode != "oneshot" {
		t.Errorf("tool keys not decoded: %+v", m.Tool)
	}
	if m.Tool.Limits == nil || m.Tool.Limits.Nproc == nil || *m.Tool.Limits.Nproc != 64 ||
		m.Tool.Limits.CPUSeconds == nil || *m.Tool.Limits.CPUSeconds != 30 {
		t.Errorf("tool.limits not decoded: %+v", m.Tool.Limits)
	}
	if m.Tool.Evidence == nil || m.Tool.Evidence.Screenshots {
		t.Errorf("tool.evidence.screenshots not decoded: %+v", m.Tool.Evidence)
	}
	if !m.Args["target"].BlockInternal {
		t.Errorf("args.target.block_internal not decoded: %+v", m.Args["target"])
	}
	if m.Output.MaxBytes == nil || *m.Output.MaxBytes != 1024 || m.Output.MaxBytesLimit() != 1024 {
		t.Errorf("output.max_bytes not decoded: %+v", m.Output)
	}

	sessionBrowser := writeTmp(t, `
[tool]
name = "session_browser"
version = "1.0.0"
binary = "msfconsole"
description = "exercises every session and browser key"
mode = "session"

[session]
startup_command = "msfconsole -q"
ready_pattern = "msf6 >"
startup_timeout_seconds = 60
idle_timeout_seconds = 300
session_timeout_seconds = 3600
max_interactions = 100

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 1048576
output_wait_ms = 500

[session.commands.set_target]
pattern = "set RHOSTS {target}"
description = "Set the target"
risk_tier = "low"
human_approval = false
extract_target = true

[session.commands.set_target.args.target]
position = 1
required = true
type = "scope_target"
block_internal = true

[session.child_detection]
pattern = "^nmap "
type = "oneshot"
manifest = "nmap_scan.clad.toml"

[browser]
engine = "chromium"
headless = true
connect = "ws://localhost:9222"
extract_mode = "text"
startup_timeout_seconds = 30
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 50

[browser.defaults]
extract_mode = "markdown"

[browser.scope]
allowed_domains = ["example.com"]
blocked_domains = ["evil.example"]
allow_external = false

[browser.commands.navigate]
description = "Open a page"
risk_tier = "low"
human_approval = false

[browser.commands.navigate.args.url]
position = 1
required = true
type = "url"
block_internal = true

[browser.state]
fields = ["url", "title"]

[output]
format = "text"
`)
	m, err = LoadManifest(sessionBrowser)
	if err != nil {
		t.Fatalf("every allowlisted session/browser key must load: %v", err)
	}
	if m.Session == nil || m.Session.ChildDetection == nil ||
		m.Session.ChildDetection.Pattern != "^nmap " ||
		m.Session.ChildDetection.Type != "oneshot" ||
		m.Session.ChildDetection.Manifest != "nmap_scan.clad.toml" {
		t.Errorf("session.child_detection not decoded: %+v", m.Session)
	}
	if m.Browser == nil || m.Browser.Defaults == nil || m.Browser.Defaults.ExtractMode != "markdown" {
		t.Errorf("browser.defaults not decoded: %+v", m.Browser)
	}
	if m.Tool.Mode != "session" {
		t.Errorf("explicit tool.mode must be kept, got %q", m.Tool.Mode)
	}
}

func TestToolModeValidation(t *testing.T) {
	header := `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
%s

[output]
format = "text"
`
	derived := []struct {
		name    string
		backend string
		want    string
	}{
		{"oneshot", "\n[command]\nexec = [\"echo\"]\n", "oneshot"},
		{"session", "\n[session]\nstartup_command = \"sh\"\n", "session"},
		{"browser", "\n[browser]\nengine = \"chromium\"\n", "browser"},
	}
	for _, c := range derived {
		t.Run("derived_"+c.name, func(t *testing.T) {
			p := writeTmp(t, strings.Replace(header, "%s", "", 1)+c.backend)
			m, err := LoadManifest(p)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.Tool.Mode != c.want {
				t.Errorf("want derived mode %q, got %q", c.want, m.Tool.Mode)
			}
		})
	}

	for _, mode := range ToolModes {
		p := writeTmp(t, strings.Replace(header, "%s", "mode = \""+mode+"\"", 1)+"\n[command]\nexec = [\"echo\"]\n")
		m, err := LoadManifest(p)
		if err != nil {
			t.Fatalf("mode %q must be accepted: %v", mode, err)
		}
		if m.Tool.Mode != mode {
			t.Errorf("want mode %q, got %q", mode, m.Tool.Mode)
		}
	}

	p := writeTmp(t, strings.Replace(header, "%s", "mode = \"rocket\"", 1)+"\n[command]\nexec = [\"echo\"]\n")
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "invalid tool.mode 'rocket'") {
		t.Fatalf("expected invalid tool.mode error, got %v", err)
	}
}

func TestOutputMaxBytesDefault(t *testing.T) {
	p := writeTmp(t, manifestHeader+`
[command]
exec = ["echo"]
`)
	m, err := LoadManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Output.MaxBytes != nil {
		t.Errorf("absent max_bytes must decode as nil, got %v", *m.Output.MaxBytes)
	}
	if m.Output.MaxBytesLimit() != DefaultOutputMaxBytes || DefaultOutputMaxBytes != 8388608 {
		t.Errorf("want default 8388608, got %d", m.Output.MaxBytesLimit())
	}
}

func TestCaseVariantKeyRefused(t *testing.T) {
	// The decoder would fill TimeoutSeconds from a case-variant key; the
	// allowlist is exact so the other runtimes and this one agree.
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "echo"
Timeout_Seconds = 5

[command]
exec = ["echo"]

[output]
format = "text"
`)
	_, err := LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "unknown key 'tool.Timeout_Seconds' in manifest") {
		t.Fatalf("expected case-variant key to be refused, got %v", err)
	}
}

func TestUnknownKeyInNestedCommandArgsRefused(t *testing.T) {
	p := writeTmp(t, `
[tool]
name = "x"
version = "1.0.0"
binary = "sh"

[session]
startup_command = "sh"

[session.commands.set_target]
pattern = "set RHOSTS {target}"
descriptionn = "typo"

[session.commands.set_target.args.target]
position = 1
type = "scope_target"
block_internal_typo = true

[browser]
engine = "chromium"

[browser.commands.navigate]
description = "x"
risk = "low"

[browser.commands.navigate.args.url]
type = "url"
schemas = ["https"]

[output]
format = "text"
`)
	_, err := LoadManifest(p)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, w := range []string{
		"unknown key 'session.commands.set_target.descriptionn' in manifest",
		"unknown key 'session.commands.set_target.args.target.block_internal_typo' in manifest",
		"unknown key 'browser.commands.navigate.risk' in manifest",
		"unknown key 'browser.commands.navigate.args.url.schemas' in manifest",
	} {
		if strings.Count(err.Error(), w) != 1 {
			t.Errorf("want %q exactly once in: %v", w, err)
		}
	}
}

// D5: the egress lint. A manifest that reaches the network — by naming an
// egress binary, by declaring network_egress, or by dispatching through
// [http] or [browser] — must set block_internal on every network-typed
// argument.
func TestEgressLint(t *testing.T) {
	const want = "argument 'target' is a network target for an egress binary but block_internal is not set; " +
		"set block_internal = true to default-deny internal/SSRF targets"
	body := func(tool, args, backend string) string {
		return "[tool]\nname = \"t\"\n" + tool + "\n\n[args.target]\nposition = 1\nrequired = true\n" + args +
			"\n\n" + backend + "\n\n[output]\nformat = \"text\"\n"
	}
	cases := []struct {
		name     string
		manifest string
		refused  bool
	}{
		{"curl template without flag", body(``, `type = "scope_target"`, "[command]\ntemplate = \"curl {target}\""), true},
		{"nmap exec without flag", body(``, `type = "scope_target"`, "[command]\nexec = [\"nmap\", \"{target}\"]"), true},
		{"nmap exec with flag", body(``, "type = \"scope_target\"\nblock_internal = true", "[command]\nexec = [\"nmap\", \"{target}\"]"), false},
		{"tool.binary path basename", body(`binary = "/usr/bin/curl"`, `type = "url"`, "[command]\nexec = [\"fetch\", \"{target}\"]"), true},
		{"exec[0] path basename", body(``, `type = "url"`, "[command]\nexec = [\"/opt/bin/WGET\", \"{target}\"]"), true},
		{"quoted template first token", body(``, `type = "url"`, "[command]\ntemplate = \"'curl' {target}\""), true},
		{"network_egress on unlisted binary", body(`network_egress = true`, `type = "ip_address"`, "[command]\nexec = [\"scanner\", \"{target}\"]"), true},
		{"network_egress with flag", body(`network_egress = true`, "type = \"cidr\"\nblock_internal = true", "[command]\nexec = [\"scanner\", \"{target}\"]"), false},
		{"http backend url arg", body(``, `type = "url"`, "[http]\nmethod = \"GET\"\nurl = \"{target}\""), true},
		{"http backend with flag", body(``, "type = \"url\"\nblock_internal = true", "[http]\nmethod = \"GET\"\nurl = \"{target}\""), false},
		{"browser backend", body(``, `type = "url"`, "[browser]\nengine = \"chromium\""), true},
		{"non-egress whois", body(``, `type = "scope_target"`, "[command]\nexec = [\"whois\", \"{target}\"]"), false},
		{"non-egress binary string arg", body(`binary = "curl"`, `type = "string"`, "[command]\nexec = [\"curl\", \"{target}\"]"), false},
		{"executor only is not inspected", body(``, `type = "scope_target"`, "[command]\nexecutor = \"scripts/curl-wrapper.sh\""), false},
		{"executor with network_egress", body(`network_egress = true`, `type = "scope_target"`, "[command]\nexecutor = \"scripts/curl-wrapper.sh\""), true},
		{"mcp backend is not egress", body(``, `type = "scope_target"`, "[mcp]\nserver = \"mcp://example.com\"\ntool = \"scan\""), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadManifest(writeTmp(t, c.manifest))
			if !c.refused {
				if err != nil {
					t.Fatalf("must load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want %q, got %v", want, err)
			}
		})
	}
}

// The lint reports the first offending argument in name order and names
// each of the four network types.
func TestEgressLintCoversEveryNetworkType(t *testing.T) {
	for _, typ := range []string{"scope_target", "url", "ip_address", "cidr"} {
		m := &Manifest{
			Tool: ToolMeta{Name: "t"},
			Args: map[string]*ArgDef{
				"zeta":  {Name: "zeta", Type: typ},
				"alpha": {Name: "alpha", Type: typ},
				"port":  {Name: "port", Type: "port"},
			},
			Command: CommandDef{Exec: []string{"nmap", "{alpha}", "{zeta}"}},
		}
		err := m.LintEgress(nil)
		if err == nil || !strings.HasPrefix(err.Error(), "argument 'alpha' is a network target") {
			t.Errorf("%s: want alpha reported first, got %v", typ, err)
		}
		m.Args["alpha"].BlockInternal = true
		if err := m.LintEgress(nil); err == nil || !strings.HasPrefix(err.Error(), "argument 'zeta'") {
			t.Errorf("%s: want zeta reported next, got %v", typ, err)
		}
		m.Args["zeta"].BlockInternal = true
		if err := m.LintEgress(nil); err != nil {
			t.Errorf("%s: all flagged must pass: %v", typ, err)
		}
	}
}

// Manifests built in memory get the lint through EnsureCompiled, and a
// failed lint leaves the manifest uncompiled so a retry is not skipped.
func TestEgressLintInEnsureCompiled(t *testing.T) {
	m := &Manifest{
		Tool:    ToolMeta{Name: "t"},
		Args:    map[string]*ArgDef{"target": {Name: "target", Type: "scope_target"}},
		Command: CommandDef{Template: "nmap -sV {target}"},
	}
	err := m.EnsureCompiled()
	if err == nil || !strings.Contains(err.Error(), "block_internal is not set") {
		t.Fatalf("want lint failure, got %v", err)
	}
	if err := m.EnsureCompiled(); err == nil {
		t.Fatal("a second EnsureCompiled must not skip the failed lint")
	}
	m.Args["target"].BlockInternal = true
	if err := m.EnsureCompiled(); err != nil {
		t.Fatalf("flagged manifest must compile: %v", err)
	}
	if !m.compiled || len(m.Command.Exec) != 3 {
		t.Errorf("manifest not compiled: compiled=%v exec=%v", m.compiled, m.Command.Exec)
	}
}

func TestIsNetworkEgress(t *testing.T) {
	cases := []struct {
		name string
		m    Manifest
		want bool
	}{
		{"plain", Manifest{Command: CommandDef{Exec: []string{"whois"}}}, false},
		{"flag", Manifest{Tool: ToolMeta{NetworkEgress: true}}, true},
		{"http", Manifest{Http: &HttpDef{}}, true},
		{"browser", Manifest{Browser: &BrowserDef{}}, true},
		{"mcp", Manifest{Mcp: &McpProxyDef{}}, false},
		{"session", Manifest{Session: &SessionDef{}}, false},
		{"binary", Manifest{Tool: ToolMeta{Binary: "nikto"}}, true},
		{"binary windows path", Manifest{Tool: ToolMeta{Binary: `C:\tools\Hydra`}}, true},
		{"binary suffixed", Manifest{Tool: ToolMeta{Binary: "curl.exe"}}, false},
		{"binary unix path", Manifest{Tool: ToolMeta{Binary: "/usr/local/bin/ffuf"}}, true},
		{"exec", Manifest{Command: CommandDef{Exec: []string{"ncat", "-z"}}}, true},
		{"template", Manifest{Command: CommandDef{Template: "  ping -c 1 {target}"}}, true},
		{"template later token", Manifest{Command: CommandDef{Template: "timeout 5 curl {target}"}}, false},
		{"executor", Manifest{Command: CommandDef{Executor: "scripts/curl.sh"}}, false},
		{"curl-like name", Manifest{Command: CommandDef{Exec: []string{"curlish"}}}, false},
	}
	for _, c := range cases {
		if got := c.m.IsNetworkEgress(); got != c.want {
			t.Errorf("%s: IsNetworkEgress = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEgressLintCoversNestedCommandArgs(t *testing.T) {
	base := `
[tool]
name = "b"
version = "1.0.0"
binary = "chrome"
description = "x"

[browser]

[browser.commands.navigate]
description = "go"

[browser.commands.navigate.args.url]
position = 1
required = true
type = "url"
%s
description = "u"

[output]
format = "json"
`
	_, err := LoadManifest(writeTmp(t, fmt.Sprintf(base, "")))
	if err == nil || !strings.Contains(err.Error(), "browser.commands.navigate.args.url") {
		t.Fatalf("expected nested browser arg to be linted, got %v", err)
	}
	if _, err := LoadManifest(writeTmp(t, fmt.Sprintf(base, "block_internal = true"))); err != nil {
		t.Fatalf("flagged nested arg should load: %v", err)
	}
}
