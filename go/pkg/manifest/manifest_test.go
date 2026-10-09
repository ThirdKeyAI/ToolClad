package manifest

import (
	"bytes"
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
