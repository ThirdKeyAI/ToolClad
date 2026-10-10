package executor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

func boolPtr(v bool) *bool { return &v }

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		name     string
		manifest *manifest.Manifest
		args     map[string]string
		want     string
		wantErr  bool
	}{
		{
			name: "simple template",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "whois_lookup"},
				Args: map[string]*manifest.ArgDef{
					"target": {
						Name:     "target",
						Position: 1,
						Required: true,
						Type:     "scope_target",
					},
				},
				Command: manifest.CommandDef{
					Template: "whois {target}",
				},
			},
			args: map[string]string{"target": "example.com"},
			want: "whois example.com",
		},
		{
			name: "template with defaults",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "nmap"},
				Args: map[string]*manifest.ArgDef{
					"target": {
						Name:          "target",
						Position:      1,
						Required:      true,
						Type:          "scope_target",
						BlockInternal: true, // required: nmap is an egress binary
					},
				},
				Command: manifest.CommandDef{
					Template: "nmap --max-rate {max_rate} {target}",
					Defaults: map[string]any{
						"max_rate": 1000,
					},
				},
			},
			args: map[string]string{"target": "93.184.216.34"},
			want: "nmap --max-rate 1000 93.184.216.34",
		},
		{
			name: "template with mappings",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "nmap"},
				Args: map[string]*manifest.ArgDef{
					"target": {
						Name:          "target",
						Position:      1,
						Required:      true,
						Type:          "scope_target",
						BlockInternal: true, // required: nmap is an egress binary
					},
					"scan_type": {
						Name:     "scan_type",
						Position: 2,
						Required: true,
						Type:     "enum",
						Allowed:  []string{"ping", "service", "syn"},
					},
				},
				Command: manifest.CommandDef{
					// Mapping variables use the unified _<arg_name>_flags
					// name; the old _<prefix>_flags alias is gone.
					Template: "nmap {_scan_type_flags} {target}",
					Mappings: map[string]map[string]string{
						"scan_type": {
							"ping":    "-sn -PE",
							"service": "-sT -sV",
							"syn":     "-sS",
						},
					},
				},
			},
			args: map[string]string{"target": "93.184.216.34", "scan_type": "service"},
			want: "nmap -sT -sV 93.184.216.34",
		},
		{
			name: "missing required arg",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "test"},
				Args: map[string]*manifest.ArgDef{
					"target": {
						Name:     "target",
						Position: 1,
						Required: true,
						Type:     "scope_target",
					},
				},
				Command: manifest.CommandDef{
					Template: "cmd {target}",
				},
			},
			args:    map[string]string{},
			wantErr: true,
		},
		{
			name: "optional arg with default",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "test"},
				Args: map[string]*manifest.ArgDef{
					"target": {
						Name:     "target",
						Position: 1,
						Required: true,
						Type:     "scope_target",
					},
					"extra": {
						Name:     "extra",
						Position: 2,
						Required: false,
						Type:     "string",
						Default:  "default-val",
					},
				},
				Command: manifest.CommandDef{
					Template: "cmd {extra} {target}",
				},
			},
			args: map[string]string{"target": "10.0.0.1"},
			want: "cmd default-val 10.0.0.1",
		},
		{
			name: "injection in arg rejected",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "test"},
				Args: map[string]*manifest.ArgDef{
					"input": {
						Name:     "input",
						Position: 1,
						Required: true,
						Type:     "string",
					},
				},
				Command: manifest.CommandDef{
					Template: "cmd {input}",
				},
			},
			args:    map[string]string{"input": "hello; rm -rf /"},
			wantErr: true,
		},
		{
			name: "custom executor returns executor path",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "msf"},
				Args: map[string]*manifest.ArgDef{},
				Command: manifest.CommandDef{
					Executor: "scripts/msf-wrapper.sh",
				},
			},
			args: map[string]string{},
			want: "scripts/msf-wrapper.sh",
		},
		{
			name: "no template or executor",
			manifest: &manifest.Manifest{
				Tool:    manifest.ToolMeta{Name: "empty"},
				Args:    map[string]*manifest.ArgDef{},
				Command: manifest.CommandDef{},
			},
			args:    map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildCommand(tt.manifest, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (cmd=%q)", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateMCPSchema(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name:        "nmap_scan",
			Description: "Network port scanning",
		},
		Args: map[string]*manifest.ArgDef{
			"target": {
				Name:        "target",
				Position:    1,
				Required:    true,
				Type:        "scope_target",
				Description: "Target IP",
			},
			"scan_type": {
				Name:        "scan_type",
				Position:    2,
				Required:    true,
				Type:        "enum",
				Allowed:     []string{"ping", "syn"},
				Description: "Scan type",
			},
		},
		Output: &manifest.OutputDef{
			Schema: map[string]any{
				"type": "object",
			},
		},
	}

	schema := GenerateMCPSchema(m)

	if schema["name"] != "nmap_scan" {
		t.Errorf("expected name 'nmap_scan', got %v", schema["name"])
	}

	// Verify it marshals to valid JSON.
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("failed to marshal schema: %v", err)
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"target"`) {
		t.Error("schema JSON missing 'target' property")
	}
	if !strings.Contains(jsonStr, `"required"`) {
		t.Error("schema JSON missing 'required' field")
	}
}

func TestExecuteEcho(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name:           "echo_test",
			TimeoutSeconds: 5,
		},
		Args: map[string]*manifest.ArgDef{
			"msg": {
				Name:     "msg",
				Position: 1,
				Required: true,
				Type:     "string",
			},
		},
		Command: manifest.CommandDef{
			Template: "echo {msg}",
		},
		Output: &manifest.OutputDef{
			Format: "text",
		},
	}

	env, err := Execute(m, map[string]string{"msg": "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "success" {
		t.Errorf("expected status 'success', got %q (error: %s)", env.Status, env.Error)
	}
	raw, ok := env.Results["raw_output"].(string)
	if !ok {
		t.Fatal("expected raw_output in results")
	}
	if !strings.Contains(raw, "hello") {
		t.Errorf("expected output to contain 'hello', got %q", raw)
	}
	if env.OutputHash == "" {
		t.Error("expected non-empty output hash")
	}
	if !strings.HasPrefix(env.OutputHash, "sha256:") {
		t.Errorf("expected hash prefix 'sha256:', got %q", env.OutputHash)
	}
}

func TestInjectTemplateVars(t *testing.T) {
	os.Setenv("TOOLCLAD_SECRET_API_KEY", "test-key-123")
	defer os.Unsetenv("TOOLCLAD_SECRET_API_KEY")

	result, err := injectTemplateVars("Bearer {_secret:api_key}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer test-key-123" {
		t.Errorf("got %q, want %q", result, "Bearer test-key-123")
	}
}

func TestInjectTemplateVarsMissing(t *testing.T) {
	os.Unsetenv("TOOLCLAD_SECRET_MISSING")
	_, err := injectTemplateVars("{_secret:missing}")
	if err == nil {
		t.Error("expected error for missing env var, got nil")
	}
	if !strings.Contains(err.Error(), "TOOLCLAD_SECRET_MISSING") {
		t.Errorf("error should mention TOOLCLAD_SECRET_MISSING, got: %v", err)
	}
}

func TestInjectTemplateVarsNoSecrets(t *testing.T) {
	result, err := injectTemplateVars("hello {world}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello {world}" {
		t.Errorf("got %q, want %q", result, "hello {world}")
	}
}

func TestExecuteHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header, got %q", r.Header.Get("Accept"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name:           "http_test",
			TimeoutSeconds: 5,
		},
		Args: map[string]*manifest.ArgDef{},
		Http: &manifest.HttpDef{
			Method:        "GET",
			URL:           ts.URL + "/status",
			Headers:       map[string]string{"Accept": "application/json"},
			SuccessStatus: []int{200},
		},
	}

	env, err := ExecuteHTTP(m, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "success" {
		t.Errorf("expected status 'success', got %q (error: %s)", env.Status, env.Error)
	}
	if env.ExitCode != 200 {
		t.Errorf("expected exit_code 200, got %d", env.ExitCode)
	}
	raw, ok := env.Results["raw_output"].(string)
	if !ok || !strings.Contains(raw, "ok") {
		t.Errorf("expected raw_output containing 'ok', got %v", env.Results)
	}
}

func TestExecuteHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name:           "http_err_test",
			TimeoutSeconds: 5,
		},
		Args: map[string]*manifest.ArgDef{},
		Http: &manifest.HttpDef{
			Method:        "GET",
			URL:           ts.URL + "/missing",
			SuccessStatus: []int{200},
		},
	}

	env, err := ExecuteHTTP(m, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "error" {
		t.Errorf("expected status 'error', got %q", env.Status)
	}
	if !strings.Contains(env.Error, "404") {
		t.Errorf("expected error to mention 404, got %q", env.Error)
	}
}

func TestExecuteMCP(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "mcp_test"},
		Args: map[string]*manifest.ArgDef{
			"target": {
				Name:     "target",
				Position: 1,
				Required: true,
				Type:     "scope_target",
			},
			"scan_type": {
				Name:     "scan_type",
				Position: 2,
				Required: true,
				Type:     "enum",
				Allowed:  []string{"ping", "syn"},
			},
		},
		Mcp: &manifest.McpProxyDef{
			Server:   "mcp://security-tools.example.com",
			Tool:     "remote_scan",
			FieldMap: map[string]string{"target": "host", "scan_type": "mode"},
		},
	}

	env, err := ExecuteMCP(m, map[string]string{"target": "10.0.1.1", "scan_type": "ping"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "delegation_preview" {
		t.Errorf("expected status 'delegation_preview', got %q", env.Status)
	}
	if env.Command != "mcp://mcp://security-tools.example.com/remote_scan" {
		t.Errorf("envelope command must be mcp://<server>/<tool>, got %q", env.Command)
	}
	if env.Results["mcp_server"] != "mcp://security-tools.example.com" {
		t.Errorf("unexpected mcp_server: %v", env.Results["mcp_server"])
	}
	if env.Results["mcp_tool"] != "remote_scan" {
		t.Errorf("unexpected mcp_tool: %v", env.Results["mcp_tool"])
	}
	mappedArgs, ok := env.Results["mapped_args"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapped_args map, got %T", env.Results["mapped_args"])
	}
	if mappedArgs["host"] != "10.0.1.1" {
		t.Errorf("expected mapped host=10.0.1.1, got %v", mappedArgs["host"])
	}
	if mappedArgs["mode"] != "ping" {
		t.Errorf("expected mapped mode=ping, got %v", mappedArgs["mode"])
	}
}

func TestExecuteMCPNoFieldMap(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "mcp_passthrough"},
		Args: map[string]*manifest.ArgDef{
			"msg": {
				Name:     "msg",
				Position: 1,
				Required: true,
				Type:     "string",
			},
		},
		Mcp: &manifest.McpProxyDef{
			Server: "mcp://tools.example.com",
			Tool:   "echo",
		},
	}

	env, err := ExecuteMCP(m, map[string]string{"msg": "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "delegation_preview" {
		t.Errorf("expected status 'delegation_preview', got %q", env.Status)
	}
	mappedArgs, ok := env.Results["mapped_args"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapped_args map, got %T", env.Results["mapped_args"])
	}
	if mappedArgs["msg"] != "hello" {
		t.Errorf("expected msg=hello, got %v", mappedArgs["msg"])
	}
}

func TestExecuteMCPMissingSection(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "no_mcp"},
		Args: map[string]*manifest.ArgDef{},
	}

	_, err := ExecuteMCP(m, map[string]string{})
	if err == nil {
		t.Error("expected error for missing mcp section")
	}
}

func assertArgv(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

func TestMappingAliasRemoved(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"scan_type": {Name: "scan_type", Required: true, Type: "enum", Allowed: []string{"syn"}},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "{_scan_flags}"},
			Mappings: map[string]map[string]string{"scan_type": {"syn": "-sS"}},
		},
	}
	_, err := BuildCommandArgv(m, map[string]string{"scan_type": "syn"})
	if err == nil || !strings.Contains(err.Error(), "unresolved placeholder '{_scan_flags}'") {
		t.Fatalf("expected unresolved placeholder for removed alias, got %v", err)
	}
}

func TestMappingSplicesTokens(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"target":    {Name: "target", Required: true, Type: "scope_target"},
			"scan_type": {Name: "scan_type", Required: true, Type: "enum", Allowed: []string{"ping", "syn"}},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "{_scan_type_flags}", "{target}"},
			Mappings: map[string]map[string]string{"scan_type": {"ping": "-sn -PE", "syn": "-sS"}},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"target": "10.0.0.1", "scan_type": "ping"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-sn", "-PE", "10.0.0.1"})
}

// A value containing whitespace, permitted via allow_whitespace on a
// declared exec array, stays exactly one argv element.
func TestWhitespaceValueIsOneArgvElement(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"msg": {Name: "msg", Required: true, Type: "string", AllowWhitespace: true},
		},
		Command: manifest.CommandDef{
			Exec:            []string{"echo", "{msg}", "tail"},
			ExecWasDeclared: true,
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"msg": "hello big world"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "hello big world", "tail"})

	// Embedded in literal text the token is still never re-split.
	m.Command.Exec = []string{"echo", "--msg={msg}"}
	argv, err = BuildCommandArgv(m, map[string]string{"msg": "hello big world"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "--msg=hello big world"})
}

// allow_whitespace is not honored for a template that was compiled to exec.
func TestWhitespaceRejectedInTemplateMode(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"msg": {Name: "msg", Required: true, Type: "string", AllowWhitespace: true},
		},
		Command: manifest.CommandDef{Template: "echo {msg}"},
	}
	_, err := BuildCommandArgv(m, map[string]string{"msg": "hello world"})
	if err == nil || !strings.Contains(err.Error(), "must not contain whitespace") {
		t.Fatalf("expected whitespace rejection in template mode, got %v", err)
	}
}

func TestEndOfOptionsInsertedBeforeFirstUserArg(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"target": {Name: "target", Required: true, Type: "scope_target"},
			"extra":  {Name: "extra", Required: false, Type: "string"},
		},
		Command: manifest.CommandDef{
			Exec:         []string{"echo", "--level", "{level}", "{target}", "{extra}"},
			Defaults:     map[string]any{"level": 3},
			EndOfOptions: "--",
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"target": "example.com", "extra": "foo"})
	if err != nil {
		t.Fatal(err)
	}
	// `--` goes before the first user-arg token, not before the default,
	// and is inserted only once.
	assertArgv(t, argv, []string{"echo", "--level", "3", "--", "example.com", "foo"})

	// A dropped (empty) first user arg does not consume the insertion.
	m.Command.Exec = []string{"echo", "{extra}", "{target}"}
	argv, err = BuildCommandArgv(m, map[string]string{"target": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "--", "example.com"})

	// No user-arg token at all: nothing is inserted.
	m.Command.Exec = []string{"echo", "{level}"}
	argv, err = BuildCommandArgv(m, map[string]string{"target": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "3"})
}

func TestConditionalsEvaluateAndSplice(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"headers": {Name: "headers", Required: false, Type: "string", AllowWhitespace: true},
			"url":     {Name: "url", Required: true, Type: "url"},
		},
		Command: manifest.CommandDef{
			Exec:            []string{"echo", "-s", "{_header_flags}", "{url}"},
			ExecWasDeclared: true,
			Conditionals: map[string]manifest.ConditionalDef{
				"header_flags": {When: "headers != ''", Template: "-H {headers}"},
			},
		},
	}
	// True: the conditional's tokens are substituted individually and
	// spliced; the header value with a space stays one element.
	argv, err := BuildCommandArgv(m, map[string]string{"headers": "X-Trace: abc", "url": "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-s", "-H", "X-Trace: abc", "https://example.com/"})

	// False: the conditional contributes nothing.
	argv, err = BuildCommandArgv(m, map[string]string{"url": "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-s", "https://example.com/"})
}

func TestConditionalLiteralComparison(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"max_rate": {Name: "max_rate", Required: false, Type: "integer", Default: 100},
		},
		Command: manifest.CommandDef{
			Exec: []string{"echo", "{_rate_flag}"},
			Conditionals: map[string]manifest.ConditionalDef{
				"rate_flag": {When: "max_rate != '100'", Template: "-maxrate {max_rate}"},
			},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo"})

	argv, err = BuildCommandArgv(m, map[string]string{"max_rate": "50"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-maxrate", "50"})
}

func TestEvaluateCondition(t *testing.T) {
	vars := map[string]string{"a": "1", "b": ""}
	cases := []struct {
		when string
		want bool
	}{
		{"a != ''", true},
		{"b != ''", false},
		{"a == ''", false},
		{"b == ''", true},
		{"a == '1'", true},
		{"a == \"1\"", true},
		{"a == 1", true},
		{"a != 1", false},
		{"missing == ''", true},
		{"a != '' and b != ''", false},
		{"a != '' and b == ''", true},
		{"a != '' or b != ''", true},
		{"b != '' or a == ''", false},
		{"a", false},
		{"", false},
	}
	for _, c := range cases {
		if got := evaluateCondition(c.when, vars); got != c.want {
			t.Errorf("evaluateCondition(%q) = %v, want %v", c.when, got, c.want)
		}
	}
}

func TestBraceEscapesInArgv(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"msg": {Name: "msg", Required: true, Type: "string"},
		},
		Command: manifest.CommandDef{
			Exec: []string{"echo", "-w", "%{{http_code}}", "{msg}"},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"msg": "hi"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-w", "%{http_code}", "hi"})
}

func TestUnresolvedPlaceholderIsBuildError(t *testing.T) {
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "t"},
		Command: manifest.CommandDef{Exec: []string{"echo", "{nope}"}},
	}
	_, err := BuildCommandArgv(m, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "unresolved placeholder '{nope}' in command") {
		t.Fatalf("expected unresolved placeholder error, got %v", err)
	}
}

func TestInjectedVars(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", dir)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "t"},
		Command: manifest.CommandDef{Exec: []string{"echo", "{_scan_id}", "{_evidence_dir}", "{_output_file}"}},
	}
	argv, err := BuildCommandArgv(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 4 {
		t.Fatalf("argv = %q, want 4 elements", argv)
	}
	if argv[1] == "" {
		t.Error("_scan_id must be non-empty")
	}
	if argv[2] != dir {
		t.Errorf("_evidence_dir = %q, want %q", argv[2], dir)
	}
	if want := filepath.Join(dir, argv[1]+"-t", "scan.txt"); argv[3] != want {
		t.Errorf("_output_file = %q, want %q", argv[3], want)
	}

	t.Setenv("TOOLCLAD_EVIDENCE_DIR", "")
	argv, err = BuildCommandArgv(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(os.TempDir(), "toolclad-evidence"); argv[2] != want {
		t.Errorf("default _evidence_dir = %q, want %q", argv[2], want)
	}
}

func TestEmptyOptionalPlaceholderDropped(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"opt": {Name: "opt", Required: false, Type: "string"},
		},
		Command: manifest.CommandDef{Exec: []string{"echo", "{opt}", "--prefix={opt}", "end"}},
	}
	argv, err := BuildCommandArgv(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	// The sole-placeholder token is dropped; the embedded one keeps its
	// surrounding literal text.
	assertArgv(t, argv, []string{"echo", "--prefix=", "end"})
}

// The exec array form runs end to end (it used to fail before argv was built
// from the canonical exec form).
func TestExecuteExecArray(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "echo_exec", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{
			"msg": {Name: "msg", Required: true, Type: "string", AllowWhitespace: true},
		},
		Command: manifest.CommandDef{
			Exec:            []string{"echo", "{msg}"},
			ExecWasDeclared: true,
		},
		Output: &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, map[string]string{"msg": "hello there"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.Status != "success" {
		t.Fatalf("status = %q (error: %s)", env.Status, env.Error)
	}
	raw, _ := env.Results["raw_output"].(string)
	if strings.TrimSpace(raw) != "hello there" {
		t.Errorf("raw_output = %q", raw)
	}
	// The executed envelope carries the declared command, not the resolved
	// argv (the dry run keeps that).
	if env.Command != "echo {msg}" {
		t.Errorf("envelope command = %q", env.Command)
	}
}

func TestFormatArgv(t *testing.T) {
	got := FormatArgv([]string{"echo", "plain", "has space", "it's", ""})
	want := `echo plain 'has space' 'it'\''s' ''`
	if got != want {
		t.Errorf("FormatArgv = %q, want %q", got, want)
	}
}

func TestMissingMappingIsBuildError(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"mode": {Name: "mode", Required: true, Type: "string"},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "{_mode_flags}"},
			Mappings: map[string]map[string]string{"mode": {"fast": "-T4"}},
		},
	}
	_, err := BuildCommandArgv(m, map[string]string{"mode": "slow"})
	want := "no mapping for argument 'mode' value 'slow' in [command.mappings.mode]"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q, got %v", want, err)
	}
}

func TestMappingToEmptyStringMeansNoFlags(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"mode": {Name: "mode", Required: true, Type: "enum", Allowed: []string{"fast", "plain"}},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "{_mode_flags}", "end"},
			Mappings: map[string]map[string]string{"mode": {"fast": "-T4", "plain": ""}},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"mode": "plain"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "end"})
}

func TestAbsentOptionalMappedArgContributesNothing(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"mode": {Name: "mode", Required: false, Type: "string"},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "{_mode_flags}", "end"},
			Mappings: map[string]map[string]string{"mode": {"fast": "-T4"}},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "end"})
}

func TestTrustedVarGluedToLiteralRefused(t *testing.T) {
	want := "placeholder '{_mode_flags}' expands to multiple tokens and must be a whole token in command"
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"mode": {Name: "mode", Required: true, Type: "enum", Allowed: []string{"fast"}},
		},
		Command: manifest.CommandDef{
			Exec:     []string{"echo", "--f={_mode_flags}"},
			Mappings: map[string]map[string]string{"mode": {"fast": "-T4 -v"}},
		},
	}
	_, err := BuildCommandArgv(m, map[string]string{"mode": "fast"})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q, got %v", want, err)
	}

	// The build-time guard fires on its own even when the load-time check
	// was bypassed (tokens produced after compilation).
	vars := map[string]string{}
	trusted := map[string][]string{"_mode_flags": {"-T4", "-v"}}
	_, err = expandTokens([]string{"--f={_mode_flags}"}, vars, trusted, nil)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expandTokens: expected %q, got %v", want, err)
	}
}

func TestExecutorHatchValidatesInStrictMode(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"msg": {Name: "msg", Required: true, Type: "string", AllowWhitespace: true},
		},
		Command: manifest.CommandDef{
			Executor:        "scripts/wrapper.sh",
			Exec:            []string{"echo", "{msg}"},
			ExecWasDeclared: true,
		},
	}
	// executor takes precedence over exec and validates strictly.
	argv, err := BuildCommandArgv(m, map[string]string{"msg": "plain"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"scripts/wrapper.sh"})
	_, err = BuildCommandArgv(m, map[string]string{"msg": "has space"})
	if err == nil || !strings.Contains(err.Error(), "must not contain whitespace") {
		t.Fatalf("executor hatch must reject whitespace even with allow_whitespace, got %v", err)
	}
}

// end_of_options counts only direct exec tokens: a user-arg placeholder
// inside a spliced conditional never attracts the `--`.
func TestEndOfOptionsIgnoresSplicedTokens(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{
			"headers": {Name: "headers", Required: false, Type: "string"},
			"target":  {Name: "target", Required: true, Type: "scope_target"},
		},
		Command: manifest.CommandDef{
			Exec:         []string{"echo", "{_header_flags}", "{target}"},
			EndOfOptions: "--",
			Conditionals: map[string]manifest.ConditionalDef{
				"header_flags": {When: "headers != ''", Template: "-H {headers}"},
			},
		},
	}
	argv, err := BuildCommandArgv(m, map[string]string{"headers": "X-Trace", "target": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "-H", "X-Trace", "--", "example.com"})
}

func TestUnknownArgumentRefused(t *testing.T) {
	declared := map[string]*manifest.ArgDef{
		"target": {Name: "target", Position: 1, Required: true, Type: "scope_target"},
		"scan_type": {
			Name: "scan_type", Position: 2, Required: false, Type: "enum",
			Allowed: []string{"ping"},
		},
	}
	// An argument the manifest no longer declares must not be dropped
	// silently: the caller would otherwise get a successful run with no
	// indication that extra_flags never reached the command.
	args := map[string]string{"target": "example.com", "extra_flags": "-iL /etc/passwd"}
	want := "unknown argument 'extra_flags' (declared arguments: scan_type, target)"

	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "echo_tool", TimeoutSeconds: 5},
		Args:    declared,
		Command: manifest.CommandDef{Exec: []string{"echo", "{target}"}},
	}
	if _, err := BuildCommandArgv(m, args); err == nil || err.Error() != want {
		t.Fatalf("dry run: want %q, got %v", want, err)
	}
	env, err := Execute(m, args)
	if err == nil || err.Error() != want {
		t.Fatalf("execute: want %q, got %v", want, err)
	}
	if env == nil || env.Status != "error" || env.Command != "" {
		t.Errorf("execute must return an error envelope without running: %+v", env)
	}

	hm := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "http_tool", TimeoutSeconds: 5},
		Args: declared,
		Http: &manifest.HttpDef{Method: "GET", URL: "http://127.0.0.1:9/never-contacted"},
	}
	if _, err := ExecuteHTTP(hm, args); err == nil || err.Error() != want {
		t.Fatalf("http: want %q, got %v", want, err)
	}

	mm := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "mcp_tool"},
		Args: declared,
		Mcp:  &manifest.McpProxyDef{Server: "mcp://example.com", Tool: "scan"},
	}
	if _, err := ExecuteMCP(mm, args); err == nil || err.Error() != want {
		t.Fatalf("mcp: want %q, got %v", want, err)
	}

	// Several unknown names: the first in sorted order is reported.
	many := map[string]string{"target": "example.com", "zeta": "1", "alpha": "2"}
	wantFirst := "unknown argument 'alpha' (declared arguments: scan_type, target)"
	if _, err := BuildCommandArgv(m, many); err == nil || err.Error() != wantFirst {
		t.Fatalf("want %q, got %v", wantFirst, err)
	}

	// A manifest with no [args] at all.
	none := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "noargs"},
		Args:    map[string]*manifest.ArgDef{},
		Command: manifest.CommandDef{Exec: []string{"true"}},
	}
	wantNone := "unknown argument 'x' (declared arguments: none)"
	if _, err := BuildCommandArgv(none, map[string]string{"x": "1"}); err == nil || err.Error() != wantNone {
		t.Fatalf("want %q, got %v", wantNone, err)
	}

	// Declared arguments only: still builds.
	if _, err := BuildCommandArgv(m, map[string]string{"target": "example.com"}); err != nil {
		t.Fatalf("declared-only args must build: %v", err)
	}
}

// TC-7: {_secret:name} is expanded on the manifest template before argument
// interpolation, so an argument value can never smuggle a secret reference
// into the request. Nothing is sent: the request is only built.
func TestHTTPSecretsExpandBeforeArgs(t *testing.T) {
	const secret = "test-key-123"
	t.Setenv("TOOLCLAD_SECRET_API_KEY", secret)

	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "secret_order", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{
			"target": {Name: "target", Type: "string", Required: true},
		},
		Http: &manifest.HttpDef{
			Method: "POST",
			URL:    "https://api.example.com/fetch?u={target}",
			Headers: map[string]string{
				"Authorization": "Bearer {_secret:api_key}",
				"X-Echo":        "{target}",
			},
			BodyTemplate: `{"t":"{target}"}`,
		},
	}
	// The value is fed in as if it had passed validation, so the test does
	// not depend on the url validator's brace check being the only defense.
	smuggled := "https://attacker.example/?k={_secret:api_key}"
	cleaned := map[string]string{"target": smuggled}

	req, err := buildHTTPRequest(m, cleaned)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	built := req.URL.String()
	if strings.Contains(built, secret) {
		t.Errorf("secret leaked into URL: %q", built)
	}
	// The argument text survives literally (percent-encoded as one query
	// value), so its secret reference is never expanded.
	if got := req.URL.Query().Get("u"); got != smuggled {
		t.Errorf("argument text must survive literally in the URL, got %q", got)
	}
	if got := req.Header.Get("X-Echo"); got != smuggled {
		t.Errorf("header from argument must stay literal: got %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+secret {
		t.Errorf("manifest-template secret must still expand: got %q", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Errorf("secret leaked into body: %q", body)
	}
	if string(body) != `{"t":"`+smuggled+`"}` {
		t.Errorf("body must carry the argument literally, got %q", body)
	}
}

// A url-typed argument carrying a secret reference is refused at validation
// in ExecuteHTTP, before any request is built or sent.
func TestExecuteHTTPRejectsSecretInURLArg(t *testing.T) {
	t.Setenv("TOOLCLAD_SECRET_API_KEY", "test-key-123")
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "secret_arg", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{
			// block_internal is required by the egress lint for an [http]
			// manifest; the metacharacter check still fires first.
			"target": {Name: "target", Type: "url", Required: true, BlockInternal: true},
		},
		Http: &manifest.HttpDef{Method: "GET", URL: "https://api.example.com/fetch?u={target}"},
	}
	_, err := ExecuteHTTP(m, map[string]string{"target": "https://attacker.example/?k={_secret:api_key}"})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "metacharacter") {
		t.Errorf("want metacharacter rejection, got %v", err)
	}
}
