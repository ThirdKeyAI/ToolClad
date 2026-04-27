package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
						Name:     "target",
						Position: 1,
						Required: true,
						Type:     "scope_target",
					},
				},
				Command: manifest.CommandDef{
					Template: "nmap --max-rate {max_rate} {target}",
					Defaults: map[string]any{
						"max_rate": 1000,
					},
				},
			},
			args: map[string]string{"target": "10.0.0.1"},
			want: "nmap --max-rate 1000 10.0.0.1",
		},
		{
			name: "template with mappings",
			manifest: &manifest.Manifest{
				Tool: manifest.ToolMeta{Name: "nmap"},
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
						Allowed:  []string{"ping", "service", "syn"},
					},
				},
				Command: manifest.CommandDef{
					Template: "nmap {_scan_flags} {target}",
					Mappings: map[string]map[string]string{
						"scan_type": {
							"ping":    "-sn -PE",
							"service": "-sT -sV",
							"syn":     "-sS",
						},
					},
				},
			},
			args: map[string]string{"target": "10.0.0.1", "scan_type": "service"},
			want: "nmap -sT -sV 10.0.0.1",
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
