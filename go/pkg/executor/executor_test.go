package executor

import (
	"encoding/json"
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
		Output: manifest.OutputDef{
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
		Output: manifest.OutputDef{
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
