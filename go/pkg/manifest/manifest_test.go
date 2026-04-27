package manifest

import (
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
