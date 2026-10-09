package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/scope"
)

func scopedArgs() map[string]*manifest.ArgDef {
	return map[string]*manifest.ArgDef{
		"target": {Name: "target", Position: 1, Required: true, Type: "scope_target", ScopeCheck: true, BlockInternal: true},
	}
}

// Every execution path passes the manifest's scope to the validator.
func TestScopeEnforcedOnEveryPath(t *testing.T) {
	sc := &scope.ScopeDef{AllowedCIDRs: []string{"93.184.216.0/24"}}

	oneshot := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "t"},
		Args:    scopedArgs(),
		Command: manifest.CommandDef{Exec: []string{"echo", "{target}"}},
		Scope:   sc,
	}
	argv, err := BuildCommandArgv(oneshot, map[string]string{"target": "93.184.216.34"})
	if err != nil {
		t.Fatal(err)
	}
	assertArgv(t, argv, []string{"echo", "93.184.216.34"})
	if _, err := BuildCommandArgv(oneshot, map[string]string{"target": "8.8.8.8"}); err == nil ||
		!strings.Contains(err.Error(), "target '8.8.8.8' is not in scope") {
		t.Errorf("oneshot: want scope refusal, got %v", err)
	}
	if _, err := Execute(oneshot, map[string]string{"target": "8.8.8.8"}); err == nil ||
		!strings.Contains(err.Error(), "is not in scope") {
		t.Errorf("execute: want scope refusal, got %v", err)
	}

	httpM := &manifest.Manifest{
		Tool:  manifest.ToolMeta{Name: "t"},
		Args:  scopedArgs(),
		Http:  &manifest.HttpDef{Method: "GET", URL: "https://api.example.com/{target}"},
		Scope: sc,
	}
	if _, err := ExecuteHTTP(httpM, map[string]string{"target": "8.8.8.8"}); err == nil ||
		!strings.Contains(err.Error(), "is not in scope") {
		t.Errorf("http: want scope refusal before any request, got %v", err)
	}

	mcpM := &manifest.Manifest{
		Tool:  manifest.ToolMeta{Name: "t"},
		Args:  scopedArgs(),
		Mcp:   &manifest.McpProxyDef{Server: "mcp://x", Tool: "y"},
		Scope: sc,
	}
	if _, err := ExecuteMCP(mcpM, map[string]string{"target": "93.184.216.34"}); err != nil {
		t.Errorf("mcp in scope: %v", err)
	}
	if _, err := ExecuteMCP(mcpM, map[string]string{"target": "8.8.8.8"}); err == nil ||
		!strings.Contains(err.Error(), "is not in scope") {
		t.Errorf("mcp: want scope refusal, got %v", err)
	}
}

// A manifest built in memory discovers its scope through the environment
// (or the working directory) the first time it is used.
func TestInMemoryManifestDiscoversScope(t *testing.T) {
	f := filepath.Join(t.TempDir(), "scope.toml")
	if err := os.WriteFile(f, []byte("[scope]\nallowed_cidrs = [\"93.184.216.0/24\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(scope.EnvVar, f)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "t"},
		Args:    scopedArgs(),
		Command: manifest.CommandDef{Exec: []string{"echo", "{target}"}},
	}
	if _, err := BuildCommandArgv(m, map[string]string{"target": "93.184.216.34"}); err != nil {
		t.Fatal(err)
	}
	if m.Scope == nil {
		t.Fatal("scope not cached on the manifest")
	}
	if _, err := BuildCommandArgv(m, map[string]string{"target": "8.8.8.8"}); err == nil {
		t.Error("out-of-scope target accepted")
	}
}

// A loaded manifest uses the scope file found above its own directory.
func TestLoadedManifestUsesDiscoveredScope(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scope", "scope.toml"),
		[]byte("[scope]\nallowed_domains = [\"*.example.com\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "manifests")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "t.clad.toml")
	body := "[tool]\nname = \"t\"\nversion = \"1\"\ndescription = \"d\"\n\n" +
		"[args.target]\nposition = 1\nrequired = true\ntype = \"scope_target\"\nscope_check = true\n\n" +
		"[command]\nexec = [\"echo\", \"{target}\"]\n\n[output]\nformat = \"text\"\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.LoadManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCommandArgv(m, map[string]string{"target": "app.example.com"}); err != nil {
		t.Errorf("in scope: %v", err)
	}
	if _, err := BuildCommandArgv(m, map[string]string{"target": "example.com"}); err == nil ||
		!strings.Contains(err.Error(), "is not in scope") {
		t.Errorf("apex: want scope refusal, got %v", err)
	}
}
