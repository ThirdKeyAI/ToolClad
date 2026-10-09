package validator

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/scope"
)

const noScopeMsg = "scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)"

// TestSharedScopeVectorsValidation runs the validator-level sections of the
// shared tests/scope_vectors.json file.
func TestSharedScopeVectorsValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "scope_vectors.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("tests/scope_vectors.json not present; shared scope vectors skipped")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors struct {
			ScopeTargetValidation []struct {
				Value string `json:"value"`
				Valid bool   `json:"valid"`
			} `json:"scope_target_validation"`
			URLScopeCheck []struct {
				URL          string   `json:"url"`
				AllowedHosts []string `json:"allowed_hosts"`
				Expected     bool     `json:"expected"`
			} `json:"url_scope_check"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors.ScopeTargetValidation) == 0 || len(v.Vectors.URLScopeCheck) == 0 {
		t.Fatal("scope vector sections missing")
	}
	for _, c := range v.Vectors.ScopeTargetValidation {
		_, err := ValidateArg(&manifest.ArgDef{Name: "target", Type: "scope_target"}, c.Value)
		if (err == nil) != c.Valid {
			t.Errorf("scope_target %q: valid=%v, err=%v", c.Value, c.Valid, err)
		}
	}
	for _, c := range v.Vectors.URLScopeCheck {
		sc := &scope.ScopeDef{AllowedDomains: c.AllowedHosts}
		def := &manifest.ArgDef{Name: "url", Type: "url", ScopeCheck: true}
		_, err := ValidateArgIn(def, c.URL, false, sc)
		if (err == nil) != c.Expected {
			t.Errorf("url %q in %v: expected=%v, err=%v", c.URL, c.AllowedHosts, c.Expected, err)
		}
	}
}

func TestScopeCheckFailsClosed(t *testing.T) {
	for _, typ := range []string{"scope_target", "url", "ip_address", "cidr"} {
		val := map[string]string{
			"scope_target": "example.com",
			"url":          "https://example.com/",
			"ip_address":   "10.0.1.5",
			"cidr":         "10.0.1.0/25",
		}[typ]
		def := &manifest.ArgDef{Name: "t", Type: typ, ScopeCheck: true}
		_, err := ValidateArgIn(def, val, false, nil)
		if err == nil || err.Error() != "validation error for 't': "+noScopeMsg {
			t.Errorf("%s: want fail-closed refusal, got %v", typ, err)
		}
		// The legacy entry points have no scope and must fail closed too.
		if _, err := ValidateArg(def, val); err == nil {
			t.Errorf("%s: ValidateArg without scope accepted a scope_check arg", typ)
		}
	}
}

func TestScopeCheckMatching(t *testing.T) {
	sc := &scope.ScopeDef{
		AllowedDomains: []string{"example.com", "*.example.com"},
		AllowedCIDRs:   []string{"10.0.1.0/24"},
		BlockedDomains: []string{"admin.example.com"},
		BlockedCIDRs:   []string{"10.0.1.250/32"},
	}
	cases := []struct {
		typ, val string
		ok       bool
	}{
		{"scope_target", "example.com", true},
		{"scope_target", "app.example.com", true},
		{"scope_target", "deep.sub.example.com", true},
		{"scope_target", "evil-example.com", false},
		{"scope_target", "admin.example.com", false}, // blocked beats allowed
		{"scope_target", "10.0.1.5", true},
		{"scope_target", "10.0.1.250", false},
		{"scope_target", "10.0.1.0/25", true},
		{"scope_target", "10.0.0.0/8", false},
		{"url", "https://app.example.com:8443/x?y#z", true},
		{"url", "https://admin.example.com/", false},
		{"url", "http://10.0.1.7/", true},
		{"url", "https://example.com.evil.com/", false},
		{"ip_address", "10.0.1.9", true},
		{"ip_address", "10.0.2.9", false},
		{"cidr", "10.0.1.0/28", true},
		{"cidr", "10.0.0.0/16", false},
		{"cidr", "10.0.1.248/29", false}, // overlaps the blocked host
	}
	for _, c := range cases {
		def := &manifest.ArgDef{Name: "t", Type: c.typ, ScopeCheck: true}
		_, err := ValidateArgIn(def, c.val, false, sc)
		if (err == nil) != c.ok {
			t.Errorf("%s %q: ok=%v, err=%v", c.typ, c.val, c.ok, err)
		}
		if err != nil && !c.ok && !strings.Contains(err.Error(), "is not in scope") {
			t.Errorf("%s %q: unexpected refusal %v", c.typ, c.val, err)
		}
	}
	// Apex not matched by the wildcard alone.
	wild := &scope.ScopeDef{AllowedDomains: []string{"*.example.com"}}
	_, err := ValidateArgIn(&manifest.ArgDef{Name: "t", Type: "scope_target", ScopeCheck: true}, "example.com", false, wild)
	if err == nil || err.Error() != "validation error for 't': target 'example.com' is not in scope" {
		t.Errorf("apex: got %v", err)
	}
	// A url refusal names the host.
	_, err = ValidateArgIn(&manifest.ArgDef{Name: "u", Type: "url", ScopeCheck: true}, "https://evil.com/a", false, wild)
	if err == nil || err.Error() != "validation error for 'u': target 'evil.com' is not in scope" {
		t.Errorf("url refusal: got %v", err)
	}
}

func TestScopeAndBlockInternalBothApply(t *testing.T) {
	sc := &scope.ScopeDef{AllowedCIDRs: []string{"10.0.1.0/24"}, AllowedDomains: []string{"example.com"}}
	def := &manifest.ArgDef{Name: "t", Type: "scope_target", ScopeCheck: true, BlockInternal: true}
	// In scope but internal: block_internal still refuses.
	_, err := ValidateArgIn(def, "10.0.1.5", false, sc)
	if err == nil || !strings.Contains(err.Error(), "block_internal") {
		t.Errorf("in-scope internal target: want block_internal refusal, got %v", err)
	}
	// Public but out of scope: the scope refuses.
	_, err = ValidateArgIn(def, "8.8.8.8", false, sc)
	if err == nil || !strings.Contains(err.Error(), "is not in scope") {
		t.Errorf("public out-of-scope target: want scope refusal, got %v", err)
	}
}

func TestScopeCheckWithCustomTypes(t *testing.T) {
	cts := map[string]*manifest.CustomTypeDef{"host": {Base: "scope_target"}, "label": {Base: "string"}}
	sc := &scope.ScopeDef{AllowedDomains: []string{"example.com"}}
	def := &manifest.ArgDef{Name: "t", Type: "host", ScopeCheck: true}
	if _, err := ValidateArgWithCustomTypesIn(def, "example.com", cts, false, sc); err != nil {
		t.Errorf("in scope: %v", err)
	}
	if _, err := ValidateArgWithCustomTypesIn(def, "other.com", cts, false, sc); err == nil {
		t.Error("out of scope custom type accepted")
	}
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "t"},
		Args: map[string]*manifest.ArgDef{"l": {Name: "l", Type: "label", ScopeCheck: true}},
	}
	if err := ValidateManifestWithCustomTypes(m, cts); err == nil ||
		!strings.Contains(err.Error(), "scope_check is not supported for type 'string'") {
		t.Errorf("scope_check on a custom string type: got %v", err)
	}
}

// writeManifest writes a manifest into dir (created if needed).
func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tool.clad.toml")
	content := "[tool]\nname = \"t\"\nversion = \"1.0.0\"\ndescription = \"d\"\n\n" + body +
		"\n[command]\nexec = [\"echo\", \"{target}\"]\n\n[output]\nformat = \"text\"\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeScopeFile(t *testing.T, dir, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "scope", "scope.toml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const scopeArg = "[args.target]\nposition = 1\nrequired = true\ntype = \"scope_target\"\nscope_check = true\n"

func TestManifestScopeDiscovery(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	root := t.TempDir()
	writeScopeFile(t, root, "[scope]\nallowed_domains = [\"walk.example\"]\n")
	p := writeManifest(t, filepath.Join(root, "tools", "nested"), scopeArg)
	m, err := manifest.LoadManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope == nil || m.Scope.AllowedDomains[0] != "walk.example" {
		t.Fatalf("scope not discovered upward: %+v", m.Scope)
	}
	if _, err := ValidateArgIn(m.Args["target"], "walk.example", false, m.Scope); err != nil {
		t.Errorf("in scope: %v", err)
	}

	// TOOLCLAD_SCOPE_FILE wins over the upward walk.
	envFile := filepath.Join(t.TempDir(), "env.toml")
	if err := os.WriteFile(envFile, []byte("[scope]\nallowed_domains = [\"env.example\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(scope.EnvVar, envFile)
	m, err = manifest.LoadManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope == nil || m.Scope.AllowedDomains[0] != "env.example" {
		t.Fatalf("env var did not win: %+v", m.Scope)
	}

	// An unreadable TOOLCLAD_SCOPE_FILE is a load error, not a fallback.
	t.Setenv(scope.EnvVar, filepath.Join(t.TempDir(), "missing.toml"))
	if _, err := manifest.LoadManifest(p); err == nil {
		t.Error("missing TOOLCLAD_SCOPE_FILE accepted")
	}
}

func TestManifestScopeFailClosedWithoutFile(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	dir := t.TempDir()
	if s, _ := scope.Discover(dir); s != nil {
		t.Skipf("a scope file exists above the temp directory (%s)", s.Path)
	}
	m, err := manifest.LoadManifest(writeManifest(t, dir, scopeArg))
	if err != nil {
		t.Fatal(err)
	}
	if m.Scope != nil {
		t.Fatal("unexpected scope")
	}
	_, err = ValidateArgIn(m.Args["target"], "example.com", false, m.Scope)
	if err == nil || !strings.Contains(err.Error(), noScopeMsg) {
		t.Errorf("want fail-closed refusal, got %v", err)
	}
}

func TestManifestScopeFileErrorsAreLoadErrors(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	cases := map[string]string{
		"unknown key":    "[scope]\nallowed_domains = []\nallowed_hostz = []\n",
		"malformed cidr": "[scope]\nallowed_cidrs = [\"10.0.0.0/40\"]\n",
		"bad wildcard":   "[scope]\nallowed_domains = [\"a.*.example.com\"]\n",
	}
	for name, content := range cases {
		root := t.TempDir()
		writeScopeFile(t, root, content)
		if _, err := manifest.LoadManifest(writeManifest(t, root, scopeArg)); err == nil {
			t.Errorf("%s: manifest loaded with a bad scope file", name)
		}
	}
}

func TestScopeCheckUnsupportedTypeIsLoadError(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	p := writeManifest(t, t.TempDir(), "[args.target]\nposition = 1\nrequired = true\ntype = \"string\"\nscope_check = true\n")
	_, err := manifest.LoadManifest(p)
	if err == nil || !strings.Contains(err.Error(), "scope_check is not supported for type 'string'") {
		t.Errorf("got %v", err)
	}
}

func TestDefaultsValidatedAtLoad(t *testing.T) {
	t.Setenv(scope.EnvVar, "")
	t.Setenv(manifest.ConfigEnvVar, "")
	bad := map[string]string{
		"port zero":         "type = \"port\"\ndefault = 0\n",
		"integer below min": "type = \"integer\"\nmin = 1\ndefault = 0\n",
		"string with space": "type = \"string\"\ndefault = \"a b\"\n",
		"enum not allowed":  "type = \"enum\"\nallowed = [\"a\"]\ndefault = \"b\"\n",
		"duration":          "type = \"duration\"\ndefault = \"5 m\"\n",
	}
	for name, spec := range bad {
		p := writeManifest(t, t.TempDir(), "[args.target]\nposition = 1\n"+spec)
		_, err := manifest.LoadManifest(p)
		if err == nil || !strings.Contains(err.Error(), "argument 'target': invalid default") {
			t.Errorf("%s: want load error naming the argument, got %v", name, err)
		}
	}
	good := map[string]string{
		"empty string":              "type = \"string\"\ndefault = \"\"\n",
		"empty string with pattern": "type = \"string\"\npattern = \"^[a-z]+$\"\ndefault = \"\"\n",
		"port":                      "type = \"port\"\ndefault = 443\n",
		"integer":                   "type = \"integer\"\nmin = 1\ndefault = 5\n",
		"enum":                      "type = \"enum\"\nallowed = [\"a\"]\ndefault = \"a\"\n",
		"number":                    "type = \"number\"\ndefault = 0.5\n",
		"boolean":                   "type = \"boolean\"\ndefault = true\n",
	}
	for name, spec := range good {
		p := writeManifest(t, t.TempDir(), "[args.target]\nposition = 1\n"+spec)
		if _, err := manifest.LoadManifest(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An unknown type is a load error; a custom-typed default is checked
	// at load against the custom type.
	unknown := writeManifest(t, t.TempDir(), "[args.target]\nposition = 1\ntype = \"rate\"\ndefault = 0\n")
	if _, err := manifest.LoadManifest(unknown); err == nil || !strings.Contains(err.Error(), "unknown type 'rate' for argument 'target'") {
		t.Errorf("unknown type: got %v", err)
	}
	cts := map[string]*manifest.CustomTypeDef{"rate": {Base: "integer", Min: intPtr(1)}}
	if _, err := manifest.LoadManifestWithOptions(unknown, manifest.LoadOptions{CustomTypes: cts}); err == nil || !strings.Contains(err.Error(), "argument 'target': invalid default") {
		t.Errorf("custom-typed default: got %v", err)
	}
	ok := writeManifest(t, t.TempDir(), "[args.target]\nposition = 1\ntype = \"rate\"\ndefault = 3\n")
	m, err := manifest.LoadManifestWithOptions(ok, manifest.LoadOptions{CustomTypes: cts})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestWithCustomTypes(m, map[string]*manifest.CustomTypeDef{"rate": {Base: "integer", Min: intPtr(5)}}); err == nil || !strings.Contains(err.Error(), "invalid default") {
		t.Errorf("custom-typed default re-check: got %v", err)
	}
}

func TestStrictNumericAndDuration(t *testing.T) {
	cases := []struct {
		typ, in, out string
		ok           bool
	}{
		{"integer", "", "", false},
		{"integer", "0x10", "", false},
		{"integer", "1_000", "", false},
		{"integer", " 7 ", "", false},
		{"integer", "7\n", "", false},
		{"integer", "+7", "7", true},
		{"integer", "42", "42", true},
		{"port", "+80", "", false},
		{"port", "0", "", false},
		{"port", "65536", "", false},
		{"port", " 80", "", false},
		{"port", "080", "80", true},
		{"port", "443", "443", true},
		{"duration", "5m\n", "", false},
		{"duration", "1_000", "", false},
		{"duration", " 7 ", "", false},
		{"duration", "5 m", "", false},
		{"duration", "+5", "", false},
		{"duration", "-5", "", false},
		{"duration", "", "", false},
		{"duration", "30", "30", true},
		{"duration", "1h30m", "1h30m", true},
		{"duration", "500ms", "500ms", true},
		{"number", "NaN", "", false},
		{"number", "inf", "", false},
		{"number", "Infinity", "", false},
		{"number", "0x1p3", "", false},
		{"number", " 1.5", "", false},
		{"number", "1_0", "", false},
		{"number", "", "", false},
		{"number", "1e2", "100", true},
		{"number", "0.50", "0.5", true},
		{"number", ".5", "0.5", true},
		{"number", "5.", "5", true},
		{"number", "+2.5", "2.5", true},
		{"boolean", "True", "true", true},
		{"boolean", "FALSE", "false", true},
		{"boolean", "yes", "", false},
	}
	for _, c := range cases {
		got, err := ValidateArg(&manifest.ArgDef{Name: "v", Type: c.typ}, c.in)
		if (err == nil) != c.ok {
			t.Errorf("%s %q: ok=%v, err=%v", c.typ, c.in, c.ok, err)
			continue
		}
		if c.ok && got != c.out {
			t.Errorf("%s %q: got %q, want %q", c.typ, c.in, got, c.out)
		}
	}
}

func TestHostShapeAndPathParity(t *testing.T) {
	cases := []struct {
		typ, in string
		ok      bool
	}{
		{"scope_target", "example.com.", false},
		{"url", "https://example.com./", false},
		{"scope_target", "2001:db8::/32", true},
		{"cidr", "2001:db8::/32", true},
		{"scope_target", "example.123", false},
		{"scope_target", "0x7f000001", false},
		{"path", "..", false},
		{"path", "foo/..", false},
		{"path", `foo\..`, false},
		{"path", `foo/..\bar`, false},
		{"path", "foo/..bar", true},
		{"path", "foo/bar", true},
		{"credential_file", "..", false},
		{"credential_file", `a\..\b`, false},
	}
	for _, c := range cases {
		_, err := ValidateArg(&manifest.ArgDef{Name: "v", Type: c.typ}, c.in)
		if (err == nil) != c.ok {
			t.Errorf("%s %q: ok=%v, err=%v", c.typ, c.in, c.ok, err)
		}
	}
	// The IP policy applies to an IPv6 CIDR prefix under block_internal.
	if _, err := ValidateArg(&manifest.ArgDef{Name: "v", Type: "scope_target", BlockInternal: true}, "2001:db8::/32"); err == nil {
		t.Error("documentation IPv6 CIDR accepted under block_internal")
	}
}
