package scope

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scopeVectors mirrors the shared tests/scope_vectors.json file.
type scopeVectors struct {
	Vectors struct {
		IPv4InCIDR []struct {
			IP       string `json:"ip"`
			CIDR     string `json:"cidr"`
			Expected bool   `json:"expected"`
		} `json:"ipv4_in_cidr"`
		IPv6InCIDR []struct {
			IP       string `json:"ip"`
			CIDR     string `json:"cidr"`
			Expected bool   `json:"expected"`
		} `json:"ipv6_in_cidr"`
		HostnameWildcardMatch []struct {
			Hostname string `json:"hostname"`
			Pattern  string `json:"pattern"`
			Expected bool   `json:"expected"`
		} `json:"hostname_wildcard_match"`
	} `json:"vectors"`
}

func TestSharedScopeVectorsHelpers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "scope_vectors.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("tests/scope_vectors.json not present; shared scope vectors skipped")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v scopeVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors.IPv4InCIDR) == 0 || len(v.Vectors.IPv6InCIDR) == 0 || len(v.Vectors.HostnameWildcardMatch) == 0 {
		t.Fatal("scope vector sections missing")
	}
	for _, c := range append(v.Vectors.IPv4InCIDR, v.Vectors.IPv6InCIDR...) {
		if got := IPInCIDR(c.IP, c.CIDR); got != c.Expected {
			t.Errorf("IPInCIDR(%q, %q) = %v, want %v", c.IP, c.CIDR, got, c.Expected)
		}
	}
	for _, c := range v.Vectors.HostnameWildcardMatch {
		if got := HostMatchesRule(c.Hostname, c.Pattern); got != c.Expected {
			t.Errorf("HostMatchesRule(%q, %q) = %v, want %v", c.Hostname, c.Pattern, got, c.Expected)
		}
	}
}

func writeScope(t *testing.T, dir, content string) string {
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

func TestContainsMatching(t *testing.T) {
	s := &ScopeDef{
		AllowedDomains: []string{"example.com", "*.example.com"},
		AllowedCIDRs:   []string{"10.0.1.0/24", "2001:db8::/32"},
		BlockedDomains: []string{"admin.example.com"},
		BlockedCIDRs:   []string{"10.0.1.128/25"},
	}
	cases := []struct {
		subject string
		want    bool
	}{
		{"example.com", true},
		{"EXAMPLE.com", true},
		{"app.example.com", true},
		{"deep.sub.example.com", true},
		{"evil-example.com", false},
		{"example.com.evil.com", false},
		{"admin.example.com", false},  // blocked beats allowed
		{"x.admin.example.com", true}, // an exact blocked rule does not cover subdomains
		{"10.0.1.5", true},
		{"10.0.1.200", false}, // blocked range
		{"10.0.2.5", false},
		{"::ffff:10.0.1.5", true},
		{"10.0.1.0/26", true},  // fully contained
		{"10.0.1.0/25", true},  // fully contained, no overlap with the block
		{"10.0.1.0/24", false}, // overlaps the blocked half
		{"10.0.0.0/8", false},  // not contained
		{"2001:db8:1::/48", true},
		{"2001:db8::/16", false},
		{"2001:db8::1", true},
	}
	for _, c := range cases {
		if got := s.Contains(c.subject); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.subject, got, c.want)
		}
	}
}

func TestEmptyScopeAllowsNothing(t *testing.T) {
	s := &ScopeDef{}
	for _, subj := range []string{"example.com", "10.0.0.1", "10.0.0.0/24"} {
		if s.Contains(subj) {
			t.Errorf("empty scope contains %q", subj)
		}
	}
}

func TestCheckMessages(t *testing.T) {
	if err := Check(nil, "example.com"); err == nil || err.Error() != ErrNoScope.Error() {
		t.Fatalf("nil scope: got %v", err)
	}
	s := &ScopeDef{AllowedDomains: []string{"example.com"}}
	if err := Check(s, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := Check(s, "evil.com"); err == nil || err.Error() != "target 'evil.com' is not in scope" {
		t.Fatalf("got %v", err)
	}
	bad := &ScopeDef{AllowedCIDRs: []string{"10.0.0.0/33"}}
	if err := Check(bad, "10.0.0.1"); err == nil {
		t.Fatal("invalid scope definition accepted")
	}
}

func TestParseRejectsBadFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":       "[scope]\nallowed_domains = []\nallowed_hosts = []\n",
		"unknown table":     "[scope]\nallowed_domains = []\n[extra]\nx = 1\n",
		"malformed cidr":    "[scope]\nallowed_cidrs = [\"10.0.1.0/33\"]\n",
		"not a cidr":        "[scope]\nblocked_cidrs = [\"example.com\"]\n",
		"inner wildcard":    "[scope]\nallowed_domains = [\"app.*.example.com\"]\n",
		"bare wildcard":     "[scope]\nallowed_domains = [\"*\"]\n",
		"trailing wildcard": "[scope]\nallowed_domains = [\"example.*\"]\n",
		"uppercase":         "[scope]\nallowed_domains = [\"Example.com\"]\n",
		"bad character":     "[scope]\nblocked_domains = [\"exa_mple.com\"]\n",
		"empty label":       "[scope]\nallowed_domains = [\"example..com\"]\n",
		"wrong value type":  "[scope]\nallowed_domains = \"example.com\"\n",
	}
	for name, content := range cases {
		if _, err := Parse([]byte(content), "scope.toml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("[scope]\nallowed_hosts = []\n"), "scope.toml"); err == nil ||
		!strings.Contains(err.Error(), "unknown key 'scope.allowed_hosts' in scope file") {
		t.Errorf("unknown key message: %v", err)
	}
	s, err := Parse([]byte("[scope]\nallowed_domains = [\"example.com\", \"*.example.com\"]\nallowed_cidrs = [\"10.0.1.0/24\"]\nblocked_domains = []\nblocked_cidrs = []\n"), "scope.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.AllowedDomains) != 2 || len(s.AllowedCIDRs) != 1 {
		t.Fatalf("parsed %+v", s)
	}
}

func TestRepositoryScopeFileLoads(t *testing.T) {
	p := filepath.Join("..", "..", "..", "scope", "scope.toml")
	if _, err := os.Stat(p); err != nil {
		t.Skip("repository scope file not present")
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverEnvVarWins(t *testing.T) {
	root := t.TempDir()
	writeScope(t, root, "[scope]\nallowed_domains = [\"walk.example\"]\n")
	envFile := filepath.Join(t.TempDir(), "custom.toml")
	if err := os.WriteFile(envFile, []byte("[scope]\nallowed_domains = [\"env.example\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVar, envFile)
	s, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || len(s.AllowedDomains) != 1 || s.AllowedDomains[0] != "env.example" {
		t.Fatalf("env var did not win: %+v", s)
	}
}

func TestDiscoverUnreadableEnvVarIsError(t *testing.T) {
	root := t.TempDir()
	writeScope(t, root, "[scope]\nallowed_domains = [\"walk.example\"]\n")
	t.Setenv(EnvVar, filepath.Join(t.TempDir(), "missing.toml"))
	if s, err := Discover(root); err == nil {
		t.Fatalf("missing TOOLCLAD_SCOPE_FILE fell back to %+v", s)
	}
}

func TestDiscoverWalksUpward(t *testing.T) {
	t.Setenv(EnvVar, "")
	root := t.TempDir()
	writeScope(t, root, "[scope]\nallowed_domains = [\"walk.example\"]\n")
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Discover(deep)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil || s.AllowedDomains[0] != "walk.example" {
		t.Fatalf("upward walk did not find the file: %+v", s)
	}
	if s.Path != filepath.Join(root, "scope", "scope.toml") {
		t.Errorf("Path = %q", s.Path)
	}
}

func TestDiscoverMalformedFoundFileIsError(t *testing.T) {
	t.Setenv(EnvVar, "")
	root := t.TempDir()
	writeScope(t, root, "[scope]\nallowed_cidrs = [\"bad\"]\n")
	if _, err := Discover(root); err == nil {
		t.Fatal("malformed scope file accepted")
	}
}

func TestDiscoverNotFound(t *testing.T) {
	t.Setenv(EnvVar, "")
	dir := t.TempDir()
	s, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Skipf("a scope file exists above the temp directory (%s); not-found case cannot be exercised", s.Path)
	}
}
