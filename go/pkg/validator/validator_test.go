package validator

import (
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

func intPtr(v int) *int { return &v }

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
			name:  "port/zero",
			def:   &manifest.ArgDef{Name: "p", Type: "port"},
			value: "0",
			want:  "0",
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
			name:  "path/valid",
			def:   &manifest.ArgDef{Name: "f", Type: "path"},
			value: "/usr/share/wordlists/rockyou.txt",
			want:  "/usr/share/wordlists/rockyou.txt",
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
