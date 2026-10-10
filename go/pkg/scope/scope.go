// Package scope loads a project scope file (scope/scope.toml) and decides
// whether a target is in scope for an argument that sets scope_check = true.
//
// File format:
//
//	[scope]
//	allowed_domains = ["example.com", "*.example.com"]
//	allowed_cidrs   = ["10.0.1.0/24"]
//	blocked_domains = []
//	blocked_cidrs   = []
//
// Matching rules: blocked rules are evaluated first and always win. A domain
// rule "example.com" matches exactly that host (case-insensitively); a rule
// "*.example.com" matches a strict subdomain at any depth, never the apex
// and never a mere string suffix such as evil-example.com. An IP matches a
// CIDR rule that contains it; a CIDR subject matches an allowed rule only
// when it is fully contained in it, and a blocked rule when it overlaps it
// at all. Anything that matches no allowed rule is out of scope, so a file
// whose allowed lists are empty puts nothing in scope.
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// EnvVar names the environment variable that points at a scope file. When
// set it takes precedence over the upward search, and a file it names that
// cannot be read is an error rather than a fallback.
const EnvVar = "TOOLCLAD_SCOPE_FILE"

// ErrNoScope is the fail-closed refusal returned by Check when scope_check is
// enabled but no scope file was found.
var ErrNoScope = errors.New("scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)")

// ScopeDef is the [scope] table of a scope file.
type ScopeDef struct {
	AllowedDomains []string `toml:"allowed_domains"`
	AllowedCIDRs   []string `toml:"allowed_cidrs"`
	BlockedDomains []string `toml:"blocked_domains"`
	BlockedCIDRs   []string `toml:"blocked_cidrs"`
	// Path is the file the definition was loaded from, empty when built in
	// memory.
	Path string `toml:"-"`
}

// scopeFile is the document shape of scope/scope.toml.
type scopeFile struct {
	Scope ScopeDef `toml:"scope"`
}

// allowedKeys is the complete key allowlist of a scope file.
var allowedKeys = map[string]bool{
	"allowed_domains": true,
	"allowed_cidrs":   true,
	"blocked_domains": true,
	"blocked_cidrs":   true,
}

// unknownKeys returns every key of a raw scope document outside the
// allowlist, as sorted dotted paths. A wholly unknown table is reported once
// by its own path. The check reads the raw table rather than the decoder's
// Undecoded() list, which is unreliable in the pinned decoder release.
func unknownKeys(raw map[string]any) []string {
	var out []string
	for k, v := range raw {
		if k != "scope" {
			out = append(out, toml.Key{k}.String())
			continue
		}
		tbl, ok := v.(map[string]any)
		if !ok {
			continue // a non-table [scope] is a decode error
		}
		for sk := range tbl {
			if !allowedKeys[sk] {
				out = append(out, toml.Key{"scope", sk}.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// Parse decodes and validates scope file text. path is used in messages only.
func Parse(data []byte, path string) (*ScopeDef, error) {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}
	if unknown := unknownKeys(raw); len(unknown) > 0 {
		msgs := make([]string, len(unknown))
		for i, k := range unknown {
			msgs[i] = fmt.Sprintf("unknown key '%s' in scope file", k)
		}
		return nil, fmt.Errorf("scope file %s: %s", path, strings.Join(msgs, "; "))
	}
	var f scopeFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}
	if err := f.Scope.Validate(); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}
	f.Scope.Path = path
	return &f.Scope, nil
}

// Load reads and validates the scope file at path.
func Load(path string) (*ScopeDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}
	return Parse(data, path)
}

// Discover locates and loads the scope file for a manifest in manifestDir:
// the file named by TOOLCLAD_SCOPE_FILE when set, otherwise the first
// scope/scope.toml found walking upward from manifestDir (the process
// working directory when manifestDir is empty) to the filesystem root. It
// returns nil, nil when no file is found; the caller then fails closed.
func Discover(manifestDir string) (*ScopeDef, error) {
	if p := os.Getenv(EnvVar); p != "" {
		s, err := Load(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvVar, err)
		}
		return s, nil
	}
	dir := manifestDir
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving scope search directory: %w", err)
	}
	for {
		candidate := filepath.Join(dir, "scope", "scope.toml")
		info, statErr := os.Stat(candidate)
		switch {
		case statErr == nil && !info.IsDir():
			return Load(candidate)
		case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
			return nil, fmt.Errorf("checking scope file %s: %w", candidate, statErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil
		}
		dir = parent
	}
}

// Validate checks every rule: CIDR rules must parse, and domain rules may
// contain only [a-z0-9.-] with non-empty labels, plus an optional leading
// "*." label. A "*" anywhere else is refused.
func (s *ScopeDef) Validate() error {
	for _, list := range []struct {
		key   string
		rules []string
	}{
		{"allowed_domains", s.AllowedDomains},
		{"blocked_domains", s.BlockedDomains},
	} {
		for _, r := range list.rules {
			if err := validateDomainRule(r); err != nil {
				return fmt.Errorf("%s: %w", list.key, err)
			}
		}
	}
	for _, list := range []struct {
		key   string
		rules []string
	}{
		{"allowed_cidrs", s.AllowedCIDRs},
		{"blocked_cidrs", s.BlockedCIDRs},
	} {
		for _, r := range list.rules {
			if _, err := parseRuleCIDR(r); err != nil {
				return fmt.Errorf("%s: %w", list.key, err)
			}
		}
	}
	return nil
}

func validateDomainRule(rule string) error {
	name := strings.TrimPrefix(rule, "*.")
	if name == "" {
		return fmt.Errorf("invalid domain rule %q", rule)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			if c == '*' {
				return fmt.Errorf("invalid domain rule %q: '*' is only permitted as a leading '*.' label", rule)
			}
			return fmt.Errorf("invalid domain rule %q: only lowercase letters, digits, '.' and '-' are permitted", rule)
		}
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("invalid domain rule %q: empty label", rule)
		}
	}
	return nil
}

func parseRuleCIDR(rule string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(rule)
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("malformed CIDR %q", rule)
	}
	return unmapPrefix(p.Masked()), nil
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix to its IPv4 form.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

// IPInCIDR reports whether ip lies inside cidr. Malformed input is false.
func IPInCIDR(ip, cidr string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	p, err := parseRuleCIDR(cidr)
	if err != nil {
		return false
	}
	return p.Contains(addr.Unmap())
}

// HostMatchesRule reports whether host matches a domain rule: an exact rule
// matches the identical host case-insensitively; a "*.suffix" rule matches
// any host ending in ".suffix" — a strict subdomain at any depth, on a
// label boundary.
func HostMatchesRule(host, rule string) bool {
	host = strings.ToLower(host)
	rule = strings.ToLower(rule)
	if suffix, ok := strings.CutPrefix(rule, "*."); ok {
		return suffix != "" && strings.HasSuffix(host, "."+suffix)
	}
	return host == rule
}

// Contains reports whether subject (a hostname, an IP literal, or a CIDR) is
// in scope: it matches no blocked rule and at least one allowed rule.
// Unparsable CIDR rules never match; call Validate to reject them.
func (s *ScopeDef) Contains(subject string) bool {
	if addr, err := netip.ParseAddr(subject); err == nil {
		addr = addr.Unmap()
		match := func(rules []string) bool {
			for _, r := range rules {
				if p, err := parseRuleCIDR(r); err == nil && p.Contains(addr) {
					return true
				}
			}
			return false
		}
		return !match(s.BlockedCIDRs) && match(s.AllowedCIDRs)
	}
	if strings.Contains(subject, "/") {
		sp, err := netip.ParsePrefix(subject)
		if err != nil {
			return false
		}
		sp = unmapPrefix(sp.Masked())
		for _, r := range s.BlockedCIDRs {
			if p, err := parseRuleCIDR(r); err == nil && p.Overlaps(sp) {
				return false
			}
		}
		for _, r := range s.AllowedCIDRs {
			if p, err := parseRuleCIDR(r); err == nil &&
				p.Addr().BitLen() == sp.Addr().BitLen() &&
				p.Bits() <= sp.Bits() && p.Contains(sp.Addr()) {
				return true
			}
		}
		return false
	}
	for _, r := range s.BlockedDomains {
		if HostMatchesRule(subject, r) {
			return false
		}
	}
	for _, r := range s.AllowedDomains {
		if HostMatchesRule(subject, r) {
			return true
		}
	}
	return false
}

// Check is the scope_check decision for one subject: ErrNoScope when s is
// nil (fail closed), an error naming the subject when it is out of scope or
// the definition is invalid, and nil when it is in scope.
func Check(s *ScopeDef, subject string) error {
	if s == nil {
		return ErrNoScope
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("invalid scope definition: %w", err)
	}
	if !s.Contains(subject) {
		return fmt.Errorf("target '%s' is not in scope", subject)
	}
	return nil
}
