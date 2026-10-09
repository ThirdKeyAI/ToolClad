// Package validator provides argument type validation for ToolClad manifests.
package validator

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// shellMetacharacters contains characters that indicate injection attempts.
const shellMetacharacters = ";|&$`(){}[]<>!\n\r"

// hostnameRe is the structural hostname check: dot-separated LDH labels of
// 1-63 characters that neither start nor end with a hyphen. No trailing dot
// is admitted, so the rightmost label is always the TLD that
// tldNotAllNumeric inspects.
var hostnameRe = regexp.MustCompile(
	`^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.)*(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$`,
)

// defaultURLSchemes is the scheme allowlist used when an arg sets none.
var defaultURLSchemes = []string{"http", "https"}

// deniedURLSchemes are never permitted, even when a manifest lists one in
// `schemes`: each either executes content, reads local files, or speaks a
// protocol that can be driven at an internal service by a crafted URL.
var deniedURLSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"file":       true,
	"blob":       true,
	"about":      true,
	"gopher":     true,
	"dict":       true,
	"ftp":        true,
	"ldap":       true,
	"jar":        true,
	"netdoc":     true,
	"mailto":     true,
	"ws":         true,
	"wss":        true,
}

// ValidationError represents a failed argument validation.
type ValidationError struct {
	Arg     string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Arg != "" {
		return fmt.Sprintf("validation error for '%s': %s", e.Arg, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

func newErr(arg, msg string) *ValidationError {
	return &ValidationError{Arg: arg, Message: msg}
}

// CheckInjection rejects values containing shell metacharacters.
func CheckInjection(value string) error {
	for _, c := range value {
		if strings.ContainsRune(shellMetacharacters, c) {
			return &ValidationError{
				Message: fmt.Sprintf("injection check failed: value contains shell metacharacter: %q", string(c)),
			}
		}
	}
	return nil
}

// stringDerived lists the types whose value is passed to the tool as text and
// therefore gets the value-hygiene rules (control characters, quotes and
// backslashes, whitespace, leading dash) before type-specific parsing.
var stringDerived = map[string]bool{
	"string":          true,
	"path":            true,
	"credential_file": true,
	"regex_match":     true,
	"url":             true,
	"scope_target":    true,
	"duration":        true,
	"msf_options":     true,
}

// numericTypes get the leading-dash rule applied to their output value, after
// range checks and clamping.
var numericTypes = map[string]bool{
	"integer": true,
	"number":  true,
	"port":    true,
}

// ValidateArg validates a value against an argument definition in template
// mode (the strict default: whitespace is always rejected) and returns the
// cleaned value.
func ValidateArg(def *manifest.ArgDef, value string) (string, error) {
	return ValidateArgMode(def, value, false)
}

// ValidateArgMode validates a value against an argument definition. execMode
// must be true only when the manifest declared `exec = [...]` directly; it is
// the sole condition under which `allow_whitespace = true` is honored, because
// only the exec form guarantees that a value stays one argv element.
func ValidateArgMode(def *manifest.ArgDef, value string, execMode bool) (string, error) {
	handler, ok := typeHandlers[def.Type]
	if !ok {
		return "", newErr(def.Name, fmt.Sprintf("unknown type: %q", def.Type))
	}
	// NUL is rejected for every type, enum and numerics included.
	if strings.ContainsRune(value, 0) {
		return "", newErr(def.Name, "must not contain NUL bytes")
	}
	if stringDerived[def.Type] {
		if err := checkHygiene(def, value, execMode); err != nil {
			return "", err
		}
	}
	out, err := handler(def, value)
	if err != nil {
		return "", err
	}
	if numericTypes[def.Type] {
		if err := checkLeadingDash(def, out); err != nil {
			return "", err
		}
	}
	return out, nil
}

// checkHygiene applies the string-derived value rules in order: control
// characters, quotes and backslashes, whitespace, leading dash.
func checkHygiene(def *manifest.ArgDef, value string, execMode bool) error {
	// Control characters are rejected unconditionally: every C0 character
	// (tab, newline and carriage return included), DEL, and the C1 range. A
	// tool argument never needs a control byte, and CR/LF are the
	// line-injection characters.
	for _, r := range value {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return newErr(def.Name, "must not contain control characters")
		}
	}
	if strings.ContainsAny(value, `'"\`) {
		if def.Type == "scope_target" && strings.Contains(value, `\`) {
			return newErr(def.Name, fmt.Sprintf("scope_target must not contain backslash escape sequences: %q", value))
		}
		return newErr(def.Name, "must not contain quote or backslash characters")
	}
	// Whitespace: msf_options uses a space as its KEY VALUE separator, and an
	// arg may opt in with allow_whitespace when the manifest declared exec.
	// Either way only the ASCII space U+0020 is permitted; a non-breaking or
	// exotic space is a homoglyph, never a separator. url never permits any.
	spaceAllowed := def.Type == "msf_options" ||
		(def.AllowWhitespace && execMode && def.Type != "url")
	for _, r := range value {
		if unicode.IsSpace(r) && !(spaceAllowed && r == ' ') {
			return newErr(def.Name, "must not contain whitespace")
		}
	}
	return checkLeadingDash(def, value)
}

// checkLeadingDash rejects a value that would be read as an option by the tool.
func checkLeadingDash(def *manifest.ArgDef, value string) error {
	if def.AllowLeadingDash {
		return nil
	}
	if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
		return newErr(def.Name, "must not start with '-' or '+' (set allow_leading_dash = true to permit)")
	}
	return nil
}

// AnchorPattern rewrites a manifest `pattern` so it must match the whole
// value: one leading `^` and one trailing unescaped `$` are stripped, then
// the pattern is wrapped as `^(?:<pat>)$`.
func AnchorPattern(pat string) string {
	pat = strings.TrimPrefix(pat, "^")
	if strings.HasSuffix(pat, "$") {
		// Count the backslashes immediately before the final `$`; an odd
		// count means the `$` is escaped and is a literal, not an anchor.
		n := 0
		for i := len(pat) - 2; i >= 0 && pat[i] == '\\'; i-- {
			n++
		}
		if n%2 == 0 {
			pat = pat[:len(pat)-1]
		}
	}
	return "^(?:" + pat + ")$"
}

// compilePattern compiles an anchored manifest pattern.
func compilePattern(def *manifest.ArgDef) (*regexp.Regexp, error) {
	re, err := regexp.Compile(AnchorPattern(def.Pattern))
	if err != nil {
		return nil, newErr(def.Name, fmt.Sprintf("invalid pattern %q: %v", def.Pattern, err))
	}
	return re, nil
}

// typeHandler is a function that validates a value for a specific type.
type typeHandler func(def *manifest.ArgDef, value string) (string, error)

var typeHandlers = map[string]typeHandler{
	"string":          validateString,
	"integer":         validateInteger,
	"number":          validateNumber,
	"port":            validatePort,
	"boolean":         validateBoolean,
	"enum":            validateEnum,
	"scope_target":    validateScopeTarget,
	"url":             validateURL,
	"path":            validatePath,
	"ip_address":      validateIPAddress,
	"cidr":            validateCIDR,
	"msf_options":     validateMsfOptions,
	"credential_file": validateCredentialFile,
	"duration":        validateDuration,
	"regex_match":     validateRegexMatch,
}

// SupportedTypes returns a sorted list of supported type names.
func SupportedTypes() []string {
	types := make([]string, 0, len(typeHandlers))
	for t := range typeHandlers {
		types = append(types, t)
	}
	// Sort for deterministic output.
	for i := 0; i < len(types); i++ {
		for j := i + 1; j < len(types); j++ {
			if types[i] > types[j] {
				types[i], types[j] = types[j], types[i]
			}
		}
	}
	return types
}

func validateString(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	if def.Pattern != "" {
		re, err := compilePattern(def)
		if err != nil {
			return "", err
		}
		if !re.MatchString(value) {
			return "", newErr(def.Name, fmt.Sprintf("value %q does not match pattern: %s", value, def.Pattern))
		}
	}
	return value, nil
}

func validateInteger(def *manifest.ArgDef, value string) (string, error) {
	num, err := strconv.Atoi(value)
	if err != nil {
		return "", newErr(def.Name, fmt.Sprintf("expected integer, got: %q", value))
	}

	// Only a declared bound participates in clamping or range checking.
	if def.Clamp {
		if def.Min != nil && num < *def.Min {
			num = *def.Min
		}
		if def.Max != nil && num > *def.Max {
			num = *def.Max
		}
	} else {
		if def.Min != nil && num < *def.Min {
			return "", newErr(def.Name, fmt.Sprintf("value %d is below minimum %d", num, *def.Min))
		}
		if def.Max != nil && num > *def.Max {
			return "", newErr(def.Name, fmt.Sprintf("value %d is above maximum %d", num, *def.Max))
		}
	}
	return strconv.Itoa(num), nil
}

func validateNumber(def *manifest.ArgDef, value string) (string, error) {
	num, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", newErr(def.Name, fmt.Sprintf("expected number, got: %q", value))
	}
	if math.IsNaN(num) || math.IsInf(num, 0) {
		return "", newErr(def.Name, fmt.Sprintf("number must be finite (no NaN or infinity), got: %q", value))
	}

	var lo, hi *float64
	if def.MinFloat != nil {
		lo = def.MinFloat
	} else if def.Min != nil {
		v := float64(*def.Min)
		lo = &v
	}
	if def.MaxFloat != nil {
		hi = def.MaxFloat
	} else if def.Max != nil {
		v := float64(*def.Max)
		hi = &v
	}

	if def.Clamp {
		if lo != nil && num < *lo {
			num = *lo
		}
		if hi != nil && num > *hi {
			num = *hi
		}
	} else {
		if lo != nil && num < *lo {
			return "", newErr(def.Name, fmt.Sprintf("value %g is below minimum %g", num, *lo))
		}
		if hi != nil && num > *hi {
			return "", newErr(def.Name, fmt.Sprintf("value %g is above maximum %g", num, *hi))
		}
	}
	return strconv.FormatFloat(num, 'g', -1, 64), nil
}

func validatePort(def *manifest.ArgDef, value string) (string, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return "", newErr(def.Name, fmt.Sprintf("expected port number, got: %q", value))
	}
	if port < 1 || port > 65535 {
		return "", newErr(def.Name, fmt.Sprintf("port %d out of range 1-65535", port))
	}
	return strconv.Itoa(port), nil
}

func validateBoolean(def *manifest.ArgDef, value string) (string, error) {
	lower := strings.ToLower(value)
	if lower != "true" && lower != "false" {
		return "", newErr(def.Name, fmt.Sprintf("expected 'true' or 'false', got: %q", value))
	}
	return lower, nil
}

func validateEnum(def *manifest.ArgDef, value string) (string, error) {
	if len(def.Allowed) == 0 {
		return "", newErr(def.Name, "enum type requires 'allowed' list in arg definition")
	}
	for _, a := range def.Allowed {
		if a == value {
			return value, nil
		}
	}
	return "", newErr(def.Name, fmt.Sprintf("value %q not in allowed values: %v", value, def.Allowed))
}

// isValidHostname is the structural hostname check plus the rule that the
// rightmost label is not all digits — no valid TLD is numeric (RFC 3696
// §2), which also stops dotted-decimal IP forms from passing as names.
func isValidHostname(value string) bool {
	return len(value) <= 253 && hostnameRe.MatchString(value) && tldNotAllNumeric(value)
}

func isValidIP(value string) bool {
	_, ok := parseCanonicalIP(value)
	return ok
}

// parseCanonicalCIDR parses only canonical CIDR text: a canonical address
// (see parseCanonicalIP) followed by a decimal prefix length in range.
func parseCanonicalCIDR(value string) (netip.Prefix, bool) {
	if !strings.Contains(value, "/") {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func isValidCIDR(value string) bool {
	_, ok := parseCanonicalCIDR(value)
	return ok
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// scopeTargetMaxLen is the RFC 1035 §2.3.4 fully-qualified domain name
// length limit (253 octets). IPv6 textual form maxes out at 45 chars,
// so 253 is a generous upper bound for any scope_target shape and
// rejecting anything longer is defense-in-depth against buffer-
// pathological payloads.
const scopeTargetMaxLen = 253

func validateScopeTarget(def *manifest.ArgDef, value string) (string, error) {
	// Scope validation rules (aligned across Rust, Python, JS, Go):
	// 1. Reject shell metacharacters  2. Block * and ? wildcards
	// 3. Surface specific failure modes (traversal, slashes, escape sequences,
	//    non-ASCII, IDN/punycode) BEFORE the generic regex catch-all so that
	//    forensic triage and per-fence bite-rate analysis can distinguish
	//    attack shapes.
	// 4. Accept valid IPv4, IPv6, CIDR, or hostname.
	if value == "" {
		return "", newErr(def.Name, "scope_target must not be empty")
	}
	if value != strings.TrimSpace(value) {
		// RFC 1035 / RFC 5891 don't permit terminal whitespace in
		// hostname labels.
		return "", newErr(def.Name, fmt.Sprintf("scope_target must not contain leading or trailing whitespace: %q", value))
	}
	if len(value) > scopeTargetMaxLen {
		return "", newErr(def.Name, fmt.Sprintf("scope_target exceeds %d-character limit (RFC 1035 §2.3.4): length=%d", scopeTargetMaxLen, len(value)))
	}
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	if strings.ContainsAny(value, "*?") {
		return "", newErr(def.Name, fmt.Sprintf("wildcard targets are not allowed: %q", value))
	}

	if strings.Contains(value, "../") || strings.Contains(value, "..\\") || strings.Contains(value, "/..") {
		return "", newErr(def.Name, fmt.Sprintf("scope_target must not contain path traversal sequences: %q", value))
	}
	if strings.Contains(value, "/") && !isValidCIDR(value) && !isValidIP(value) {
		return "", newErr(def.Name, fmt.Sprintf("scope_target must not contain '/' (use CIDR notation for ranges): %q", value))
	}
	if strings.Contains(value, "\\") {
		return "", newErr(def.Name, fmt.Sprintf("scope_target must not contain backslash escape sequences: %q", value))
	}
	if !isASCII(value) {
		return "", newErr(def.Name, fmt.Sprintf("scope_target must be ASCII (non-ASCII hostnames including IDN homoglyphs are rejected; gate IDN registration upstream if needed): %q", value))
	}
	// Defense-in-depth against IDN homoglyph bypass via punycode.
	if hasPunycodeLabel(value) {
		return "", newErr(def.Name, fmt.Sprintf("scope_target must not contain punycode (xn--) labels — IDN/IDNA hostnames are rejected to prevent homoglyph bypass; gate IDN registration upstream if needed: %q", value))
	}

	// Canonical IP literals only (see parseCanonicalIP): the egress policy
	// is applied to the literal address.
	if addr, ok := parseCanonicalIP(value); ok {
		if err := enforceIPPolicy(def.Name, addr, def.BlockInternal); err != nil {
			return "", err
		}
		return value, nil
	}

	// CIDR ranges: the policy is tested for overlap with every blocked
	// range, so a supernet cannot carry a blocked range past the check.
	if prefix, ok := parseCanonicalCIDR(value); ok {
		if err := enforceCIDRPolicy(def.Name, prefix, def.BlockInternal); err != nil {
			return "", err
		}
		return value, nil
	}

	// Name-side policy, in order: the internal-name denylist (always), an
	// IP literal embedded in the leading labels (range policy on that
	// address), the non-canonical literal rule, the structural hostname
	// check, and finally resolution under block_internal.
	if err := enforceInternalName(def.Name, value); err != nil {
		return "", err
	}
	if addr, ok := embeddedIPLiteral(value); ok {
		if err := enforceIPPolicy(def.Name, addr, def.BlockInternal); err != nil {
			return "", err
		}
	}

	// A non-canonical IP-literal encoding must not slip through as a
	// "hostname": a downstream resolver would expand it to an address. No
	// legitimate hostname is all-numeric labels or a 0x-prefixed hex literal.
	if looksLikeIPLiteral(value) {
		return "", newErr(def.Name, fmt.Sprintf("scope_target looks like a non-canonical IP literal; use dotted-quad IPv4 or standard IPv6: %q", value))
	}

	if !isValidHostname(value) {
		return "", newErr(def.Name, fmt.Sprintf("invalid scope target: %q (must be a valid IP, CIDR, or hostname)", value))
	}
	if def.BlockInternal {
		if err := enforceResolvedPolicy(def.Name, value); err != nil {
			return "", err
		}
	}
	return value, nil
}

// validateURL is the structural url validator. The string-derived hygiene
// rules (NUL, control characters, quotes and backslash, whitespace — never
// permitted for url — and the leading dash) have already run in
// ValidateArgMode; the shell-metacharacter blocklist here rejects `{` and
// `}` so a url value can never carry a {_secret:…} reference. The rest is a
// deliberate hand parse rather than net/url, which accepts any scheme,
// spaces in the path and other forms a fetcher would happily act on.
func validateURL(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}

	// scheme://rest — a value without "://" is not a URL.
	scheme, rest, found := strings.Cut(value, "://")
	if !found {
		return "", newErr(def.Name, fmt.Sprintf("invalid URL: %q (expected scheme://host)", value))
	}
	scheme = strings.ToLower(scheme)

	// Scheme allowlist: def.Schemes when non-empty, else http and https.
	allowed := def.Schemes
	if len(allowed) == 0 {
		allowed = defaultURLSchemes
	}
	schemeAllowed := false
	for _, s := range allowed {
		if strings.ToLower(s) == scheme {
			schemeAllowed = true
			break
		}
	}
	if !schemeAllowed {
		return "", newErr(def.Name, fmt.Sprintf("URL scheme %q not in allowed schemes: %v", scheme, allowed))
	}

	// Explicit denial, even when a manifest lists the scheme in `schemes`.
	if deniedURLSchemes[scheme] {
		return "", newErr(def.Name, fmt.Sprintf("URL scheme %q is never permitted", scheme))
	}

	// Userinfo: an "@" before the first "/" of the authority hides the real
	// host from a human reviewer and is a classic SSRF decoy.
	authority := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority = rest[:i]
	}
	if strings.Contains(authority, "@") {
		return "", newErr(def.Name, "URL must not contain userinfo (user:password@host)")
	}

	// Host: everything between "://" and the first "/", "?" or "#".
	hostport := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		hostport = rest[:i]
	}
	host, port, err := splitURLHostPort(hostport)
	if err != nil {
		return "", newErr(def.Name, err.Error())
	}
	if port != "" {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || !allASCIIDigits(port) {
			return "", newErr(def.Name, fmt.Sprintf("invalid URL port: %q", port))
		}
		if n < 1 || n > 65535 {
			return "", newErr(def.Name, fmt.Sprintf("URL port %d out of range 1-65535", n))
		}
	}

	// Host policy: punycode, then a literal goes through the range table
	// directly; a name goes through the internal-name denylist, the
	// embedded-literal rule, the non-canonical literal rule, the structural
	// check and, under block_internal, resolution of every answer.
	if hasPunycodeLabel(host) {
		return "", newErr(def.Name, "URL host must not contain punycode (xn--) labels")
	}
	if addr, ok := parseCanonicalIP(host); ok {
		if err := enforceIPPolicy(def.Name, addr, def.BlockInternal); err != nil {
			return "", err
		}
	} else {
		if err := enforceInternalName(def.Name, host); err != nil {
			return "", err
		}
		if addr, ok := embeddedIPLiteral(host); ok {
			if err := enforceIPPolicy(def.Name, addr, def.BlockInternal); err != nil {
				return "", err
			}
		}
		if looksLikeIPLiteral(host) {
			return "", newErr(def.Name, fmt.Sprintf("URL host looks like a non-canonical IP literal; use dotted-quad IPv4 or a hostname: %q", host))
		}
		if !isValidHostname(host) {
			return "", newErr(def.Name, fmt.Sprintf("URL host is not a valid hostname or IP literal: %q", host))
		}
		if def.BlockInternal {
			if err := enforceResolvedPolicy(def.Name, host); err != nil {
				return "", err
			}
		}
	}

	// SCOPE HOOK: when def.ScopeCheck is set, the scope checker will be
	// consulted here with `host` once scope enforcement lands. Until then
	// scope_check is parsed and carried on the ArgDef but not applied.

	return value, nil
}

// splitURLHostPort separates the authority (already stripped of any path,
// query or fragment) into host and optional port. A bracketed IPv6 literal
// is unwrapped and must be a canonical IPv6 address; an unbracketed value
// splits at its last ":" so an unbracketed IPv6 form can never pass as a
// host. An empty host is an error, as is a ":" with nothing after it; the
// port, when present, is returned unparsed for the caller to range-check.
func splitURLHostPort(hostport string) (host, port string, err error) {
	if hostport == "" {
		return "", "", fmt.Errorf("URL host must not be empty")
	}
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return "", "", fmt.Errorf("URL host has an unterminated IPv6 bracket: %q", hostport)
		}
		host = hostport[1:end]
		addr, ok := parseCanonicalIP(host)
		if !ok || !addr.Is6() {
			return "", "", fmt.Errorf("URL host is not a valid IPv6 literal: %q", host)
		}
		tail := hostport[end+1:]
		if tail == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(tail, ":") {
			return "", "", fmt.Errorf("unexpected characters after IPv6 literal: %q", tail)
		}
		port = tail[1:]
	} else if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host, port = hostport[:i], hostport[i+1:]
	} else {
		return hostport, "", nil
	}
	if host == "" {
		return "", "", fmt.Errorf("URL host must not be empty")
	}
	if port == "" {
		return "", "", fmt.Errorf("URL port must not be empty after ':' in %q", hostport)
	}
	return host, port, nil
}

func validatePath(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	// Block absolute paths
	if strings.HasPrefix(value, "/") || (len(value) >= 2 && value[1] == ':') {
		return "", newErr(def.Name, "path must be relative, not absolute")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", newErr(def.Name, fmt.Sprintf("path traversal detected in: %q", value))
		}
	}
	for _, part := range strings.Split(value, "\\") {
		if part == ".." {
			return "", newErr(def.Name, fmt.Sprintf("path traversal detected in: %q", value))
		}
	}
	return value, nil
}

func validateIPAddress(def *manifest.ArgDef, value string) (string, error) {
	addr, ok := parseCanonicalIP(value)
	if !ok {
		return "", newErr(def.Name, fmt.Sprintf("invalid IP address: %q", value))
	}
	if err := enforceIPPolicy(def.Name, addr, def.BlockInternal); err != nil {
		return "", err
	}
	return value, nil
}

func validateCIDR(def *manifest.ArgDef, value string) (string, error) {
	if !strings.Contains(value, "/") {
		return "", newErr(def.Name, fmt.Sprintf("CIDR notation requires '/': %q", value))
	}
	prefix, ok := parseCanonicalCIDR(value)
	if !ok {
		return "", newErr(def.Name, fmt.Sprintf("invalid CIDR: %q", value))
	}
	if err := enforceCIDRPolicy(def.Name, prefix, def.BlockInternal); err != nil {
		return "", err
	}
	return value, nil
}

func validateMsfOptions(def *manifest.ArgDef, value string) (string, error) {
	keyRe := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	metacharNoSemi := "|&$`(){}[]<>!\n\r"
	for _, pair := range strings.Split(value, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, " ", 2)
		if len(parts) != 2 {
			return "", newErr(def.Name, fmt.Sprintf("msf_options: invalid pair '%s' (expected 'KEY VALUE')", pair))
		}
		if !keyRe.MatchString(parts[0]) {
			return "", newErr(def.Name, fmt.Sprintf("msf_options: invalid key '%s' (must be uppercase alphanumeric)", parts[0]))
		}
		for _, c := range parts[1] {
			if strings.ContainsRune(metacharNoSemi, c) {
				return "", newErr(def.Name, fmt.Sprintf("msf_options: value contains disallowed character: %q", string(c)))
			}
		}
	}
	return value, nil
}

func validateCredentialFile(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	if strings.HasPrefix(value, "/") || (len(value) >= 2 && value[1] == ':') {
		return "", newErr(def.Name, "credential file must be a relative path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", newErr(def.Name, fmt.Sprintf("path traversal detected: %q", value))
		}
	}
	info, err := os.Stat(value)
	if err != nil {
		return "", newErr(def.Name, fmt.Sprintf("credential file not found: %q", value))
	}
	if info.IsDir() {
		return "", newErr(def.Name, fmt.Sprintf("not a file: %q", value))
	}
	return value, nil
}

func validateDuration(def *manifest.ArgDef, value string) (string, error) {
	// Plain integer seconds
	if _, err := strconv.Atoi(value); err == nil {
		return value, nil
	}
	// Duration with suffix
	durationRe := regexp.MustCompile(`^(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?$`)
	if !durationRe.MatchString(value) || value == "" {
		return "", newErr(def.Name, fmt.Sprintf("invalid duration: %q (e.g. '30', '5m', '2h', '1h30m', '500ms')", value))
	}
	return value, nil
}

func validateRegexMatch(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	if def.Pattern == "" {
		return "", newErr(def.Name, "regex_match type requires a 'pattern' field")
	}
	re, err := compilePattern(def)
	if err != nil {
		return "", err
	}
	if !re.MatchString(value) {
		return "", newErr(def.Name, fmt.Sprintf("value %q does not match required pattern: %s", value, def.Pattern))
	}
	return value, nil
}

// ValidateArgWithCustomTypes validates using custom type definitions in
// template mode.
func ValidateArgWithCustomTypes(def *manifest.ArgDef, value string, customTypes map[string]*manifest.CustomTypeDef) (string, error) {
	return ValidateArgWithCustomTypesMode(def, value, customTypes, false)
}

// ValidateArgWithCustomTypesMode validates using custom type definitions.
// A custom type is resolved to a synthetic definition with its base type and
// merged constraints, then validated exactly like a built-in type, so value
// hygiene and pattern anchoring apply to custom types too.
func ValidateArgWithCustomTypesMode(def *manifest.ArgDef, value string, customTypes map[string]*manifest.CustomTypeDef, execMode bool) (string, error) {
	ct, ok := customTypes[def.Type]
	if !ok {
		return ValidateArgMode(def, value, execMode)
	}
	if _, ok := typeHandlers[ct.Base]; !ok {
		return "", newErr(def.Name, fmt.Sprintf("custom type '%s' has invalid base type '%s'", def.Type, ct.Base))
	}
	// Create synthetic def with merged constraints
	synthetic := *def
	synthetic.Type = ct.Base
	if len(ct.Allowed) > 0 {
		synthetic.Allowed = ct.Allowed
	}
	if ct.Pattern != "" {
		synthetic.Pattern = ct.Pattern
	}
	if ct.Min != nil {
		synthetic.Min = ct.Min
	}
	if ct.Max != nil {
		synthetic.Max = ct.Max
	}
	if ct.MinFloat != nil {
		synthetic.MinFloat = ct.MinFloat
	}
	if ct.MaxFloat != nil {
		synthetic.MaxFloat = ct.MaxFloat
	}
	return ValidateArgMode(&synthetic, value, execMode)
}

// ValidateManifestWithCustomTypes checks a loaded manifest against the
// custom type table the CLI will read from toolclad.toml: every argument
// type must be a built-in or a custom type with a built-in base, and the
// egress lint is run with the custom types visible, so a custom type whose
// base is a network target is refused in an egress manifest (a custom type
// cannot carry block_internal). LoadManifest already runs the lint for the
// built-in types; this is the entry point to call once custom types are
// available.
func ValidateManifestWithCustomTypes(m *manifest.Manifest, customTypes map[string]*manifest.CustomTypeDef) error {
	names := make([]string, 0, len(m.Args))
	for name := range m.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		def := m.Args[name]
		if _, ok := typeHandlers[def.Type]; ok {
			continue
		}
		ct, ok := customTypes[def.Type]
		if !ok {
			return fmt.Errorf("argument '%s' has unknown type '%s'", name, def.Type)
		}
		if _, ok := typeHandlers[ct.Base]; !ok {
			return fmt.Errorf("argument '%s': custom type '%s' has invalid base type '%s'", name, def.Type, ct.Base)
		}
	}
	return m.LintEgress(customTypes)
}
