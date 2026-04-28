// Package validator provides argument type validation for ToolClad manifests.
package validator

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// shellMetacharacters contains characters that indicate injection attempts.
const shellMetacharacters = ";|&$`(){}[]<>!\n\r"

var hostnameRe = regexp.MustCompile(
	`^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.)*(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.?$`,
)

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

// ValidateArg validates a value against an argument definition and returns the cleaned value.
func ValidateArg(def *manifest.ArgDef, value string) (string, error) {
	handler, ok := typeHandlers[def.Type]
	if !ok {
		return "", newErr(def.Name, fmt.Sprintf("unknown type: %q", def.Type))
	}
	return handler(def, value)
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
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			return "", newErr(def.Name, fmt.Sprintf("invalid pattern %q: %v", def.Pattern, err))
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

	if def.Min != nil || def.Max != nil {
		lo := num
		hi := num
		if def.Min != nil {
			lo = *def.Min
		}
		if def.Max != nil {
			hi = *def.Max
		}
		if def.Clamp {
			if num < lo {
				num = lo
			}
			if num > hi {
				num = hi
			}
		} else {
			if def.Min != nil && num < lo {
				return "", newErr(def.Name, fmt.Sprintf("value %d is below minimum %d", num, lo))
			}
			if def.Max != nil && num > hi {
				return "", newErr(def.Name, fmt.Sprintf("value %d is above maximum %d", num, hi))
			}
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

func isValidHostname(value string) bool {
	return hostnameRe.MatchString(value) && len(value) <= 253
}

func isValidIP(value string) bool {
	return net.ParseIP(value) != nil
}

func isValidCIDR(value string) bool {
	if !strings.Contains(value, "/") {
		return false
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

// hasPunycodeLabel returns true if any DNS label in `host` is an A-label
// (xn-- prefix, case-insensitive). Used to defend against IDN homoglyph bypass.
func hasPunycodeLabel(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) >= 4 && strings.EqualFold(label[:4], "xn--") {
			return true
		}
	}
	return false
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

	if !isValidIP(value) && !isValidCIDR(value) && !isValidHostname(value) {
		return "", newErr(def.Name, fmt.Sprintf("invalid scope target: %q (must be a valid IP, CIDR, or hostname)", value))
	}
	return value, nil
}

func validateURL(def *manifest.ArgDef, value string) (string, error) {
	if err := CheckInjection(value); err != nil {
		return "", newErr(def.Name, err.Error())
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", newErr(def.Name, fmt.Sprintf("invalid URL: %q", value))
	}
	if len(def.Schemes) > 0 {
		found := false
		for _, s := range def.Schemes {
			if s == parsed.Scheme {
				found = true
				break
			}
		}
		if !found {
			return "", newErr(def.Name, fmt.Sprintf("URL scheme %q not in allowed schemes: %v", parsed.Scheme, def.Schemes))
		}
	}
	return value, nil
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
	if net.ParseIP(value) == nil {
		return "", newErr(def.Name, fmt.Sprintf("invalid IP address: %q", value))
	}
	return value, nil
}

func validateCIDR(def *manifest.ArgDef, value string) (string, error) {
	if !strings.Contains(value, "/") {
		return "", newErr(def.Name, fmt.Sprintf("CIDR notation requires '/': %q", value))
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return "", newErr(def.Name, fmt.Sprintf("invalid CIDR: %q", value))
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
	re, err := regexp.Compile(def.Pattern)
	if err != nil {
		return "", newErr(def.Name, fmt.Sprintf("invalid pattern %q: %v", def.Pattern, err))
	}
	if !re.MatchString(value) {
		return "", newErr(def.Name, fmt.Sprintf("value %q does not match required pattern: %s", value, def.Pattern))
	}
	return value, nil
}

// ValidateArgWithCustomTypes validates using custom type definitions.
func ValidateArgWithCustomTypes(def *manifest.ArgDef, value string, customTypes map[string]*manifest.CustomTypeDef) (string, error) {
	if ct, ok := customTypes[def.Type]; ok {
		handler, ok := typeHandlers[ct.Base]
		if !ok {
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
		return handler(&synthetic, value)
	}
	return ValidateArg(def, value)
}
