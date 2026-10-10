package manifest

import (
	"fmt"
	"strings"
)

// MaxOutputMaxBytes is the largest [output] max_bytes accepted (1 GiB).
const MaxOutputMaxBytes int64 = 1073741824

// BuiltinParsers are the only [output] parser values the reference runtimes
// accept.
var BuiltinParsers = map[string]bool{
	"builtin:json":  true,
	"builtin:jsonl": true,
	"builtin:csv":   true,
	"builtin:xml":   true,
	"builtin:text":  true,
}

// CheckOutput applies the load-time [output] rules: max_bytes is an integer
// in 1..=1 GiB (a non-integer already fails to decode), and parser, when
// set, names a builtin parser. A custom parser used to be ignored silently,
// so a manifest declaring one got an unparsed result it did not ask for.
func (m *Manifest) CheckOutput() error {
	o := m.Output
	if o == nil {
		return nil
	}
	if o.MaxBytes != nil && (*o.MaxBytes < 1 || *o.MaxBytes > MaxOutputMaxBytes) {
		return fmt.Errorf("output.max_bytes must be an integer between 1 and %d, got %d",
			MaxOutputMaxBytes, *o.MaxBytes)
	}
	if o.Parser != "" && !BuiltinParsers[o.Parser] {
		return fmt.Errorf("custom output parsers are not supported by the reference runtimes (parser = %q)", o.Parser)
	}
	return nil
}

// HostPolicy applies the host / IP egress policy to the literal host (with
// optional :port) of an [http] url. The validator package registers it on
// import; this package cannot import the validator without a cycle. Nil
// skips the host policy (the structural checks still run).
var HostPolicy func(hostport string, blockInternal bool) error

// CheckHTTP applies the load-time [http] rules:
//
//   - http.url may not interpolate into the scheme or host: the host is the
//     SSRF boundary and must be manifest-controlled. Everything up to the
//     first "/", "?" or "#" after "://" must be literal.
//   - the literal host goes through the host policy, with the non-public
//     tier applied when any argument sets block_internal.
//   - every header name must be an RFC 9110 token.
func (m *Manifest) CheckHTTP() error {
	h := m.Http
	if h == nil {
		return nil
	}
	scheme, rest, found := strings.Cut(h.URL, "://")
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	// Without "://" the whole value is scheme-and-host position.
	if strings.ContainsAny(scheme, "{}") || strings.ContainsAny(authority, "{}") {
		return fmt.Errorf("http.url may not interpolate into the scheme or host")
	}
	if found && authority != "" && HostPolicy != nil {
		blockInternal := false
		for _, def := range m.Args {
			if def.BlockInternal {
				blockInternal = true
				break
			}
		}
		if err := HostPolicy(authority, blockInternal); err != nil {
			return fmt.Errorf("http.url host: %w", err)
		}
	}
	for name := range h.Headers {
		if !isHTTPToken(name) {
			return fmt.Errorf("http.headers: header name %q is not a valid token", name)
		}
	}
	return nil
}

// isHTTPToken reports whether s is a non-empty RFC 9110 token.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
