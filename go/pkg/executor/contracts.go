package executor

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/validator"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const maxRequestBytes = 1024 * 1024
const maxResponseBytes = 4 * 1024 * 1024

var tokenPattern = regexp.MustCompile(`\{(_secret:[A-Za-z0-9_]+|\w+)\}`)
var argumentName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// ValidateArguments validates supplied arguments and defaults, rejecting unknown names.
func ValidateArguments(m *manifest.Manifest, args map[string]string) (map[string]string, error) {
	for name := range args {
		if _, ok := m.Args[name]; !ok {
			return nil, fmt.Errorf("unknown argument: %s", name)
		}
	}
	result := make(map[string]string)
	size := 0
	for name, def := range m.Args {
		if !argumentName.MatchString(name) {
			return nil, fmt.Errorf("invalid argument name: %s", name)
		}
		value, ok := args[name]
		if !ok {
			fallback := def.Default
			if fallback == nil {
				fallback = m.Command.Defaults[name]
			}
			if fallback == nil {
				if def.Required {
					return nil, fmt.Errorf("missing required argument: %s", name)
				}
				continue
			}
			value = fmt.Sprint(fallback)
		}
		if strings.ContainsRune(value, 0) || (def.Required && strings.TrimSpace(value) == "") {
			return nil, fmt.Errorf("invalid empty or NUL argument: %s", name)
		}
		clean, err := validator.ValidateArg(def, value)
		if err != nil {
			return nil, fmt.Errorf("argument %s: %w", name, err)
		}
		result[name] = clean
		size += len(clean)
	}
	if size > maxRequestBytes {
		return nil, fmt.Errorf("arguments exceed 1 MiB")
	}
	return result, nil
}

func checkExecution(m *manifest.Manifest, dryRun bool) error {
	if m.Tool.TimeoutSeconds < 1 || m.Tool.TimeoutSeconds > 3600 {
		return fmt.Errorf("timeout_seconds must be between 1 and 3600")
	}
	count := 0
	for _, present := range []bool{len(m.Command.Exec) > 0 || m.Command.Template != "", m.Command.Executor != "", m.Http != nil, m.Mcp != nil, m.Session != nil, m.Browser != nil} {
		if present {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("ambiguous execution backends")
	}
	if dryRun {
		return nil
	}
	scoped := false
	for _, a := range m.Args {
		scoped = scoped || a.ScopeCheck
	}
	if (m.Tool.Dispatch != "" && m.Tool.Dispatch != "exec") || m.Tool.HumanApproval || m.Tool.Cedar != nil || scoped {
		return fmt.Errorf("execution requires an embedding runtime for dispatch, approval, Cedar or scope enforcement")
	}
	if m.Output != nil {
		switch m.Output.Parser {
		case "", "builtin:json", "builtin:xml", "builtin:csv", "builtin:jsonl", "builtin:text":
		default:
			return fmt.Errorf("custom output parsers require an embedding runtime")
		}
	}
	return nil
}

func childEnvironment() []string {
	env := []string{}
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "SYSTEMROOT"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func splitTemplate(text string) ([]string, error) {
	parts := []string{}
	var current strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\\' && quote != '\'':
			i++
			if i >= len(text) {
				return nil, fmt.Errorf("unfinished command escape")
			}
			next := text[i]
			if quote == '"' && !strings.ContainsRune("\"\\$`\n", rune(next)) {
				current.WriteByte('\\')
			}
			if next != '\n' {
				current.WriteByte(next)
			}
			started = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				current.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			started = true
		case strings.ContainsRune(" \t\r\n", rune(c)):
			if started {
				parts = append(parts, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteByte(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed command quote")
	}
	if started {
		parts = append(parts, current.String())
	}
	return parts, nil
}

var safeDisplay = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func displayArgv(argv []string) string {
	result := make([]string, len(argv))
	for i, v := range argv {
		if safeDisplay.MatchString(v) {
			result[i] = v
		} else {
			result[i] = "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(result, " ")
}

func evaluateCondition(expr string, values map[string]string) bool {
	if strings.Contains(expr, " and ") {
		for _, p := range strings.Split(expr, " and ") {
			if !evaluateCondition(p, values) {
				return false
			}
		}
		return true
	}
	if strings.Contains(expr, " or ") {
		for _, p := range strings.Split(expr, " or ") {
			if evaluateCondition(p, values) {
				return true
			}
		}
		return false
	}
	for _, op := range []string{"!=", "=="} {
		if lhs, rhs, ok := strings.Cut(expr, op); ok {
			equal := values[strings.TrimSpace(lhs)] == strings.Trim(strings.TrimSpace(rhs), "'\"")
			if op == "==" {
				return equal
			}
			return !equal
		}
	}
	return false
}

func commandFragments(m *manifest.Manifest, values map[string]string) map[string]string {
	result := map[string]string{}
	for name, table := range m.Command.Mappings {
		value := table[values[name]]
		result["_"+name+"_flags"] = value
		result["_"+name] = value
		if strings.HasSuffix(name, "_type") {
			result["_"+strings.TrimSuffix(name, "_type")+"_flags"] = value
		}
	}
	for name, cond := range m.Command.Conditionals {
		value := ""
		if evaluateCondition(cond.When, values) {
			value = cond.Template
		}
		result["_"+name] = value
	}
	return result
}

func templateArgv(template string, values, fragments map[string]string) ([]string, error) {
	tokens, err := splitTemplate(template)
	if err != nil {
		return nil, err
	}
	argv := []string{}
	for _, token := range tokens {
		match := tokenPattern.FindStringSubmatch(token)
		if len(match) > 0 && match[0] == token {
			if fragment, ok := fragments[match[1]]; ok {
				parts, err := splitTemplate(fragment)
				if err != nil {
					return nil, err
				}
				for _, p := range parts {
					argv = append(argv, interpolateString(p, values))
				}
				continue
			}
		}
		value := interpolateString(token, values)
		if value != "" || token == "" {
			argv = append(argv, value)
		}
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("command produced empty argv")
	}
	return argv, nil
}

var httpAuthority = regexp.MustCompile(`^(https?)://([^/?#]+)`)

func httpURL(template string, args map[string]string) (string, error) {
	authority := httpAuthority.FindStringSubmatch(template)
	if len(authority) == 0 || strings.ContainsAny(authority[2], "{}@\\") || strings.Contains(template, "{_secret:") {
		return "", fmt.Errorf("HTTP URL requires a fixed http(s) authority without credentials or secrets")
	}
	value := interpolateString(template, args)
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme+"://"+parsed.Host != authority[0] || parsed.Fragment != "" || strings.ContainsAny(value, "\\\r\n\t ") {
		return "", fmt.Errorf("invalid HTTP URL or changed authority")
	}
	return value, nil
}

func httpTemplate(template string, args map[string]string, dryRun, jsonString bool) (string, error) {
	var failure error
	value := tokenPattern.ReplaceAllStringFunc(template, func(token string) string {
		key := token[1 : len(token)-1]
		value, ok := args[key]
		if !ok {
			value = token
		}
		if strings.HasPrefix(key, "_secret:") {
			if dryRun {
				value = "[REDACTED]"
			} else {
				name := "TOOLCLAD_SECRET_" + strings.ToUpper(key[8:])
				value, ok = os.LookupEnv(name)
				if !ok {
					failure = fmt.Errorf("missing secret environment variable: %s", name)
				}
			}
		}
		if jsonString {
			encoded, _ := json.Marshal(value)
			return string(encoded[1 : len(encoded)-1])
		}
		return value
	})
	return value, failure
}

// DryRun validates the complete invocation without effects or secret lookups.
func DryRun(m *manifest.Manifest, args map[string]string) (string, error) {
	clean, err := ValidateArguments(m, args)
	if err != nil {
		return "", err
	}
	if err = checkExecution(m, true); err != nil {
		return "", err
	}
	if m.Tool.Dispatch == "callback" {
		return "callback (embedding runtime required)", nil
	}
	if m.Http != nil {
		url, err := httpURL(m.Http.URL, clean)
		if err != nil {
			return "", err
		}
		return m.Http.Method + " " + url, nil
	}
	if m.Mcp != nil {
		return "mcp://" + m.Mcp.Server + "/" + m.Mcp.Tool, nil
	}
	return BuildCommand(m, args)
}

// cappedBuffer bounds memory and stops the original process group on overflow.
type cappedBuffer struct {
	buffer bytes.Buffer
	stop   func() error
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	if b.buffer.Len()+len(value) > maxResponseBytes {
		_ = b.stop()
		return 0, fmt.Errorf("process output exceeds 4 MiB per stream")
	}
	return b.buffer.Write(value)
}

func (b *cappedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedBuffer) String() string { return b.buffer.String() }

func newScanID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", value)
}
