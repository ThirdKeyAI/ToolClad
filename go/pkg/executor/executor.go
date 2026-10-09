// Package executor provides command construction and execution for ToolClad manifests.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/validator"
)

// EvidenceEnvelope wraps tool execution results in a standard envelope.
type EvidenceEnvelope struct {
	Status     string         `json:"status"`
	ScanID     string         `json:"scan_id"`
	Tool       string         `json:"tool"`
	Command    string         `json:"command"`
	ExitCode   int            `json:"exit_code"`
	Stderr     string         `json:"stderr"`
	DurationMs int64          `json:"duration_ms"`
	Timestamp  string         `json:"timestamp"`
	OutputHash string         `json:"output_hash,omitempty"`
	Results    map[string]any `json:"results"`
	Error      string         `json:"error,omitempty"`
}

// newScanID returns a scan identifier for one invocation.
func newScanID(start time.Time) string {
	return fmt.Sprintf("%d-%d", start.Unix(), start.UnixNano()%100000)
}

// evidenceDir returns the evidence root: TOOLCLAD_EVIDENCE_DIR or
// <tmpdir>/toolclad-evidence.
func evidenceDir() string {
	if dir := os.Getenv("TOOLCLAD_EVIDENCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(os.TempDir(), "toolclad-evidence")
}

// resolveVars validates arguments and resolves every template variable into
// the two variable classes of the command model:
//
//   - vars holds single-token variables: every declared arg (validated),
//     [command.defaults] entries, and the executor-injected _scan_id,
//     _evidence_dir and _output_file. Each is exactly one argv token's worth
//     of text and is never split.
//   - trusted holds multi-token variables produced from manifest-controlled
//     text: _<arg>_flags from [command.mappings] (tokenized here) and
//     _<cond> from [command.conditionals] (tokenized at load, substituted
//     here). A whole-token placeholder naming one of these splices its
//     token vector into argv.
func resolveVars(m *manifest.Manifest, args map[string]string, scanID string) (map[string]string, map[string][]string, error) {
	if err := checkDeclaredArgs(m, args); err != nil {
		return nil, nil, err
	}
	if err := m.EnsureScope(); err != nil {
		return nil, nil, err
	}

	// allow_whitespace is honored only for a manifest that declared exec
	// itself; the executor escape hatch always validates in strict mode.
	execMode := m.Command.ExecWasDeclared && m.Command.Executor == ""
	vars := make(map[string]string)
	for name, argDef := range m.Args {
		val, provided := args[name]
		if !provided {
			if argDef.Required {
				return nil, nil, fmt.Errorf("missing required argument: %q", name)
			}
			if argDef.Default == nil {
				// Unset optional: resolves to the empty string so a
				// whole-token placeholder for it disappears from argv.
				vars[name] = ""
				continue
			}
			val = fmt.Sprintf("%v", argDef.Default)
		}

		validated, err := validator.ValidateArgIn(argDef, val, execMode, m.Scope)
		if err != nil {
			return nil, nil, fmt.Errorf("argument %q: %w", name, err)
		}
		vars[name] = validated
	}

	for k, v := range m.Command.Defaults {
		if _, exists := vars[k]; !exists {
			vars[k] = fmt.Sprintf("%v", v)
		}
	}

	evDir := evidenceDir()
	vars["_scan_id"] = scanID
	vars["_evidence_dir"] = evDir
	vars["_output_file"] = filepath.Join(evDir, scanID+"-output")

	trusted := make(map[string][]string)
	for argName, mapping := range m.Command.Mappings {
		val := vars[argName]
		mapped, ok := mapping[val]
		if !ok {
			if val == "" {
				// An absent optional argument contributes nothing.
				trusted["_"+argName+"_flags"] = []string{}
				continue
			}
			return nil, nil, fmt.Errorf(
				"no mapping for argument '%s' value '%s' in [command.mappings.%s]",
				argName, val, argName)
		}
		// Mapping values come from the manifest, so splitting them is safe.
		// A value mapped to "" yields no tokens.
		tokens, err := manifest.TokenizeTemplate(mapped)
		if err != nil {
			return nil, nil, fmt.Errorf("command.mappings.%s: %w", argName, err)
		}
		if tokens == nil {
			tokens = []string{}
		}
		trusted["_"+argName+"_flags"] = tokens
	}

	// Conditionals are evaluated in name order so the result is deterministic.
	condNames := make([]string, 0, len(m.Command.Conditionals))
	for name := range m.Command.Conditionals {
		condNames = append(condNames, name)
	}
	sort.Strings(condNames)
	for _, name := range condNames {
		cond := m.Command.Conditionals[name]
		if !evaluateCondition(cond.When, vars) {
			trusted["_"+name] = []string{}
			continue
		}
		tokens := cond.Tokens
		if tokens == nil && cond.Template != "" {
			// Manifest built in memory without going through load.
			var err error
			tokens, err = manifest.TokenizeTemplate(cond.Template)
			if err != nil {
				return nil, nil, fmt.Errorf("command.conditionals.%s.template: %w", name, err)
			}
		}
		expanded, err := expandTokens(tokens, vars, trusted, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("command.conditionals.%s: %w", name, err)
		}
		trusted["_"+name] = expanded
	}

	return vars, trusted, nil
}

// checkDeclaredArgs refuses a supplied argument name that the manifest does
// not declare in [args]. An undeclared name never reaches the command, so
// this is not an injection boundary; it closes the gap between what the
// caller asked for and what ran, instead of silently dropping the argument.
// Names are checked in sorted order so the reported one is deterministic.
func checkDeclaredArgs(m *manifest.Manifest, args map[string]string) error {
	supplied := make([]string, 0, len(args))
	for name := range args {
		supplied = append(supplied, name)
	}
	sort.Strings(supplied)
	for _, name := range supplied {
		if _, ok := m.Args[name]; ok {
			continue
		}
		declared := make([]string, 0, len(m.Args))
		for d := range m.Args {
			declared = append(declared, d)
		}
		sort.Strings(declared)
		list := strings.Join(declared, ", ")
		if list == "" {
			list = "none"
		}
		return fmt.Errorf("unknown argument '%s' (declared arguments: %s)", name, list)
	}
	return nil
}

// evaluateCondition evaluates a [command.conditionals.<n>].when expression
// against the single-token variables.
//
// Supported forms: a comparison of a variable against the empty string or a
// quoted or bare literal using != or ==, joined by ` and ` or ` or ` (one
// level, no nesting). A missing variable compares as the empty string.
//
// SECURITY: this is a closed-vocabulary evaluator. Never replace it with
// dynamic code evaluation of any kind.
func evaluateCondition(when string, vars map[string]string) bool {
	if strings.Contains(when, " and ") {
		for _, part := range strings.Split(when, " and ") {
			if !evaluateSingle(strings.TrimSpace(part), vars) {
				return false
			}
		}
		return true
	}
	if strings.Contains(when, " or ") {
		for _, part := range strings.Split(when, " or ") {
			if evaluateSingle(strings.TrimSpace(part), vars) {
				return true
			}
		}
		return false
	}
	return evaluateSingle(strings.TrimSpace(when), vars)
}

// evaluateSingle evaluates one `lhs OP rhs` comparison, OP being != or ==.
// Any other shape evaluates to false.
func evaluateSingle(expr string, vars map[string]string) bool {
	for _, op := range []string{"!=", "=="} {
		idx := strings.Index(expr, op)
		if idx < 0 {
			continue
		}
		lhs := strings.TrimSpace(expr[:idx])
		rhs := strings.Trim(strings.TrimSpace(expr[idx+len(op):]), "'\"")
		val := vars[lhs]
		if op == "!=" {
			return val != rhs
		}
		return val == rhs
	}
	return false
}

// endOfOptionsState tracks the single `--` insertion for one build.
type endOfOptionsState struct {
	enabled  bool
	inserted bool
	isUser   func(name string) bool
}

// expandTokens substitutes a compiled token vector into argv tokens:
//
//  1. A token that is exactly `{name}` naming a trusted multi-token variable
//     splices that variable's token vector (0..n tokens).
//  2. Otherwise every `{name}` occurrence is substituted textually inside
//     the single token, which is never re-split. A token that was exactly one
//     placeholder resolving to the empty string is dropped. `{{` and `}}`
//     become literal braces. An unresolved name is an error, and so is a
//     trusted multi-token variable glued to literal text.
//
// When eoo is non-nil and enabled, a literal `--` is inserted immediately
// before the first argv token produced from a whole-token user-arg
// placeholder, at most once.
func expandTokens(tokens []string, vars map[string]string, trusted map[string][]string, eoo *endOfOptionsState) ([]string, error) {
	argv := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if name, ok := manifest.SolePlaceholder(tok); ok {
			if tv, ok := trusted[name]; ok {
				argv = append(argv, tv...)
				continue
			}
			v, ok := vars[name]
			if !ok {
				return nil, fmt.Errorf("unresolved placeholder '{%s}' in command", name)
			}
			if v == "" {
				continue
			}
			if eoo != nil && eoo.enabled && !eoo.inserted && eoo.isUser(name) {
				argv = append(argv, "--")
				eoo.inserted = true
			}
			argv = append(argv, v)
			continue
		}
		// A multi-token variable may only appear as a whole token; glued
		// to literal text it is never joined into one token.
		for _, name := range manifest.Placeholders(tok) {
			if _, ok := trusted[name]; ok {
				return nil, fmt.Errorf(
					"placeholder '{%s}' expands to multiple tokens and must be a whole token in command", name)
			}
		}
		out, err := manifest.ExpandToken(tok, func(name string) (string, bool) {
			v, ok := vars[name]
			return v, ok
		})
		if err != nil {
			return nil, err
		}
		argv = append(argv, out)
	}
	return argv, nil
}

// compiledExec returns the manifest's canonical exec form, compiling a
// legacy template on the fly for manifests built in memory.
func compiledExec(m *manifest.Manifest) ([]string, error) {
	if err := m.EnsureCompiled(); err != nil {
		return nil, err
	}
	return m.Command.Exec, nil
}

// build constructs argv and returns the resolved single-token variables
// alongside it (the executor escape hatch exports them as environment
// variables).
func build(m *manifest.Manifest, args map[string]string, scanID string) ([]string, map[string]string, error) {
	tokens, err := compiledExec(m)
	if err != nil {
		return nil, nil, err
	}
	if m.Command.Executor == "" && len(tokens) == 0 {
		return nil, nil, fmt.Errorf("manifest %q has no command exec, template, or executor", m.Tool.Name)
	}

	vars, trusted, err := resolveVars(m, args, scanID)
	if err != nil {
		return nil, nil, err
	}

	if m.Command.Executor != "" {
		return []string{m.Command.Executor}, vars, nil
	}

	eoo := &endOfOptionsState{
		enabled: m.Command.EndOfOptions == "--",
		isUser:  func(name string) bool { return m.Args[name] != nil },
	}
	argv, err := expandTokens(tokens, vars, trusted, eoo)
	if err != nil {
		return nil, nil, err
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, nil, fmt.Errorf("command produced empty argv")
	}
	return argv, vars, nil
}

// BuildCommandArgv validates arguments and builds the argv array from the
// manifest's canonical exec form. Each element is one argv token: values are
// substituted into single tokens and never re-split, so a value containing
// whitespace or quote characters cannot change the argument structure.
func BuildCommandArgv(m *manifest.Manifest, args map[string]string) ([]string, error) {
	argv, _, err := build(m, args, newScanID(time.Now()))
	return argv, err
}

// BuildCommand validates arguments and returns the constructed command as a
// display string (argv joined, with tokens quoted where needed). The string
// is for display and evidence only; execution always uses BuildCommandArgv.
func BuildCommand(m *manifest.Manifest, args map[string]string) (string, error) {
	argv, err := BuildCommandArgv(m, args)
	if err != nil {
		return "", err
	}
	return FormatArgv(argv), nil
}

// FormatArgv renders argv for display. Tokens containing whitespace, quotes
// or shell metacharacters are single-quoted so argument boundaries are
// visible; the result is never executed.
func FormatArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, tok := range argv {
		parts[i] = quoteForDisplay(tok)
	}
	return strings.Join(parts, " ")
}

func quoteForDisplay(tok string) string {
	if tok == "" {
		return "''"
	}
	needsQuote := false
	for _, r := range tok {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`'"\$`+"`;|&<>(){}[]!*?~#", r) {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return tok
	}
	return "'" + strings.ReplaceAll(tok, "'", `'\''`) + "'"
}

// Execute validates arguments, builds the command, executes it with a timeout,
// captures output, and returns an EvidenceEnvelope.
func Execute(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	// Route to HTTP backend
	if m.Http != nil {
		return ExecuteHTTP(m, args)
	}
	// Route to MCP proxy backend
	if m.Mcp != nil {
		return ExecuteMCP(m, args)
	}
	// Gate unimplemented modes
	if m.Session != nil {
		return nil, fmt.Errorf("session mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for session execution")
	}
	if m.Browser != nil {
		return nil, fmt.Errorf("browser mode is parsed but not yet executable in the reference implementation — use the Symbiont runtime for browser execution")
	}

	start := time.Now()
	scanID := newScanID(start)

	cmdArgs, vars, err := build(m, args, scanID)
	if err != nil {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Timestamp: start.UTC().Format(time.RFC3339),
			ExitCode:  -1,
			Error:     err.Error(),
		}, err
	}
	cmdStr := FormatArgv(cmdArgs)

	timeout := time.Duration(m.Tool.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	// Set process group so we can kill the entire group on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// If using a custom executor, pass validated args as env vars.
	if m.Command.Executor != "" {
		for name := range m.Args {
			envKey := "TOOLCLAD_ARG_" + strings.ToUpper(name)
			cmd.Env = append(cmd.Env, envKey+"="+vars[name])
		}
		cmd.Env = append(cmd.Env, "TOOLCLAD_SCAN_ID="+scanID)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	execErr := cmd.Run()
	duration := time.Since(start)

	// On context deadline exceeded, kill the entire process group.
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	stdoutBytes := stdoutBuf.Bytes()
	stderrStr := stderrBuf.String()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	} else if execErr != nil {
		exitCode = -1
	}

	envelope := &EvidenceEnvelope{
		ScanID:     scanID,
		Tool:       m.Tool.Name,
		Command:    cmdStr,
		ExitCode:   exitCode,
		Stderr:     stderrStr,
		DurationMs: duration.Milliseconds(),
		Timestamp:  start.UTC().Format(time.RFC3339),
	}

	if execErr != nil {
		envelope.Status = "error"
		envelope.Error = execErr.Error()
		envelope.Results = map[string]any{
			"raw_output": string(stdoutBytes),
		}
		return envelope, execErr
	}

	envelope.Status = "success"

	// Compute hash of output.
	hash := sha256.Sum256(stdoutBytes)
	envelope.OutputHash = fmt.Sprintf("sha256:%x", hash)

	// Parse output based on format. Callback-only manifests have no [output];
	// for the execute path we always have one (validated at load).
	outFormat := "text"
	if m.Output != nil {
		outFormat = m.Output.Format
	}
	results, parseErr := parseOutput(outFormat, stdoutBytes)
	if parseErr != nil {
		envelope.Results = map[string]any{
			"raw_output": string(stdoutBytes),
		}
	} else {
		envelope.Results = results
	}

	return envelope, nil
}

// parseOutput converts raw command output based on the declared format.
func parseOutput(format string, data []byte) (map[string]any, error) {
	switch format {
	case "json":
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parsing JSON output: %w", err)
		}
		return result, nil

	case "jsonl":
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var parsed []any
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var obj any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				return nil, fmt.Errorf("parsing JSONL line: %w", err)
			}
			parsed = append(parsed, obj)
		}
		return map[string]any{"parsed_output": parsed}, nil

	case "csv":
		return parseCsvOutput(data), nil

	case "xml":
		return parseXmlOutput(data), nil

	case "text", "":
		return map[string]any{"raw_output": string(data)}, nil

	default:
		return map[string]any{"raw_output": string(data)}, nil
	}
}

// parseCsvOutput parses CSV data with auto-delimiter detection and type inference.
func parseCsvOutput(data []byte) map[string]any {
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return map[string]any{"parsed_output": []any{}}
	}

	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return map[string]any{"parsed_output": []any{}}
	}

	// Auto-detect delimiter
	firstLine := lines[0]
	delimiter := ','
	if strings.Contains(firstLine, "\t") {
		delimiter = '\t'
	} else if strings.Contains(firstLine, "|") && !strings.Contains(firstLine, ",") {
		delimiter = '|'
	}

	headers := splitCsvLine(firstLine, delimiter)
	for i := range headers {
		headers[i] = strings.TrimSpace(headers[i])
	}

	var rows []any
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitCsvLine(line, delimiter)
		row := make(map[string]any)
		for i, h := range headers {
			val := ""
			if i < len(fields) {
				val = strings.TrimSpace(fields[i])
			}
			// Type inference
			if strings.ToLower(val) == "true" || strings.ToLower(val) == "false" {
				row[h] = strings.ToLower(val) == "true"
			} else if n, err := strconv.Atoi(val); err == nil {
				row[h] = n
			} else if f, err := strconv.ParseFloat(val, 64); err == nil {
				row[h] = f
			} else {
				row[h] = val
			}
		}
		rows = append(rows, row)
	}

	return map[string]any{"parsed_output": rows}
}

// splitCsvLine splits a CSV line respecting quoted fields and escaped quotes.
func splitCsvLine(line string, delimiter rune) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	runes := []rune(line)

	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == '"' {
			if inQuotes && i+1 < len(runes) && runes[i+1] == '"' {
				current.WriteRune('"')
				i++ // skip escaped quote
			} else {
				inQuotes = !inQuotes
			}
		} else if c == delimiter && !inQuotes {
			fields = append(fields, current.String())
			current.Reset()
		} else {
			current.WriteRune(c)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// parseXmlOutput parses XML data into a nested map structure.
func parseXmlOutput(data []byte) map[string]any {
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return map[string]any{"raw_output": ""}
	}

	// Strip XML declaration
	if strings.HasPrefix(raw, "<?xml") {
		if idx := strings.Index(raw, "?>"); idx != -1 {
			raw = strings.TrimSpace(raw[idx+2:])
		}
	}

	type stackEntry struct {
		name string
		obj  map[string]any
	}

	var stack []stackEntry
	currentName := ""
	currentObj := make(map[string]any)
	var textBuf strings.Builder
	pos := 0

	attrRe := regexp.MustCompile(`(\w+)\s*=\s*["']([^"']*)["']`)

	for pos < len(raw) {
		if raw[pos] == '<' {
			// Flush text
			text := strings.TrimSpace(textBuf.String())
			if text != "" && currentName != "" {
				currentObj["#text"] = text
			}
			textBuf.Reset()
			pos++
			if pos >= len(raw) {
				break
			}

			if raw[pos] == '/' {
				// Closing tag
				pos++
				tagEnd := strings.Index(raw[pos:], ">")
				if tagEnd == -1 {
					break
				}
				pos += tagEnd + 1

				finishedObj := currentObj
				if len(stack) > 0 {
					parent := stack[len(stack)-1]
					stack = stack[:len(stack)-1]

					if existing, ok := parent.obj[currentName]; ok {
						if arr, ok := existing.([]any); ok {
							parent.obj[currentName] = append(arr, finishedObj)
						} else {
							parent.obj[currentName] = []any{existing, finishedObj}
						}
					} else {
						parent.obj[currentName] = finishedObj
					}
					currentName = parent.name
					currentObj = parent.obj
				}
			} else if raw[pos] == '!' || raw[pos] == '?' {
				// Comment or PI — skip
				tagEnd := strings.Index(raw[pos:], ">")
				if tagEnd == -1 {
					break
				}
				pos += tagEnd + 1
			} else {
				// Opening tag
				tagEnd := strings.Index(raw[pos:], ">")
				if tagEnd == -1 {
					break
				}
				tagContent := raw[pos : pos+tagEnd]
				selfClosing := strings.HasSuffix(tagContent, "/")
				if selfClosing {
					tagContent = tagContent[:len(tagContent)-1]
				}

				parts := strings.Fields(tagContent)
				tagName := ""
				if len(parts) > 0 {
					tagName = parts[0]
				}

				attrs := make(map[string]any)
				attrStr := ""
				if len(tagContent) > len(tagName) {
					attrStr = tagContent[len(tagName):]
				}
				for _, match := range attrRe.FindAllStringSubmatch(attrStr, -1) {
					attrs["@"+match[1]] = match[2]
				}

				if selfClosing {
					if existing, ok := currentObj[tagName]; ok {
						if arr, ok := existing.([]any); ok {
							currentObj[tagName] = append(arr, attrs)
						} else {
							currentObj[tagName] = []any{existing, attrs}
						}
					} else {
						currentObj[tagName] = attrs
					}
				} else {
					stack = append(stack, stackEntry{name: currentName, obj: currentObj})
					currentName = tagName
					currentObj = attrs
				}
				pos += tagEnd + 1
			}
		} else {
			textBuf.WriteByte(raw[pos])
			pos++
		}
	}

	if currentName != "" {
		result := make(map[string]any)
		result[currentName] = currentObj
		return result
	}
	return currentObj
}

// secretPattern matches {_secret:name} placeholders in templates.
var secretPattern = regexp.MustCompile(`\{_secret:(\w+)\}`)

// injectTemplateVars replaces {_secret:name} with TOOLCLAD_SECRET_<NAME> env vars.
func injectTemplateVars(template string) (string, error) {
	var missingErr error
	result := secretPattern.ReplaceAllStringFunc(template, func(match string) string {
		sub := secretPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		envKey := "TOOLCLAD_SECRET_" + strings.ToUpper(sub[1])
		val := os.Getenv(envKey)
		if val == "" {
			missingErr = fmt.Errorf("missing environment variable: %s", envKey)
			return match
		}
		return val
	})
	if missingErr != nil {
		return "", missingErr
	}
	return result, nil
}

// interpolateString replaces {key} placeholders with values from the context map.
func interpolateString(template string, ctx map[string]string) string {
	result := template
	for k, v := range ctx {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
	}
	return result
}

// expandHTTPTemplate turns one [http] template string into its final form.
// Secrets are expanded on the manifest template FIRST and argument values
// are interpolated afterwards, so a validated argument can never introduce
// a {_secret:name} reference of its own: by the time the argument text is
// in place, no secret expansion happens any more. The url validator's
// metacharacter blocklist also rejects braces, but the ordering here does
// not rely on that check being the only defense.
func expandHTTPTemplate(template string, cleaned map[string]string) (string, error) {
	withSecrets, err := injectTemplateVars(template)
	if err != nil {
		return "", err
	}
	return interpolateString(withSecrets, cleaned), nil
}

// buildHTTPRequest assembles the request for an [http] manifest from
// already-validated arguments without sending it. The URL, every header
// value and the body template each go through expandHTTPTemplate.
func buildHTTPRequest(m *manifest.Manifest, cleaned map[string]string) (*http.Request, error) {
	url, err := expandHTTPTemplate(m.Http.URL, cleaned)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range m.Http.Headers {
		hv, err := expandHTTPTemplate(v, cleaned)
		if err != nil {
			return nil, err
		}
		headers[k] = hv
	}

	method := strings.ToUpper(m.Http.Method)
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if m.Http.BodyTemplate != "" && method != "GET" && method != "HEAD" {
		body, err := expandHTTPTemplate(m.Http.BodyTemplate, cleaned)
		if err != nil {
			return nil, err
		}
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building HTTP request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// ExecuteHTTP performs an HTTP request based on the manifest's [http] section.
func ExecuteHTTP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	if m.Http == nil || m.Http.URL == "" {
		return nil, fmt.Errorf("manifest %q has no [http] section or http.url", m.Tool.Name)
	}
	if err := checkDeclaredArgs(m, args); err != nil {
		return nil, err
	}
	// Manifests built in memory never passed LoadManifest's egress lint;
	// run it here so an [http] backend (always egress) and a
	// network_egress tool get the same block_internal requirement.
	if err := m.LintEgress(nil); err != nil {
		return nil, err
	}
	if err := m.EnsureScope(); err != nil {
		return nil, err
	}

	start := time.Now()
	scanID := fmt.Sprintf("%d-%d", start.Unix(), start.UnixNano()%100000)

	// Validate args
	cleaned := make(map[string]string)
	for name, argDef := range m.Args {
		val, provided := args[name]
		if !provided {
			if argDef.Required {
				return nil, fmt.Errorf("missing required argument: %q", name)
			}
			if argDef.Default != nil {
				val = fmt.Sprintf("%v", argDef.Default)
			} else {
				continue
			}
		}
		validated, err := validator.ValidateArgIn(argDef, val, false, m.Scope)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", name, err)
		}
		cleaned[name] = validated
	}

	req, err := buildHTTPRequest(m, cleaned)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(m.Tool.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	resp, err := client.Do(req)
	if err != nil {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Timestamp: start.UTC().Format(time.RFC3339),
			Error:     err.Error(),
		}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	duration := time.Since(start)
	hash := sha256.Sum256(respBody)

	successStatus := m.Http.SuccessStatus
	if len(successStatus) == 0 {
		successStatus = []int{200, 201, 202, 204}
	}
	isSuccess := false
	for _, s := range successStatus {
		if resp.StatusCode == s {
			isSuccess = true
			break
		}
	}

	envelope := &EvidenceEnvelope{
		ScanID:     scanID,
		Tool:       m.Tool.Name,
		DurationMs: duration.Milliseconds(),
		Timestamp:  start.UTC().Format(time.RFC3339),
		OutputHash: fmt.Sprintf("sha256:%x", hash),
		ExitCode:   resp.StatusCode,
		Results: map[string]any{
			"raw_output": string(respBody),
		},
	}

	if isSuccess {
		envelope.Status = "success"
	} else {
		envelope.Status = "error"
		body := string(respBody)
		if len(body) > 500 {
			body = body[:500]
		}
		envelope.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, body)
	}

	return envelope, nil
}

// ExecuteMCP performs field mapping and returns a delegated envelope for MCP proxy.
func ExecuteMCP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	if m.Mcp == nil || m.Mcp.Server == "" || m.Mcp.Tool == "" {
		return nil, fmt.Errorf("manifest %q has no [mcp] section or mcp.server/mcp.tool", m.Tool.Name)
	}
	if err := checkDeclaredArgs(m, args); err != nil {
		return nil, err
	}
	// Manifests built in memory never passed LoadManifest's egress lint;
	// run it here so an [http] backend (always egress) and a
	// network_egress tool get the same block_internal requirement.
	if err := m.LintEgress(nil); err != nil {
		return nil, err
	}
	if err := m.EnsureScope(); err != nil {
		return nil, err
	}

	start := time.Now()
	scanID := fmt.Sprintf("%d-%d", start.Unix(), start.UnixNano()%100000)

	// Validate args
	cleaned := make(map[string]string)
	for name, argDef := range m.Args {
		val, provided := args[name]
		if !provided {
			if argDef.Required {
				return nil, fmt.Errorf("missing required argument: %q", name)
			}
			if argDef.Default != nil {
				val = fmt.Sprintf("%v", argDef.Default)
			} else {
				continue
			}
		}
		validated, err := validator.ValidateArgIn(argDef, val, false, m.Scope)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", name, err)
		}
		cleaned[name] = validated
	}

	// Apply field_map
	mappedArgs := make(map[string]any)
	if len(m.Mcp.FieldMap) > 0 {
		for ourName, theirName := range m.Mcp.FieldMap {
			if val, ok := cleaned[ourName]; ok {
				mappedArgs[theirName] = val
			}
		}
	} else {
		for k, v := range cleaned {
			mappedArgs[k] = v
		}
	}

	return &EvidenceEnvelope{
		Status:    "delegation_preview",
		ScanID:    scanID,
		Tool:      m.Tool.Name,
		Timestamp: start.UTC().Format(time.RFC3339),
		Results: map[string]any{
			"mcp_server":  m.Mcp.Server,
			"mcp_tool":    m.Mcp.Tool,
			"mapped_args": mappedArgs,
		},
	}, nil
}

// GenerateMCPSchema produces an MCP-compatible JSON schema from the manifest.
func GenerateMCPSchema(m *manifest.Manifest) map[string]any {
	properties := make(map[string]any)
	var required []string

	for _, arg := range m.ArgsSorted() {
		prop := mcpTypeConstraints(arg.Type)
		if arg.Type == "number" {
			if arg.MinFloat != nil {
				prop["minimum"] = *arg.MinFloat
			}
			if arg.MaxFloat != nil {
				prop["maximum"] = *arg.MaxFloat
			}
		}
		prop["description"] = arg.Description
		if len(arg.Allowed) > 0 {
			prop["enum"] = arg.Allowed
		}
		if arg.Default != nil {
			prop["default"] = arg.Default
		}
		properties[arg.Name] = prop
		if arg.Required {
			required = append(required, arg.Name)
		}
	}

	inputSchema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		inputSchema["required"] = required
	}

	schema := map[string]any{
		"name":        m.Tool.Name,
		"description": m.Tool.Description,
		"inputSchema": inputSchema,
	}

	if m.Output != nil && len(m.Output.Schema) > 0 {
		schema["outputSchema"] = m.Output.Schema
	}

	// Always include exit_code and stderr in the envelope schema.
	schema["envelopeSchema"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"exit_code": map[string]any{
				"type":        "integer",
				"description": "Process exit code (0 = success)",
			},
			"stderr": map[string]any{
				"type":        "string",
				"description": "Standard error output from the tool",
			},
		},
	}

	return schema
}

// mcpTypeConstraints maps ToolClad types to JSON Schema type and constraints for MCP.
func mcpTypeConstraints(t string) map[string]any {
	switch t {
	case "integer":
		return map[string]any{"type": "integer"}
	case "number":
		return map[string]any{"type": "number"}
	case "port":
		return map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}
	case "boolean":
		return map[string]any{"type": "boolean"}
	case "ip_address":
		return map[string]any{"type": "string", "format": "ipv4"}
	case "cidr":
		return map[string]any{"type": "string", "pattern": `^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`}
	case "url":
		return map[string]any{"type": "string", "format": "uri"}
	case "duration":
		return map[string]any{"type": "string", "pattern": `^(\d+|(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?)$`}
	default:
		return map[string]any{"type": "string"}
	}
}
