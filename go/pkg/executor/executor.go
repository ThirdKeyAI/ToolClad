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
	"regexp"
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

// BuildCommand validates arguments and interpolates the command template.
// It returns the fully constructed command string ready for execution.
func BuildCommand(m *manifest.Manifest, args map[string]string) (string, error) {
	// If there is a custom executor, we do not build a template command.
	if m.Command.Executor != "" {
		return m.Command.Executor, nil
	}

	if m.Command.Template == "" {
		return "", fmt.Errorf("manifest %q has no command template or executor", m.Tool.Name)
	}

	// Validate all provided args and collect cleaned values.
	cleaned := make(map[string]string)
	for name, argDef := range m.Args {
		val, provided := args[name]
		if !provided {
			if argDef.Required {
				return "", fmt.Errorf("missing required argument: %q", name)
			}
			// Use default value if available.
			if argDef.Default != nil {
				val = fmt.Sprintf("%v", argDef.Default)
			} else {
				val = ""
			}
		}

		validated, err := validator.ValidateArg(argDef, val)
		if err != nil {
			return "", fmt.Errorf("argument %q: %w", name, err)
		}
		cleaned[name] = validated
	}

	// Apply command defaults for template variables not covered by args.
	for k, v := range m.Command.Defaults {
		if _, exists := cleaned[k]; !exists {
			cleaned[k] = fmt.Sprintf("%v", v)
		}
	}

	// Resolve mappings: e.g., scan_type -> _scan_flags.
	for argName, mapping := range m.Command.Mappings {
		val, ok := cleaned[argName]
		if !ok {
			continue
		}
		mapped, ok := mapping[val]
		if ok {
			// Convention: mapping result is stored as _{argName}_flags
			// but we also check for _scan_flags style references in the template.
			cleaned["_"+argName+"_flags"] = mapped
			// Also store as _scan_flags if the arg name ends with _type.
			if strings.HasSuffix(argName, "_type") {
				prefix := strings.TrimSuffix(argName, "_type")
				cleaned["_"+prefix+"_flags"] = mapped
			}
		}
	}

	// SECURITY: This evaluator uses a closed-vocabulary parser.
	// Never use eval() or equivalent dynamic code execution for conditions.

	// Interpolate the template.
	result := m.Command.Template
	for k, v := range cleaned {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
	}

	// Replace any remaining executor-injected variables with empty strings
	// for variables that start with _ (internal variables like _output_file).
	// In a real runtime these would be injected; for the reference impl we leave them.

	return result, nil
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
	scanID := fmt.Sprintf("%d-%d", start.Unix(), start.UnixNano()%100000)

	cmdStr, err := BuildCommand(m, args)
	if err != nil {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Timestamp: start.UTC().Format(time.RFC3339),
			Error:     err.Error(),
		}, err
	}

	timeout := time.Duration(m.Tool.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use array-based execution to avoid shell interpretation.
	cmdArgs := strings.Fields(cmdStr)
	if len(cmdArgs) == 0 {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Timestamp: start.UTC().Format(time.RFC3339),
			ExitCode:  -1,
			Error:     "empty command after splitting",
		}, fmt.Errorf("empty command after splitting")
	}
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	// Set process group so we can kill the entire group on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// If using a custom executor, pass validated args as env vars.
	if m.Command.Executor != "" {
		for name, argDef := range m.Args {
			val, provided := args[name]
			if !provided {
				if argDef.Default != nil {
					val = fmt.Sprintf("%v", argDef.Default)
				} else {
					val = ""
				}
			}
			validated, vErr := validator.ValidateArg(argDef, val)
			if vErr != nil {
				return nil, fmt.Errorf("argument %q: %w", name, vErr)
			}
			envKey := "TOOLCLAD_ARG_" + strings.ToUpper(name)
			cmd.Env = append(cmd.Env, envKey+"="+validated)
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

	// Parse output based on format.
	results, parseErr := parseOutput(m.Output.Format, stdoutBytes)
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

// ExecuteHTTP performs an HTTP request based on the manifest's [http] section.
func ExecuteHTTP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	if m.Http == nil || m.Http.URL == "" {
		return nil, fmt.Errorf("manifest %q has no [http] section or http.url", m.Tool.Name)
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
		validated, err := validator.ValidateArg(argDef, val)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", name, err)
		}
		cleaned[name] = validated
	}

	// Interpolate URL
	url := interpolateString(m.Http.URL, cleaned)
	url, err := injectTemplateVars(url)
	if err != nil {
		return nil, err
	}

	// Interpolate headers
	headers := make(map[string]string)
	for k, v := range m.Http.Headers {
		hv := interpolateString(v, cleaned)
		hv, err := injectTemplateVars(hv)
		if err != nil {
			return nil, err
		}
		headers[k] = hv
	}

	// Interpolate body
	method := strings.ToUpper(m.Http.Method)
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if m.Http.BodyTemplate != "" && method != "GET" && method != "HEAD" {
		body := interpolateString(m.Http.BodyTemplate, cleaned)
		body, err = injectTemplateVars(body)
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
		validated, err := validator.ValidateArg(argDef, val)
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

	if len(m.Output.Schema) > 0 {
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
