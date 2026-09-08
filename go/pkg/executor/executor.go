// Package executor provides command construction and execution for ToolClad manifests.
package executor

import (
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
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

// resolveVars validates arguments and resolves all template variables (args,
// defaults, mappings) into a single interpolation context.
func resolveVars(m *manifest.Manifest, args map[string]string) (map[string]string, error) {
	cleaned, err := ValidateArguments(m, args)
	if err != nil {
		return nil, err
	}
	for name := range m.Args {
		if _, ok := cleaned[name]; !ok {
			cleaned[name] = ""
		}
	}

	for k, v := range m.Command.Defaults {
		if _, exists := cleaned[k]; !exists {
			cleaned[k] = fmt.Sprintf("%v", v)
		}
	}

	for name, fragment := range commandFragments(m, cleaned) {
		cleaned[name] = interpolateString(fragment, cleaned)
	}

	scanID := newScanID()
	evidenceDir := os.Getenv("TOOLCLAD_EVIDENCE_DIR")
	if evidenceDir == "" {
		evidenceDir = filepath.Join(os.TempDir(), "toolclad-evidence")
	}
	cleaned["_scan_id"] = scanID
	cleaned["_evidence_dir"] = evidenceDir
	cleaned["_output_file"] = filepath.Join(evidenceDir, scanID+"-output")
	return cleaned, nil
}

// BuildCommandArgv builds an argv array from the manifest's exec field.
// Each element is interpolated independently, preserving argument boundaries.
// This avoids the template→string→split round-trip that breaks when values
// contain spaces or quote characters.
func BuildCommandArgv(m *manifest.Manifest, args map[string]string) ([]string, error) {
	if len(m.Command.Exec) == 0 {
		return nil, fmt.Errorf("manifest %q has no exec array", m.Tool.Name)
	}

	cleaned, err := resolveVars(m, args)
	if err != nil {
		return nil, err
	}

	argv := make([]string, len(m.Command.Exec))
	for i, element := range m.Command.Exec {
		argv[i] = interpolateString(element, cleaned)
	}

	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("exec array produced empty argv")
	}

	return argv, nil
}

// BuildCommand validates arguments and interpolates the command template.
// It returns the fully constructed command string ready for execution.
// For new manifests, prefer BuildCommandArgv with the exec array format.
func BuildCommand(m *manifest.Manifest, args map[string]string) (string, error) {
	cleaned, err := resolveVars(m, args)
	if err != nil {
		return "", err
	}
	argv, err := preparedArgv(m, cleaned)
	return displayArgv(argv), err
}

func preparedArgv(m *manifest.Manifest, vars map[string]string) ([]string, error) {
	if m.Command.Executor != "" {
		return []string{m.Command.Executor}, nil
	}
	if len(m.Command.Exec) > 0 {
		argv := make([]string, len(m.Command.Exec))
		for i, v := range m.Command.Exec {
			argv[i] = interpolateString(v, vars)
		}
		if argv[0] == "" {
			return nil, fmt.Errorf("empty executable")
		}
		return argv, nil
	}
	return templateArgv(m.Command.Template, vars, commandFragments(m, vars))
}

func shellSplit(command string) []string { argv, _ := splitTemplate(command); return argv }

// Execute validates arguments, builds the command, executes it with a timeout,
// captures output, and returns an EvidenceEnvelope.
func Execute(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	clean, err := ValidateArguments(m, args)
	if err != nil {
		return nil, err
	}
	args = clean
	if err = checkExecution(m, false); err != nil {
		return nil, err
	}
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
	vars, err := resolveVars(m, args)
	if err != nil {
		return nil, err
	}
	scanID := vars["_scan_id"]
	cmdArgs, err := preparedArgv(m, vars)
	if err != nil {
		return nil, err
	}
	cmdStr := displayArgv(cmdArgs)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.Tool.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)

	// Set process group so we can kill the entire group on timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = childEnvironment()
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 200 * time.Millisecond

	// If using a custom executor, pass validated args as env vars.
	if m.Command.Executor != "" {
		for name, value := range args {
			cmd.Env = append(cmd.Env, "TOOLCLAD_ARG_"+strings.ToUpper(name)+"="+value)
		}

		cmd.Env = append(cmd.Env, "TOOLCLAD_SCAN_ID="+scanID)
	}

	stdoutBuf := cappedBuffer{stop: cmd.Cancel}
	stderrBuf := cappedBuffer{stop: cmd.Cancel}
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	execErr := cmd.Run()
	duration := time.Since(start)

	// On context deadline exceeded, kill the entire process group.
	if cmd.Process != nil {
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
	return tokenPattern.ReplaceAllStringFunc(template, func(token string) string {
		if value, ok := ctx[token[1:len(token)-1]]; ok {
			return value
		}
		return token
	})
}

// ExecuteHTTP performs an HTTP request based on the manifest's [http] section.
func ExecuteHTTP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	if m.Http == nil || m.Http.URL == "" {
		return nil, fmt.Errorf("manifest %q has no [http] section or http.url", m.Tool.Name)
	}

	start := time.Now()
	scanID := fmt.Sprintf("%d-%d", start.Unix(), start.UnixNano()%100000)

	cleaned, err := ValidateArguments(m, args)
	if err != nil {
		return nil, err
	}
	if err = checkExecution(m, false); err != nil {
		return nil, err
	}
	url, err := httpURL(m.Http.URL, cleaned)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	requestSize := len(url)
	for key, template := range m.Http.Headers {
		value, err := httpTemplate(template, cleaned, false, false)
		if err != nil {
			return nil, err
		}
		headers[key] = value
		requestSize += len(key) + len(value)
	}
	method := strings.ToUpper(m.Http.Method)
	if method == "" {
		method = "GET"
	}
	body, err := httpTemplate(m.Http.BodyTemplate, cleaned, false, true)
	if err != nil {
		return nil, err
	}
	requestSize += len(body)
	if requestSize > maxRequestBytes {
		return nil, fmt.Errorf("HTTP request exceeds 1 MiB")
	}
	var bodyReader io.Reader
	if body != "" {
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
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if len(respBody) > maxResponseBytes {
		return nil, fmt.Errorf("HTTP response exceeds 4 MiB")
	}
	duration := time.Since(start)
	hash := sha256.Sum256(respBody)

	isSuccess := resp.StatusCode >= 200 && resp.StatusCode < 300
	if len(m.Http.SuccessStatus) > 0 {
		isSuccess = false
		for _, code := range m.Http.SuccessStatus {
			if code == resp.StatusCode {
				isSuccess = true
			}
		}
	}

	for _, status := range m.Http.ErrorStatus {
		if status == resp.StatusCode {
			isSuccess = false
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

	cleaned, err := ValidateArguments(m, args)
	if err != nil {
		return nil, err
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
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
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
