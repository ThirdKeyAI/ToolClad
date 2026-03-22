// Package executor provides command construction and execution for ToolClad manifests.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
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
	case "text", "":
		return map[string]any{
			"raw_output": string(data),
		}, nil
	default:
		// For xml, csv, jsonl -- fall back to raw text in the reference impl.
		return map[string]any{
			"raw_output": string(data),
		}, nil
	}
}

// GenerateMCPSchema produces an MCP-compatible JSON schema from the manifest.
func GenerateMCPSchema(m *manifest.Manifest) map[string]any {
	properties := make(map[string]any)
	var required []string

	for _, arg := range m.ArgsSorted() {
		prop := map[string]any{
			"type":        mcpType(arg.Type),
			"description": arg.Description,
		}
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

	return schema
}

// mcpType maps ToolClad types to JSON Schema types for MCP.
func mcpType(t string) string {
	switch t {
	case "integer", "port":
		return "integer"
	case "boolean":
		return "boolean"
	default:
		return "string"
	}
}
