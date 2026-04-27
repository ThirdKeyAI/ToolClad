// Package manifest provides types and loading for .clad.toml ToolClad manifests.
package manifest

import (
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
)

// CedarDef holds Cedar policy integration metadata.
type CedarDef struct {
	Resource string `toml:"resource"`
	Action   string `toml:"action"`
}

// EvidenceDef holds evidence capture configuration.
type EvidenceDef struct {
	OutputDir string `toml:"output_dir"`
	Capture   bool   `toml:"capture"`
	Hash      string `toml:"hash"`
}

// ToolMeta holds the top-level [tool] section metadata.
type ToolMeta struct {
	Name           string       `toml:"name"`
	Version        string       `toml:"version"`
	Binary         string       `toml:"binary"`
	Description    string       `toml:"description"`
	TimeoutSeconds int          `toml:"timeout_seconds"`
	RiskTier       string       `toml:"risk_tier"`
	HumanApproval  bool         `toml:"human_approval"`
	// Dispatch mode: "exec" (default) runs an execution backend; "callback"
	// declares the manifest as validator-only — no [output] block or backend
	// is required. Useful for in-process embeddings where ToolClad is the
	// typed-argument fence and dispatch happens elsewhere.
	Dispatch string       `toml:"dispatch"`
	Cedar    *CedarDef    `toml:"cedar"`
	Evidence *EvidenceDef `toml:"evidence"`
}

// ArgDef defines a single tool argument from [args.*].
type ArgDef struct {
	Name        string   `toml:"-"`
	Position    int      `toml:"position"`
	Required    bool     `toml:"required"`
	Type        string   `toml:"type"`
	Description string   `toml:"description"`
	Default     any      `toml:"default"`
	Allowed     []string `toml:"allowed"`
	Pattern     string   `toml:"pattern"`
	Min         *int     `toml:"min"`
	Max         *int     `toml:"max"`
	// Float bounds for `number` type. Fall back to Min/Max cast to float64 when nil.
	MinFloat    *float64 `toml:"min_float"`
	MaxFloat    *float64 `toml:"max_float"`
	Clamp       bool     `toml:"clamp"`
	Sanitize    []string `toml:"sanitize"`
	Schemes     []string `toml:"schemes"`
	ScopeCheck  bool     `toml:"scope_check"`
}

// ConditionalDef represents a conditional command fragment.
type ConditionalDef struct {
	When     string `toml:"when"`
	Template string `toml:"template"`
}

// CommandDef holds the [command] section.
//
// Supports two invocation forms:
//   - exec = ["cmd", "arg1", "{placeholder}"] — preferred, shell-free array execution
//   - template = "cmd arg1 {placeholder}" — legacy string template (split via shlex)
//
// When both are present, exec takes precedence.
type CommandDef struct {
	Template     string                        `toml:"template"`
	Exec         []string                      `toml:"exec"`
	Executor     string                        `toml:"executor"`
	Defaults     map[string]any                `toml:"defaults"`
	Mappings     map[string]map[string]string  `toml:"mappings"`
	Conditionals map[string]ConditionalDef     `toml:"conditionals"`
}

// OutputDef holds the [output] section.
type OutputDef struct {
	Format   string         `toml:"format"`
	Parser   string         `toml:"parser"`
	Envelope *bool          `toml:"envelope"`
	Schema   map[string]any `toml:"schema"`
}

// EnvelopeEnabled returns whether the evidence envelope is enabled (default true).
func (o *OutputDef) EnvelopeEnabled() bool {
	if o.Envelope == nil {
		return true
	}
	return *o.Envelope
}

// HttpDef holds the [http] section for HTTP-based tool execution.
type HttpDef struct {
	Method        string            `toml:"method"`
	URL           string            `toml:"url"`
	Headers       map[string]string `toml:"headers"`
	BodyTemplate  string            `toml:"body_template"`
	SuccessStatus []int             `toml:"success_status"`
	ErrorStatus   []int             `toml:"error_status"`
}

// McpProxyDef holds the [mcp] section for MCP proxy delegation.
type McpProxyDef struct {
	Server   string            `toml:"server"`
	Tool     string            `toml:"tool"`
	FieldMap map[string]string `toml:"field_map"`
}

// SessionDef holds the [session] section for interactive session mode.
type SessionDef struct {
	StartupCommand     string                       `toml:"startup_command"`
	ReadyPattern       string                       `toml:"ready_pattern"`
	StartupTimeoutSecs int                          `toml:"startup_timeout_seconds"`
	IdleTimeoutSecs    int                          `toml:"idle_timeout_seconds"`
	SessionTimeoutSecs int                          `toml:"session_timeout_seconds"`
	MaxInteractions    int                          `toml:"max_interactions"`
	Interaction        *SessionInteractionDef       `toml:"interaction"`
	Commands           map[string]SessionCommandDef `toml:"commands"`
}

// SessionInteractionDef holds session interaction constraints.
type SessionInteractionDef struct {
	InputSanitize  []string `toml:"input_sanitize"`
	OutputMaxBytes int64    `toml:"output_max_bytes"`
	OutputWaitMs   int64    `toml:"output_wait_ms"`
}

// SessionCommandDef defines a command within a session.
type SessionCommandDef struct {
	Pattern       string             `toml:"pattern"`
	Description   string             `toml:"description"`
	RiskTier      string             `toml:"risk_tier"`
	HumanApproval bool               `toml:"human_approval"`
	ExtractTarget bool               `toml:"extract_target"`
	Args          map[string]*ArgDef `toml:"args"`
}

// BrowserDef holds the [browser] section for browser automation mode.
type BrowserDef struct {
	Engine             string                       `toml:"engine"`
	Headless           bool                         `toml:"headless"`
	Connect            string                       `toml:"connect"`
	ExtractMode        string                       `toml:"extract_mode"`
	StartupTimeoutSecs int                          `toml:"startup_timeout_seconds"`
	SessionTimeoutSecs int                          `toml:"session_timeout_seconds"`
	IdleTimeoutSecs    int                          `toml:"idle_timeout_seconds"`
	MaxInteractions    int                          `toml:"max_interactions"`
	Scope              *BrowserScopeDef             `toml:"scope"`
	Commands           map[string]BrowserCommandDef `toml:"commands"`
	State              *BrowserStateDef             `toml:"state"`
}

// BrowserScopeDef defines domain scope restrictions for browser mode.
type BrowserScopeDef struct {
	AllowedDomains []string `toml:"allowed_domains"`
	BlockedDomains []string `toml:"blocked_domains"`
	AllowExternal  bool     `toml:"allow_external"`
}

// BrowserCommandDef defines a command within browser mode.
type BrowserCommandDef struct {
	Description   string             `toml:"description"`
	RiskTier      string             `toml:"risk_tier"`
	HumanApproval bool               `toml:"human_approval"`
	Args          map[string]*ArgDef `toml:"args"`
}

// BrowserStateDef defines observable state fields for browser mode.
type BrowserStateDef struct {
	Fields []string `toml:"fields"`
}

// Manifest is a fully parsed .clad.toml file.
//
// Output is a pointer because callback-dispatch manifests may omit [output].
type Manifest struct {
	Tool       ToolMeta           `toml:"tool"`
	Args       map[string]*ArgDef `toml:"args"`
	Command    CommandDef         `toml:"command"`
	Output     *OutputDef         `toml:"output"`
	Http       *HttpDef           `toml:"http"`
	Mcp        *McpProxyDef       `toml:"mcp"`
	Session    *SessionDef        `toml:"session"`
	Browser    *BrowserDef        `toml:"browser"`
	SourcePath string             `toml:"-"`
}

// ArgsSorted returns the argument definitions sorted by position.
func (m *Manifest) ArgsSorted() []*ArgDef {
	args := make([]*ArgDef, 0, len(m.Args))
	for _, a := range m.Args {
		args = append(args, a)
	}
	sort.Slice(args, func(i, j int) bool {
		return args[i].Position < args[j].Position
	})
	return args
}

// RequiredArgs returns only required arguments, sorted by position.
func (m *Manifest) RequiredArgs() []*ArgDef {
	var result []*ArgDef
	for _, a := range m.ArgsSorted() {
		if a.Required {
			result = append(result, a)
		}
	}
	return result
}

// LoadManifest parses a .clad.toml file and returns a Manifest.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m Manifest
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	if m.Tool.Name == "" {
		return nil, fmt.Errorf("manifest %s: missing required tool.name", path)
	}

	// Set default timeout if not specified.
	if m.Tool.TimeoutSeconds == 0 {
		m.Tool.TimeoutSeconds = 60
	}

	// Set default risk tier.
	if m.Tool.RiskTier == "" {
		m.Tool.RiskTier = "low"
	}

	// Set default dispatch mode.
	if m.Tool.Dispatch == "" {
		m.Tool.Dispatch = "exec"
	}
	if m.Tool.Dispatch != "exec" && m.Tool.Dispatch != "callback" {
		return nil, fmt.Errorf(
			"manifest %s: invalid dispatch '%s', must be 'exec' or 'callback'",
			path, m.Tool.Dispatch,
		)
	}

	// Populate arg names from map keys.
	for name, arg := range m.Args {
		arg.Name = name
		// Default type to string.
		if arg.Type == "" {
			arg.Type = "string"
		}
	}

	// Cross-section validation. Callback dispatch is for validator-only
	// embeddings; no backend or [output] block is required.
	if m.Tool.Dispatch != "callback" {
		hasBackend := m.Command.Template != "" ||
			len(m.Command.Exec) > 0 ||
			m.Command.Executor != "" ||
			m.Http != nil ||
			m.Mcp != nil ||
			m.Session != nil ||
			m.Browser != nil
		if !hasBackend {
			return nil, fmt.Errorf(
				"manifest %s: must define at least one execution backend: "+
					"[command] template/executor, [http], [mcp], [session], or [browser] "+
					"(or set tool.dispatch = \"callback\" for validator-only manifests)",
				path,
			)
		}
		if m.Output == nil {
			return nil, fmt.Errorf(
				"manifest %s: missing [output] block "+
					"(or set tool.dispatch = \"callback\" for validator-only manifests)",
				path,
			)
		}
	}

	m.SourcePath = path
	return &m, nil
}
