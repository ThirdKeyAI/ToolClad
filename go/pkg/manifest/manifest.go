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
	Cedar          *CedarDef    `toml:"cedar"`
	Evidence       *EvidenceDef `toml:"evidence"`
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
type CommandDef struct {
	Template     string                        `toml:"template"`
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

// Manifest is a fully parsed .clad.toml file.
type Manifest struct {
	Tool       ToolMeta           `toml:"tool"`
	Args       map[string]*ArgDef `toml:"args"`
	Command    CommandDef         `toml:"command"`
	Output     OutputDef          `toml:"output"`
	Http       *HttpDef           `toml:"http"`
	Mcp        *McpProxyDef       `toml:"mcp"`
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

	// Populate arg names from map keys.
	for name, arg := range m.Args {
		arg.Name = name
		// Default type to string.
		if arg.Type == "" {
			arg.Type = "string"
		}
	}

	m.SourcePath = path
	return &m, nil
}
