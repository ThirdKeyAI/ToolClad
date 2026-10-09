// Package manifest provides types and loading for .clad.toml ToolClad manifests.
package manifest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

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
	Name           string `toml:"name"`
	Version        string `toml:"version"`
	Binary         string `toml:"binary"`
	Description    string `toml:"description"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
	RiskTier       string `toml:"risk_tier"`
	HumanApproval  bool   `toml:"human_approval"`
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
	MinFloat   *float64 `toml:"min_float"`
	MaxFloat   *float64 `toml:"max_float"`
	Clamp      bool     `toml:"clamp"`
	Sanitize   []string `toml:"sanitize"`
	Schemes    []string `toml:"schemes"`
	ScopeCheck bool     `toml:"scope_check"`
	// AllowLeadingDash permits a value that starts with '-' or '+'. Off by
	// default so a user value can never be parsed as an option by the tool.
	AllowLeadingDash bool `toml:"allow_leading_dash"`
	// AllowWhitespace permits whitespace inside a value. Honored only when the
	// manifest declares `exec = [...]` directly, because only then is a value
	// guaranteed to stay a single argv element.
	AllowWhitespace bool `toml:"allow_whitespace"`
}

// ConditionalDef represents a conditional command fragment.
type ConditionalDef struct {
	When     string `toml:"when"`
	Template string `toml:"template"`
	// Tokens is Template tokenized at load. The tokens still contain
	// placeholders; they are substituted individually at build time.
	Tokens []string `toml:"-"`
}

// CommandDef holds the [command] section.
//
// `exec` (an argv array) is the canonical internal form. `template` is legacy
// sugar: at load it is tokenized into Exec with TokenizeTemplate and a
// deprecation warning is printed. When both are present, exec is used as-is.
type CommandDef struct {
	Template     string                       `toml:"template"`
	Exec         []string                     `toml:"exec"`
	Executor     string                       `toml:"executor"`
	Defaults     map[string]any               `toml:"defaults"`
	Mappings     map[string]map[string]string `toml:"mappings"`
	Conditionals map[string]ConditionalDef    `toml:"conditionals"`
	// EndOfOptions, when set to "--", inserts a literal "--" before the first
	// argv token produced from a user-argument placeholder.
	EndOfOptions string `toml:"end_of_options"`
	// ExecWasDeclared is true only when the manifest itself declared `exec`.
	// A template compiled into Exec leaves it false, which keeps the stricter
	// template-mode validation rules in force for that manifest.
	ExecWasDeclared bool `toml:"-"`
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

	compiled bool
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

// InjectedVars are the single-token variables the executor provides on every
// run, in addition to declared args and [command.defaults].
var InjectedVars = []string{"_scan_id", "_output_file", "_evidence_dir"}

// TemplateDeprecationWarning is printed once per load of a manifest that
// still uses [command] template.
const TemplateDeprecationWarning = "warning: [command] template is deprecated and will be removed in the next minor release; use exec = [...]"

// WarningOutput receives load-time warnings. Defaults to stderr.
var WarningOutput io.Writer = os.Stderr

// placeholderRe drives the single left-to-right substitution pass: `{{` and
// `}}` are escapes for literal braces and are never placeholders; `{name}` is
// a placeholder.
var placeholderRe = regexp.MustCompile(`\{\{|\}\}|\{(\w+)\}`)

// solePlaceholderRe matches a token that is exactly one placeholder.
var solePlaceholderRe = regexp.MustCompile(`^\{(\w+)\}$`)

// TokenizeTemplate splits a trusted manifest string into tokens with a
// POSIX-like splitter honoring single and double quotes and backslash
// escapes. A placeholder opening brace inside quotes is rejected because a
// quoted placeholder can never be made safe: placeholders must be whole,
// unquoted tokens. The `{{` escape is allowed inside quotes.
//
// This function must only ever run on manifest-controlled text. Substituted
// values are never re-split.
func TokenizeTemplate(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	started, inSingle, inDouble := false, false, false
	runes := []rune(s)
	flush := func() {
		tokens = append(tokens, cur.String())
		cur.Reset()
		started = false
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '\\' && !inSingle:
			if i+1 >= len(runes) {
				return nil, errors.New("trailing backslash in command template")
			}
			i++
			cur.WriteRune(runes[i])
			started = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			started = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			started = true
		case c == '{' && (inSingle || inDouble):
			if i+1 < len(runes) && runes[i+1] == '{' {
				// `{{` is the literal-brace escape; keep it for ExpandToken.
				cur.WriteString("{{")
				i++
				started = true
				continue
			}
			return nil, fmt.Errorf(
				"command template places a placeholder inside quotes at offset %d; "+
					"placeholders must be whole, unquoted tokens (use exec = [...])", i)
		case unicode.IsSpace(c) && !inSingle && !inDouble:
			if started {
				flush()
			}
		default:
			cur.WriteRune(c)
			started = true
		}
	}
	if inSingle || inDouble {
		return nil, errors.New("unbalanced quote in command template")
	}
	if started {
		flush()
	}
	return tokens, nil
}

// SolePlaceholder reports whether token is exactly `{name}` and returns name.
func SolePlaceholder(token string) (string, bool) {
	m := solePlaceholderRe.FindStringSubmatch(token)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Placeholders returns the placeholder names referenced by token, using the
// same single pass as ExpandToken so escaped braces are skipped.
func Placeholders(token string) []string {
	var names []string
	for _, m := range placeholderRe.FindAllStringSubmatch(token, -1) {
		if m[1] != "" {
			names = append(names, m[1])
		}
	}
	return names
}

// ExpandToken performs one left-to-right pass over token mapping `{{` to `{`,
// `}}` to `}`, and `{name}` to the value returned by resolve. The result is a
// single token and is never re-split. An unresolved name is an error.
func ExpandToken(token string, resolve func(name string) (string, bool)) (string, error) {
	var firstErr error
	out := placeholderRe.ReplaceAllStringFunc(token, func(match string) string {
		switch match {
		case "{{":
			return "{"
		case "}}":
			return "}"
		}
		name := match[1 : len(match)-1]
		v, ok := resolve(name)
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("unresolved placeholder '{%s}' in command", name)
			}
			return match
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// TrustedPlaceholders returns the names of the multi-token variables:
// `_<arg>_flags` for each mapping and `_<cond>` for each conditional. These
// may only ever appear as a whole token, never glued to literal text.
func (m *Manifest) TrustedPlaceholders() map[string]bool {
	trusted := make(map[string]bool)
	for argName := range m.Command.Mappings {
		trusted["_"+argName+"_flags"] = true
	}
	for cond := range m.Command.Conditionals {
		trusted["_"+cond] = true
	}
	return trusted
}

// KnownPlaceholders returns every placeholder name the manifest can resolve:
// declared args, [command.defaults] keys, `_<arg>_flags` for each mapping,
// `_<cond>` for each conditional, and the executor-injected variables.
func (m *Manifest) KnownPlaceholders() map[string]bool {
	known := make(map[string]bool)
	for name := range m.Args {
		known[name] = true
	}
	for k := range m.Command.Defaults {
		known[k] = true
	}
	for argName := range m.Command.Mappings {
		known["_"+argName+"_flags"] = true
	}
	for cond := range m.Command.Conditionals {
		known["_"+cond] = true
	}
	for _, v := range InjectedVars {
		known[v] = true
	}
	return known
}

// EnsureCompiled compiles the [command] section if LoadManifest has not
// already done so. It lets manifests constructed in memory go through the
// same tokenization and placeholder checks, without the deprecation warning.
func (m *Manifest) EnsureCompiled() error {
	if m.compiled {
		return nil
	}
	return m.compileCommand(false)
}

// compileCommand turns the [command] section into its canonical exec form:
// tokenizes a legacy template into Exec, tokenizes every conditional
// template, validates end_of_options, and checks that every placeholder
// names something the manifest can resolve.
func (m *Manifest) compileCommand(warn bool) error {
	c := &m.Command
	c.ExecWasDeclared = len(c.Exec) > 0
	if c.Template != "" && !c.ExecWasDeclared {
		tokens, err := TokenizeTemplate(c.Template)
		if err != nil {
			return fmt.Errorf("command.template: %w", err)
		}
		c.Exec = tokens
		if warn {
			fmt.Fprintln(WarningOutput, TemplateDeprecationWarning)
		}
	}

	condNames := make([]string, 0, len(c.Conditionals))
	for name := range c.Conditionals {
		condNames = append(condNames, name)
	}
	sort.Strings(condNames)
	for _, name := range condNames {
		cd := c.Conditionals[name]
		tokens, err := TokenizeTemplate(cd.Template)
		if err != nil {
			return fmt.Errorf("command.conditionals.%s.template: %w", name, err)
		}
		cd.Tokens = tokens
		c.Conditionals[name] = cd
	}

	if c.EndOfOptions != "" && c.EndOfOptions != "--" {
		return fmt.Errorf("command.end_of_options must be \"--\" if set, got %q", c.EndOfOptions)
	}

	// An enum mapping table must cover every allowed value; map a value to
	// "" to mean "no flags". This turns a missing case into a load failure
	// instead of a silently flag-less invocation.
	mapNames := make([]string, 0, len(c.Mappings))
	for argName := range c.Mappings {
		mapNames = append(mapNames, argName)
	}
	sort.Strings(mapNames)
	for _, argName := range mapNames {
		arg := m.Args[argName]
		if arg == nil || arg.Type != "enum" {
			continue
		}
		var missing []string
		for _, allowed := range arg.Allowed {
			if _, ok := c.Mappings[argName][allowed]; !ok {
				missing = append(missing, allowed)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf(
				"command.mappings.%s: no entry for enum value(s) %q (map a value to \"\" for no flags)",
				argName, missing)
		}
	}

	known := m.KnownPlaceholders()
	trusted := m.TrustedPlaceholders()
	check := func(where string, tokens []string) error {
		for _, tok := range tokens {
			_, whole := SolePlaceholder(tok)
			for _, name := range Placeholders(tok) {
				if !known[name] {
					return fmt.Errorf("%s: unresolved placeholder '{%s}' in command", where, name)
				}
				if trusted[name] && !whole {
					return fmt.Errorf(
						"%s: placeholder '{%s}' expands to multiple tokens and must be a whole token in command",
						where, name)
				}
			}
		}
		return nil
	}
	if err := check("command.exec", c.Exec); err != nil {
		return err
	}
	for _, name := range condNames {
		if err := check("command.conditionals."+name+".template", c.Conditionals[name].Tokens); err != nil {
			return err
		}
	}

	m.compiled = true
	return nil
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

	// Compile [command] into canonical exec form and check placeholders.
	if err := m.compileCommand(true); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}

	// Cross-section validation. Callback dispatch is for validator-only
	// embeddings; no backend or [output] block is required.
	if m.Tool.Dispatch != "callback" {
		hasBackend := len(m.Command.Exec) > 0 ||
			m.Command.Executor != "" ||
			m.Http != nil ||
			m.Mcp != nil ||
			m.Session != nil ||
			m.Browser != nil
		if !hasBackend {
			return nil, fmt.Errorf(
				"manifest %s: must define at least one execution backend: "+
					"[command] exec/executor, [http], [mcp], [session], or [browser] "+
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
