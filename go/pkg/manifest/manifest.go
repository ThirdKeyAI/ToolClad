// Package manifest provides types and loading for .clad.toml ToolClad manifests.
package manifest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/thirdkeyai/toolclad/pkg/scope"
)

// The manifest structs below ARE the key allowlist. Every key a .clad.toml
// may contain is a tagged field on one of them, and loading refuses any key
// without a field (see unknownKeys, which reads these tags by reflection).
// The tagged fields must match the "Complete key allowlist" in SEMANTICS.md
// section W2 exactly, section by section; add a key there before adding a
// field here. A map-typed field whose values are not structs ([command]
// defaults and mappings, [output] schema, [http] headers, [mcp] field_map)
// is an open map: its keys are the author's to choose and are not checked.

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
	// Screenshots requests screenshot capture for browser-mode tools.
	// Registered as a known key; capture itself is not implemented here.
	Screenshots bool `toml:"screenshots"`
}

// ToolLimitsDef holds the optional [tool.limits] resource ceilings for the
// child process. Nil means "no limit requested" for each field. Registered as
// known keys. The Go runtime cannot set resource limits on a child process
// portably (os/exec has no pre-exec hook), so these are not enforced here.
type ToolLimitsDef struct {
	Nproc             *int64 `toml:"nproc"`
	Nofile            *int64 `toml:"nofile"`
	FsizeBytes        *int64 `toml:"fsize_bytes"`
	AddressSpaceBytes *int64 `toml:"address_space_bytes"`
	CPUSeconds        *int64 `toml:"cpu_seconds"`
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
	Dispatch string `toml:"dispatch"`
	// Mode is advisory: "oneshot", "session", or "browser". When absent it
	// is derived at load from which backend section is present.
	Mode string `toml:"mode"`
	// NetworkEgress declares that the tool reaches a network destination
	// taken from its arguments. It makes the manifest an egress manifest
	// for LintEgress regardless of which binary the command names.
	NetworkEgress bool `toml:"network_egress"`
	// AllowInterpreter permits argv[0] to be a shell or language
	// interpreter (see InterpreterBasenames). Off by default: a load-time
	// check refuses an interpreter as argv[0] unless this is set.
	AllowInterpreter bool           `toml:"allow_interpreter"`
	Cedar            *CedarDef      `toml:"cedar"`
	Evidence         *EvidenceDef   `toml:"evidence"`
	Limits           *ToolLimitsDef `toml:"limits"`
}

// ToolModes are the accepted values of [tool] mode.
var ToolModes = []string{"oneshot", "session", "browser"}

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
	// BlockInternal rejects loopback, private, CGNAT, unspecified,
	// broadcast, documentation, benchmarking and reserved targets for the
	// network-typed arguments (scope_target, url, ip_address, cidr). The
	// link-local / cloud-metadata ranges are refused regardless of this
	// flag. The range table lives in validator/hostpolicy.go.
	BlockInternal bool `toml:"block_internal"`
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

// DefaultOutputMaxBytes is the [output] max_bytes value used when the
// manifest does not set one (8 MiB).
const DefaultOutputMaxBytes int64 = 8388608

// OutputDef holds the [output] section.
type OutputDef struct {
	Format   string         `toml:"format"`
	Parser   string         `toml:"parser"`
	Envelope *bool          `toml:"envelope"`
	Schema   map[string]any `toml:"schema"`
	// MaxBytes caps captured tool output. Nil means DefaultOutputMaxBytes;
	// use MaxBytesLimit. Registered as a known key; the cap is not enforced
	// here.
	MaxBytes *int64 `toml:"max_bytes"`
}

// EnvelopeEnabled returns whether the evidence envelope is enabled (default true).
func (o *OutputDef) EnvelopeEnabled() bool {
	if o.Envelope == nil {
		return true
	}
	return *o.Envelope
}

// MaxBytesLimit returns the output cap, defaulting to DefaultOutputMaxBytes.
func (o *OutputDef) MaxBytesLimit() int64 {
	if o.MaxBytes == nil {
		return DefaultOutputMaxBytes
	}
	return *o.MaxBytes
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
	ChildDetection     *SessionChildDetectionDef    `toml:"child_detection"`
}

// SessionChildDetectionDef describes how a session recognizes a child
// process it spawns and which manifest governs it. Registered as known keys;
// detection is not implemented here.
type SessionChildDetectionDef struct {
	Pattern  string `toml:"pattern"`
	Type     string `toml:"type"`
	Manifest string `toml:"manifest"`
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
	Defaults           *BrowserDefaultsDef          `toml:"defaults"`
}

// BrowserDefaultsDef holds per-command defaults for browser mode.
type BrowserDefaultsDef struct {
	ExtractMode string `toml:"extract_mode"`
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
	// Scope is the project scope consulted by arguments that set
	// scope_check = true. LoadManifest discovers it once (see EnsureScope)
	// when any argument needs it; an embedder may set it directly. Nil
	// with scope_check set is a fail-closed refusal at validation.
	Scope *scope.ScopeDef `toml:"-"`

	compiled      bool
	scopeResolved bool
}

// scopeCheckTypes are the argument types on which scope_check is honored.
var scopeCheckTypes = map[string]bool{
	"scope_target": true,
	"url":          true,
	"ip_address":   true,
	"cidr":         true,
}

// builtinTypes are the built-in argument types. Any other type name is a
// custom type from toolclad.toml, resolved by the validator package.
var builtinTypes = map[string]bool{
	"string": true, "integer": true, "number": true, "port": true,
	"boolean": true, "enum": true, "scope_target": true, "url": true,
	"path": true, "ip_address": true, "cidr": true, "msf_options": true,
	"credential_file": true, "duration": true, "regex_match": true,
}

// ScopeCheckSupported reports whether scope_check is honored on the
// built-in type t (scope_target, url, ip_address, cidr).
func ScopeCheckSupported(t string) bool {
	return scopeCheckTypes[t]
}

// UsesScopeCheck reports whether any argument sets scope_check = true.
func (m *Manifest) UsesScopeCheck() bool {
	for _, def := range m.allArgDefs() {
		if def.ScopeCheck {
			return true
		}
	}
	return false
}

// EnsureScope discovers the scope file once per manifest when an argument
// sets scope_check and Scope was not set by the caller: TOOLCLAD_SCOPE_FILE,
// else scope/scope.toml searched upward from the manifest's directory (the
// working directory for a manifest built in memory). Not finding a file is
// not an error here; validation then refuses fail-closed. A scope file that
// exists but cannot be read or parsed is an error.
func (m *Manifest) EnsureScope() error {
	if m.Scope != nil || m.scopeResolved || !m.UsesScopeCheck() {
		return nil
	}
	dir := ""
	if m.SourcePath != "" {
		dir = filepath.Dir(m.SourcePath)
	}
	s, err := scope.Discover(dir)
	if err != nil {
		return err
	}
	m.Scope = s
	m.scopeResolved = true
	return nil
}

// checkArgDefs applies the per-argument load-time rules: scope_check only
// on a type that supports it, and every declared default valid for its own
// argument (through DefaultValidator, when one is registered).
func (m *Manifest) checkArgDefs() error {
	all := m.allArgDefs()
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		def := all[name]
		t := def.Type
		if t == "" {
			t = "string"
		}
		// A custom type is checked by its base type once custom types are
		// loaded (validator.ValidateManifestWithCustomTypes).
		if def.ScopeCheck && builtinTypes[t] && !scopeCheckTypes[t] {
			return fmt.Errorf("argument '%s': scope_check is not supported for type '%s'", name, t)
		}
	}
	if DefaultValidator == nil {
		return nil
	}
	for _, name := range names {
		def := all[name]
		if def.Default == nil {
			continue
		}
		val := fmt.Sprintf("%v", def.Default)
		if val == "" && (def.Type == "string" || def.Type == "") {
			continue // an empty string default is always acceptable
		}
		if err := DefaultValidator(def, val, m.Scope); err != nil {
			return fmt.Errorf("argument '%s': invalid default %q: %w", name, val, err)
		}
	}
	return nil
}

// DefaultValidator validates a declared per-argument default at load. The
// validator package registers its strict entry point here on import (this
// package cannot import it without a cycle). Arguments of a type it does not
// know (custom types) must be accepted; they are checked once custom types
// are available. Nil disables the check.
var DefaultValidator func(def *ArgDef, value string, s *scope.ScopeDef) error

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
	if err := m.compileCommand(false); err != nil {
		return err
	}
	if err := m.LintEgress(nil); err != nil {
		return err
	}
	if err := m.EnsureScope(); err != nil {
		return err
	}
	if err := m.checkArgDefs(); err != nil {
		return err
	}
	if err := m.CheckSpawnPolicy(); err != nil {
		return err
	}
	m.compiled = true
	return nil
}

// InterpreterBasenames are the argv[0] basenames refused at load unless
// [tool] allow_interpreter = true: a shell or language interpreter turns a
// validated argument into code. The list is shared verbatim across the
// ToolClad runtimes; extend it in all of them or in none.
var InterpreterBasenames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true,
	"env": true, "eval": true, "xargs": true, "python": true, "python2": true,
	"python3": true, "perl": true, "ruby": true, "node": true, "deno": true,
	"bun": true, "lua": true, "php": true, "awk": true,
}

// CheckSpawnPolicy runs the load-time checks on the command the runtime
// will spawn:
//
//   - timeout_seconds may not be negative (zero is refused at load, where
//     an explicit value can be told apart from an absent one);
//   - argv[0] may not be an interpreter unless allow_interpreter is set;
//   - for the exec/template form with a non-empty tool.binary, the basename
//     of argv[0] must equal the basename of tool.binary.
//
// Callback-dispatch manifests never spawn anything and are skipped, and so
// are [http]/[mcp]/[session]/[browser] manifests without a [command].
func (m *Manifest) CheckSpawnPolicy() error {
	if m.Tool.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds must be greater than zero")
	}
	if m.Tool.Dispatch == "callback" {
		return nil
	}
	var argv0 string
	execForm := false
	switch {
	case m.Command.Executor != "":
		argv0 = m.Command.Executor
	case len(m.Command.Exec) > 0:
		argv0 = m.Command.Exec[0]
		execForm = true
	default:
		return nil
	}
	if !m.Tool.AllowInterpreter && InterpreterBasenames[commandBasename(argv0)] {
		return fmt.Errorf("command argv[0] '%s' is an interpreter; set allow_interpreter = true to permit it", argv0)
	}
	if execForm && m.Tool.Binary != "" && commandBasename(argv0) != commandBasename(m.Tool.Binary) {
		return fmt.Errorf("command argv[0] '%s' does not match tool.binary '%s'", argv0, m.Tool.Binary)
	}
	return nil
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
	return nil
}

// egressBinaries are the basenames of tools that connect to a network
// destination derived from their arguments — the ones for which an
// unconstrained network-typed argument is an SSRF surface. The list is
// shared verbatim across the ToolClad runtimes; extend it in all of them or
// in none.
var egressBinaries = map[string]bool{
	"curl":    true,
	"wget":    true,
	"nmap":    true,
	"nc":      true,
	"ncat":    true,
	"netcat":  true,
	"masscan": true,
	"telnet":  true,
	"ssh":     true,
	"ping":    true,
	"fping":   true,
	"httpie":  true,
	"http":    true,
	"wfuzz":   true,
	"ffuf":    true,
	"hydra":   true,
	"nikto":   true,
}

// networkTargetTypes are the argument types that name a network
// destination and therefore carry block_internal.
var networkTargetTypes = map[string]bool{
	"scope_target": true,
	"url":          true,
	"ip_address":   true,
	"cidr":         true,
}

// commandBasename returns the lower-cased final path element of a command
// token, so /usr/bin/curl, ./curl and CURL all compare as curl.
func commandBasename(s string) string {
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

// IsNetworkEgress reports whether the manifest is an egress manifest: it
// declares network_egress = true, dispatches through [http] or [browser],
// or names a known egress binary in tool.binary, exec[0] or the first token
// of the legacy template.
//
// An executor-only manifest runs a script this check cannot see into, so it
// is an egress manifest only through network_egress = true, [http] or
// [browser]. That escape hatch is the author's responsibility: a wrapper
// around curl must declare network_egress = true itself.
func (m *Manifest) IsNetworkEgress() bool {
	if m.Tool.NetworkEgress || m.Http != nil || m.Browser != nil {
		return true
	}
	var names []string
	if m.Tool.Binary != "" {
		names = append(names, commandBasename(m.Tool.Binary))
	}
	if len(m.Command.Exec) > 0 {
		names = append(names, commandBasename(m.Command.Exec[0]))
	}
	if first := strings.Fields(m.Command.Template); len(first) > 0 {
		names = append(names, commandBasename(first[0]))
	}
	for _, n := range names {
		if egressBinaries[n] {
			return true
		}
	}
	return false
}

// LintEgress is the egress safety lint: a tool that connects to a network
// target must default-deny internal / SSRF addresses. For an egress
// manifest (IsNetworkEgress) every argument of a network target type must
// set block_internal = true, and an argument of a custom type whose base is
// a network target type is refused outright, because a custom type cannot
// carry block_internal. customTypes may be nil when the caller has none
// loaded; the built-in checks still run. Arguments are visited in name
// order so the reported failure is stable.
func (m *Manifest) LintEgress(customTypes map[string]*CustomTypeDef) error {
	if !m.IsNetworkEgress() {
		return nil
	}
	all := m.allArgDefs()
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		def := all[name]
		if networkTargetTypes[def.Type] {
			if !def.BlockInternal {
				return fmt.Errorf(
					"argument '%s' is a network target for an egress binary but block_internal is not set; "+
						"set block_internal = true to default-deny internal/SSRF targets", name)
			}
			continue
		}
		if ct, ok := customTypes[def.Type]; ok && networkTargetTypes[ct.Base] {
			return fmt.Errorf(
				"argument '%s' uses custom type '%s' as a network target; "+
					"custom types cannot carry block_internal — use the built-in %s type",
				name, def.Type, ct.Base)
		}
	}
	return nil
}

// allArgDefs returns every argument definition the manifest declares, keyed by
// name: top-level [args] by their own name, and the arguments of each
// [session.commands.<c>] and [browser.commands.<c>] by their key path. A
// [browser] manifest's real network targets live under its commands, so a
// lint that only looked at top-level [args] would be hollow for it.
func (m *Manifest) allArgDefs() map[string]*ArgDef {
	out := make(map[string]*ArgDef, len(m.Args))
	for name, def := range m.Args {
		out[name] = def
	}
	if m.Session != nil {
		for cname, cmd := range m.Session.Commands {
			for aname, def := range cmd.Args {
				out["session.commands."+cname+".args."+aname] = def
			}
		}
	}
	if m.Browser != nil {
		for cname, cmd := range m.Browser.Commands {
			for aname, def := range cmd.Args {
				out["browser.commands."+cname+".args."+aname] = def
			}
		}
	}
	return out
}

// unknownKeys walks the raw document against the Manifest struct type and
// returns the dotted path of every key that no tagged field accepts, sorted.
// Matching is exact (case-sensitive). A wholly unknown table is reported once,
// by its own path, rather than once per entry beneath it. Nothing beneath an
// open map is checked.
//
// The walk is deliberately independent of toml.MetaData.Undecoded(): in the
// pinned decoder release that list is built from aliased key slices and drops
// or repeats entries for any table header with three or more segments, such
// as [command.conditionals.<n>] or [session.commands.<n>].
func unknownKeys(doc map[string]any) []string {
	var out []string
	walkUnknownKeys(reflect.TypeOf(Manifest{}), doc, nil, &out)
	sort.Strings(out)
	return out
}

// walkUnknownKeys checks table against struct type t at path, appending the
// path of each key t has no field for. It descends into struct-typed fields
// and into map-typed fields whose values are structs (the [args.*],
// [command.conditionals.*], [session.commands.*] and [browser.commands.*]
// families). A map whose values are not structs is an open map: its keys are
// the author's to choose and its contents are not checked.
func walkUnknownKeys(t reflect.Type, table map[string]any, path toml.Key, out *[]string) {
	fields := tomlFields(t)
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// Three-index slicing forces a copy so sibling paths never share a
		// backing array.
		kpath := append(path[:len(path):len(path)], k)
		ft, known := fields[k]
		if !known {
			*out = append(*out, kpath.String())
			continue
		}
		sub, isTable := table[k].(map[string]any)
		if !isTable {
			continue
		}
		switch elem := derefType(ft); elem.Kind() {
		case reflect.Struct:
			walkUnknownKeys(elem, sub, kpath, out)
		case reflect.Map:
			vt := derefType(elem.Elem())
			if vt.Kind() != reflect.Struct {
				continue // open map
			}
			names := make([]string, 0, len(sub))
			for name := range sub {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if vsub, ok := sub[name].(map[string]any); ok {
					walkUnknownKeys(vt, vsub, append(kpath[:len(kpath):len(kpath)], name), out)
				}
			}
		}
	}
}

// tomlFields returns the TOML key each exported, non-skipped field of struct
// type t decodes from, mapped to the field's type.
func tomlFields(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported: the decoder never fills it
		}
		name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
}

// derefType strips pointer indirections from a type.
func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// LoadOptions controls how LoadManifestWithOptions treats a manifest. The
// zero value is the strict behavior of LoadManifest.
type LoadOptions struct {
	// AllowUnknownKeys downgrades unknown manifest keys from a load error to
	// a `warning: unknown key '…' in manifest` line on WarningOutput. It
	// exists for the CLI's `validate --allow-unknown-keys`; library callers
	// should load strictly.
	AllowUnknownKeys bool
}

// LoadManifest parses a .clad.toml file and returns a Manifest. Loading is
// strict: a key the manifest schema does not know is a load error.
func LoadManifest(path string) (*Manifest, error) {
	return LoadManifestWithOptions(path, LoadOptions{})
}

// LoadManifestWithOptions parses a .clad.toml file with explicit LoadOptions.
func LoadManifestWithOptions(path string, opts LoadOptions) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m Manifest
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	// Refuse keys the schema does not know. A misspelled key would otherwise
	// silently disable the control it was meant to set. The document is
	// re-read as a raw table so the check sees every key the author wrote.
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if unknown := unknownKeys(raw); len(unknown) > 0 {
		msgs := make([]string, len(unknown))
		for i, k := range unknown {
			msgs[i] = fmt.Sprintf("unknown key '%s' in manifest", k)
		}
		if !opts.AllowUnknownKeys {
			return nil, fmt.Errorf("manifest %s: %s", path, strings.Join(msgs, "; "))
		}
		for _, msg := range msgs {
			fmt.Fprintf(WarningOutput, "warning: %s\n", msg)
		}
	}

	if m.Tool.Name == "" {
		return nil, fmt.Errorf("manifest %s: missing required tool.name", path)
	}

	// tool.mode is advisory: validate it when set, derive it when absent.
	switch m.Tool.Mode {
	case "":
		switch {
		case m.Session != nil:
			m.Tool.Mode = "session"
		case m.Browser != nil:
			m.Tool.Mode = "browser"
		default:
			m.Tool.Mode = "oneshot"
		}
	case "oneshot", "session", "browser":
	default:
		return nil, fmt.Errorf(
			"manifest %s: invalid tool.mode '%s', must be one of %s",
			path, m.Tool.Mode, strings.Join(ToolModes, ", "),
		)
	}

	// An explicit timeout_seconds must be positive: zero used to disable
	// the timeout entirely in one runtime. Only an absent key defaults.
	if tool, ok := raw["tool"].(map[string]any); ok {
		if _, set := tool["timeout_seconds"]; set && m.Tool.TimeoutSeconds <= 0 {
			return nil, fmt.Errorf("manifest %s: timeout_seconds must be greater than zero", path)
		}
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
	m.compiled = true

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

	// Egress safety lint (built-in types; the CLI re-runs it with custom
	// types through validator.ValidateManifestWithCustomTypes once it loads
	// toolclad.toml).
	if err := m.LintEgress(nil); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}

	m.SourcePath = path
	if err := m.EnsureScope(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	if err := m.checkArgDefs(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	if err := m.CheckSpawnPolicy(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return &m, nil
}
