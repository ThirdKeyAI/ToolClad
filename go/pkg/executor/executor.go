// Package executor provides command construction and execution for ToolClad manifests.
package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

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
	// Truncated is set when stdout, stderr or an HTTP response body
	// exceeded [output] max_bytes and capture stopped at the cap.
	Truncated bool `json:"output_truncated,omitempty"`
}

// newScanID returns a scan identifier for one invocation:
// <unix_seconds>-<32 hex chars>, the random part being 128 bits from
// crypto/rand so an id (and the evidence paths derived from it) cannot be
// predicted.
func newScanID(start time.Time) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms; refuse to fall
		// back to a predictable id if it ever does.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return fmt.Sprintf("%d-%s", start.Unix(), hex.EncodeToString(b[:]))
}

// evidenceDir returns the evidence root: TOOLCLAD_EVIDENCE_DIR or
// <tmpdir>/toolclad-evidence.
func evidenceDir() string {
	if dir := os.Getenv("TOOLCLAD_EVIDENCE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(os.TempDir(), "toolclad-evidence")
}

// outputDir returns the per-invocation output directory: [tool.evidence]
// output_dir formatted with {evidence_dir} and {scan_id} when set, else
// <evidence_dir>/<scan_id>-<tool_name>.
func outputDir(m *manifest.Manifest, evDir, scanID string) string {
	if m.Tool.Evidence != nil && m.Tool.Evidence.OutputDir != "" {
		r := strings.NewReplacer("{evidence_dir}", evDir, "{scan_id}", scanID)
		return r.Replace(m.Tool.Evidence.OutputDir)
	}
	return filepath.Join(evDir, scanID+"-"+m.Tool.Name)
}

// outputFile returns <output dir>/scan.<ext>, ext following output.format.
func outputFile(m *manifest.Manifest, outDir string) string {
	ext := "txt"
	if m.Output != nil {
		switch m.Output.Format {
		case "xml", "json", "csv", "jsonl":
			ext = m.Output.Format
		}
	}
	return filepath.Join(outDir, "scan."+ext)
}

// ensurePrivateDir creates dir (and parents) and sets it to mode 0700. A
// symlink in its place is refused so a pre-planted link in a shared temp
// directory cannot redirect evidence.
func ensurePrivateDir(dir string) error {
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use evidence directory '%s': it is a symlink", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating evidence directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("securing evidence directory: %w", err)
	}
	return nil
}

// writeEvidenceFile creates path and writes data to it. The file is opened
// with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0600, so an existing file or a
// pre-planted symlink at path makes the write fail instead of being
// followed or overwritten.
func writeEvidenceFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fixedPath is the PATH every child receives and the only PATH argv[0] is
// resolved against. The runtime's own PATH is never inherited: an inherited
// PATH is how a renamed binary earlier in the search order wins.
const fixedPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// passthroughEnv are the only parent variables copied to a child, and only
// when set.
var passthroughEnv = []string{"HOME", "LANG", "LC_ALL", "TZ", "TERM"}

// childEnv builds the child environment from the allowlist: the fixed PATH
// plus HOME, LANG, LC_ALL, TZ and TERM when set, plus extra. Nothing else
// from the runtime's environment reaches the child; in particular the
// runtime's secrets (TOOLCLAD_SECRET_*) are filtered out even if a future
// edit puts one into extra. The result is never nil: a nil cmd.Env would
// inherit the whole parent environment.
func childEnv(extra []string) []string {
	env := []string{"PATH=" + fixedPath}
	for _, k := range passthroughEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for _, kv := range extra {
		if strings.HasPrefix(kv, "TOOLCLAD_SECRET_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// resolveArgv0 returns the absolute path the runtime will execute. A name
// without a path separator is looked up in fixedPath only; a name with one
// is used as given, made absolute against the runtime's working directory
// (the child runs in a scratch directory, where a relative path would
// otherwise resolve differently).
func resolveArgv0(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return filepath.Abs(name)
	}
	for _, dir := range filepath.SplitList(fixedPath) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("cannot resolve command '%s' in PATH %s", name, fixedPath)
}

// defaultKillGrace is the SIGTERM-to-SIGKILL interval when
// TOOLCLAD_KILL_GRACE_MS is unset or invalid.
const defaultKillGrace = 2000 * time.Millisecond

// killGrace returns TOOLCLAD_KILL_GRACE_MS as a duration. Anything other
// than a non-negative integer yields the 2000 ms default.
func killGrace() time.Duration {
	v := os.Getenv("TOOLCLAD_KILL_GRACE_MS")
	if v == "" {
		return defaultKillGrace
	}
	ms, err := strconv.ParseInt(v, 10, 64)
	if err != nil || ms < 0 {
		return defaultKillGrace
	}
	return time.Duration(ms) * time.Millisecond
}

// minWaitDelay bounds how long Run waits for the output pipes after the
// child exits or is signaled, even with a zero grace period: a WaitDelay of
// zero would mean "wait for the pipes forever".
const minWaitDelay = 100 * time.Millisecond

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
	// allow_whitespace is honored only for a manifest that declared exec
	// itself; the executor escape hatch always validates in strict mode.
	execMode := m.Command.ExecWasDeclared && m.Command.Executor == ""
	cleaned, err := validateArgs(m, args, execMode)
	if err != nil {
		return nil, nil, err
	}
	vars := make(map[string]string, len(m.Args))
	for name := range m.Args {
		// An unset optional resolves to the empty string so a whole-token
		// placeholder for it disappears from argv.
		vars[name] = cleaned[name]
	}

	for k, v := range m.Command.Defaults {
		if _, exists := vars[k]; !exists {
			vars[k] = fmt.Sprintf("%v", v)
		}
	}

	evDir := evidenceDir()
	vars["_scan_id"] = scanID
	vars["_evidence_dir"] = evDir
	vars["_output_file"] = outputFile(m, outputDir(m, evDir, scanID))

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

// validateArgs is the one argument-validation routine every backend
// calls: it refuses undeclared names, loads the manifest's scope, refuses a
// missing required argument, applies declared defaults and validates every
// supplied or defaulted value through validator.ValidateArgWithCustomTypesIn
// with the manifest's custom types. The result
// holds exactly those values; an unset optional without a default is
// absent. execMode is true only for a manifest that declared exec itself.
func validateArgs(m *manifest.Manifest, args map[string]string, execMode bool) (map[string]string, error) {
	if err := checkDeclaredArgs(m, args); err != nil {
		return nil, err
	}
	if err := m.EnsureScope(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(m.Args))
	for name := range m.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	cleaned := make(map[string]string, len(names))
	for _, name := range names {
		argDef := m.Args[name]
		val, provided := args[name]
		if !provided {
			if argDef.Required {
				return nil, fmt.Errorf("missing required argument: %q", name)
			}
			if argDef.Default == nil {
				continue
			}
			val = fmt.Sprintf("%v", argDef.Default)
		}
		validated, err := validator.ValidateArgWithCustomTypesIn(argDef, val, m.CustomTypes, execMode, m.Scope)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", name, err)
		}
		cleaned[name] = validated
	}
	return cleaned, nil
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

// Execute validates arguments, consults DefaultGate, builds the command,
// executes it with a timeout, captures output, and returns an
// EvidenceEnvelope. It is ExecuteWithGate(m, args, DefaultGate): a manifest
// with human_approval = true or a high/critical risk_tier is denied; use
// ExecuteWithGate with ApproveGate (or a gate of your own) to run it.
func Execute(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	return ExecuteWithGate(m, args, DefaultGate)
}

// ExecuteWithGate is Execute with an explicit policy gate (nil means
// DefaultGate). The gate is consulted after validation and before anything
// runs on every backend; a denial returns a *GateDeniedError and no
// envelope.
func ExecuteWithGate(m *manifest.Manifest, args map[string]string, gate Gate) (*EvidenceEnvelope, error) {
	// Route to HTTP backend
	if m.Http != nil {
		return executeHTTP(m, args, gate)
	}
	// Route to MCP proxy backend
	if m.Mcp != nil {
		return executeMCP(m, args, gate)
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
	errEnvelope := func(err error) (*EvidenceEnvelope, error) {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Timestamp: start.UTC().Format(time.RFC3339),
			ExitCode:  -1,
			Error:     err.Error(),
		}, err
	}

	cmdArgs, vars, err := build(m, args, scanID)
	if err != nil {
		return errEnvelope(err)
	}
	// build compiled the manifest, which ran the load-time spawn checks for
	// a manifest constructed in memory; a loaded one ran them at load.

	// The gate sees the validated values and decides before anything is
	// created or spawned. A denial is not an execution, so no envelope.
	if err := consultGate(gate, m, gateView(m, args, vars)); err != nil {
		return nil, err
	}
	cmdStr := declaredCommand(m)

	timeoutSecs := m.Tool.TimeoutSeconds
	if timeoutSecs == 0 {
		// Only a manifest built in memory can get here with zero; a loaded
		// one either had the key absent (defaulted to 60) or was refused.
		timeoutSecs = 60
	}

	binPath, err := resolveArgv0(cmdArgs[0])
	if err != nil {
		return errEnvelope(err)
	}

	// Evidence root, output directory and per-invocation scratch directory,
	// all mode 0700, created before the spawn so a tool that writes to
	// {_output_file} finds its directory.
	evDir := evidenceDir()
	outDir := outputDir(m, evDir, scanID)
	workDir := filepath.Join(evDir, scanID+"-work")
	for _, d := range []string{evDir, outDir, workDir} {
		if err := ensurePrivateDir(d); err != nil {
			return errEnvelope(err)
		}
	}
	// The scratch directory is removed only when empty: anything a tool
	// wrote there is evidence. os.Remove refuses a non-empty directory.
	defer os.Remove(workDir)

	var extraEnv []string
	if m.Command.Executor != "" {
		// The executor escape hatch receives the validated arguments and
		// the invocation metadata as environment variables.
		names := make([]string, 0, len(m.Args))
		for name := range m.Args {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			extraEnv = append(extraEnv, "TOOLCLAD_ARG_"+strings.ToUpper(name)+"="+vars[name])
		}
		extraEnv = append(extraEnv,
			"TOOLCLAD_SCAN_ID="+scanID,
			"TOOLCLAD_TOOL_NAME="+m.Tool.Name,
			"TOOLCLAD_EVIDENCE_DIR="+evDir,
			"TOOLCLAD_OUTPUT_DIR="+outDir,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, cmdArgs[1:]...)
	cmd.Args[0] = cmdArgs[0]
	// Never nil: a nil Env would inherit the runtime's whole environment.
	cmd.Env = childEnv(extraEnv)
	// A nil Stdin connects the child to /dev/null, so a tool can neither
	// read the operator's terminal nor consume a pipe the runtime owns.
	cmd.Stdin = nil
	cmd.Dir = workDir
	// New process group so the whole group can be signaled on timeout.
	// umask and resource limits (RLIMIT_CORE, RLIMIT_NPROC, ...) cannot be
	// set for the child portably from Go: os/exec has no pre-exec hook, and
	// changing them in the runtime would affect every goroutine. They are
	// deliberately not applied here rather than faked.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Kill sequence on deadline: SIGTERM to the process group, then SIGKILL
	// to the group after the grace period. WaitDelay bounds how long Run
	// waits for the output pipes independently of the process, so a
	// descendant that keeps stdout open cannot hang Run; after it elapses
	// Go closes the pipes and kills the direct child.
	//
	// A child that calls setsid() leaves the group and escapes this in
	// every language, so this is cleanup rather than containment;
	// escape-proof cleanup needs a cgroup, which is out of scope.
	grace := killGrace()
	// Set only by Cancel, which runs before Run returns.
	var killTimer *time.Timer
	cmd.Cancel = func() error {
		pid := cmd.Process.Pid
		killTimer = time.AfterFunc(grace, func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
		if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	cmd.WaitDelay = max(grace, minWaitDelay)

	// Each stream is capped at max_bytes; past the cap the writer keeps
	// accepting (and discarding) so the pipe drains and the child never
	// blocks on a full pipe.
	limit := outputLimit(m)
	stdoutBuf := &cappedBuffer{limit: limit}
	stderrBuf := &cappedBuffer{limit: limit}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	execErr := cmd.Run()
	duration := time.Since(start)
	timedOut := ctx.Err() != nil && execErr != nil

	// Take the rest of the group: on a timeout, and when the direct child
	// exited but a descendant kept the output pipes open past WaitDelay.
	if cmd.Process != nil && (timedOut || errors.Is(execErr, exec.ErrWaitDelay)) {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if killTimer != nil {
		killTimer.Stop()
	}

	stdoutBytes := stdoutBuf.buf.Bytes()
	stderrStr := stderrBuf.buf.String()
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
		Truncated:  stdoutBuf.truncated || stderrBuf.truncated,
	}

	if timedOut {
		err := fmt.Errorf("tool timed out after %d seconds", timeoutSecs)
		envelope.Status = "timeout"
		envelope.ExitCode = -1
		envelope.Error = err.Error()
		envelope.Results = map[string]any{"raw_output": string(stdoutBytes)}
		return envelope, err
	}
	if errors.Is(execErr, exec.ErrWaitDelay) && cmd.ProcessState != nil {
		// The tool itself exited; only a leftover descendant held the
		// pipes, and it has been killed. Judge the run by the exit status.
		execErr = nil
		if !cmd.ProcessState.Success() {
			execErr = &exec.ExitError{ProcessState: cmd.ProcessState}
		}
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

	// [tool.evidence] capture = true keeps stdout at {_output_file}, unless
	// the tool wrote that file itself. The write never follows a symlink
	// and never overwrites an existing file.
	if m.Tool.Evidence != nil && m.Tool.Evidence.Capture {
		if err := captureOutput(outputFile(m, outDir), stdoutBytes); err != nil {
			envelope.Status = "error"
			envelope.Error = err.Error()
			envelope.Results = map[string]any{"raw_output": string(stdoutBytes)}
			return envelope, err
		}
	}

	applyResults(envelope, m, stdoutBytes)
	return envelope, nil
}

// gateView returns the validated values a gate sees: every declared
// argument that was supplied or has a default, as validateArgs produced it.
func gateView(m *manifest.Manifest, args map[string]string, vars map[string]string) map[string]string {
	out := make(map[string]string, len(m.Args))
	for name, def := range m.Args {
		if _, ok := args[name]; ok || def.Default != nil {
			out[name] = vars[name]
		}
	}
	return out
}

// declaredCommand is the envelope's command on the oneshot path: the exec
// array as written in the manifest joined by single spaces, or the legacy
// template string itself, with placeholders intact. Executor-injected paths
// and secrets therefore never reach the agent or the evidence; the dry run
// (BuildCommand) keeps the resolved argv.
func declaredCommand(m *manifest.Manifest) string {
	if m.Command.Executor != "" {
		return m.Command.Executor + " (custom executor)"
	}
	if !m.Command.ExecWasDeclared && m.Command.Template != "" {
		return m.Command.Template
	}
	return strings.Join(m.Command.Exec, " ")
}

// outputLimit returns [output] max_bytes, defaulting to 8 MiB.
func outputLimit(m *manifest.Manifest) int64 {
	if m.Output == nil {
		return manifest.DefaultOutputMaxBytes
	}
	if n := m.Output.MaxBytesLimit(); n > 0 {
		return n
	}
	return manifest.DefaultOutputMaxBytes
}

// cappedBuffer keeps the first limit bytes written to it and discards the
// rest, recording that it did. Write always reports the full length so the
// copy goroutine keeps draining the pipe.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - int64(c.buf.Len())
	if room <= 0 {
		if len(p) > 0 {
			c.truncated = true
		}
		return len(p), nil
	}
	if int64(len(p)) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

// applyResults parses raw according to [output] format and validates the
// result against [output.schema] (default {"type": "object"}), failing
// closed: a parse failure sets status parse_error and a schema failure sets
// status schema_error, each with the raw output preserved. On success the
// envelope's status is left as it is.
func applyResults(env *EvidenceEnvelope, m *manifest.Manifest, raw []byte) {
	format := "text"
	var schema any = map[string]any{"type": "object"}
	if m.Output != nil {
		format = m.Output.Format
		if len(m.Output.Schema) > 0 {
			schema = m.Output.Schema
		}
	}
	results, err := parseOutput(format, raw)
	if err != nil {
		env.Status = "parse_error"
		env.Error = err.Error()
		env.Results = map[string]any{"parse_error": err.Error(), "raw_output": string(raw)}
		return
	}
	if err := ValidateSchema(schema, results); err != nil {
		env.Status = "schema_error"
		env.Error = err.Error()
		env.Results = map[string]any{"schema_error": err.Error(), "raw_output": string(raw)}
		return
	}
	env.Results = results
}

// captureOutput writes captured stdout to path. When a regular file is
// already there the tool produced it, and it is kept as is; a symlink (or
// anything else) is refused.
func captureOutput(path string, data []byte) error {
	err := writeEvidenceFile(path, data)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode().IsRegular() {
			return nil
		}
	}
	return fmt.Errorf("refusing to write evidence file '%s': %w", path, err)
}

// parseOutput converts raw command output based on the declared format.
// The result is always an object: jsonl and csv as {"parsed_output": [...]},
// text as {"raw_output": "..."}, a JSON object as itself and any other JSON
// value as {"parsed_output": value}. JSON numbers are kept exact
// (json.Number).
func parseOutput(format string, data []byte) (map[string]any, error) {
	switch format {
	case "json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("parsing JSON output: %w", err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, fmt.Errorf("parsing JSON output: trailing data after the JSON value")
		}
		if obj, ok := v.(map[string]any); ok {
			return obj, nil
		}
		return map[string]any{"parsed_output": v}, nil

	case "jsonl":
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		parsed := []any{}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			dec := json.NewDecoder(strings.NewReader(line))
			dec.UseNumber()
			var obj any
			if err := dec.Decode(&obj); err != nil {
				return nil, fmt.Errorf("parsing JSONL line: %w", err)
			}
			if _, err := dec.Token(); err != io.EOF {
				return nil, fmt.Errorf("parsing JSONL line: trailing data after the JSON value")
			}
			parsed = append(parsed, obj)
		}
		return map[string]any{"parsed_output": parsed}, nil

	case "csv":
		return parseCsvOutput(data), nil

	case "xml":
		if xmlHasDeclarations(data) {
			return nil, errors.New("XML output contains a DOCTYPE or ENTITY declaration; refusing to parse")
		}
		return parseXmlOutput(data), nil

	default:
		return map[string]any{"raw_output": string(data)}, nil
	}
}

// xmlHasDeclarations reports whether XML output carries a DOCTYPE or ENTITY
// declaration anywhere (case-insensitive). Such output is refused before
// parsing rather than given to any entity-aware parser.
func xmlHasDeclarations(data []byte) bool {
	lower := bytes.ToLower(data)
	return bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity"))
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

// secretSource resolves {_secret:name} values for one call. The file named
// by TOOLCLAD_SECRETS_FILE is read at most once per source, on first use.
type secretSource struct {
	loaded bool
	file   map[string]string
	err    error
}

// loadSecretsFile reads TOOLCLAD_SECRETS_FILE: a TOML file of top-level
// name = "value" pairs. It is refused when group or others can read it,
// which is what makes it better than an environment variable. An unset
// variable yields no file secrets.
func loadSecretsFile() (map[string]string, error) {
	path := os.Getenv("TOOLCLAD_SECRETS_FILE")
	if path == "" {
		return nil, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("TOOLCLAD_SECRETS_FILE '%s': %w", path, err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf(
			"TOOLCLAD_SECRETS_FILE '%s' is readable by group or others (mode %04o); chmod 600 it", path, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("TOOLCLAD_SECRETS_FILE '%s': %w", path, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("TOOLCLAD_SECRETS_FILE '%s': %w", path, err)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		sv, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("TOOLCLAD_SECRETS_FILE '%s': value of '%s' must be a string", path, k)
		}
		out[k] = sv
	}
	return out, nil
}

// lookup returns the secret for name: the secrets file wins over
// TOOLCLAD_SECRET_<NAME>. An empty value counts as missing.
func (s *secretSource) lookup(name string) (string, error) {
	if !s.loaded {
		s.file, s.err = loadSecretsFile()
		s.loaded = true
	}
	if s.err != nil {
		return "", s.err
	}
	if v := s.file[name]; v != "" {
		return v, nil
	}
	envKey := "TOOLCLAD_SECRET_" + strings.ToUpper(name)
	if v := os.Getenv(envKey); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("missing environment variable: %s (and no '%s' in TOOLCLAD_SECRETS_FILE)", envKey, name)
}

// expand replaces each {_secret:name} in template with its value.
func (s *secretSource) expand(template string) (string, error) {
	var firstErr error
	result := secretPattern.ReplaceAllStringFunc(template, func(match string) string {
		sub := secretPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		val, err := s.lookup(sub[1])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return val
	})
	if firstErr != nil {
		return "", firstErr
	}
	return result, nil
}

// injectTemplateVars replaces {_secret:name} with its value from
// TOOLCLAD_SECRETS_FILE or TOOLCLAD_SECRET_<NAME>.
func injectTemplateVars(template string) (string, error) {
	return (&secretSource{}).expand(template)
}

// interpolateString replaces {key} placeholders with values from the
// context map, unencoded.
func interpolateString(template string, ctx map[string]string) string {
	return interpolateWith(template, ctx, func(v string, _ int) string { return v })
}

// interpolateWith replaces each {key} naming an entry of ctx with
// encode(value, offset), offset being the placeholder's position in
// template. Unknown placeholders are left as written. The template is
// scanned once, so substituted text is never rescanned.
func interpolateWith(template string, ctx map[string]string, encode func(v string, offset int) string) string {
	var b strings.Builder
	i := 0
	for i < len(template) {
		if template[i] == '{' {
			if end := strings.IndexByte(template[i+1:], '}'); end >= 0 {
				name := template[i+1 : i+1+end]
				if v, ok := ctx[name]; ok {
					b.WriteString(encode(v, i))
					i += end + 2
					continue
				}
			}
		}
		b.WriteByte(template[i])
		i++
	}
	return b.String()
}

// interpolateURL interpolates validated values into an expanded http.url,
// percent-encoding each by position: before the first "?" (or "#") as one
// path segment, after it as a query value. "/", "?", "#", "%", "&" and "="
// in a value therefore can never change the URL's structure, and a value of
// "." or ".." is encoded so it cannot act as a dot segment. The scheme and
// host never hold a placeholder (refused at load by CheckHTTP).
func interpolateURL(template string, ctx map[string]string) string {
	queryAt := strings.IndexAny(template, "?#")
	return interpolateWith(template, ctx, func(v string, offset int) string {
		if queryAt >= 0 && offset > queryAt {
			return url.QueryEscape(v)
		}
		switch v {
		case ".":
			return "%2E"
		case "..":
			return "%2E%2E"
		}
		return url.PathEscape(v)
	})
}

// jsonEscapeString returns v as the inside of a JSON string literal.
func jsonEscapeString(v string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // encoding a string cannot fail
	out := strings.TrimSuffix(buf.String(), "\n")
	return out[1 : len(out)-1]
}

// buildHTTPRequest assembles the request for an [http] manifest from
// already-validated arguments without sending it. In the URL, every header
// value and the body template, {_secret:name} references in the manifest
// template are expanded FIRST and argument values interpolated afterwards,
// so a validated argument can never introduce a secret reference of its
// own. Values are percent-encoded by position in the URL and JSON-escaped
// in the body; an assembled header value containing CR or LF is refused.
func buildHTTPRequest(m *manifest.Manifest, cleaned map[string]string) (*http.Request, error) {
	// One source per request: the secrets file is read at most once.
	secrets := &secretSource{}
	urlTemplate, err := secrets.expand(m.Http.URL)
	if err != nil {
		return nil, err
	}
	target := interpolateURL(urlTemplate, cleaned)

	headers := make(map[string]string)
	for k, v := range m.Http.Headers {
		withSecrets, err := secrets.expand(v)
		if err != nil {
			return nil, err
		}
		hv := interpolateString(withSecrets, cleaned)
		if strings.ContainsAny(hv, "\r\n") {
			return nil, fmt.Errorf("http header '%s' contains a CR or LF after interpolation", k)
		}
		headers[k] = hv
	}

	method := strings.ToUpper(m.Http.Method)
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if m.Http.BodyTemplate != "" && method != "GET" && method != "HEAD" {
		withSecrets, err := secrets.expand(m.Http.BodyTemplate)
		if err != nil {
			return nil, err
		}
		body := interpolateWith(withSecrets, cleaned, func(v string, _ int) string { return jsonEscapeString(v) })
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building HTTP request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// prepareDelegated runs the checks shared by the HTTP and MCP backends for
// a manifest that may have been built in memory, validates the arguments
// through validateArgs and consults the gate.
func prepareDelegated(m *manifest.Manifest, args map[string]string, gate Gate) (map[string]string, error) {
	if err := checkDeclaredArgs(m, args); err != nil {
		return nil, err
	}
	// Manifests built in memory never passed LoadManifest's checks; run the
	// egress lint (an [http] backend is always egress) and the [output] and
	// [http] load rules here.
	if err := m.LintEgress(nil); err != nil {
		return nil, err
	}
	if err := m.CheckOutput(); err != nil {
		return nil, err
	}
	if err := m.CheckHTTP(); err != nil {
		return nil, err
	}
	cleaned, err := validateArgs(m, args, false)
	if err != nil {
		return nil, err
	}
	if err := consultGate(gate, m, cleaned); err != nil {
		return nil, err
	}
	return cleaned, nil
}

// ExecuteHTTP performs an HTTP request based on the manifest's [http]
// section, after consulting DefaultGate. Use ExecuteWithGate to supply a
// different gate.
func ExecuteHTTP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	return executeHTTP(m, args, DefaultGate)
}

func executeHTTP(m *manifest.Manifest, args map[string]string, gate Gate) (*EvidenceEnvelope, error) {
	if m.Http == nil || m.Http.URL == "" {
		return nil, fmt.Errorf("manifest %q has no [http] section or http.url", m.Tool.Name)
	}
	cleaned, err := prepareDelegated(m, args, gate)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	scanID := newScanID(start)

	req, err := buildHTTPRequest(m, cleaned)
	if err != nil {
		return nil, err
	}
	method := req.Method
	// The declared request, placeholders and {_secret:...} intact.
	cmdStr := method + " " + m.Http.URL

	timeout := time.Duration(m.Tool.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		// Redirects are never followed: an allowed host could otherwise
		// send the request on to an internal address unchecked.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Do(req)
	if err != nil {
		return &EvidenceEnvelope{
			Status:    "error",
			ScanID:    scanID,
			Tool:      m.Tool.Name,
			Command:   cmdStr,
			Timestamp: start.UTC().Format(time.RFC3339),
			Error:     err.Error(),
		}, err
	}
	defer resp.Body.Close()

	limit := outputLimit(m)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	truncated := int64(len(respBody)) > limit
	if truncated {
		respBody = respBody[:limit]
	}

	duration := time.Since(start)
	hash := sha256.Sum256(respBody)

	envelope := &EvidenceEnvelope{
		ScanID:     scanID,
		Tool:       m.Tool.Name,
		Command:    cmdStr,
		DurationMs: duration.Milliseconds(),
		Timestamp:  start.UTC().Format(time.RFC3339),
		OutputHash: fmt.Sprintf("sha256:%x", hash),
		ExitCode:   resp.StatusCode,
		Truncated:  truncated,
		Results: map[string]any{
			"raw_output": string(respBody),
		},
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		envelope.Status = "redirect_blocked"
		envelope.Error = fmt.Sprintf("HTTP %d redirect not followed (Location: %s)", resp.StatusCode, loc)
		envelope.Results = map[string]any{"location": loc, "raw_output": string(respBody)}
		return envelope, nil
	}

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

	if isSuccess {
		envelope.Status = "success"
		applyResults(envelope, m, respBody)
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

// ExecuteMCP performs field mapping and returns a delegated envelope for MCP
// proxy, after consulting DefaultGate. Use ExecuteWithGate to supply a
// different gate.
func ExecuteMCP(m *manifest.Manifest, args map[string]string) (*EvidenceEnvelope, error) {
	return executeMCP(m, args, DefaultGate)
}

func executeMCP(m *manifest.Manifest, args map[string]string, gate Gate) (*EvidenceEnvelope, error) {
	if m.Mcp == nil || m.Mcp.Server == "" || m.Mcp.Tool == "" {
		return nil, fmt.Errorf("manifest %q has no [mcp] section or mcp.server/mcp.tool", m.Tool.Name)
	}
	cleaned, err := prepareDelegated(m, args, gate)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	scanID := newScanID(start)

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
		Command:   "mcp://" + m.Mcp.Server + "/" + m.Mcp.Tool,
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
		// A custom type is described by its base type.
		prop := mcpTypeConstraints(m.BaseType(arg.Type))
		if m.BaseType(arg.Type) == "number" {
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
