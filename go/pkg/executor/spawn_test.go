package executor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// helperToolName is the tool name of the manifests that re-execute this
// test binary as a tool. Together with TOOLCLAD_ARG_TEST_HELPER it is the
// flag that switches the binary into helper mode. The child environment is
// an allowlist, so the flag reaches the helper through the executor hatch's
// TOOLCLAD_TOOL_NAME / TOOLCLAD_ARG_* variables rather than a variable of
// its own.
const helperToolName = "toolclad-test-helper"

// TestMain runs the helper modes when, and only when, this binary was
// re-executed by a helper manifest; otherwise it runs the tests.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TOOLCLAD_ARG_TEST_HELPER"); mode != "" && os.Getenv("TOOLCLAD_TOOL_NAME") == helperToolName {
		runHelper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runHelper(mode string) {
	switch mode {
	case "hold-stdout":
		// Leave a background child holding stdout, then exit: the TC-11
		// shape (an NSE script or `nohup ... &`).
		c := exec.Command("sleep", "30")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		fmt.Printf("child-pid %d\n", c.Process.Pid)
	case "print-sleep", "ignore-term":
		if mode == "ignore-term" {
			signal.Ignore(syscall.SIGTERM)
		}
		fmt.Println("partial-line")
		fmt.Printf("child-pid %d\n", os.Getpid())
		time.Sleep(30 * time.Second)
	default:
		os.Exit(2)
	}
}

func helperManifest(timeout int) *manifest.Manifest {
	return &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: helperToolName, TimeoutSeconds: timeout},
		Args: map[string]*manifest.ArgDef{
			"test_helper": {Name: "test_helper", Required: true, Type: "string"},
		},
		Command: manifest.CommandDef{Executor: os.Args[0]},
		Output:  &manifest.OutputDef{Format: "text"},
	}
}

var childPidRe = regexp.MustCompile(`child-pid (\d+)`)

func childPid(t *testing.T, out string) int {
	t.Helper()
	m := childPidRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no child pid in output %q", out)
	}
	pid, _ := strconv.Atoi(m[1])
	return pid
}

// waitGone polls until pid no longer exists (or is a zombie awaiting its
// reaper) and fails the test if it is still running after a few seconds.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			if f := strings.Fields(string(b)); len(f) > 2 && f[2] == "Z" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d is still alive", pid)
}

func rawOutput(env *EvidenceEnvelope) string {
	if env == nil {
		return ""
	}
	s, _ := env.Results["raw_output"].(string)
	return s
}

func envMap(out string) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			vars[k] = v
		}
	}
	return vars
}

func setSentinels(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	t.Setenv("TOOLCLAD_SECRET_LEAK", "sentinel-one")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sentinel-two")
	t.Setenv("LD_PRELOAD", "/tmp/x")
	t.Setenv("PATH", "/nonexistent:"+os.Getenv("PATH"))
	t.Setenv("LANG", "C.UTF-8")
}

func TestChildEnvironmentIsAllowlisted(t *testing.T) {
	setSentinels(t)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "env_dump", Binary: "printenv", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"printenv"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := rawOutput(env)
	for _, s := range []string{"sentinel-one", "sentinel-two", "/tmp/x", "/nonexistent"} {
		if strings.Contains(out, s) {
			t.Errorf("child environment leaked %q:\n%s", s, out)
		}
	}
	allowed := map[string]bool{"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "TZ": true, "TERM": true}
	vars := envMap(out)
	for k := range vars {
		if !allowed[k] {
			t.Errorf("unexpected child variable %s", k)
		}
	}
	if vars["PATH"] != fixedPath {
		t.Errorf("PATH = %q, want %q", vars["PATH"], fixedPath)
	}
	if vars["LANG"] != "C.UTF-8" {
		t.Errorf("LANG not passed through: %q", vars["LANG"])
	}
}

func TestExecutorHatchEnvironment(t *testing.T) {
	setSentinels(t)
	bin, err := exec.LookPath("printenv")
	if err != nil {
		t.Skip("printenv not available")
	}
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "hatch", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{
			"target": {Name: "target", Required: true, Type: "string"},
		},
		Command: manifest.CommandDef{Executor: bin},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, map[string]string{"target": "example"})
	if err != nil {
		t.Fatal(err)
	}
	out := rawOutput(env)
	vars := envMap(out)
	evDir := os.Getenv("TOOLCLAD_EVIDENCE_DIR")
	want := map[string]string{
		"PATH":                  fixedPath,
		"TOOLCLAD_ARG_TARGET":   "example",
		"TOOLCLAD_SCAN_ID":      env.ScanID,
		"TOOLCLAD_TOOL_NAME":    "hatch",
		"TOOLCLAD_EVIDENCE_DIR": evDir,
		"TOOLCLAD_OUTPUT_DIR":   filepath.Join(evDir, env.ScanID+"-hatch"),
	}
	for k, v := range want {
		if vars[k] != v {
			t.Errorf("%s = %q, want %q", k, vars[k], v)
		}
	}
	for k := range vars {
		if strings.HasPrefix(k, "TOOLCLAD_SECRET_") || k == "AWS_SECRET_ACCESS_KEY" || k == "LD_PRELOAD" {
			t.Errorf("hatch leaked %s", k)
		}
	}
	if strings.Contains(out, "sentinel") {
		t.Errorf("hatch leaked a sentinel:\n%s", out)
	}
}

// The explicit filter holds even if a TOOLCLAD_SECRET_* entry is handed to
// childEnv directly, so a future allowlist edit cannot reintroduce it.
func TestChildEnvFiltersSecrets(t *testing.T) {
	env := childEnv([]string{"TOOLCLAD_SECRET_X=v", "TOOLCLAD_ARG_A=b"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "TOOLCLAD_SECRET_") {
			t.Fatalf("childEnv passed %q", kv)
		}
	}
	if env[0] != "PATH="+fixedPath || env[len(env)-1] != "TOOLCLAD_ARG_A=b" {
		t.Fatalf("childEnv = %q", env)
	}
}

func writeSecrets(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretsFile(t *testing.T) {
	p := writeSecrets(t, 0o600, "api_key = \"from-file\"\n")
	t.Setenv("TOOLCLAD_SECRETS_FILE", p)
	t.Setenv("TOOLCLAD_SECRET_API_KEY", "from-env")
	got, err := injectTemplateVars("Bearer {_secret:api_key}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer from-file" {
		t.Errorf("file must win over env: got %q", got)
	}

	// A name only in the environment still resolves.
	t.Setenv("TOOLCLAD_SECRET_OTHER", "env-only")
	if got, err := injectTemplateVars("{_secret:other}"); err != nil || got != "env-only" {
		t.Errorf("env fallback: %q, %v", got, err)
	}

	// A missing secret is still an error.
	if _, err := injectTemplateVars("{_secret:absent}"); err == nil ||
		!strings.Contains(err.Error(), "TOOLCLAD_SECRET_ABSENT") {
		t.Errorf("missing secret: want error, got %v", err)
	}
}

func TestSecretsFileRefusedWhenGroupReadable(t *testing.T) {
	p := writeSecrets(t, 0o644, "api_key = \"x\"\n")
	t.Setenv("TOOLCLAD_SECRETS_FILE", p)
	_, err := injectTemplateVars("{_secret:api_key}")
	want := fmt.Sprintf("TOOLCLAD_SECRETS_FILE '%s' is readable by group or others (mode 0644); chmod 600 it", p)
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
}

// One request reads the secrets file once however many placeholders it has.
func TestSecretsFileReadOncePerSource(t *testing.T) {
	p := writeSecrets(t, 0o600, "a = \"1\"\n")
	t.Setenv("TOOLCLAD_SECRETS_FILE", p)
	src := &secretSource{}
	if got, err := src.expand("{_secret:a}"); err != nil || got != "1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := os.WriteFile(p, []byte("a = \"2\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := src.expand("{_secret:a}"); got != "1" {
		t.Errorf("source re-read the file: got %q", got)
	}
}

func TestResolveArgv0(t *testing.T) {
	p, err := resolveArgv0("echo")
	if err != nil || !filepath.IsAbs(p) || filepath.Base(p) != "echo" {
		t.Fatalf("resolveArgv0(echo) = %q, %v", p, err)
	}
	_, err = resolveArgv0("toolclad-no-such-binary")
	if err == nil || !strings.Contains(err.Error(), "toolclad-no-such-binary") || !strings.Contains(err.Error(), fixedPath) {
		t.Fatalf("want resolution error naming binary and PATH, got %v", err)
	}
	// A path with a separator is used as given (made absolute).
	if p, err := resolveArgv0("./x/y"); err != nil || !filepath.IsAbs(p) {
		t.Fatalf("relative path: %q, %v", p, err)
	}

	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "nobin", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"toolclad-no-such-binary"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, nil)
	if err == nil || env == nil || env.Status != "error" {
		t.Fatalf("unresolvable argv[0] must be an execution error: %+v, %v", env, err)
	}
}

func TestInMemoryInterpreterRefused(t *testing.T) {
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "sh"},
		Command: manifest.CommandDef{Exec: []string{"/bin/sh", "-c", "true"}},
	}
	_, err := BuildCommandArgv(m, nil)
	want := "command argv[0] '/bin/sh' is an interpreter; set allow_interpreter = true to permit it"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
}

func TestStdinIsDevNull(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "cat", Binary: "cat", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"cat"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	start := time.Now()
	env, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second || env.Status != "success" || rawOutput(env) != "" {
		t.Fatalf("cat must read EOF from /dev/null at once: %+v", env)
	}
}

func TestWorkingDirectoryIsScratch(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "pwd", Binary: "pwd", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"pwd"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(evDir, env.ScanID+"-work")
	if got := strings.TrimSpace(rawOutput(env)); got != work {
		t.Errorf("cwd = %q, want %q", got, work)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Errorf("empty scratch directory must be removed, stat err = %v", err)
	}

	// The scratch directory is mode 0700 while the tool runs.
	m = &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "stat", Binary: "stat", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"stat", "-c", "%a", "."}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err = Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(rawOutput(env)); got != "700" {
		t.Errorf("scratch directory mode = %q, want 700", got)
	}

	// A scratch directory the tool wrote into is kept.
	m = &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "touch", Binary: "touch", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"touch", "left-behind"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err = Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(evDir, env.ScanID+"-work", "left-behind")); err != nil {
		t.Errorf("non-empty scratch directory must be kept: %v", err)
	}
}

var scanIDRe = regexp.MustCompile(`^\d+-[0-9a-f]{32}$`)

func TestEvidencePaths(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "touch", Binary: "touch", TimeoutSeconds: 5},
		Command: manifest.CommandDef{Exec: []string{"touch", "{_output_file}"}},
		Output:  &manifest.OutputDef{Format: "xml"},
	}
	env1, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	env2, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if env1.ScanID == env2.ScanID || !scanIDRe.MatchString(env1.ScanID) || !scanIDRe.MatchString(env2.ScanID) {
		t.Errorf("scan ids %q / %q must differ and match <unix>-<32 hex>", env1.ScanID, env2.ScanID)
	}
	outDir := filepath.Join(evDir, env1.ScanID+"-touch")
	// touch succeeded, so the directory existed before the spawn.
	if _, err := os.Stat(filepath.Join(outDir, "scan.xml")); err != nil {
		t.Errorf("tool could not write {_output_file}: %v", err)
	}
	for _, d := range []string{evDir, outDir} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v, err %v; want 0700", d, fi.Mode().Perm(), err)
		}
	}

	// [tool.evidence] output_dir is honored.
	m.Tool.Evidence = &manifest.EvidenceDef{OutputDir: "{evidence_dir}/custom-{scan_id}"}
	m.Output.Format = "weird"
	env, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(evDir, "custom-"+env.ScanID, "scan.txt")); err != nil {
		t.Errorf("output_dir not honored: %v", err)
	}
}

func TestEvidenceWriteRefusesSymlink(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	fixed := filepath.Join(evDir, "fixed")
	if err := os.MkdirAll(fixed, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(fixed, "scan.txt")); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name: "echo", Binary: "echo", TimeoutSeconds: 5,
			Evidence: &manifest.EvidenceDef{OutputDir: "{evidence_dir}/fixed", Capture: true},
		},
		Command: manifest.CommandDef{Exec: []string{"echo", "overwritten"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, nil)
	if err == nil || env.Status != "error" || !strings.Contains(err.Error(), "refusing to write evidence file") {
		t.Fatalf("want symlink refusal, got %+v, %v", env, err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Errorf("symlink target was written: %q", b)
	}

	// The low-level writer refuses the symlink and an existing file.
	if err := writeEvidenceFile(filepath.Join(fixed, "scan.txt"), []byte("x")); err == nil {
		t.Error("writeEvidenceFile followed a symlink")
	}

	// A symlinked output directory is refused too.
	if err := os.Symlink(t.TempDir(), filepath.Join(evDir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(filepath.Join(evDir, "linkdir")); err == nil {
		t.Error("ensurePrivateDir accepted a symlink")
	}
}

func TestEvidenceCaptureWritesOutput(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{
			Name: "echo", Binary: "echo", TimeoutSeconds: 5,
			Evidence: &manifest.EvidenceDef{Capture: true},
		},
		Command: manifest.CommandDef{Exec: []string{"echo", "kept"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(evDir, env.ScanID+"-echo", "scan.txt")
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("captured file %s: %v, %v", p, fi, err)
	}
	if b, _ := os.ReadFile(p); strings.TrimSpace(string(b)) != "kept" {
		t.Errorf("captured %q", b)
	}
}

func TestKillGraceParsing(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"":     defaultKillGrace,
		"250":  250 * time.Millisecond,
		"0":    0,
		"-5":   defaultKillGrace,
		"abc":  defaultKillGrace,
		"1.5":  defaultKillGrace,
		"2000": 2 * time.Second,
	} {
		t.Setenv("TOOLCLAD_KILL_GRACE_MS", v)
		if got := killGrace(); got != want {
			t.Errorf("TOOLCLAD_KILL_GRACE_MS=%q: got %v, want %v", v, got, want)
		}
	}
}

func TestTimeoutFires(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	t.Setenv("TOOLCLAD_KILL_GRACE_MS", "200")
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "sleep", Binary: "sleep", TimeoutSeconds: 1},
		Command: manifest.CommandDef{Exec: []string{"sleep", "10"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	start := time.Now()
	env, err := Execute(m, nil)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	if err == nil || env.Status != "timeout" || env.ExitCode != -1 {
		t.Fatalf("want timeout envelope, got %+v, %v", env, err)
	}
}

// Partial output is kept, and the tool is gone afterwards, whether it
// honors SIGTERM or ignores it (the SIGKILL after the grace period).
func TestTimeoutKeepsPartialOutputAndKills(t *testing.T) {
	for _, mode := range []string{"print-sleep", "ignore-term"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
			t.Setenv("TOOLCLAD_KILL_GRACE_MS", "200")
			start := time.Now()
			env, err := Execute(helperManifest(1), map[string]string{"test_helper": mode})
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("timeout took %v", elapsed)
			}
			if err == nil || env.Status != "timeout" || env.ExitCode != -1 {
				t.Fatalf("want timeout envelope, got %+v, %v", env, err)
			}
			out := rawOutput(env)
			if !strings.Contains(out, "partial-line") {
				t.Errorf("partial output lost: %q", out)
			}
			waitGone(t, childPid(t, out))
		})
	}
}

// TC-11: a tool that exits but leaves a background child holding stdout
// must not hang the runtime until (or past) the deadline, and the leftover
// child is killed with the group.
func TestBackgroundChildHoldingStdoutDoesNotHang(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	t.Setenv("TOOLCLAD_KILL_GRACE_MS", "200")
	start := time.Now()
	env, err := Execute(helperManifest(5), map[string]string{"test_helper": "hold-stdout"})
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Execute took %v; the held stdout pipe blocked it", elapsed)
	}
	if err != nil || env.Status != "success" {
		t.Fatalf("want success, got %+v, %v", env, err)
	}
	waitGone(t, childPid(t, rawOutput(env)))
}
