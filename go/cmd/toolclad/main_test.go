package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/executor"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

const approvalManifest = `
[tool]
name = "echo_approval"
version = "1.0.0"
description = "echo behind the approval gate"
human_approval = true

[args.msg]
type = "string"
required = true
description = "message"

[command]
exec = ["echo", "{msg}"]

[output]
format = "text"
`

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool.clad.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWithoutApproveIsDenied(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	cmd := runCmd()
	cmd.SetArgs([]string{writeManifest(t, approvalManifest), "--arg", "msg=hello"})
	cmd.SilenceErrors = true
	err := cmd.Execute()
	want := "policy gate denied: manifest requires human approval (human_approval = true)"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
}

func TestRunWithApproveRuns(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	cmd := runCmd()
	cmd.SetArgs([]string{writeManifest(t, approvalManifest), "--arg", "msg=hello", "--approve"})
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("approved run failed: %v", err)
	}
}

func TestDryRunIsNotGated(t *testing.T) {
	cmd := testCmd()
	cmd.SetArgs([]string{writeManifest(t, approvalManifest), "--arg", "msg=hello"})
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("dry run must not be gated: %v", err)
	}
}

// The shipped nikto example sets human_approval = true. Without --approve it
// must exit non-zero and never execute nikto. (No test runs it with
// --approve: that would execute nikto.)
func TestRunNiktoExampleWithoutApproveFails(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	cmd := runCmd()
	cmd.SetArgs([]string{"../../../examples/nikto_scan.clad.toml", "--arg", "target=93.184.216.34"})
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("nikto example must not run without --approve")
	}
	// The CLI loads the project toolclad.toml, so the custom types resolve
	// and the refusal comes from the policy gate, before anything runs.
	if !strings.Contains(err.Error(), "policy gate denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// examplesDir resolves the repository's examples directory relative to the
// Go runtime directory, skipping when it is genuinely absent (a module
// copied out of the repository).
func examplesDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "examples")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Skipf("examples directory %s not present; skipping example dry runs", dir)
	}
	return dir
}

// TestShippedExamplesEndToEnd loads every shipped example through the same
// path the CLI uses (toolclad.toml and scope discovery included) and checks
// the dry-run argv. Nothing is executed.
func TestShippedExamplesEndToEnd(t *testing.T) {
	t.Setenv("TOOLCLAD_SCOPE_FILE", "")
	t.Setenv("TOOLCLAD_CONFIG_FILE", "")
	dir := examplesDir(t)
	load := func(name string) *manifest.Manifest {
		t.Helper()
		m, err := loadManifest(filepath.Join(dir, name), manifest.LoadOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return m
	}
	for _, name := range []string{
		"curl_fetch.clad.toml", "dig_lookup.clad.toml", "nikto_scan.clad.toml",
		"nmap_scan.clad.toml", "whois_lookup.clad.toml",
	} {
		load(name)
		cmd := validateCmd()
		cmd.SetArgs([]string{filepath.Join(dir, name)})
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Errorf("validate %s: %v", name, err)
		}
	}

	nikto := load("nikto_scan.clad.toml")
	argv, err := executor.BuildCommandArgv(nikto, map[string]string{
		"target": "93.184.216.34", "port": "8080-8090", "protocol": "https", "max_rate": "250",
	})
	if err != nil {
		t.Fatalf("nikto dry run: %v", err)
	}
	joined := "\x00" + strings.Join(argv, "\x00") + "\x00"
	for _, tok := range []string{"-h", "https://93.184.216.34:8080-8090", "-Plugins", "@@ALL", "-maxrate", "250"} {
		if !strings.Contains(joined, "\x00"+tok+"\x00") {
			t.Errorf("nikto argv %q lacks token %q", argv, tok)
		}
	}
	if _, err := executor.BuildCommandArgv(nikto, map[string]string{
		"target": "93.184.216.34", "port": "80;id",
	}); err == nil {
		t.Error("nikto: port=80;id must be refused by the anchored port_range pattern")
	}

	curl := load("curl_fetch.clad.toml")
	if _, err := executor.BuildCommandArgv(curl, map[string]string{"url": "https://93.184.216.34/"}); err == nil ||
		!strings.Contains(err.Error(), "not in scope") {
		t.Errorf("curl: public IP literal must be refused as not in scope, got %v", err)
	}
	// block_internal resolves example.com; assert only when DNS works.
	if _, err := net.LookupHost("example.com"); err != nil {
		t.Logf("skipping the curl example.com assertion: DNS unavailable (%v)", err)
		return
	}
	if _, err := executor.BuildCommandArgv(curl, map[string]string{"url": "https://example.com/"}); err != nil {
		t.Errorf("curl: https://example.com/ must be accepted: %v", err)
	}
}
