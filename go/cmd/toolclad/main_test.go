package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// The Go CLI's run does not load project custom types yet, so this
	// manifest stops at validation of its custom-typed defaults, which
	// precedes the gate. Either refusal keeps nikto from running.
	if !strings.Contains(err.Error(), "policy gate denied") && !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("unexpected error: %v", err)
	}
}
