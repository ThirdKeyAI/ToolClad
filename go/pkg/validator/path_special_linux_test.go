//go:build linux

package validator

import (
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"os"
	"syscall"
	"testing"
)

func TestCredentialRejectsFIFO(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	}()
	if err := syscall.Mkfifo("credential.pipe", 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateArg(&manifest.ArgDef{Type: "credential_file"}, "credential.pipe"); err == nil {
		t.Fatal("accepted FIFO as regular credential file")
	}
}
