package validator

import (
	"encoding/json"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"os"
	"path/filepath"
	"testing"
)

func TestRelativePathContract(t *testing.T) {
	data, err := os.ReadFile("../../../tests/path_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name, Value string
			Error       bool
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
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
	for _, c := range vectors.Cases {
		if !c.Error {
			if err := os.MkdirAll(filepath.Dir(c.Value), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.Value, []byte("synthetic fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, kind := range []string{"path", "credential_file"} {
		def := &manifest.ArgDef{Name: "value", Type: kind}
		alias := &manifest.ArgDef{Name: "value", Type: "relative_file"}
		types := map[string]*manifest.CustomTypeDef{"relative_file": {Base: kind}}
		for _, c := range vectors.Cases {
			for _, custom := range []bool{false, true} {
				var got string
				var err error
				if custom {
					got, err = ValidateArgWithCustomTypes(alias, c.Value, types)
				} else {
					got, err = ValidateArg(def, c.Value)
				}
				if c.Error {
					if err == nil {
						t.Errorf("accepted %s: %q", c.Name, c.Value)
					}
				} else if err != nil || got != c.Value {
					t.Errorf("%s: got %q, error %v", c.Name, got, err)
				}
			}
		}
		if kind == "credential_file" {
			for _, value := range []string{"data", "missing.txt"} {
				if _, err := ValidateArg(def, value); err == nil {
					t.Errorf("accepted %s", value)
				}
			}
		}
	}
}
