package executor

import (
	"encoding/json"
	"github.com/BurntSushi/toml"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"os"
	"reflect"
	"testing"
)

func TestSharedExecutionVectors(t *testing.T) {
	data, err := os.ReadFile("../../../tests/execution_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name     string
			Manifest string
			Args     map[string]string
			Expected []string `json:"expected_argv"`
			Error    bool
		}
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var m manifest.Manifest
			if _, err := toml.Decode(c.Manifest, &m); err != nil {
				t.Fatal(err)
			}
			command, err := BuildCommand(&m, c.Args)
			if c.Error {
				if err == nil {
					t.Fatal("expected refusal")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, err := splitTemplate(command)
			if err != nil || !reflect.DeepEqual(actual, c.Expected) {
				t.Fatalf("argv=%q expected=%q err=%v", actual, c.Expected, err)
			}
		})
	}
}
