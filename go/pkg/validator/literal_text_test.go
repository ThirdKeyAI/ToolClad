package validator

import (
	"encoding/json"
	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"os"
	"strings"
	"testing"
)

func TestLiteralTextVectors(t *testing.T) {
	data, err := os.ReadFile("../../../tests/literal_text_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name, Value, Pattern string
			Repeat               int
			Error                bool
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) != 12 {
		t.Fatal("incomplete vectors")
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			value := strings.Repeat(c.Value, c.Repeat)
			def := &manifest.ArgDef{Name: "value", Type: "literal_text", Required: true, Pattern: c.Pattern}
			alias := &manifest.ArgDef{Name: "value", Type: "source_text", Required: true}
			types := map[string]*manifest.CustomTypeDef{"source_text": {Base: "literal_text", Pattern: c.Pattern}}
			for _, custom := range []bool{false, true} {
				var got string
				var err error
				if custom {
					got, err = ValidateArgWithCustomTypes(alias, value, types)
				} else {
					got, err = ValidateArg(def, value)
				}
				if c.Error {
					if err == nil {
						t.Fatal("expected refusal")
					}
				} else if err != nil || got != value {
					t.Fatalf("text changed or refused: %v", err)
				}
			}
		})
	}
}
func TestLiteralTextInvalidUTF8(t *testing.T) {
	for _, value := range []string{string([]byte{0xff}), string([]byte{0xed, 0xa0, 0x80})} {
		if _, err := ValidateArg(&manifest.ArgDef{Type: "literal_text"}, value); err == nil {
			t.Fatal("accepted invalid UTF-8")
		}
	}
}
