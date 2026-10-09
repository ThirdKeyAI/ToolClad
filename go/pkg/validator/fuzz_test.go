package validator

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// fuzzDefs are the string-derived argument definitions the fuzzer drives,
// none with block_internal, so no input can cause a DNS lookup.
var fuzzDefs = []*manifest.ArgDef{
	{Name: "v", Type: "string"},
	{Name: "v", Type: "string", Pattern: "^[a-z0-9.:/_-]+$"},
	{Name: "v", Type: "path"},
	{Name: "v", Type: "regex_match", Pattern: ".*"},
	{Name: "v", Type: "url"},
	{Name: "v", Type: "url", Schemes: []string{"http", "https", "ftp"}},
	{Name: "v", Type: "scope_target"},
	{Name: "v", Type: "duration"},
	{Name: "v", Type: "msf_options"},
}

// checkHygieneProperty reports the first hygiene rule an accepted value
// breaks for def (none of the fuzz definitions opts in to anything):
// no whitespace (msf_options may use the ASCII space), no quote or
// backslash, no control character, no leading '-' or '+'.
func checkHygieneProperty(def *manifest.ArgDef, out string) error {
	for _, r := range out {
		switch {
		case unicode.IsControl(r) || (r >= 0x7f && r <= 0x9f):
			return errors.New("control character in output")
		case unicode.IsSpace(r) && !(def.Type == "msf_options" && r == ' '):
			return errors.New("whitespace in output")
		case r == '\'' || r == '"' || r == '\\':
			return errors.New("quote or backslash in output")
		}
	}
	if strings.HasPrefix(out, "-") || strings.HasPrefix(out, "+") {
		return errors.New("leading '-' or '+' in output")
	}
	return nil
}

// FuzzValidateArg checks that the strict validator never panics and never
// accepts a value whose output violates the hygiene rules for a
// string-derived type. The seed corpus is every value of the shared
// injection-vector suite, crossed with every fuzz definition.
func FuzzValidateArg(f *testing.F) {
	seeds := []string{"", "example.com", "https://example.com/a", "a b", "-x", "5m", "RHOSTS 10.0.0.1"}
	if vectors, ok := loadInjectionVectors(f); ok {
		for _, v := range vectors.ArgVectors {
			seeds = append(seeds, v.Value)
		}
	}
	for _, s := range seeds {
		for i := range fuzzDefs {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, value string) {
		def := fuzzDefs[int(which)%len(fuzzDefs)]
		for _, execMode := range []bool{false, true} {
			out, err := ValidateArgMode(def, value, execMode)
			if err != nil {
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("%s: unexpected error type %T: %v", def.Type, err, err)
				}
				continue
			}
			if perr := checkHygieneProperty(def, out); perr != nil {
				t.Fatalf("%s (exec=%v): %v: input %q, output %q", def.Type, execMode, perr, value, out)
			}
		}
	})
}
