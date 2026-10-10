package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// injectionVectorsPath is the shared negative suite, relative to this
// package directory (the repository's tests/ directory).
var injectionVectorsPath = filepath.Join("..", "..", "..", "tests", "injection_vectors.json")

type argVector struct {
	ID     string         `json:"id"`
	Arg    map[string]any `json:"arg"`
	Value  string         `json:"value"`
	Expect string         `json:"expect"`
	Note   string         `json:"note"`
}

type manifestVector struct {
	ID       string `json:"id"`
	Manifest string `json:"manifest"`
	Expect   string `json:"expect"`
	Note     string `json:"note"`
}

type injectionVectors struct {
	ArgVectors      []argVector      `json:"arg_vectors"`
	ManifestVectors []manifestVector `json:"manifest_vectors"`
}

// loadInjectionVectors reads the shared vector file; ok is false when the
// file is genuinely absent (a module copied out of the repository).
func loadInjectionVectors(tb testing.TB) (injectionVectors, bool) {
	tb.Helper()
	var v injectionVectors
	data, err := os.ReadFile(injectionVectorsPath)
	if errors.Is(err, os.ErrNotExist) {
		return v, false
	}
	if err != nil {
		tb.Fatalf("reading %s: %v", injectionVectorsPath, err)
	}
	if err := json.Unmarshal(data, &v); err != nil {
		tb.Fatalf("parsing %s: %v", injectionVectorsPath, err)
	}
	return v, true
}

// argDefFromVector builds an ArgDef from a vector's [args.<n>] keys by
// round-tripping them through TOML, refusing any key ArgDef does not have
// so a vector can never be silently weakened.
func argDefFromVector(tb testing.TB, v argVector) *manifest.ArgDef {
	tb.Helper()
	known := map[string]bool{}
	t := reflect.TypeOf(manifest.ArgDef{})
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("toml"), ",")
		if name != "" && name != "-" {
			known[name] = true
		}
	}
	for k := range v.Arg {
		if !known[k] {
			tb.Fatalf("vector %s: arg key %q is not an [args.<n>] key", v.ID, k)
		}
	}
	var buf strings.Builder
	if err := toml.NewEncoder(&buf).Encode(v.Arg); err != nil {
		tb.Fatalf("vector %s: encoding arg: %v", v.ID, err)
	}
	def := &manifest.ArgDef{}
	if _, err := toml.Decode(buf.String(), def); err != nil {
		tb.Fatalf("vector %s: decoding arg: %v", v.ID, err)
	}
	def.Name = "v"
	if def.Type == "" {
		def.Type = "string"
	}
	return def
}

// TestInjectionVectors runs every vector of tests/injection_vectors.json:
// arg vectors through the strict single-argument entry point in template
// mode, manifest vectors through the strict string loader.
func TestInjectionVectors(t *testing.T) {
	vectors, ok := loadInjectionVectors(t)
	if !ok {
		t.Skipf("%s not present (built outside the repository); skipping the shared vector suite", injectionVectorsPath)
	}
	// Silence the template deprecation warning some vectors trigger.
	prev := manifest.WarningOutput
	manifest.WarningOutput = io.Discard
	defer func() { manifest.WarningOutput = prev }()

	executed := 0
	for _, v := range vectors.ArgVectors {
		def := argDefFromVector(t, v)
		got, err := ValidateArgMode(def, v.Value, false)
		switch v.Expect {
		case "reject":
			if err == nil {
				t.Errorf("arg vector %s: accepted %q as %q, want reject (%s)", v.ID, v.Value, got, v.Note)
			}
		case "accept":
			if err != nil {
				t.Errorf("arg vector %s: rejected %q: %v, want accept (%s)", v.ID, v.Value, err, v.Note)
			}
		default:
			t.Fatalf("arg vector %s: unknown expect %q", v.ID, v.Expect)
		}
		executed++
	}
	for _, v := range vectors.ManifestVectors {
		_, err := manifest.LoadManifestFromString(v.Manifest)
		switch v.Expect {
		case "reject":
			if err == nil {
				t.Errorf("manifest vector %s: loaded, want reject (%s)", v.ID, v.Note)
			}
		case "accept":
			if err != nil {
				t.Errorf("manifest vector %s: refused: %v, want accept (%s)", v.ID, err, v.Note)
			}
		default:
			t.Fatalf("manifest vector %s: unknown expect %q", v.ID, v.Expect)
		}
		executed++
	}
	if executed == 0 {
		t.Fatal("no injection vectors executed")
	}
	fmt.Printf("injection vectors executed: %d (%d arg, %d manifest)\n",
		executed, len(vectors.ArgVectors), len(vectors.ManifestVectors))
}
