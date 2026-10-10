package manifest_test

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
	"github.com/thirdkeyai/toolclad/pkg/scope"
	// Registers the load-time hooks (defaults validator, host policy) so
	// the fuzzer drives the loader exactly as the CLI does.
	_ "github.com/thirdkeyai/toolclad/pkg/validator"
)

// FuzzLoadManifest checks that the strict string loader never panics on
// arbitrary source and never returns a nil manifest without an error. The
// seed corpus is every manifest of the shared injection-vector suite.
// Custom types are fixed (empty) so discovery never reads a toolclad.toml,
// and a declared default is validated with block_internal cleared so an
// invented hostname default never triggers a DNS lookup (the load-time
// [http] host check never resolves names).
func FuzzLoadManifest(f *testing.F) {
	f.Add("[tool]\nname = \"t\"\nversion = \"1.0.0\"\nbinary = \"echo\"\ndescription = \"d\"\n\n" +
		"[args.v]\nposition = 1\ntype = \"string\"\n\n[command]\nexec = [\"echo\", \"{v}\"]\n\n[output]\nformat = \"text\"\n")
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "injection_vectors.json"))
	if err == nil {
		var vectors struct {
			ManifestVectors []struct {
				Manifest string `json:"manifest"`
			} `json:"manifest_vectors"`
		}
		if err := json.Unmarshal(data, &vectors); err != nil {
			f.Fatalf("parsing injection_vectors.json: %v", err)
		}
		for _, v := range vectors.ManifestVectors {
			f.Add(v.Manifest)
		}
	}
	prev := manifest.WarningOutput
	manifest.WarningOutput = io.Discard
	f.Cleanup(func() { manifest.WarningOutput = prev })
	realDefault := manifest.DefaultValidator
	manifest.DefaultValidator = func(def *manifest.ArgDef, value string, ct map[string]*manifest.CustomTypeDef, sc *scope.ScopeDef) error {
		d := *def
		d.BlockInternal = false
		return realDefault(&d, value, ct, sc)
	}
	f.Cleanup(func() { manifest.DefaultValidator = realDefault })
	opts := manifest.LoadOptions{CustomTypes: map[string]*manifest.CustomTypeDef{}}
	f.Fuzz(func(t *testing.T, src string) {
		m, err := manifest.LoadManifestFromStringWithOptions(src, opts)
		if err == nil && m == nil {
			t.Fatal("nil manifest without an error")
		}
	})
}
