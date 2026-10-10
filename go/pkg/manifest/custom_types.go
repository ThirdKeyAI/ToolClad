package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// ConfigEnvVar names an explicit toolclad.toml path. When set, the file
// must be readable; discovery does not fall back to the upward search.
const ConfigEnvVar = "TOOLCLAD_CONFIG_FILE"

// ConfigFileName is the project-level configuration file holding custom
// type definitions.
const ConfigFileName = "toolclad.toml"

// CustomTypeDef represents a custom type defined in toolclad.toml.
type CustomTypeDef struct {
	Base     string   `toml:"base"`
	Allowed  []string `toml:"allowed"`
	Pattern  string   `toml:"pattern"`
	Min      *int     `toml:"min"`
	Max      *int     `toml:"max"`
	MinFloat *float64 `toml:"min_float"`
	MaxFloat *float64 `toml:"max_float"`
}

// projectConfig is the schema of toolclad.toml. Only [types.<n>] tables
// are accepted; any other key is refused by the unknown-key walk.
type projectConfig struct {
	Types map[string]*CustomTypeDef `toml:"types"`
}

// LoadCustomTypes reads custom type definitions from a toolclad.toml file.
// A missing file yields no custom types. A key outside the schema
// ([types.<n>] with base, allowed, pattern, min, max, min_float, max_float)
// is refused, and so is a custom type whose base is not a built-in type.
func LoadCustomTypes(path string) (map[string]*CustomTypeDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No custom types file
		}
		return nil, fmt.Errorf("reading toolclad.toml: %w", err)
	}
	return ParseCustomTypes(data, path)
}

// ParseCustomTypes parses toolclad.toml source; label names it in errors.
func ParseCustomTypes(data []byte, label string) (map[string]*CustomTypeDef, error) {
	var config projectConfig
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", label, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", label, err)
	}
	// Same reflection walk as the manifest (not MetaData.Undecoded()).
	var unknown []string
	walkUnknownKeys(reflect.TypeOf(projectConfig{}), raw, nil, &unknown)
	// A [types] entry that is not a table would decode to nothing silently.
	if types, ok := raw["types"].(map[string]any); ok {
		for name, v := range types {
			if _, isTable := v.(map[string]any); !isTable {
				unknown = append(unknown, "types."+name)
			}
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		msgs := make([]string, len(unknown))
		for i, k := range unknown {
			msgs[i] = fmt.Sprintf("unknown key '%s' in toolclad.toml", k)
		}
		return nil, fmt.Errorf("%s: %s", label, strings.Join(msgs, "; "))
	}
	names := make([]string, 0, len(config.Types))
	for name := range config.Types {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ct := config.Types[name]
		// A custom type may not reuse a built-in name: [types.url] with
		// base = "string" would otherwise replace the url validator.
		if builtinTypes[name] {
			return nil, fmt.Errorf("%s: custom type '%s' shadows a built-in type", label, name)
		}
		if ct == nil || !builtinTypes[ct.Base] {
			base := ""
			if ct != nil {
				base = ct.Base
			}
			return nil, fmt.Errorf("%s: custom type '%s' has invalid base type '%s' (must be a built-in type)",
				label, name, base)
		}
	}
	return config.Types, nil
}

// DiscoverCustomTypes finds and loads the project toolclad.toml the way the
// scope file is found: TOOLCLAD_CONFIG_FILE if set (unreadable is an error),
// else toolclad.toml searched upward from dir (the working directory when
// dir is empty) to the filesystem root. Not finding one yields no custom
// types and no error.
func DiscoverCustomTypes(dir string) (map[string]*CustomTypeDef, error) {
	if p := os.Getenv(ConfigEnvVar); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: reading %s: %w", ConfigEnvVar, p, err)
		}
		return ParseCustomTypes(data, p)
	}
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving toolclad.toml search directory: %w", err)
	}
	for {
		candidate := filepath.Join(dir, ConfigFileName)
		info, statErr := os.Stat(candidate)
		switch {
		case statErr == nil && !info.IsDir():
			return LoadCustomTypes(candidate)
		case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
			return nil, fmt.Errorf("checking %s: %w", candidate, statErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil
		}
		dir = parent
	}
}

// checkArgTypes refuses any argument whose type is neither a built-in nor
// one of the manifest's custom types. Arguments are visited in name order.
func (m *Manifest) checkArgTypes() error {
	all := m.allArgDefs()
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := all[name].Type
		if t == "" {
			t = "string"
		}
		if builtinTypes[t] {
			continue
		}
		if _, ok := m.CustomTypes[t]; !ok {
			return fmt.Errorf("unknown type '%s' for argument '%s'", t, name)
		}
	}
	return nil
}

// BaseType resolves t through the manifest's custom types: a custom type's
// base, else t itself.
func (m *Manifest) BaseType(t string) string {
	if ct, ok := m.CustomTypes[t]; ok {
		return ct.Base
	}
	return t
}
