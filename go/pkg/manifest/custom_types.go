package manifest

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

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

// LoadCustomTypes reads custom type definitions from a toolclad.toml file.
func LoadCustomTypes(path string) (map[string]*CustomTypeDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No custom types file
		}
		return nil, fmt.Errorf("reading toolclad.toml: %w", err)
	}

	var config struct {
		Types map[string]*CustomTypeDef `toml:"types"`
	}
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing toolclad.toml: %w", err)
	}
	return config.Types, nil
}
