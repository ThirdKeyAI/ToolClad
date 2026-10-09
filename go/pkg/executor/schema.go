package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/thirdkeyai/toolclad/pkg/validator"
)

// This file is a small JSON-Schema subset validator, bundled so a manifest's
// [output.schema] is enforced without a new dependency. Supported keywords:
// type, properties, required, additionalProperties (boolean only), items (a
// single schema), enum, minimum, maximum, minLength, maxLength and pattern
// (anchored like every other pattern, ^(?:pat)$). Unknown keywords are
// ignored. Values are compared in JSON terms: both the schema and the
// document are normalized through encoding/json with UseNumber, so numeric
// checks are exact rather than float64 approximations.
//
// Object keys are visited in sorted order (Go maps keep no document order),
// which makes the reported first failure deterministic.

// SchemaError is the first failure found while validating a document. Path
// is a JSON pointer ("" for the root).
type SchemaError struct {
	Path    string
	Message string
}

// Error renders "<pointer>: <message>", the root pointer shown as "/".
func (e *SchemaError) Error() string {
	p := e.Path
	if p == "" {
		p = "/"
	}
	return p + ": " + e.Message
}

// normalizeJSON round-trips v through encoding/json so every value is one of
// map[string]any, []any, string, bool, nil or json.Number.
func normalizeJSON(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateSchema validates doc against schema. Both may be any Go value
// encoding/json can marshal (a TOML-decoded schema, parsed tool output). It
// returns nil when the document conforms and a *SchemaError otherwise.
func ValidateSchema(schema, doc any) error {
	s, err := normalizeJSON(schema)
	if err != nil {
		return &SchemaError{Message: fmt.Sprintf("schema is not representable as JSON: %v", err)}
	}
	d, err := normalizeJSON(doc)
	if err != nil {
		return &SchemaError{Message: fmt.Sprintf("value is not representable as JSON: %v", err)}
	}
	if e := validateNode(s, d, ""); e != nil {
		return e
	}
	return nil
}

// escapePointer escapes one JSON-pointer reference token.
func escapePointer(tok string) string {
	b := make([]byte, 0, len(tok))
	for i := 0; i < len(tok); i++ {
		switch tok[i] {
		case '~':
			b = append(b, '~', '0')
		case '/':
			b = append(b, '~', '1')
		default:
			b = append(b, tok[i])
		}
	}
	return string(b)
}

// toRat returns the exact value of a JSON number.
func toRat(v any) (*big.Rat, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(string(n))
	return r, ok
}

// jsonType names v's JSON type; an integral number is "integer".
func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case json.Number:
		if r, ok := toRat(v); ok && r.IsInt() {
			return "integer"
		}
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

// typeMatches reports whether v is of JSON-Schema type t. An integer is
// also a number, and a number with no fractional part (30.0) is an integer.
func typeMatches(t string, v any) bool {
	got := jsonType(v)
	switch t {
	case "number":
		return got == "number" || got == "integer"
	default:
		return got == t
	}
}

// jsonEqual is deep equality in JSON terms: numbers by value.
func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case json.Number:
		ar, ok1 := toRat(av)
		br, ok2 := toRat(b)
		return ok1 && ok2 && ar.Cmp(br) == 0
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !jsonEqual(x, y) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// schemaInt reads a non-negative integer keyword value (minLength, ...).
func schemaInt(v any) (int, bool) {
	r, ok := toRat(v)
	if !ok || !r.IsInt() || r.Sign() < 0 || !r.Num().IsInt64() {
		return 0, false
	}
	return int(r.Num().Int64()), true
}

func validateNode(schemaVal, v any, path string) *SchemaError {
	schema, ok := schemaVal.(map[string]any)
	if !ok {
		// A boolean schema: true accepts everything, false nothing. Any
		// other non-object schema constrains nothing.
		if b, isBool := schemaVal.(bool); isBool && !b {
			return &SchemaError{path, "no value is allowed here"}
		}
		return nil
	}
	fail := func(format string, a ...any) *SchemaError {
		return &SchemaError{path, fmt.Sprintf(format, a...)}
	}

	if t, ok := schema["type"]; ok {
		switch tv := t.(type) {
		case string:
			if !typeMatches(tv, v) {
				return fail("expected %s, got %s", tv, jsonType(v))
			}
		case []any:
			matched := false
			names := ""
			for i, x := range tv {
				s, _ := x.(string)
				if i > 0 {
					names += " or "
				}
				names += s
				if typeMatches(s, v) {
					matched = true
				}
			}
			if !matched {
				return fail("expected %s, got %s", names, jsonType(v))
			}
		}
	}

	if allowed, ok := schema["enum"].([]any); ok {
		found := false
		for _, a := range allowed {
			if jsonEqual(a, v) {
				found = true
				break
			}
		}
		if !found {
			return fail("value is not one of the allowed enum values")
		}
	}

	if r, isNum := toRat(v); isNum {
		if minR, ok := toRat(schema["minimum"]); ok && r.Cmp(minR) < 0 {
			return fail("%s is less than minimum %s", v, schema["minimum"])
		}
		if maxR, ok := toRat(schema["maximum"]); ok && r.Cmp(maxR) > 0 {
			return fail("%s is greater than maximum %s", v, schema["maximum"])
		}
	}

	if s, isStr := v.(string); isStr {
		n := utf8.RuneCountInString(s)
		if minL, ok := schemaInt(schema["minLength"]); ok && n < minL {
			return fail("string length %d is less than minLength %d", n, minL)
		}
		if maxL, ok := schemaInt(schema["maxLength"]); ok && n > maxL {
			return fail("string length %d is greater than maxLength %d", n, maxL)
		}
		if pat, ok := schema["pattern"].(string); ok {
			re, err := regexp.Compile(validator.AnchorPattern(pat))
			if err != nil {
				return fail("invalid pattern %s in schema: %v", strconv.Quote(pat), err)
			}
			if !re.MatchString(s) {
				return fail("string does not match pattern %s", strconv.Quote(pat))
			}
		}
	}

	if obj, isObj := v.(map[string]any); isObj {
		if req, ok := schema["required"].([]any); ok {
			for _, x := range req {
				name, _ := x.(string)
				if _, present := obj[name]; !present {
					return fail("missing required property '%s'", name)
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		if ap, ok := schema["additionalProperties"].(bool); ok && !ap {
			for _, k := range sortedKeys(obj) {
				if _, declared := props[k]; !declared {
					return fail("additional property '%s' is not allowed", k)
				}
			}
		}
		for _, k := range sortedKeys(obj) {
			sub, declared := props[k]
			if !declared {
				continue
			}
			if e := validateNode(sub, obj[k], path+"/"+escapePointer(k)); e != nil {
				return e
			}
		}
	}

	if arr, isArr := v.([]any); isArr {
		if items, ok := schema["items"]; ok {
			for i, x := range arr {
				if e := validateNode(items, x, path+"/"+strconv.Itoa(i)); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
