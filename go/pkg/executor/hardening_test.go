package executor

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// ---- W7: policy gate -------------------------------------------------------

func gatedEcho() *manifest.Manifest {
	return &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "gated_echo", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{
			"msg":  {Name: "msg", Required: true, Type: "string"},
			"mode": {Name: "mode", Type: "string", Default: "quick"},
		},
		// touch would create the output file: proof that something ran.
		Command: manifest.CommandDef{Exec: []string{"touch", "{_output_file}"}},
		Output:  &manifest.OutputDef{Format: "text"},
	}
}

func assertNothingRan(t *testing.T, evDir string) {
	t.Helper()
	entries, err := os.ReadDir(evDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a denied call must create nothing, found %v", entries)
	}
}

func assertGateDenied(t *testing.T, env *EvidenceEnvelope, err error, reason string) {
	t.Helper()
	var gd *GateDeniedError
	if !errors.As(err, &gd) {
		t.Fatalf("want *GateDeniedError, got %v", err)
	}
	if want := "policy gate denied: " + reason; err.Error() != want {
		t.Fatalf("want %q, got %q", want, err.Error())
	}
	if env != nil {
		t.Fatalf("a denied call returns no envelope, got %+v", env)
	}
}

func TestDefaultGateDeniesHumanApproval(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := gatedEcho()
	m.Tool.HumanApproval = true
	env, err := Execute(m, map[string]string{"msg": "hi"})
	assertGateDenied(t, env, err, "manifest requires human approval (human_approval = true)")
	assertNothingRan(t, evDir)
}

func TestDefaultGateByRiskTier(t *testing.T) {
	for _, tier := range []string{"high", "critical"} {
		evDir := t.TempDir()
		t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
		m := gatedEcho()
		m.Tool.RiskTier = tier
		env, err := Execute(m, map[string]string{"msg": "hi"})
		assertGateDenied(t, env, err, "risk_tier '"+tier+"' requires explicit approval")
		assertNothingRan(t, evDir)
	}
	for _, tier := range []string{"", "info", "low", "medium"} {
		t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
		m := gatedEcho()
		m.Tool.RiskTier = tier
		env, err := Execute(m, map[string]string{"msg": "hi"})
		if err != nil || env.Status != "success" {
			t.Fatalf("tier %q must be allowed: %v %+v", tier, err, env)
		}
	}
}

func TestApproveGateRuns(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := gatedEcho()
	m.Tool.HumanApproval = true
	m.Tool.RiskTier = "critical"
	env, err := ExecuteWithGate(m, map[string]string{"msg": "hi"}, ApproveGate)
	if err != nil || env.Status != "success" {
		t.Fatalf("approved call must run: %v %+v", err, env)
	}
}

func TestCustomGateSeesValidatedValues(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	var seen map[string]string
	gate := func(_ *manifest.Manifest, args map[string]string) GateDecision {
		seen = args
		if args["msg"] == "forbidden" {
			return Deny("msg 'forbidden' is not allowed here")
		}
		return Allow()
	}
	m := gatedEcho()
	env, err := ExecuteWithGate(m, map[string]string{"msg": "forbidden"}, gate)
	assertGateDenied(t, env, err, "msg 'forbidden' is not allowed here")
	// The default for the unsupplied optional is applied before the gate.
	if seen["mode"] != "quick" || seen["msg"] != "forbidden" || len(seen) != 2 {
		t.Fatalf("gate must receive the validated values, got %v", seen)
	}
	if env, err := ExecuteWithGate(m, map[string]string{"msg": "fine"}, gate); err != nil || env.Status != "success" {
		t.Fatalf("custom gate allow: %v %+v", err, env)
	}
}

func TestGateRunsAfterValidation(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	called := false
	gate := func(*manifest.Manifest, map[string]string) GateDecision {
		called = true
		return Deny("never")
	}
	m := gatedEcho()
	m.Tool.HumanApproval = true
	_, err := ExecuteWithGate(m, map[string]string{"msg": "a;b"}, gate)
	var gd *GateDeniedError
	if err == nil || errors.As(err, &gd) || !strings.Contains(err.Error(), "metacharacter") {
		t.Fatalf("an invalid call must report the validation error, got %v", err)
	}
	if called {
		t.Fatal("the gate must not be consulted for an invalid call")
	}
	// The default gate too.
	if _, err := Execute(m, map[string]string{}); err == nil || !strings.Contains(err.Error(), "missing required argument") {
		t.Fatalf("want missing-argument error, got %v", err)
	}
}

func TestGateOnHTTPAndMCPPaths(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer ts.Close()

	hm := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "http_gated", TimeoutSeconds: 5, HumanApproval: true},
		Args: map[string]*manifest.ArgDef{},
		Http: &manifest.HttpDef{Method: "GET", URL: ts.URL + "/x"},
	}
	env, err := Execute(hm, map[string]string{})
	assertGateDenied(t, env, err, "manifest requires human approval (human_approval = true)")
	env, err = ExecuteHTTP(hm, map[string]string{})
	assertGateDenied(t, env, err, "manifest requires human approval (human_approval = true)")
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("a denied HTTP call must make no request, got %d", n)
	}
	if env, err := ExecuteWithGate(hm, map[string]string{}, ApproveGate); err != nil || env.Status != "success" {
		t.Fatalf("approved HTTP call: %v %+v", err, env)
	}

	mm := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "mcp_gated", RiskTier: "high"},
		Args: map[string]*manifest.ArgDef{},
		Mcp:  &manifest.McpProxyDef{Server: "srv", Tool: "scan"},
	}
	env, err = Execute(mm, map[string]string{})
	assertGateDenied(t, env, err, "risk_tier 'high' requires explicit approval")
	env, err = ExecuteMCP(mm, map[string]string{})
	assertGateDenied(t, env, err, "risk_tier 'high' requires explicit approval")
	if env, err := ExecuteWithGate(mm, map[string]string{}, ApproveGate); err != nil || env.Status != "delegation_preview" {
		t.Fatalf("approved MCP call: %v %+v", err, env)
	}
}

func TestDryRunIsNotGated(t *testing.T) {
	m := gatedEcho()
	m.Tool.HumanApproval = true
	if _, err := BuildCommand(m, map[string]string{"msg": "hi"}); err != nil {
		t.Fatalf("dry run must not be gated: %v", err)
	}
}

// ---- W9: output caps, XML, schema -----------------------------------------

func writeManifestFile(t *testing.T, body string) *manifest.Manifest {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tool.clad.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.LoadManifest(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func TestOutputCapTruncates(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	limit := int64(1024)
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "seq_cap", TimeoutSeconds: 5},
		Args:    map[string]*manifest.ArgDef{},
		Command: manifest.CommandDef{Exec: []string{"seq", "1", "5000"}},
		Output:  &manifest.OutputDef{Format: "text", MaxBytes: &limit},
	}
	env, err := Execute(m, map[string]string{})
	if err != nil || env.Status != "success" {
		t.Fatalf("capped run: %v %+v", err, env)
	}
	if !env.Truncated {
		t.Fatal("output_truncated must be set")
	}
	if got := len(rawOutput(env)); got != 1024 {
		t.Fatalf("raw_output length = %d, want 1024", got)
	}
	data, _ := json.Marshal(env)
	if !strings.Contains(string(data), `"output_truncated":true`) {
		t.Fatalf("envelope JSON must carry output_truncated: %s", data)
	}

	// Under the cap: no flag, and it is omitted from the JSON.
	big := int64(1 << 20)
	m.Output.MaxBytes = &big
	env, err = Execute(m, map[string]string{})
	if err != nil || env.Truncated {
		t.Fatalf("uncapped run: %v truncated=%v", err, env.Truncated)
	}
	data, _ = json.Marshal(env)
	if strings.Contains(string(data), "output_truncated") {
		t.Fatalf("output_truncated must be omitted when false: %s", data)
	}
}

func TestCappedBufferDrains(t *testing.T) {
	c := &cappedBuffer{limit: 4}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		if n, err := c.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write must accept everything: %d %v", n, err)
		}
	}
	if c.buf.String() != "abcd" || !c.truncated {
		t.Fatalf("got %q truncated=%v", c.buf.String(), c.truncated)
	}
}

func TestHTTPBodyCap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer ts.Close()
	limit := int64(1024)
	m := &manifest.Manifest{
		Tool:   manifest.ToolMeta{Name: "http_cap", TimeoutSeconds: 5},
		Args:   map[string]*manifest.ArgDef{},
		Http:   &manifest.HttpDef{Method: "GET", URL: ts.URL + "/big"},
		Output: &manifest.OutputDef{Format: "text", MaxBytes: &limit},
	}
	env, err := ExecuteHTTP(m, map[string]string{})
	if err != nil || env.Status != "success" {
		t.Fatalf("http cap: %v %+v", err, env)
	}
	if !env.Truncated || len(rawOutput(env)) != 1024 {
		t.Fatalf("truncated=%v len=%d", env.Truncated, len(rawOutput(env)))
	}
}

func TestXMLDeclarationsRefused(t *testing.T) {
	_, err := parseOutput("xml", []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>`))
	want := "XML output contains a DOCTYPE or ENTITY declaration; refusing to parse"
	if err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
	if _, err := parseOutput("xml", []byte(`<r><!entity x "y"></r>`)); err == nil {
		t.Fatal("lower-case ENTITY must be refused")
	}
	res, err := parseOutput("xml", []byte(`<?xml version="1.0"?><host addr="1.2.3.4"><port>80</port></host>`))
	if err != nil {
		t.Fatalf("plain XML must parse: %v", err)
	}
	if _, ok := res["host"]; !ok {
		t.Fatalf("unexpected XML result %v", res)
	}

	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	m := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "xml_echo", TimeoutSeconds: 5},
		Args:    map[string]*manifest.ArgDef{},
		Command: manifest.CommandDef{Exec: []string{"echo", `<!DOCTYPE x [<!ENTITY a "b">]><x/>`}},
		Output:  &manifest.OutputDef{Format: "xml"},
	}
	env, err := Execute(m, map[string]string{})
	if err != nil || env.Status != "parse_error" || env.Results["parse_error"] != want {
		t.Fatalf("want parse_error envelope, got %v %+v", err, env)
	}
}

const schemaManifest = `
[tool]
name = "json_echo"
version = "1.0.0"
description = "echo JSON"
timeout_seconds = 5

[command]
exec = ["echo", %s]

[output]
format = "json"

[output.schema]
type = "object"
required = ["ok"]

[output.schema.properties.ok]
type = "boolean"
`

func TestSchemaFailClosedEndToEnd(t *testing.T) {
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", t.TempDir())
	run := func(arg string) *EvidenceEnvelope {
		t.Helper()
		m := writeManifestFile(t, strings.Replace(schemaManifest, "%s", arg, 1))
		env, err := Execute(m, map[string]string{})
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		return env
	}

	env := run(`"{{\"ok\": \"yes\"}}"`)
	if env.Status != "schema_error" {
		t.Fatalf("want schema_error, got %+v", env)
	}
	if got := env.Results["schema_error"]; got != "/ok: expected boolean, got string" {
		t.Fatalf("schema_error = %v", got)
	}
	if raw := env.Results["raw_output"]; raw != "{\"ok\": \"yes\"}\n" {
		t.Fatalf("raw_output must be preserved, got %q", raw)
	}
	if env.ExitCode != 0 {
		t.Fatalf("exit_code must be kept, got %d", env.ExitCode)
	}

	env = run(`"{{\"ok\": true}}"`)
	if env.Status != "success" || env.Results["ok"] != true {
		t.Fatalf("want success, got %+v", env)
	}

	env = run(`"not json"`)
	if env.Status != "parse_error" || env.Results["raw_output"] != "not json\n" {
		t.Fatalf("want parse_error, got %+v", env)
	}
	if _, ok := env.Results["parse_error"].(string); !ok {
		t.Fatalf("parse_error message missing: %+v", env.Results)
	}

	env = run(`"{{}}"`)
	if env.Status != "schema_error" || env.Results["schema_error"] != "/: missing required property 'ok'" {
		t.Fatalf("root pointer: %+v", env)
	}
}

func TestNormalizedResultShapes(t *testing.T) {
	cases := []struct {
		format string
		in     string
		key    string
	}{
		{"jsonl", "{\"a\":1}\n{\"a\":2}\n", "parsed_output"},
		{"csv", "a,b\n1,2\n", "parsed_output"},
		{"text", "hello", "raw_output"},
		{"json", "[1,2]", "parsed_output"},
		{"json", "42", "parsed_output"},
	}
	for _, c := range cases {
		res, err := parseOutput(c.format, []byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.format, err)
		}
		if _, ok := res[c.key]; !ok || len(res) != 1 {
			t.Errorf("%s %q: want {%q: ...}, got %v", c.format, c.in, c.key, res)
		}
		if err := ValidateSchema(map[string]any{"type": "object"}, res); err != nil {
			t.Errorf("%s: default schema must accept the normalized result: %v", c.format, err)
		}
	}
	if res, _ := parseOutput("jsonl", []byte("{\"a\":1}\n{\"a\":2}\n")); len(res["parsed_output"].([]any)) != 2 {
		t.Errorf("jsonl rows: %v", res)
	}
	if res, _ := parseOutput("json", []byte(`{"a":1}`)); res["a"] == nil {
		t.Errorf("a JSON object passes through: %v", res)
	}
}

func TestValidateSchemaKeywords(t *testing.T) {
	obj := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name   string
		schema any
		doc    string
		want   string // "" = valid
	}{
		{"type ok", obj("type", "string"), `"x"`, ""},
		{"type bad", obj("type", "string"), `1`, "/: expected string, got integer"},
		{"type union", obj("type", []any{"string", "null"}), `null`, ""},
		{"type union bad", obj("type", []any{"string", "null"}), `true`, "/: expected string or null, got boolean"},
		{"integer accepts 30.0", obj("type", "integer"), `30.0`, ""},
		{"integer refuses 30.5", obj("type", "integer"), `30.5`, "/: expected integer, got number"},
		{"number accepts integer", obj("type", "number"), `3`, ""},
		{"integer exact", obj("type", "integer"), `12345678901234567890123`, ""},
		{"required", obj("required", []any{"a"}), `{}`, "/: missing required property 'a'"},
		{"additionalProperties false", obj("properties", obj("a", obj()), "additionalProperties", false), `{"a":1,"b":2}`, "/: additional property 'b' is not allowed"},
		{"additionalProperties true", obj("properties", obj("a", obj()), "additionalProperties", true), `{"a":1,"b":2}`, ""},
		{"nested items", obj("properties", obj("hosts", obj("type", "array", "items", obj("properties", obj("port", obj("type", "integer")))))),
			`{"hosts":[{"port":1},{"port":"80"}]}`, "/hosts/1/port: expected integer, got string"},
		{"enum ok", obj("enum", []any{"a", 1.0, obj("k", true)}), `1`, ""},
		{"enum deep", obj("enum", []any{obj("k", true)}), `{"k":true}`, ""},
		{"enum bad", obj("enum", []any{"a", "b"}), `"c"`, "/: value is not one of the allowed enum values"},
		{"minimum", obj("minimum", 1), `0`, "/: 0 is less than minimum 1"},
		{"minimum inclusive", obj("minimum", 1), `1`, ""},
		{"maximum", obj("maximum", 10), `10.5`, "/: 10.5 is greater than maximum 10"},
		{"minLength code points", obj("minLength", 3), `"äöü"`, ""},
		{"minLength bad", obj("minLength", 3), `"ab"`, "/: string length 2 is less than minLength 3"},
		{"maxLength bad", obj("maxLength", 2), `"abc"`, "/: string length 3 is greater than maxLength 2"},
		{"pattern anchored", obj("pattern", "[a-z]+"), `"abc1"`, `/: string does not match pattern "[a-z]+"`},
		{"pattern ok", obj("pattern", "[a-z]+"), `"abc"`, ""},
		{"unknown keyword ignored", obj("format", "email", "x-custom", 1), `"anything"`, ""},
		{"pointer escaping", obj("properties", obj("a/b", obj("type", "string"))), `{"a/b":1}`, "/a~1b: expected string, got integer"},
	}
	for _, c := range cases {
		var doc any
		if err := json.Unmarshal([]byte(c.doc), &doc); err != nil {
			t.Fatalf("%s: bad doc: %v", c.name, err)
		}
		err := ValidateSchema(c.schema, doc)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.want != "" && (err == nil || err.Error() != c.want):
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

// ---- W10: HTTP hardening and the envelope command --------------------------

func TestHTTPPathValueIsPercentEncoded(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "enc"},
		Http: &manifest.HttpDef{Method: "GET", URL: "https://api.example.com/{endpoint}"},
	}
	req, err := buildHTTPRequest(m, map[string]string{"endpoint": "../admin?role=admin"})
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Host != "api.example.com" {
		t.Fatalf("host changed: %q", req.URL.Host)
	}
	if got := req.URL.String(); got != "https://api.example.com/..%2Fadmin%3Frole=admin" {
		t.Fatalf("url = %q", got)
	}
	if strings.Contains(req.URL.EscapedPath(), "/admin") || req.URL.RawQuery != "" {
		t.Fatalf("structure changed: path %q query %q", req.URL.EscapedPath(), req.URL.RawQuery)
	}
	req, _ = buildHTTPRequest(m, map[string]string{"endpoint": ".."})
	if got := req.URL.String(); got != "https://api.example.com/%2E%2E" {
		t.Fatalf("dot segment must be encoded, got %q", got)
	}
}

func TestHTTPQueryValueIsEncoded(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "enc"},
		Http: &manifest.HttpDef{Method: "GET", URL: "https://api.example.com/search?q={q}&page=1"},
	}
	req, err := buildHTTPRequest(m, map[string]string{"q": "a&b=c d#e"})
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()
	if q.Get("q") != "a&b=c d#e" || q.Get("page") != "1" || len(q) != 2 || req.URL.Fragment != "" {
		t.Fatalf("query structure changed: %q", req.URL.String())
	}
}

func TestHTTPBodyIsJSONEscaped(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "body"},
		Http: &manifest.HttpDef{Method: "POST", URL: "https://api.example.com/msg", BodyTemplate: `{"text": "{message}"}`},
	}
	msg := `x", "admin": true, "x": "`
	req, err := buildHTTPRequest(m, map[string]string{"message": msg})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body must stay valid JSON: %v (%s)", err, body)
	}
	if len(parsed) != 1 || parsed["text"] != msg {
		t.Fatalf("body must hold a single text key with the literal value, got %v", parsed)
	}
}

func TestHTTPHeaderCRLFRefused(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "hdr"},
		Http: &manifest.HttpDef{Method: "GET", URL: "https://api.example.com/", Headers: map[string]string{"X-Trace": "{v}"}},
	}
	_, err := buildHTTPRequest(m, map[string]string{"v": "a\r\nX-Admin: 1"})
	if err == nil || !strings.Contains(err.Error(), "CR or LF") {
		t.Fatalf("want CR/LF refusal, got %v", err)
	}
}

func TestHTTPURLHostInterpolationRefusedInMemory(t *testing.T) {
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "host"},
		Args: map[string]*manifest.ArgDef{"host": {Name: "host", Type: "string", Required: true}},
		Http: &manifest.HttpDef{Method: "GET", URL: "https://{host}/x"},
	}
	_, err := ExecuteHTTP(m, map[string]string{"host": "example.com"})
	if err == nil || err.Error() != "http.url may not interpolate into the scheme or host" {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPLiteralHostPolicyAtLoad(t *testing.T) {
	body := func(url, argBlock string) string {
		return `
[tool]
name = "h"
version = "1.0.0"
description = "h"

[args.u]
type = "url"
required = true
description = "u"
` + argBlock + `

[http]
method = "GET"
url = "` + url + `"

[output]
format = "text"
`
	}
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "tool.clad.toml")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := manifest.LoadManifest(write(body("http://169.254.169.254/latest?u={u}", "block_internal = true"))); err == nil ||
		!strings.Contains(err.Error(), "http.url host") {
		t.Fatalf("metadata literal host must be refused, got %v", err)
	}
	if _, err := manifest.LoadManifest(write(body("http://127.0.0.1:8080/x?u={u}", "block_internal = true"))); err == nil ||
		!strings.Contains(err.Error(), "loopback") {
		t.Fatalf("loopback host under block_internal must be refused, got %v", err)
	}
	if _, err := manifest.LoadManifest(write(body("https://api.example.com/x?u={u}", "block_internal = true"))); err != nil {
		t.Fatalf("public literal host must load: %v", err)
	}
}

func TestHTTPRedirectNotFollowed(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	defer ts.Close()
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "redir", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{},
		Http: &manifest.HttpDef{Method: "GET", URL: ts.URL + "/start"},
	}
	env, err := ExecuteHTTP(m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if env.Status != "redirect_blocked" || env.Results["location"] != "http://127.0.0.1:1/" {
		t.Fatalf("want redirect_blocked with location, got %+v", env)
	}
	if _, ok := env.Results["raw_output"]; !ok {
		t.Fatalf("body must be kept under raw_output: %+v", env.Results)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("exactly one request expected, got %d", n)
	}
}

func TestHTTPEnvelopeCommandIsDeclared(t *testing.T) {
	const secret = "s3cr3t-value"
	t.Setenv("TOOLCLAD_SECRET_API_KEY", secret)
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer ts.Close()
	tmpl := ts.URL + "/items/{id}?key={_secret:api_key}"
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "cmd", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{"id": {Name: "id", Type: "string", Required: true}},
		Http: &manifest.HttpDef{Method: "get", URL: tmpl, Headers: map[string]string{"Authorization": "Bearer {_secret:api_key}"}},
	}
	env, err := ExecuteHTTP(m, map[string]string{"id": "42"})
	if err != nil || env.Status != "success" {
		t.Fatalf("%v %+v", err, env)
	}
	if env.Command != "GET "+tmpl {
		t.Fatalf("command = %q", env.Command)
	}
	if !strings.Contains(env.Command, "{_secret:") || strings.Contains(env.Command, secret) {
		t.Fatalf("command must keep the secret reference, never the value: %q", env.Command)
	}
	if gotAuth != "Bearer "+secret {
		t.Fatalf("the request itself must carry the secret, got %q", gotAuth)
	}
}

func TestOneshotEnvelopeCommandIsDeclared(t *testing.T) {
	evDir := t.TempDir()
	t.Setenv("TOOLCLAD_EVIDENCE_DIR", evDir)
	m := &manifest.Manifest{
		Tool: manifest.ToolMeta{Name: "decl", TimeoutSeconds: 5},
		Args: map[string]*manifest.ArgDef{"target": {Name: "target", Type: "string", Required: true}},
		Command: manifest.CommandDef{
			Exec:            []string{"echo", "{target}", "{_output_file}"},
			ExecWasDeclared: true,
		},
		Output: &manifest.OutputDef{Format: "text"},
	}
	env, err := Execute(m, map[string]string{"target": "example.com"})
	if err != nil || env.Status != "success" {
		t.Fatalf("%v %+v", err, env)
	}
	if env.Command != "echo {target} {_output_file}" {
		t.Fatalf("command = %q", env.Command)
	}
	if strings.Contains(env.Command, evDir) {
		t.Fatalf("command leaks the evidence path: %q", env.Command)
	}
	// The dry run keeps the resolved argv.
	dry, err := BuildCommand(m, map[string]string{"target": "example.com"})
	if err != nil || !strings.HasPrefix(dry, "echo example.com ") || !strings.Contains(dry, evDir) {
		t.Fatalf("dry run must show the resolved command, got %q (%v)", dry, err)
	}

	// A legacy template is reported as written.
	tm := &manifest.Manifest{
		Tool:    manifest.ToolMeta{Name: "tpl", TimeoutSeconds: 5},
		Args:    map[string]*manifest.ArgDef{"target": {Name: "target", Type: "string", Required: true}},
		Command: manifest.CommandDef{Template: "echo {target}"},
		Output:  &manifest.OutputDef{Format: "text"},
	}
	env, err = Execute(tm, map[string]string{"target": "example.com"})
	if err != nil || env.Command != "echo {target}" {
		t.Fatalf("template command = %q (%v)", env.Command, err)
	}
}
