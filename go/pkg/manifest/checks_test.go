package manifest

import (
	"strings"
	"testing"
)

func outputManifest(outputBody string) string {
	return `
[tool]
name = "echo_tool"
version = "1.0.0"
description = "echo"

[command]
exec = ["echo", "hi"]

[output]
format = "text"
` + outputBody
}

func TestMaxBytesBounds(t *testing.T) {
	cases := []struct {
		body    string
		wantErr string
	}{
		{"max_bytes = 1024\n", ""},
		{"max_bytes = 1\n", ""},
		{"max_bytes = 1073741824\n", ""},
		{"max_bytes = 0\n", "output.max_bytes must be an integer between 1 and 1073741824"},
		{"max_bytes = -5\n", "output.max_bytes must be an integer between 1 and 1073741824"},
		{"max_bytes = 1073741825\n", "output.max_bytes must be an integer between 1 and 1073741824"},
		{"max_bytes = 1.5\n", "parsing manifest"},
		{"max_bytes = \"big\"\n", "parsing manifest"},
	}
	for _, c := range cases {
		_, err := LoadManifest(writeTmp(t, outputManifest(c.body)))
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.body, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: want error containing %q, got %v", c.body, c.wantErr, err)
		}
	}
}

func TestCustomParserRefused(t *testing.T) {
	_, err := LoadManifest(writeTmp(t, outputManifest("parser = \"scripts/x.py\"\n")))
	want := `custom output parsers are not supported by the reference runtimes (parser = "scripts/x.py")`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want %q, got %v", want, err)
	}
	for p := range BuiltinParsers {
		if _, err := LoadManifest(writeTmp(t, outputManifest("parser = \""+p+"\"\n"))); err != nil {
			t.Errorf("%s must load: %v", p, err)
		}
	}
}

func httpManifest(url, extra string) string {
	return `
[tool]
name = "http_tool"
version = "1.0.0"
description = "http"

[args.endpoint]
type = "string"
required = true
description = "endpoint"

[http]
method = "GET"
url = "` + url + `"
` + extra + `
[output]
format = "text"
`
}

func TestHTTPURLMayNotInterpolateSchemeOrHost(t *testing.T) {
	const want = "http.url may not interpolate into the scheme or host"
	for _, u := range []string{
		"https://{endpoint}/x",
		"{endpoint}://example.com/x",
		"{endpoint}",
		"https://api.{endpoint}.com/x",
		"https://example.com:{endpoint}/x",
		"https://{_secret:host}/x",
	} {
		_, err := LoadManifest(writeTmp(t, httpManifest(u, "")))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", u, want, err)
		}
	}
	for _, u := range []string{
		"https://api.example.com/{endpoint}",
		"https://api.example.com/v1?q={endpoint}",
		"https://api.example.com#{endpoint}",
	} {
		if _, err := LoadManifest(writeTmp(t, httpManifest(u, ""))); err != nil {
			t.Errorf("%s must load: %v", u, err)
		}
	}
}

func TestHTTPHeaderNameMustBeToken(t *testing.T) {
	_, err := LoadManifest(writeTmp(t, httpManifest("https://api.example.com/{endpoint}",
		"[http.headers]\n\"X-{endpoint}\" = \"v\"\n")))
	if err == nil || !strings.Contains(err.Error(), "is not a valid token") {
		t.Fatalf("want token error, got %v", err)
	}
	if _, err := LoadManifest(writeTmp(t, httpManifest("https://api.example.com/{endpoint}",
		"[http.headers]\nX-Trace = \"{endpoint}\"\n"))); err != nil {
		t.Fatalf("token header name must load: %v", err)
	}
}
