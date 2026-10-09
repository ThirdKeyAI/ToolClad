"""Policy gate (W7: TC-9), output caps and fail-closed schema validation
(W9: TC-12, TC-14), HTTP hardening and the envelope command (W10: TC-16).

Every spawned tool is a local coreutils program (echo, seq). The HTTP tests
talk to an ``http.server`` bound to 127.0.0.1 in a thread; nothing else
opens a socket.
"""

from __future__ import annotations

import http.server
import json
import os
import textwrap
import threading
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from click.testing import CliRunner

from toolclad import (
    GateDecision,
    PolicyDenied,
    approve_gate,
    default_gate,
)
from toolclad.cli import main as cli_main
from toolclad.executor import execute
from toolclad.manifest import load_manifest
from toolclad.schema import SchemaError, schema_error, validate_schema
from toolclad.validator import ValidationError

_EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX spawn path")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    evidence = tmp_path / "evidence"
    monkeypatch.setenv("TOOLCLAD_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("TOOLCLAD_KILL_GRACE_MS", "200")
    for name in ("TOOLCLAD_SECRETS_FILE", "TOOLCLAD_SCOPE_FILE"):
        monkeypatch.delenv(name, raising=False)
    # The local test server must be reached directly, never via a proxy.
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    return evidence


def _load(tmp_path: Path, body: str, name: str = "t.clad.toml"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return load_manifest(str(path))


def _echo(tmp_path: Path, exec_: List[str], *, tool: str = "", args: str = "", output: str = 'format = "text"'):
    return _load(
        tmp_path,
        f"""\
        [tool]
        name = "t"
        version = "1.0.0"
        binary = "{exec_[0]}"
        description = "x"
        {tool}

        {args}

        [command]
        exec = {json.dumps(exec_)}

        [output]
        {output}
        """,
    )


# ---------------------------------------------------------------------------
# Local HTTP server
# ---------------------------------------------------------------------------


class _Server:
    """A 127.0.0.1 server that records request paths and serves canned
    responses keyed by path."""

    def __init__(self, routes: Dict[str, Tuple[int, Dict[str, str], bytes]]):
        self.requests: List[Tuple[str, Dict[str, str]]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                outer.requests.append((self.path, dict(self.headers)))
                status, headers, body = routes.get(
                    urllib.parse.urlsplit(self.path).path, (404, {}, b"missing")
                )
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _serve
            do_POST = _serve

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    created: List[_Server] = []

    def make(routes):
        s = _Server(routes)
        created.append(s)
        return s

    yield make
    for s in created:
        s.close()


def _http_manifest(tmp_path: Path, url: str, *, tool: str = "", args: str = "", headers: str = "", output: str = 'format = "text"'):
    return _load(
        tmp_path,
        f"""\
        [tool]
        name = "h"
        version = "1.0.0"
        description = "x"
        {tool}

        {args}

        [http]
        method = "GET"
        url = "{url}"
        {headers}

        [output]
        {output}
        """,
    )


# ---------------------------------------------------------------------------
# W7: policy gate
# ---------------------------------------------------------------------------


@posix_only
class TestPolicyGate:
    def test_human_approval_denied_and_nothing_ran(self, tmp_path, _isolated_env):
        m = _echo(tmp_path, ["echo", "hi"], tool="human_approval = true")
        with pytest.raises(PolicyDenied) as exc:
            execute(m, {})
        assert str(exc.value) == (
            "policy gate denied: manifest requires human approval (human_approval = true)"
        )
        # Nothing was prepared or spawned: no evidence directory exists.
        assert not _isolated_env.exists()

    @pytest.mark.parametrize("tier", ["high", "critical"])
    def test_high_risk_tiers_denied(self, tmp_path, tier, _isolated_env):
        m = _echo(tmp_path, ["echo", "hi"], tool=f'risk_tier = "{tier}"')
        with pytest.raises(PolicyDenied, match=f"^policy gate denied: risk_tier '{tier}' requires explicit approval$"):
            execute(m, {})
        assert not _isolated_env.exists()

    @pytest.mark.parametrize("tier", ["info", "low", "medium"])
    def test_lower_tiers_allowed(self, tmp_path, tier):
        m = _echo(tmp_path, ["echo", "hi"], tool=f'risk_tier = "{tier}"')
        env = execute(m, {})
        assert env["status"] == "success"

    def test_approve_and_approve_gate_run_it(self, tmp_path):
        m = _echo(tmp_path, ["echo", "hi"], tool='human_approval = true\nrisk_tier = "critical"')
        assert execute(m, {}, approve=True)["results"]["raw_output"] == "hi\n"
        assert execute(m, {}, gate=approve_gate)["status"] == "success"

    def test_gate_and_approve_together_is_an_error(self, tmp_path):
        m = _echo(tmp_path, ["echo", "hi"])
        with pytest.raises(ValueError, match="not both"):
            execute(m, {}, gate=approve_gate, approve=True)

    def test_custom_gate_sees_validated_values_and_its_reason_reaches_caller(self, tmp_path):
        m = _echo(
            tmp_path,
            ["echo", "{n}"],
            args='[args.n]\nposition = 1\nrequired = true\ntype = "integer"',
        )
        seen = []

        def gate(manifest, values):
            seen.append(dict(values))
            if values["n"] == "13":
                return GateDecision.deny("unlucky number")
            return GateDecision.allow()

        with pytest.raises(PolicyDenied, match="^policy gate denied: unlucky number$"):
            execute(m, {"n": "+13"}, gate=gate)
        assert seen == [{"n": "13"}]  # the cleaned value, not the raw input
        assert execute(m, {"n": "7"}, gate=gate)["status"] == "success"

    def test_validation_error_wins_over_gate_denial(self, tmp_path):
        m = _echo(
            tmp_path,
            ["echo", "{n}"],
            tool="human_approval = true",
            args='[args.n]\nposition = 1\nrequired = true\ntype = "integer"',
        )
        with pytest.raises(ValidationError):
            execute(m, {"n": "abc"})
        with pytest.raises(ValidationError):
            execute(m, {})

    def test_dry_run_is_not_gated(self, tmp_path):
        m = _echo(tmp_path, ["echo", "hi"], tool="human_approval = true")
        assert execute(m, {}, dry_run=True)["status"] == "dry_run"

    def test_default_gate_direct(self, tmp_path):
        m = _echo(tmp_path, ["echo", "hi"])
        assert default_gate(m, {}) == GateDecision.allow()

    def test_http_path_is_gated(self, tmp_path, server):
        srv = server({"/x": (200, {}, b"ok")})
        m = _http_manifest(tmp_path, f"http://127.0.0.1:{srv.port}/x", tool="human_approval = true")
        with pytest.raises(PolicyDenied):
            execute(m, {})
        assert srv.requests == []
        assert execute(m, {}, approve=True)["status"] == "success"
        assert len(srv.requests) == 1

    def test_mcp_path_is_gated(self, tmp_path):
        m = _load(
            tmp_path,
            """\
            [tool]
            name = "m"
            version = "1.0.0"
            description = "x"
            risk_tier = "high"

            [mcp]
            server = "s"
            tool = "t"

            [output]
            format = "json"
            """,
        )
        with pytest.raises(PolicyDenied, match="risk_tier 'high'"):
            execute(m, {})
        assert execute(m, {}, approve=True)["status"] == "delegation_preview"
        assert execute(m, {}, dry_run=True)["status"] == "dry_run"


@posix_only
class TestGateCli:
    def test_nikto_example_refused_without_approve(self):
        # Never run with --approve: that would execute nikto. The Python
        # ``run`` does not resolve project custom types yet, so the CLI may
        # stop before the gate; either way it exits non-zero with no
        # envelope, and the default gate denies the manifest.
        path = str(_EXAMPLES / "nikto_scan.clad.toml")
        result = CliRunner().invoke(cli_main, ["run", path, "--arg", "target=93.184.216.34"])
        assert result.exit_code != 0
        assert '"status"' not in result.output
        decision = default_gate(load_manifest(path), {})
        assert decision == GateDecision.deny(
            "manifest requires human approval (human_approval = true)"
        )

    def test_run_with_approve_on_echo_manifest(self, tmp_path):
        path = tmp_path / "e.clad.toml"
        path.write_text(
            textwrap.dedent(
                """\
                [tool]
                name = "e"
                version = "1.0.0"
                binary = "echo"
                description = "x"
                human_approval = true

                [command]
                exec = ["echo", "approved"]

                [output]
                format = "text"
                """
            )
        )
        denied = CliRunner().invoke(cli_main, ["run", str(path)])
        assert denied.exit_code != 0
        assert "policy gate denied:" in denied.output
        ok = CliRunner().invoke(cli_main, ["run", str(path), "--approve"])
        assert ok.exit_code == 0, ok.output
        assert json.loads(ok.output)["results"]["raw_output"] == "approved\n"
        shown = CliRunner().invoke(cli_main, ["test", str(path)])
        assert shown.exit_code == 0, shown.output
        assert "Approval:  required" in shown.output


# ---------------------------------------------------------------------------
# W9: output caps, XML, schema
# ---------------------------------------------------------------------------


@posix_only
class TestOutputCap:
    def test_stdout_capped_and_flagged(self, tmp_path):
        m = _echo(tmp_path, ["seq", "1", "5000"], output='format = "text"\nmax_bytes = 1024')
        env = execute(m, {})
        assert env["status"] == "success"
        assert env["output_truncated"] is True
        assert len(env["results"]["raw_output"].encode()) == 1024
        # The evidence file the runtime writes holds the capped stdout.
        assert os.path.getsize(env["output_file"]) == 1024

    def test_small_output_not_flagged(self, tmp_path):
        m = _echo(tmp_path, ["echo", "hi"], output='format = "text"\nmax_bytes = 1024')
        env = execute(m, {})
        assert "output_truncated" not in env
        assert env["results"]["raw_output"] == "hi\n"

    @pytest.mark.parametrize("value", ["0", "-1", '"1k"', "1.5", "true", str((1 << 30) + 1)])
    def test_bad_max_bytes_is_a_load_error(self, tmp_path, value):
        with pytest.raises(ValueError, match="max_bytes"):
            _echo(tmp_path, ["echo", "hi"], output=f'format = "text"\nmax_bytes = {value}')

    @pytest.mark.parametrize("value", ["1", str(1 << 30)])
    def test_max_bytes_bounds_accepted(self, tmp_path, value):
        m = _echo(tmp_path, ["echo", "hi"], output=f'format = "text"\nmax_bytes = {value}')
        assert m.output.max_bytes == int(value)


@posix_only
class TestXmlHardening:
    def test_doctype_refused(self, tmp_path):
        xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>'
        m = _echo(tmp_path, ["echo", xml], output='format = "xml"')
        env = execute(m, {})
        assert env["status"] == "parse_error"
        assert env["results"]["parse_error"] == (
            "XML output contains a DOCTYPE or ENTITY declaration; refusing to parse"
        )
        assert env["results"]["raw_output"] == xml + "\n"

    def test_lowercase_entity_refused(self, tmp_path):
        m = _echo(tmp_path, ["echo", '<!entity a "b"><foo/>'], output='format = "xml"')
        assert execute(m, {})["status"] == "parse_error"

    def test_plain_xml_parses(self, tmp_path):
        m = _echo(tmp_path, ["echo", '<hosts><host addr="1.2.3.4"/></hosts>'], output='format = "xml"')
        env = execute(m, {})
        assert env["status"] == "success"
        assert env["results"] == {"hosts": {"host": {"@addr": "1.2.3.4"}}}


class TestSchemaValidator:
    def test_type_and_path(self):
        schema = {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"port": {"type": "integer"}}},
                }
            },
        }
        assert schema_error({"hosts": [{"port": 1}, {"port": "x"}]}, schema) == (
            "/hosts/1/port: expected integer, got string"
        )
        assert schema_error({"hosts": [{"port": 1}]}, schema) is None

    def test_root_path_renders_as_slash(self):
        assert schema_error([], {"type": "object"}) == "/: expected object, got array"

    def test_type_list_and_null(self):
        assert schema_error(None, {"type": ["string", "null"]}) is None
        assert schema_error(1, {"type": ["string", "null"]}) is not None

    def test_integer_accepts_whole_float(self):
        assert schema_error(30.0, {"type": "integer"}) is None
        assert schema_error(30.5, {"type": "integer"}) == "/: expected integer, got number"
        assert schema_error(True, {"type": "integer"}) is not None
        assert schema_error(3, {"type": "number"}) is None

    def test_required_and_additional_properties(self):
        schema = {
            "type": "object",
            "properties": {"a": {}},
            "required": ["a"],
            "additionalProperties": False,
        }
        assert schema_error({}, schema) == "/: missing required property 'a'"
        assert schema_error({"a": 1, "b": 2}, schema) == "/b: additional property is not allowed"
        assert schema_error({"a": 1}, schema) is None

    def test_enum_deep_equality(self):
        schema = {"enum": [{"k": [1, 2]}, "x"]}
        assert schema_error({"k": [1, 2]}, schema) is None
        assert schema_error({"k": [2, 1]}, schema) is not None
        assert schema_error(1, {"enum": [True]}) is not None

    def test_numeric_bounds_inclusive(self):
        schema = {"minimum": 1, "maximum": 3}
        assert schema_error(1, schema) is None
        assert schema_error(3, schema) is None
        assert schema_error(0, schema) is not None
        assert schema_error(4, schema) is not None

    def test_string_lengths_in_code_points(self):
        schema = {"minLength": 2, "maxLength": 3}
        assert schema_error("éé", schema) is None
        assert schema_error("é", schema) is not None
        assert schema_error("abcd", schema) is not None

    def test_pattern_is_anchored(self):
        assert schema_error("abc", {"pattern": "b"}) is not None
        assert schema_error("b", {"pattern": "b"}) is None
        assert schema_error("b\n", {"pattern": "b"}) is not None
        assert schema_error("ab", {"pattern": "a|ab"}) is None

    def test_nested_items(self):
        schema = {"type": "array", "items": {"type": "array", "items": {"type": "string"}}}
        assert schema_error([["a"], ["b", 2]], schema) == "/1/1: expected string, got integer"

    def test_unknown_keywords_ignored(self):
        assert schema_error("x", {"format": "uri", "x-whatever": 1}) is None

    def test_first_failure_in_document_order(self):
        schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}}
        assert schema_error({"a": 1, "b": 2}, schema).startswith("/a:")

    def test_pointer_escaping(self):
        schema = {"properties": {"a/b": {"type": "string"}}}
        assert schema_error({"a/b": 1}, schema).startswith("/a~1b:")

    def test_validate_raises(self):
        with pytest.raises(SchemaError):
            validate_schema(1, {"type": "string"})


_OK_SCHEMA = """
[output.schema]
type = "object"
required = ["ok"]

[output.schema.properties.ok]
type = "boolean"
"""


@posix_only
class TestFailClosed:
    def test_schema_error(self, tmp_path):
        m = _echo(tmp_path, ["echo", '{{"ok": "yes"}}'], output='format = "json"\n' + _OK_SCHEMA)
        env = execute(m, {})
        assert env["status"] == "schema_error"
        assert env["results"] == {
            "schema_error": "/ok: expected boolean, got string",
            "raw_output": '{"ok": "yes"}\n',
        }
        assert env["exit_code"] == 0

    def test_schema_success(self, tmp_path):
        m = _echo(tmp_path, ["echo", '{{"ok": true}}'], output='format = "json"\n' + _OK_SCHEMA)
        env = execute(m, {})
        assert env["status"] == "success"
        assert env["results"] == {"ok": True}

    def test_parse_error(self, tmp_path):
        m = _echo(tmp_path, ["echo", "not json"], output='format = "json"\n' + _OK_SCHEMA)
        env = execute(m, {})
        assert env["status"] == "parse_error"
        assert env["results"]["parse_error"].startswith("JSON parse failed")
        assert env["results"]["raw_output"] == "not json\n"

    def test_non_object_json_is_wrapped(self, tmp_path):
        m = _echo(tmp_path, ["echo", "[1, 2]"], output='format = "json"')
        env = execute(m, {})
        assert env["status"] == "success"
        assert env["results"] == {"parsed_output": [1, 2]}

    def test_jsonl_and_csv_are_normalized(self, tmp_path):
        m = _echo(tmp_path, ["echo", '{{"a": 1}}'], output='format = "jsonl"')
        assert execute(m, {})["results"] == {"parsed_output": [{"a": 1}]}
        m = _echo(tmp_path, ["echo", "a,b"], output='format = "csv"', )
        assert execute(m, {})["results"] == {"parsed_output": []}

    def test_csv_schema_applies_to_normalized_shape(self, tmp_path):
        schema = """
[output.schema]
type = "object"
required = ["parsed_output"]

[output.schema.properties.parsed_output]
type = "array"
"""
        m = _echo(tmp_path, ["printf", "port\\n30.0\\n"], output='format = "csv"\n' + schema)
        env = execute(m, {})
        assert env["status"] == "success", env
        assert env["results"] == {"parsed_output": [{"port": 30.0}]}


class TestParserAtLoad:
    def test_custom_parser_refused(self, tmp_path):
        with pytest.raises(ValueError) as exc:
            _echo(tmp_path, ["echo", "x"], output='format = "json"\nparser = "scripts/x.py"')
        assert str(exc.value) == (
            'custom output parsers are not supported by the reference runtimes '
            '(parser = "scripts/x.py")'
        )

    @pytest.mark.parametrize("parser", ["json", "jsonl", "csv", "xml", "text"])
    def test_builtins_accepted(self, tmp_path, parser):
        m = _echo(tmp_path, ["echo", "x"], output=f'format = "text"\nparser = "builtin:{parser}"')
        assert m.output.parser == f"builtin:{parser}"


# ---------------------------------------------------------------------------
# W10: HTTP backend and the envelope command
# ---------------------------------------------------------------------------


_STRING_ARG = '[args.{name}]\nposition = 1\nrequired = true\ntype = "string"'


class TestHttpUrlEncoding:
    def test_path_value_cannot_change_structure(self, tmp_path):
        m = _http_manifest(
            tmp_path,
            "https://api.example.com/{endpoint}",
            args=_STRING_ARG.format(name="endpoint"),
        )
        env = execute(m, {"endpoint": "../admin?role=admin"}, dry_run=True)
        method, url = env["command"].split(" ", 1)
        assert url == "https://api.example.com/..%2Fadmin%3Frole%3Dadmin"
        parts = urllib.parse.urlsplit(url)
        assert parts.hostname == "api.example.com"
        assert "/admin" not in parts.path
        assert parts.query == ""

    def test_query_value_encodes_ampersand_and_equals(self, tmp_path):
        m = _http_manifest(
            tmp_path,
            "https://api.example.com/search?q={q}",
            args=_STRING_ARG.format(name="q"),
        )
        # ``&`` is refused by the string validator before it gets here; the
        # remaining query delimiters a string admits are encoded.
        env = execute(m, {"q": "a=1#frag?x%"}, dry_run=True)
        url = env["command"].split(" ", 1)[1]
        assert url == "https://api.example.com/search?q=a%3D1%23frag%3Fx%25"
        parts = urllib.parse.urlsplit(url)
        assert parts.fragment == ""
        assert urllib.parse.parse_qs(parts.query) == {"q": ["a=1#frag?x%"]}

    @pytest.mark.parametrize(
        "url",
        [
            "https://{host}/x",
            "{scheme}://api.example.com/x",
            "https://api.example.com:{port}/x",
            "https://{_secret:host}/x",
            "{whole}",
        ],
    )
    def test_placeholder_in_scheme_or_host_is_a_load_error(self, tmp_path, url):
        with pytest.raises(ValueError, match="^http.url may not interpolate into the scheme or host$"):
            _http_manifest(tmp_path, url)

    def test_metadata_literal_host_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="link-local|metadata"):
            _http_manifest(tmp_path, "http://169.254.169.254/latest")

    def test_loopback_literal_without_url_arg_loads(self, tmp_path):
        m = _http_manifest(tmp_path, "http://127.0.0.1:8080/x")
        assert m.http.url == "http://127.0.0.1:8080/x"


class TestHttpHeaders:
    def test_crlf_after_interpolation_refused(self, tmp_path, monkeypatch, server):
        srv = server({"/x": (200, {}, b"ok")})
        monkeypatch.setenv("TOOLCLAD_SECRET_TOKEN", "a\r\nX-Injected: 1")
        m = _http_manifest(
            tmp_path,
            f"http://127.0.0.1:{srv.port}/x",
            headers='headers = { X-Token = "{_secret:token}" }',
        )
        with pytest.raises(ValueError, match="CR or LF"):
            execute(m, {})
        assert srv.requests == []

    def test_invalid_header_name_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="header name"):
            _http_manifest(
                tmp_path, "https://api.example.com/x", headers='headers = { "Bad Name" = "v" }'
            )


class TestHttpLive:
    def test_redirect_is_not_followed(self, tmp_path, server):
        srv = server({"/r": (302, {"Location": "http://127.0.0.1:1/"}, b"moved")})
        m = _http_manifest(tmp_path, f"http://127.0.0.1:{srv.port}/r")
        env = execute(m, {})
        assert env["status"] == "redirect_blocked"
        assert env["http_status"] == 302
        assert env["results"] == {"location": "http://127.0.0.1:1/", "raw_output": "moved"}
        assert len(srv.requests) == 1

    def test_response_body_capped(self, tmp_path, server):
        srv = server({"/big": (200, {}, b"a" * 4096)})
        m = _http_manifest(
            tmp_path, f"http://127.0.0.1:{srv.port}/big", output='format = "text"\nmax_bytes = 1024'
        )
        env = execute(m, {})
        assert env["status"] == "success"
        assert env["output_truncated"] is True
        assert env["results"]["raw_output"] == "a" * 1024

    def test_executed_command_is_declared_form_without_secret(self, tmp_path, monkeypatch, server):
        secret = "s3cr3t-value"
        monkeypatch.setenv("TOOLCLAD_SECRET_KEY", secret)
        srv = server({"/v": (200, {}, b"ok")})
        url = f"http://127.0.0.1:{srv.port}/v?k={{_secret:key}}&q={{q}}"
        m = _http_manifest(tmp_path, url, args=_STRING_ARG.format(name="q"))
        env = execute(m, {"q": "a/b?c"})
        assert env["status"] == "success"
        assert env["command"] == f"GET {url}"
        assert "{_secret:key}" in env["command"]
        assert secret not in json.dumps(env)
        # The request itself carried the expanded secret and the encoded value.
        assert srv.requests[0][0] == f"/v?k={secret}&q=a%2Fb%3Fc"
        # The dry run shows the resolved request.
        dry = execute(m, {"q": "a/b?c"}, dry_run=True)
        assert dry["command"] == f"GET http://127.0.0.1:{srv.port}/v?k={secret}&q=a%2Fb%3Fc"


@posix_only
class TestOneshotEnvelopeCommand:
    def test_executed_command_is_declared_exec(self, tmp_path):
        m = _echo(
            tmp_path,
            ["echo", "{target}", "{_output_file}"],
            args=_STRING_ARG.format(name="target"),
        )
        env = execute(m, {"target": "hello"})
        assert env["command"] == "echo {target} {_output_file}"
        assert env["output_file"] not in env["command"]
        # The dry run keeps the resolved argv.
        dry = execute(m, {"target": "hello"}, dry_run=True)
        assert dry["command"].startswith("echo hello ")
        assert "{target}" not in dry["command"]

    def test_legacy_template_is_reported_as_written(self, tmp_path):
        with pytest.warns(DeprecationWarning):
            m = _load(
                tmp_path,
                """\
                [tool]
                name = "t"
                version = "1.0.0"
                binary = "echo"
                description = "x"

                [args.target]
                position = 1
                required = true
                type = "string"

                [command]
                template = "echo   {target}"

                [output]
                format = "text"
                """,
            )
        env = execute(m, {"target": "hello"})
        assert env["command"] == "echo   {target}"
