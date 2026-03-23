"""Tests for ToolClad command template interpolation and execution."""

from __future__ import annotations

from typing import Dict, Optional

import pytest

from toolclad.executor import (
    build_command,
    execute,
    inject_template_vars,
    _evaluate_condition,
)
from toolclad.manifest import (
    ArgDef,
    CommandDef,
    ConditionalDef,
    EvidenceDef,
    HttpDef,
    McpProxyDef,
    Manifest,
    OutputDef,
    ToolMeta,
)
from toolclad.validator import ValidationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _simple_manifest(
    template: str = "echo {target}",
    args: Optional[Dict[str, ArgDef]] = None,
    mappings: Optional[Dict[str, Dict[str, str]]] = None,
    conditionals: Optional[Dict[str, dict]] = None,
    defaults: Optional[Dict[str, str]] = None,
) -> Manifest:
    """Build a minimal manifest for testing."""
    if args is None:
        args = {
            "target": ArgDef(
                name="target", position=1, required=True, type="string"
            ),
        }
    cmd_conditionals = {}
    if conditionals:
        for k, v in conditionals.items():
            cmd_conditionals[k] = ConditionalDef(name=k, when=v["when"], template=v["template"])
    return Manifest(
        tool=ToolMeta(name="test_tool", version="1.0.0", binary="echo"),
        args=args,
        command=CommandDef(
            template=template,
            mappings=mappings or {},
            conditionals=cmd_conditionals,
            defaults=defaults or {},
        ),
        output=OutputDef(format="text"),
    )


# ---------------------------------------------------------------------------
# Basic interpolation
# ---------------------------------------------------------------------------

class TestBasicInterpolation:
    def test_single_arg(self):
        m = _simple_manifest("echo {target}")
        result = build_command(m, {"target": "hello"})
        assert result == "echo hello"

    def test_multiple_args(self):
        m = _simple_manifest(
            "tool --host {host} --port {port}",
            args={
                "host": ArgDef(name="host", position=1, required=True, type="string"),
                "port": ArgDef(name="port", position=2, required=True, type="port"),
            },
        )
        result = build_command(m, {"host": "example.com", "port": "8080"})
        assert result == "tool --host example.com --port 8080"

    def test_default_value_used(self):
        m = _simple_manifest(
            "tool --rate {max_rate} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
            },
            defaults={"max_rate": "1000"},
        )
        result = build_command(m, {"target": "10.0.1.1"})
        assert result == "tool --rate 1000 10.0.1.1"

    def test_optional_arg_defaults_to_empty(self):
        m = _simple_manifest(
            "tool {flags} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
                "flags": ArgDef(name="flags", position=2, required=False, type="string", default=None),
            },
        )
        result = build_command(m, {"target": "10.0.1.1"})
        assert result == "tool 10.0.1.1"


# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

class TestMappings:
    def test_scan_type_mapping(self):
        m = _simple_manifest(
            "nmap {_scan_flags} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="scope_target"),
                "scan_type": ArgDef(
                    name="scan_type", position=2, required=True,
                    type="enum", allowed=["ping", "service", "syn"],
                ),
            },
            mappings={
                "scan_type": {
                    "ping": "-sn -PE",
                    "service": "-sT -sV --version-intensity 5",
                    "syn": "-sS --top-ports 1000",
                },
            },
        )
        result = build_command(m, {"target": "10.0.1.0/24", "scan_type": "service"})
        assert result == "nmap -sT -sV --version-intensity 5 10.0.1.0/24"

    def test_mapping_unknown_value_empty(self):
        """A mapping value not in the table resolves to empty string."""
        m = _simple_manifest(
            "tool {_mode_flags} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
                "mode": ArgDef(
                    name="mode", position=2, required=True,
                    type="enum", allowed=["a", "b", "c"],
                ),
            },
            mappings={"mode": {"a": "--alpha", "b": "--beta"}},
        )
        result = build_command(m, {"target": "x", "mode": "c"})
        # c has no mapping, so {_mode_flags} resolves to ""
        assert result == "tool x"


# ---------------------------------------------------------------------------
# Conditionals
# ---------------------------------------------------------------------------

class TestConditionals:
    def test_conditional_included_when_true(self):
        m = _simple_manifest(
            "tool {_port_flag} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
                "port": ArgDef(name="port", position=2, required=False, type="port", default="8080"),
            },
            conditionals={
                "port_flag": {"when": "port != 0", "template": "-p {port}"},
            },
        )
        result = build_command(m, {"target": "example.com", "port": "443"})
        assert result == "tool -p 443 example.com"

    def test_conditional_excluded_when_false(self):
        m = _simple_manifest(
            "tool {_port_flag} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
                "port": ArgDef(name="port", position=2, required=False, type="port", default="0"),
            },
            conditionals={
                "port_flag": {"when": "port != 0", "template": "-p {port}"},
            },
        )
        # port == 0, so conditional is false -> fragment excluded
        result = build_command(m, {"target": "example.com"})
        assert result == "tool example.com"

    def test_conditional_with_empty_string_check(self):
        m = _simple_manifest(
            "tool {_user_flag} {target}",
            args={
                "target": ArgDef(name="target", position=1, required=True, type="string"),
                "username": ArgDef(name="username", position=2, required=False, type="string"),
            },
            conditionals={
                "user_flag": {"when": "username != ''", "template": "-l {username}"},
            },
        )
        # username not provided -> empty string -> conditional false
        result = build_command(m, {"target": "10.0.1.1"})
        assert result == "tool 10.0.1.1"

        # username provided
        result = build_command(m, {"target": "10.0.1.1", "username": "admin"})
        assert result == "tool -l admin 10.0.1.1"

    def test_compound_and_condition(self):
        resolved = {"a": "1", "b": "2"}
        assert _evaluate_condition("a != '' and b != ''", resolved) is True
        assert _evaluate_condition("a != '' and b == ''", resolved) is False

    def test_compound_or_condition(self):
        resolved = {"a": "", "b": "2"}
        assert _evaluate_condition("a != '' or b != ''", resolved) is True
        assert _evaluate_condition("a != '' or b == 'x'", resolved) is False


# ---------------------------------------------------------------------------
# Validation integration
# ---------------------------------------------------------------------------

class TestValidationInBuild:
    def test_missing_required_arg(self):
        m = _simple_manifest("echo {target}")
        with pytest.raises(ValidationError, match="Missing required"):
            build_command(m, {})

    def test_invalid_arg_value(self):
        m = _simple_manifest(
            "tool -p {port}",
            args={
                "port": ArgDef(name="port", position=1, required=True, type="port"),
            },
        )
        with pytest.raises(ValidationError, match="out of range"):
            build_command(m, {"port": "99999"})

    def test_injection_blocked(self):
        m = _simple_manifest("echo {target}")
        with pytest.raises(ValidationError, match="shell metacharacters"):
            build_command(m, {"target": "hello; rm -rf /"})


# ---------------------------------------------------------------------------
# Executor escape hatch
# ---------------------------------------------------------------------------

class TestExecutorEscapeHatch:
    def test_executor_manifest_raises(self):
        m = Manifest(
            tool=ToolMeta(name="msf", version="1.0.0", binary="msfconsole"),
            command=CommandDef(executor="scripts/msf-wrapper.sh"),
        )
        with pytest.raises(ValueError, match="custom executor"):
            build_command(m, {})


# ---------------------------------------------------------------------------
# Dry-run execution
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_returns_envelope(self):
        m = _simple_manifest("echo {target}")
        envelope = execute(m, {"target": "hello"}, dry_run=True)
        assert envelope["status"] == "dry_run"
        assert envelope["tool"] == "test_tool"
        assert "echo hello" in envelope["command"]
        assert envelope["duration_ms"] == 0

    def test_dry_run_has_envelope_keys(self):
        m = _simple_manifest("echo {target}")
        envelope = execute(m, {"target": "hello"}, dry_run=True)
        expected_keys = {
            "status", "scan_id", "tool", "command",
            "duration_ms", "timestamp", "output_file",
            "output_hash", "results",
        }
        assert expected_keys.issubset(set(envelope.keys()))


# ---------------------------------------------------------------------------
# Template variable injection (secrets)
# ---------------------------------------------------------------------------

class TestInjectTemplateVars:
    def test_secret_resolved_from_env(self, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", "s3cret")
        result = inject_template_vars("Bearer {_secret:api_key}")
        assert result == "Bearer s3cret"

    def test_missing_secret_raises(self, monkeypatch):
        monkeypatch.delenv("TOOLCLAD_SECRET_MISSING", raising=False)
        with pytest.raises(RuntimeError, match="Secret 'missing' not found"):
            inject_template_vars("{_secret:missing}")

    def test_no_secret_refs_passthrough(self):
        result = inject_template_vars("just a plain string")
        assert result == "just a plain string"


# ---------------------------------------------------------------------------
# HTTP manifest execution
# ---------------------------------------------------------------------------

class TestHttpExecution:
    def _http_manifest(
        self,
        url: str = "https://api.example.com/scan",
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body_template: Optional[str] = None,
        success_status: Optional[list] = None,
    ) -> Manifest:
        return Manifest(
            tool=ToolMeta(name="http_tool", version="1.0.0", binary=""),
            http=HttpDef(
                method=method,
                url=url,
                headers=headers or {"Content-Type": "application/json"},
                body_template=body_template,
                success_status=success_status or [200],
            ),
        )

    def test_http_dry_run_returns_envelope(self):
        m = self._http_manifest()
        envelope = execute(m, {}, dry_run=True)
        assert envelope["status"] == "dry_run"
        assert envelope["tool"] == "http_tool"
        assert "http_status" in envelope
        assert "POST" in envelope["command"]

    def test_http_dry_run_interpolates_url(self):
        m = self._http_manifest(url="https://api.example.com/{target}")
        m.args = {
            "target": ArgDef(name="target", position=1, required=True, type="string"),
        }
        envelope = execute(m, {"target": "scan123"}, dry_run=True)
        assert "scan123" in envelope["command"]

    def test_http_manifest_has_http_status_key(self):
        m = self._http_manifest()
        envelope = execute(m, {}, dry_run=True)
        assert "http_status" in envelope
        assert envelope["http_status"] == 0  # not executed in dry_run


# ---------------------------------------------------------------------------
# HTTP manifest parsing from TOML
# ---------------------------------------------------------------------------

class TestHttpManifestParsing:
    def test_load_http_manifest(self, tmp_path):
        toml_content = b"""
[tool]
name = "api-check"
version = "1.0.0"
binary = ""

[http]
method = "GET"
url = "https://api.example.com/health"
success_status = [200, 204]
error_status = [500, 503]

[http.headers]
Authorization = "Bearer {_secret:token}"
"""
        p = tmp_path / "api.clad.toml"
        p.write_bytes(toml_content)

        from toolclad.manifest import load_manifest
        m = load_manifest(str(p))
        assert m.http is not None
        assert m.http.method == "GET"
        assert m.http.url == "https://api.example.com/health"
        assert m.http.success_status == [200, 204]
        assert m.http.error_status == [500, 503]
        assert m.http.headers["Authorization"] == "Bearer {_secret:token}"


# ---------------------------------------------------------------------------
# MCP proxy execution
# ---------------------------------------------------------------------------

class TestMcpProxyExecution:
    def _mcp_manifest(self) -> Manifest:
        return Manifest(
            tool=ToolMeta(name="mcp_tool", version="1.0.0", binary=""),
            mcp=McpProxyDef(
                server="security-scanner",
                tool="run_scan",
                field_map={"target": "host", "port": "port_number"},
            ),
        )

    def test_mcp_envelope_status_delegated(self):
        m = self._mcp_manifest()
        envelope = execute(m, {"target": "10.0.1.1", "port": "443"})
        assert envelope["status"] == "delegation_preview"

    def test_mcp_envelope_has_server_and_tool(self):
        m = self._mcp_manifest()
        envelope = execute(m, {"target": "10.0.1.1"})
        assert envelope["mcp_server"] == "security-scanner"
        assert envelope["mcp_tool"] == "run_scan"

    def test_mcp_field_map_applied(self):
        m = self._mcp_manifest()
        envelope = execute(m, {"target": "10.0.1.1", "port": "443"})
        assert envelope["mcp_args"]["host"] == "10.0.1.1"
        assert envelope["mcp_args"]["port_number"] == "443"

    def test_mcp_unmapped_args_passed_through(self):
        m = self._mcp_manifest()
        envelope = execute(m, {"target": "10.0.1.1", "extra": "val"})
        assert envelope["mcp_args"]["extra"] == "val"

    def test_mcp_dry_run(self):
        m = self._mcp_manifest()
        envelope = execute(m, {"target": "10.0.1.1"}, dry_run=True)
        assert envelope["status"] == "dry_run"

    def test_mcp_command_uri(self):
        m = self._mcp_manifest()
        envelope = execute(m, {})
        assert envelope["command"] == "mcp://security-scanner/run_scan"


# ---------------------------------------------------------------------------
# MCP manifest parsing from TOML
# ---------------------------------------------------------------------------

class TestMcpManifestParsing:
    def test_load_mcp_manifest(self, tmp_path):
        toml_content = b"""
[tool]
name = "mcp-proxy"
version = "1.0.0"
binary = ""

[mcp]
server = "my-server"
tool = "my-tool"

[mcp.field_map]
source = "input"
dest = "output"
"""
        p = tmp_path / "mcp.clad.toml"
        p.write_bytes(toml_content)

        from toolclad.manifest import load_manifest
        m = load_manifest(str(p))
        assert m.mcp is not None
        assert m.mcp.server == "my-server"
        assert m.mcp.tool == "my-tool"
        assert m.mcp.field_map == {"source": "input", "dest": "output"}
