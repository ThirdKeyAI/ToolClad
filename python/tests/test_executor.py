"""Tests for ToolClad command template interpolation and execution."""

from __future__ import annotations

from typing import Dict, Optional

import pytest

from toolclad.executor import build_command, execute, _evaluate_condition
from toolclad.manifest import (
    ArgDef,
    CommandDef,
    ConditionalDef,
    EvidenceDef,
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
        assert expected_keys == set(envelope.keys())
