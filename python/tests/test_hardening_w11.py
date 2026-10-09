"""Validator strictness shared across runtimes (W11): numeric shapes,
duration, boolean, host shape, path components, and load-time validation of
per-argument defaults. No test performs a DNS lookup."""

from __future__ import annotations

import pytest

from toolclad.manifest import ArgDef, load_manifest
from toolclad.validator import ValidationError, validate_arg


def _arg(type_: str, **kw) -> ArgDef:
    return ArgDef(name="a", type=type_, **kw)


def _ok(type_: str, value: str, expected: str, **kw) -> None:
    assert validate_arg(_arg(type_, **kw), value) == expected


def _bad(type_: str, value: str, **kw) -> None:
    with pytest.raises(ValidationError):
        validate_arg(_arg(type_, **kw), value)


@pytest.mark.parametrize(
    "value", ["", "0x10", "1_000", " 7 ", "7\n", "7 ", "1.0", "1e3", "٣", "--7", "+-7", "abc"]
)
def test_integer_rejects(value):
    _bad("integer", value)


@pytest.mark.parametrize("value,expected", [("7", "7"), ("+7", "7"), ("0", "0"), ("007", "7")])
def test_integer_accepts(value, expected):
    _ok("integer", value, expected)


def test_integer_negative_with_opt_in():
    _ok("integer", "-7", "-7", allow_leading_dash=True)


@pytest.mark.parametrize("value", ["", "+80", "-1", "0", "65536", " 80", "80\n", "8_0", "0x50", "٨٠"])
def test_port_rejects(value):
    _bad("port", value)


@pytest.mark.parametrize("value,expected", [("1", "1"), ("443", "443"), ("65535", "65535"), ("0080", "80")])
def test_port_accepts(value, expected):
    _ok("port", value, expected)


@pytest.mark.parametrize(
    "value", ["NaN", "nan", "inf", "-inf", "Infinity", "0x1p3", " 1.5", "1.5\n", "1_0.5", "", ".", "e5", "1e", "1.2.3"]
)
def test_number_rejects(value):
    _bad("number", value)


@pytest.mark.parametrize(
    "value,expected",
    [("1e2", "100"), ("0.50", "0.5"), ("1.", "1"), (".5", "0.5"), ("+2.5", "2.5"),
     ("3", "3"), ("1.25E+1", "12.5"), ("0.1", "0.1")],
)
def test_number_accepts_and_normalizes(value, expected):
    _ok("number", value, expected)


@pytest.mark.parametrize("value", ["5m\n", "1_000", " 7 ", "5 m", "", "m", "5x", "1m1h", "5ms5s", "1d"])
def test_duration_rejects(value):
    _bad("duration", value)


@pytest.mark.parametrize("value", ["30", "5m", "2h", "1h30m", "500ms", "1h2m3s4ms"])
def test_duration_accepts(value):
    _ok("duration", value, value)


@pytest.mark.parametrize("value,expected", [("True", "true"), ("FALSE", "false"), ("true", "true")])
def test_boolean_case_insensitive(value, expected):
    _ok("boolean", value, expected)


@pytest.mark.parametrize("value", ["yes", "1", "", " true"])
def test_boolean_rejects(value):
    _bad("boolean", value)


def test_trailing_dot_hostname_refused():
    _bad("scope_target", "example.com.")
    _bad("url", "https://example.com./x")


def test_ipv6_cidr_accepted():
    _ok("scope_target", "2001:db8::/32", "2001:db8::/32")
    _ok("cidr", "2001:db8::/32", "2001:db8::/32")


def test_ipv6_cidr_policy_applies():
    _bad("cidr", "fe80::/10")  # link-local: always blocked
    _bad("cidr", "fc00::/7", block_internal=True)


@pytest.mark.parametrize("value", ["..", "foo/..", "foo\\..", "../x", "a/../b", "a\\..\\b"])
def test_path_traversal_components(value):
    _bad("path", value)
    _bad("credential_file", value)


@pytest.mark.parametrize("value", ["foo..bar", "..foo", "a/b..c/d"])
def test_path_dotdot_inside_a_component_is_not_traversal(value):
    _ok("path", value, value)


# ---------------------------------------------------------------------------
# Per-argument defaults are validated at load
# ---------------------------------------------------------------------------

_DOC = """\
[tool]
name = "d"
version = "1.0.0"
binary = "echo"

[args.a]
position = 1
required = false
{arg}

[command]
exec = ["echo", "{{a}}"]

[output]
format = "text"
"""


def _load(tmp_path, arg: str):
    path = tmp_path / "d.clad.toml"
    path.write_text(_DOC.format(arg=arg))
    return load_manifest(str(path))


@pytest.mark.parametrize(
    "arg",
    [
        'type = "port"\ndefault = 0',
        'type = "integer"\nmin = 1\ndefault = 0',
        'type = "string"\ndefault = "has space"',
        'type = "integer"\ndefault = "1_000"',
        'type = "enum"\nallowed = ["a", "b"]\ndefault = "c"',
        'type = "duration"\ndefault = "5 m"',
        'type = "url"\ndefault = ""',
        'type = "string"\npattern = "^[a-z]+$"\ndefault = "ABC"',
    ],
)
def test_invalid_default_is_a_load_error(tmp_path, arg):
    with pytest.raises(ValueError, match=r"argument 'a': default .* is invalid"):
        _load(tmp_path, arg)


@pytest.mark.parametrize(
    "arg",
    [
        'type = "string"\ndefault = ""',
        'type = "port"\ndefault = 443',
        'type = "integer"\nmin = 1\nmax = 5\ndefault = 3',
        'type = "number"\ndefault = 0.5',
        'type = "boolean"\ndefault = true',
        'type = "enum"\nallowed = ["a", "b"]\ndefault = "b"',
        'type = "scope_target"\ndefault = "10.0.1.1"',
    ],
)
def test_valid_default_loads(tmp_path, arg):
    _load(tmp_path, arg)


def test_boolean_default_substituted_lowercase(tmp_path):
    from toolclad.executor import build_command_argv

    m = _load(tmp_path, 'type = "boolean"\ndefault = true')
    assert build_command_argv(m, {}) == ["echo", "true"]
