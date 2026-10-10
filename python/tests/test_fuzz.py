"""Property tests for the validator and the manifest loader.

Property (SEMANTICS W13): for a string-derived type the validator either
returns a value or raises ``ValidationError`` -- never another exception --
and a returned value never carries whitespace (``msf_options`` exempt), a
quote or backslash, a control character, or a leading ``-``/``+`` unless the
argument opts in. The loader raises only ``ValueError`` (which covers TOML
decode errors) on hostile input.

No argument definition here sets ``block_internal`` and the resolver is
replaced, so no example can cause a DNS lookup.
"""

from __future__ import annotations

import json
from unittest import mock

from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from toolclad import hostpolicy
from toolclad.manifest import ArgDef, load_manifest_from_str
from toolclad.validator import ValidationError, validate_arg, validate_arg_mode

# string-derived types exercised here; credential_file is left out because it
# consults the filesystem.
FUZZ_TYPES = (
    "string", "path", "regex_match", "url", "scope_target", "duration",
    "msf_options",
)

_QUOTES = set("'\"\\")

# Unicode text, with control, format and separator characters mixed in, and
# prefixes that steer values into the type-specific parsers.
_hostile_chars = st.characters(categories=("Cc", "Cf", "Zs", "Zl", "Zp"))
_ascii = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-/:_", max_size=24)
_one_bad = st.one_of(
    st.just(""), _hostile_chars, st.sampled_from(list("'\"\\ \t\n;|&$`<>-+=%?#@[]{}")),
)
# Mostly well-formed values with at most one hostile character spliced in,
# so a fair share of examples reach the type parsers and are accepted.
_near_valid = st.builds(lambda a, c, b: a + c + b, _ascii, _one_bad, _ascii)
# Valid values of every fuzzed type, each mutated by splicing in at most one
# hostile character at a random offset.
_SEEDS = [
    "abc", "scan_01", "reports/2024/out.txt", "https://example.com/a?b=c",
    "http://93.184.216.34:8080/x", "example.com", "host-1.example.org",
    "93.184.216.34", "192.0.2.0/24", "2001:db8::1", "1h30m", "250ms", "45",
    "RHOSTS 192.0.2.1", "LPORT 4444",
]
_seeded = st.builds(
    lambda seed, i, c: seed[:i] + c + seed[i:],
    st.sampled_from(_SEEDS), st.integers(0, 32), _one_bad,
)
_text = st.one_of(
    _seeded,
    _seeded,
    _near_valid,
    st.text(),
    st.text(alphabet=_hostile_chars),
    st.lists(st.one_of(st.text(max_size=8), _hostile_chars)).map("".join),
)
_prefix = st.sampled_from(
    ["", "-", "+", "https://", "http://", "ftp://", "file://", "a", "10.", "x.example.com",
     "../", "/", "1h", "RHOSTS ", "[::1]", "%2d"]
)
_values = st.one_of(_seeded, st.builds(lambda p, t: p + t, _prefix, _text))


def _arg(arg_type: str, **kw) -> ArgDef:
    if arg_type == "regex_match":
        kw.setdefault("pattern", ".*")
    return ArgDef(name="fuzz", type=arg_type, **kw)


def _no_dns(host: str):
    raise AssertionError(f"resolver consulted for {host!r}")


def _check_hygiene(arg_type: str, out: str, allow_dash: bool) -> None:
    assert isinstance(out, str)
    if arg_type != "msf_options":
        assert not any(c.isspace() for c in out), f"whitespace in {out!r}"
    else:
        assert not any(c.isspace() and c != " " for c in out), f"non-space whitespace in {out!r}"
    assert not (set(out) & _QUOTES), f"quote or backslash in {out!r}"
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in out), f"control char in {out!r}"
    if not allow_dash:
        assert out[:1] not in ("-", "+"), f"leading dash in {out!r}"


@settings(max_examples=2000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    arg_type=st.sampled_from(FUZZ_TYPES),
    value=_values,
    allow_whitespace=st.booleans(),
)
def test_validator_property_template_mode(arg_type, value, allow_whitespace):
    # Template (strict) mode: allow_whitespace is never honored here.
    arg = _arg(arg_type, allow_whitespace=allow_whitespace)
    with mock.patch.object(hostpolicy, "resolve_host_addresses", _no_dns):
        try:
            out = validate_arg(arg, value)
        except ValidationError:
            event(f"{arg_type}: rejected")
            return
    event(f"{arg_type}: accepted")
    _check_hygiene(arg_type, out, allow_dash=False)


@settings(max_examples=1000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(arg_type=st.sampled_from(FUZZ_TYPES), value=_values)
def test_validator_property_exec_mode_opt_ins(arg_type, value):
    # Exec mode with both opt-ins: only the ASCII space may appear, and a
    # leading dash is permitted; every other rule still holds.
    arg = _arg(arg_type, allow_whitespace=True, allow_leading_dash=True)
    with mock.patch.object(hostpolicy, "resolve_host_addresses", _no_dns):
        try:
            out = validate_arg_mode(arg, value, exec_mode=True)
        except ValidationError:
            return
    assert not (set(out) & _QUOTES)
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in out)
    assert not any(c.isspace() and c != " " for c in out)
    if arg_type == "url":
        assert " " not in out


def _toml_str(s: str) -> str:
    """A TOML basic string for ``s`` (JSON escapes are valid TOML escapes;
    lone surrogates cannot be encoded and are replaced)."""
    return json.dumps(s.encode("utf-8", "replace").decode("utf-8"))


_MANIFEST = """\
[tool]
name = {name}
version = "1.0.0"
binary = {binary}

[args.target]
position = 1
required = true
type = {type}
pattern = {pattern}

[command]
exec = [{binary}, {token}]

[output]
format = "text"
"""


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    name=_values,
    binary=st.one_of(st.sampled_from(["whois", "curl", "sh", "/usr/bin/dig"]), _values),
    arg_type=st.one_of(st.sampled_from(FUZZ_TYPES + ("integer", "enum", "bogus")), _values),
    pattern=_values,
    token=st.one_of(st.sampled_from(["{target}", "-x{target}", "{_secret:k}", "{nope}"]), _values),
)
def test_manifest_loader_property(name, binary, arg_type, pattern, token):
    source = _MANIFEST.format(
        name=_toml_str(name), binary=_toml_str(binary), type=_toml_str(arg_type),
        pattern=_toml_str(pattern), token=_toml_str(token),
    )
    try:
        load_manifest_from_str(source)
    except ValueError:
        pass


@settings(max_examples=500, deadline=None)
@given(source=st.text())
def test_manifest_loader_arbitrary_text(source):
    try:
        load_manifest_from_str(source)
    except ValueError:
        pass
