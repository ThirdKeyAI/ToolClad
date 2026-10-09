"""Scope enforcement (``scope_check``) and the shared scope vector file.

No test here runs a tool, opens a socket or performs a DNS lookup: every
argument either omits ``block_internal`` or carries an IP literal.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from toolclad.cli import main
from toolclad.executor import build_command_argv, execute
from toolclad.manifest import ArgDef, HttpDef, Manifest, McpProxyDef, ToolMeta, load_manifest
from toolclad.scope import (
    ScopeDef,
    ScopeError,
    cidr_within,
    discover_scope,
    host_matches_rule,
    ip_in_cidr,
    load_scope_file,
    manifest_scope,
    parse_scope,
    url_host_in_scope,
)
from toolclad.validator import ValidationError, validate_arg, validate_arg_in

_VECTORS = Path(__file__).resolve().parents[2] / "tests" / "scope_vectors.json"
_NOT_FOUND = (
    "scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)"
)


@pytest.fixture(autouse=True)
def _no_scope_env(monkeypatch):
    monkeypatch.delenv("TOOLCLAD_SCOPE_FILE", raising=False)


def _scope(**kw) -> ScopeDef:
    return parse_scope({"scope": kw})


def _arg(type_: str, **kw) -> ArgDef:
    kw.setdefault("name", "target")
    return ArgDef(type=type_, scope_check=True, **kw)


def _write_scope(directory: Path, body: str) -> Path:
    (directory / "scope").mkdir(parents=True, exist_ok=True)
    path = directory / "scope" / "scope.toml"
    path.write_text(textwrap.dedent(body))
    return path


_SCOPE_BODY = """\
[scope]
allowed_domains = ["example.com", "*.example.com"]
allowed_cidrs = ["10.0.1.0/24"]
blocked_domains = ["bad.example.com"]
blocked_cidrs = ["10.0.1.128/25"]
"""

_MANIFEST = """\
[tool]
name = "scoped"
version = "1.0.0"
binary = "echo"

[args.target]
position = 1
required = true
type = "scope_target"
scope_check = true

[command]
exec = ["echo", "{target}"]

[output]
format = "text"
"""


def _write_manifest(directory: Path, body: str = _MANIFEST) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "t.clad.toml"
    path.write_text(body)
    return str(path)


# ---------------------------------------------------------------------------
# tests/scope_vectors.json (normative, shared by every runtime)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def vectors():
    if not _VECTORS.is_file():
        pytest.skip(f"shared vector file not found at {_VECTORS}")
    return json.loads(_VECTORS.read_text())["vectors"]


class TestScopeVectors:
    def test_ipv4_in_cidr(self, vectors):
        for v in vectors["ipv4_in_cidr"]:
            assert ip_in_cidr(v["ip"], v["cidr"]) is v["expected"], v

    def test_ipv6_in_cidr(self, vectors):
        for v in vectors["ipv6_in_cidr"]:
            assert ip_in_cidr(v["ip"], v["cidr"]) is v["expected"], v

    def test_hostname_wildcard_match(self, vectors):
        for v in vectors["hostname_wildcard_match"]:
            assert host_matches_rule(v["hostname"], v["pattern"]) is v["expected"], v

    def test_scope_target_validation(self, vectors):
        arg = ArgDef(name="target", type="scope_target")
        for v in vectors["scope_target_validation"]:
            try:
                validate_arg(arg, v["value"])
                ok = True
            except ValidationError:
                ok = False
            assert ok is v["valid"], v

    def test_url_scope_check(self, vectors):
        for v in vectors["url_scope_check"]:
            assert url_host_in_scope(v["url"], v["allowed_hosts"]) is v["expected"], v
            scope = ScopeDef(allowed_domains=list(v["allowed_hosts"]))
            try:
                validate_arg_in(_arg("url"), v["url"], False, scope)
                ok = True
            except ValidationError:
                ok = False
            assert ok is v["expected"], v


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


class TestMatching:
    scope = _scope(
        allowed_domains=["example.com", "*.example.com"],
        allowed_cidrs=["10.0.1.0/24", "2001:db8::/32"],
        blocked_domains=["bad.example.com"],
        blocked_cidrs=["10.0.1.128/25"],
    )

    def ok(self, type_: str, value: str) -> None:
        assert validate_arg_in(_arg(type_), value, False, self.scope) == value

    def refused(self, type_: str, value: str, subject: str = "") -> None:
        with pytest.raises(ValidationError) as exc:
            validate_arg_in(_arg(type_), value, False, self.scope)
        assert str(exc.value) == f"argument 'target' target '{subject or value}' is not in scope"

    def test_exact_and_wildcard_domains(self):
        self.ok("scope_target", "example.com")
        self.ok("scope_target", "EXAMPLE.com")
        self.ok("scope_target", "app.example.com")
        self.ok("scope_target", "deep.sub.example.com")

    def test_label_boundary(self):
        self.refused("scope_target", "evil-example.com")
        self.refused("scope_target", "notexample.com")
        self.refused("scope_target", "example.com.evil.com")

    def test_apex_not_matched_by_wildcard(self):
        scope = _scope(allowed_domains=["*.example.com"])
        validate_arg_in(_arg("scope_target"), "a.example.com", False, scope)
        with pytest.raises(ValidationError, match="is not in scope"):
            validate_arg_in(_arg("scope_target"), "example.com", False, scope)

    def test_blocked_beats_allowed(self):
        # bad.example.com matches *.example.com but is blocked.
        self.refused("scope_target", "bad.example.com")
        self.refused("url", "https://bad.example.com/x", "bad.example.com")
        # 10.0.1.200 is in the allowed /24 but inside the blocked /25.
        self.refused("ip_address", "10.0.1.200")
        self.ok("ip_address", "10.0.1.5")

    def test_ip_rules(self):
        self.ok("scope_target", "10.0.1.1")
        self.ok("ip_address", "2001:db8::1")
        self.refused("ip_address", "10.0.2.1")
        self.refused("scope_target", "2001:db9::1")

    def test_mapped_ipv6_compared_as_ipv4(self):
        self.ok("ip_address", "::ffff:10.0.1.5")
        self.refused("ip_address", "::ffff:10.0.1.200")

    def test_cidr_full_containment(self):
        self.ok("cidr", "10.0.1.0/26")
        self.ok("scope_target", "10.0.1.0/25")
        self.refused("cidr", "10.0.0.0/8")
        self.refused("cidr", "10.0.0.0/16")
        # Overlapping a blocked range at all is a refusal.
        self.refused("cidr", "10.0.1.0/24")
        self.ok("cidr", "2001:db8:1::/48")
        self.refused("cidr", "2001:db8::/31")
        assert cidr_within("10.0.1.0/25", "10.0.1.0/24")
        assert not cidr_within("10.0.0.0/8", "10.0.1.0/24")

    def test_url_host_is_the_subject(self):
        self.ok("url", "https://api.example.com/v1?q=1")
        self.ok("url", "http://10.0.1.7:8080/")
        self.refused("url", "https://evil.com/api", "evil.com")
        self.refused("url", "https://api.example.com.evil.com/v1", "api.example.com.evil.com")

    def test_domain_rules_do_not_match_ips(self):
        scope = _scope(allowed_domains=["example.com"])
        with pytest.raises(ValidationError, match="is not in scope"):
            validate_arg_in(_arg("ip_address"), "10.0.1.1", False, scope)

    def test_empty_allowed_lists_mean_nothing_in_scope(self):
        scope = _scope()
        for type_, value in (
            ("scope_target", "example.com"),
            ("ip_address", "10.0.1.1"),
            ("cidr", "10.0.1.0/24"),
            ("url", "https://example.com/"),
        ):
            with pytest.raises(ValidationError, match="is not in scope"):
                validate_arg_in(_arg(type_), value, False, scope)

    def test_fail_closed_without_scope(self):
        for type_, value in (("scope_target", "example.com"), ("url", "https://example.com/")):
            with pytest.raises(ValidationError) as exc:
                validate_arg_in(_arg(type_), value, False, None)
            assert str(exc.value) == f"argument 'target' {_NOT_FOUND}"
        # The legacy entry points carry no scope, so they fail closed too.
        with pytest.raises(ValidationError, match="no scope/scope.toml was found"):
            validate_arg(_arg("scope_target"), "example.com")

    def test_scope_check_off_ignores_scope(self):
        assert validate_arg_in(ArgDef(name="t", type="scope_target"), "evil.com", False, None)

    def test_in_scope_but_internal_still_refused(self):
        scope = _scope(allowed_cidrs=["127.0.0.0/8", "10.0.1.0/24"])
        arg = _arg("ip_address", block_internal=True)
        with pytest.raises(ValidationError, match="block_internal"):
            validate_arg_in(arg, "127.0.0.1", False, scope)
        with pytest.raises(ValidationError, match="block_internal"):
            validate_arg_in(arg, "10.0.1.1", False, scope)
        # And an allowed-by-policy public IP outside scope is refused by scope.
        with pytest.raises(ValidationError, match="is not in scope"):
            validate_arg_in(arg, "8.8.8.8", False, scope)

    def test_link_local_refused_even_when_in_scope(self):
        scope = _scope(allowed_cidrs=["169.254.0.0/16"])
        with pytest.raises(ValidationError, match="always blocked"):
            validate_arg_in(_arg("ip_address"), "169.254.169.254", False, scope)

    def test_unsupported_type_at_call(self):
        with pytest.raises(ValidationError, match="scope_check is not supported for type 'string'"):
            validate_arg_in(_arg("string"), "x", False, _scope())


# ---------------------------------------------------------------------------
# Scope file parsing
# ---------------------------------------------------------------------------


class TestScopeFile:
    def test_loads_repository_style_file(self, tmp_path):
        scope = load_scope_file(_write_scope(tmp_path, _SCOPE_BODY))
        assert scope.allowed_domains == ["example.com", "*.example.com"]
        assert [str(n) for n in scope.allowed_cidrs] == ["10.0.1.0/24"]
        assert [str(n) for n in scope.blocked_cidrs] == ["10.0.1.128/25"]

    def test_unknown_key_is_a_load_error(self, tmp_path):
        path = _write_scope(tmp_path, '[scope]\nallowed_domain = ["x.com"]\n')
        with pytest.raises(ScopeError, match=r"unknown key 'scope\.allowed_domain'"):
            load_scope_file(path)
        path = _write_scope(tmp_path, '[scope]\n\n[extra]\nk = 1\n')
        with pytest.raises(ScopeError, match=r"unknown key 'extra'"):
            load_scope_file(path)

    @pytest.mark.parametrize("cidr", ["10.0.1.0/33", "10.0.1/24", "10.0.1.0", "010.0.1.0/24", "x/8"])
    def test_malformed_cidr_is_a_load_error(self, cidr):
        with pytest.raises(ScopeError, match="invalid CIDR"):
            _scope(allowed_cidrs=[cidr])
        with pytest.raises(ScopeError, match="invalid CIDR"):
            _scope(blocked_cidrs=[cidr])

    @pytest.mark.parametrize(
        "rule", ["*", "*example.com", "a.*.example.com", "example.*", "**.example.com",
                 "Example.com", "exa mple.com", "example.com/x", "", "*."]
    )
    def test_bad_domain_rule_is_a_load_error(self, rule):
        with pytest.raises(ScopeError, match="invalid domain rule"):
            _scope(allowed_domains=[rule])
        with pytest.raises(ScopeError, match="invalid domain rule"):
            _scope(blocked_domains=[rule])

    def test_non_list_value_is_a_load_error(self):
        with pytest.raises(ScopeError, match="must be a list of strings"):
            _scope(allowed_domains="example.com")

    def test_invalid_toml_is_a_load_error(self, tmp_path):
        path = _write_scope(tmp_path, "[scope\n")
        with pytest.raises(ScopeError, match="not valid TOML"):
            load_scope_file(path)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_env_var_wins(self, tmp_path, monkeypatch):
        _write_scope(tmp_path / "proj", '[scope]\nallowed_domains = ["walk.example"]\n')
        env_file = _write_scope(tmp_path / "other", '[scope]\nallowed_domains = ["env.example"]\n')
        monkeypatch.setenv("TOOLCLAD_SCOPE_FILE", str(env_file))
        assert discover_scope(tmp_path / "proj").allowed_domains == ["env.example"]

    def test_env_var_relative_path(self, tmp_path, monkeypatch):
        _write_scope(tmp_path, '[scope]\nallowed_domains = ["rel.example"]\n')
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("TOOLCLAD_SCOPE_FILE", "scope/scope.toml")
        assert discover_scope(None).allowed_domains == ["rel.example"]

    def test_unreadable_env_var_is_an_error(self, tmp_path, monkeypatch):
        _write_scope(tmp_path, '[scope]\nallowed_domains = ["walk.example"]\n')
        monkeypatch.setenv("TOOLCLAD_SCOPE_FILE", str(tmp_path / "missing.toml"))
        with pytest.raises(ScopeError, match="cannot read scope file"):
            discover_scope(tmp_path)

    def test_upward_walk_finds_parent_scope(self, tmp_path):
        _write_scope(tmp_path, '[scope]\nallowed_domains = ["up.example"]\n')
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert discover_scope(nested).allowed_domains == ["up.example"]

    def test_nearest_scope_wins(self, tmp_path):
        _write_scope(tmp_path, '[scope]\nallowed_domains = ["far.example"]\n')
        _write_scope(tmp_path / "a", '[scope]\nallowed_domains = ["near.example"]\n')
        (tmp_path / "a" / "b").mkdir()
        assert discover_scope(tmp_path / "a" / "b").allowed_domains == ["near.example"]

    def test_none_found(self, tmp_path):
        if discover_scope(tmp_path) is not None:
            pytest.skip("a scope/scope.toml exists above the temp directory")
        assert discover_scope(tmp_path) is None

    def test_manifest_from_string_walks_from_cwd(self, tmp_path, monkeypatch):
        _write_scope(tmp_path, '[scope]\nallowed_domains = ["cwd.example"]\n')
        monkeypatch.chdir(tmp_path)
        m = Manifest(args={"target": _arg("scope_target")})
        assert manifest_scope(m).allowed_domains == ["cwd.example"]

    def test_manifest_scope_is_cached(self, tmp_path):
        path = _write_scope(tmp_path, '[scope]\nallowed_domains = ["one.example"]\n')
        m = load_manifest(_write_manifest(tmp_path / "tools"))
        first = manifest_scope(m)
        path.write_text('[scope]\nallowed_domains = ["two.example"]\n')
        assert manifest_scope(m) is first

    def test_no_discovery_without_scope_check(self, tmp_path, monkeypatch):
        # A broken TOOLCLAD_SCOPE_FILE does not affect a manifest that never
        # asks for scope.
        monkeypatch.setenv("TOOLCLAD_SCOPE_FILE", str(tmp_path / "missing.toml"))
        m = Manifest(args={"t": ArgDef(name="t", type="scope_target")})
        assert manifest_scope(m) is None


# ---------------------------------------------------------------------------
# Load-time checks and the executor / CLI paths
# ---------------------------------------------------------------------------


class TestWiring:
    @pytest.mark.parametrize("type_", ["string", "integer", "port", "path", "enum", "boolean"])
    def test_scope_check_on_unsupported_type_is_a_load_error(self, tmp_path, type_):
        extra = 'allowed = ["a"]\n' if type_ == "enum" else ""
        body = _MANIFEST.replace('type = "scope_target"', f'type = "{type_}"\n{extra}')
        with pytest.raises(ValueError, match=f"scope_check is not supported for type '{type_}'"):
            load_manifest(_write_manifest(tmp_path, body))

    def test_exec_path_enforces_scope(self, tmp_path):
        _write_scope(tmp_path, _SCOPE_BODY)
        m = load_manifest(_write_manifest(tmp_path / "tools"))
        assert build_command_argv(m, {"target": "app.example.com"}) == ["echo", "app.example.com"]
        with pytest.raises(ValidationError, match="target 'evil.com' is not in scope"):
            build_command_argv(m, {"target": "evil.com"})
        with pytest.raises(ValidationError, match="is not in scope"):
            execute(m, {"target": "bad.example.com"}, dry_run=True)

    def test_exec_path_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SCOPE_FILE", str(tmp_path / "nope.toml"))
        m = load_manifest(_write_manifest(tmp_path))
        with pytest.raises(ScopeError, match="cannot read scope file"):
            execute(m, {"target": "example.com"}, dry_run=True)

    def test_exec_path_fails_closed_with_no_file_anywhere(self, tmp_path):
        if discover_scope(tmp_path) is not None:
            pytest.skip("a scope/scope.toml exists above the temp directory")
        m = load_manifest(_write_manifest(tmp_path))
        with pytest.raises(ValidationError) as exc:
            execute(m, {"target": "example.com"}, dry_run=True)
        assert str(exc.value) == f"argument 'target' {_NOT_FOUND}"

    def test_default_is_scope_checked_at_call(self, tmp_path):
        _write_scope(tmp_path, _SCOPE_BODY)
        body = _MANIFEST.replace("required = true", 'required = false\ndefault = "evil.com"')
        m = load_manifest(_write_manifest(tmp_path / "tools", body))
        with pytest.raises(ValidationError, match="target 'evil.com' is not in scope"):
            build_command_argv(m, {})

    def test_executor_path_enforces_scope(self, tmp_path):
        _write_scope(tmp_path, _SCOPE_BODY)
        body = _MANIFEST.replace('exec = ["echo", "{target}"]', 'executor = "/bin/true"')
        m = load_manifest(_write_manifest(tmp_path / "tools", body))
        assert execute(m, {"target": "example.com"}, dry_run=True)["status"] == "dry_run"
        with pytest.raises(ValidationError, match="is not in scope"):
            execute(m, {"target": "evil.com"}, dry_run=True)

    def _http(self, scope: ScopeDef) -> Manifest:
        m = Manifest(
            tool=ToolMeta(name="h", version="1", binary=""),
            http=HttpDef(method="GET", url="https://api.example.com/?u={target}"),
            args={"target": _arg("url", required=True)},
        )
        object.__setattr__(m, "_scope_cache", scope)
        return m

    def test_http_path_enforces_scope(self):
        m = self._http(_scope(allowed_domains=["*.example.com"]))
        env = execute(m, {"target": "https://a.example.com/"}, dry_run=True)
        assert env["command"] == "GET https://api.example.com/?u=https://a.example.com/"
        with pytest.raises(ValidationError, match="target 'evil.com' is not in scope"):
            execute(m, {"target": "https://evil.com/"}, dry_run=True)

    def test_http_path_validates_every_type(self):
        m = Manifest(
            tool=ToolMeta(name="h", version="1", binary=""),
            http=HttpDef(method="GET", url="https://api.example.com/{n}"),
            args={"n": ArgDef(name="n", type="integer", required=True)},
        )
        with pytest.raises(ValidationError, match="Expected integer"):
            execute(m, {"n": "1/../admin"}, dry_run=True)
        with pytest.raises(ValidationError, match="Missing required argument"):
            execute(m, {}, dry_run=True)
        assert execute(m, {"n": "+7"}, dry_run=True)["command"] == "GET https://api.example.com/7"

    def test_mcp_path_enforces_scope(self):
        m = Manifest(
            tool=ToolMeta(name="m", version="1", binary=""),
            mcp=McpProxyDef(server="s", tool="t", field_map={"target": "host"}),
            args={"target": _arg("scope_target", required=True)},
        )
        object.__setattr__(m, "_scope_cache", _scope(allowed_cidrs=["10.0.1.0/24"]))
        assert execute(m, {"target": "10.0.1.1"})["mcp_args"] == {"host": "10.0.1.1"}
        with pytest.raises(ValidationError, match="is not in scope"):
            execute(m, {"target": "10.9.9.9"})

    def test_cli_test_enforces_scope(self, tmp_path):
        _write_scope(tmp_path, _SCOPE_BODY)
        path = _write_manifest(tmp_path / "tools")
        ok = CliRunner().invoke(main, ["test", path, "--arg", "target=example.com"])
        assert ok.exit_code == 0, ok.output
        bad = CliRunner().invoke(main, ["test", path, "--arg", "target=evil.com"])
        assert bad.exit_code == 1
        assert "is not in scope" in bad.output

    def test_cli_run_enforces_scope(self, tmp_path):
        _write_scope(tmp_path, _SCOPE_BODY)
        path = _write_manifest(tmp_path / "tools")
        bad = CliRunner().invoke(main, ["run", path, "--arg", "target=evil.com"])
        assert bad.exit_code == 1
        assert "is not in scope" in bad.output
