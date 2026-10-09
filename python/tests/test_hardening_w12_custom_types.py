"""TC-23: the CLI and the loaders discover ``toolclad.toml``, argument types
are checked at load, and the shipped examples load and dry-run end to end.

No tool is ever executed: the example assertions use ``toolclad test`` (a dry
run that only builds argv). The only network activity is the optional
``example.com`` lookup that ``block_internal`` performs for the curl example;
that single assertion is skipped when DNS is unavailable.
"""

from __future__ import annotations

import importlib.metadata
import json
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

import toolclad
from toolclad.cli import main
from toolclad.executor import build_command_argv
from toolclad.manifest import (
    CONFIG_FILE_ENV,
    CustomTypeDef,
    LoadOptions,
    discover_custom_types,
    load_custom_types,
    load_manifest,
    load_manifest_from_str,
    load_manifest_with_options,
)
from toolclad.validator import ValidationError

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
EXAMPLE_NAMES = (
    "curl_fetch", "dig_lookup", "nikto_scan", "nmap_scan", "whois_lookup",
)


@pytest.fixture(autouse=True)
def _no_config_env(monkeypatch):
    monkeypatch.delenv(CONFIG_FILE_ENV, raising=False)
    monkeypatch.delenv("TOOLCLAD_SCOPE_FILE", raising=False)


def _examples_dir() -> Path:
    if not EXAMPLES.is_dir():
        pytest.skip(f"examples directory not found at {EXAMPLES} (not a repository checkout)")
    return EXAMPLES


def _cli(*argv: str):
    return CliRunner().invoke(main, list(argv))


def _argv_of(output: str) -> list:
    for line in output.splitlines():
        if line.strip().startswith("Argv:"):
            return json.loads(line.split("Argv:", 1)[1])
    raise AssertionError(f"no Argv line in output:\n{output}")


_ONESHOT = (
    '[tool]\nname = "t"\nversion = "1.0.0"\nbinary = "whois"\n'
    '[args.x]\nposition = 1\nrequired = true\ntype = "{t}"\n{extra}\n'
    '[command]\nexec = ["whois", "{{x}}"]\n'
    '[output]\nformat = "text"\n'
)


def _write(tmp_path: Path, arg_type: str, extra: str = "") -> Path:
    p = tmp_path / "t.clad.toml"
    p.write_text(_ONESHOT.format(t=arg_type, extra=extra))
    return p


# ---------------------------------------------------------------------------
# L1 discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_absent_config_means_no_custom_types(self, tmp_path):
        assert discover_custom_types(tmp_path) == {}

    def test_walks_up_from_manifest_directory(self, tmp_path):
        (tmp_path / "toolclad.toml").write_text('[types.ident]\nbase = "string"\npattern = "[a-z]+"\n')
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        p = sub / "t.clad.toml"
        p.write_text(_ONESHOT.format(t="ident", extra=""))
        m = load_manifest(str(p))
        assert set(m.custom_types) == {"ident"}
        assert build_command_argv(m, {"x": "abc"}) == ["whois", "abc"]
        with pytest.raises(ValidationError):
            build_command_argv(m, {"x": "abc1"})

    def test_env_var_wins(self, tmp_path, monkeypatch):
        (tmp_path / "toolclad.toml").write_text('[types.other]\nbase = "string"\n')
        cfg = tmp_path / "elsewhere.toml"
        cfg.write_text('[types.ident]\nbase = "string"\n')
        monkeypatch.setenv(CONFIG_FILE_ENV, str(cfg))
        assert set(discover_custom_types(tmp_path)) == {"ident"}

    def test_env_var_unreadable_is_an_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_FILE_ENV, str(tmp_path / "missing.toml"))
        with pytest.raises(ValueError, match=CONFIG_FILE_ENV):
            discover_custom_types(tmp_path)
        with pytest.raises(ValueError, match=CONFIG_FILE_ENV):
            load_manifest(str(_write(tmp_path, "string")))

    @pytest.mark.parametrize(
        "text, needle",
        [
            ('[types.a]\nbase = "string"\nblock_internal = true\n', "unknown key 'types.a.block_internal'"),
            ('[types.a]\nbase = "string"\nscope_check = true\n', "unknown key 'types.a.scope_check'"),
            ('[other]\nx = 1\n', "unknown key 'other'"),
            ('[types.a]\nbase = "nope"\n', "invalid base type 'nope'"),
            ('[types.a]\nbase = "string"\n[types.b]\nbase = "a"\n', "invalid base type 'a'"),
            ('[types.a]\n', "invalid base type ''"),
        ],
    )
    def test_config_is_strict(self, tmp_path, text, needle):
        cfg = tmp_path / "toolclad.toml"
        cfg.write_text(text)
        with pytest.raises(ValueError, match=needle):
            load_custom_types(str(cfg))
        with pytest.raises(ValueError, match=needle):
            load_manifest(str(_write(tmp_path, "string")))


# ---------------------------------------------------------------------------
# L2 load-time type checking
# ---------------------------------------------------------------------------


class TestLoadTimeTypes:
    def test_unknown_type_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError) as exc:
            load_manifest(str(_write(tmp_path, "port_range")))
        assert str(exc.value) == "unknown type 'port_range' for argument 'x'"

    def test_unknown_type_refused_by_string_loader(self):
        with pytest.raises(ValueError, match="unknown type 'bogus' for argument 'x'"):
            load_manifest_from_str(_ONESHOT.format(t="bogus", extra=""))

    def test_override_supplies_custom_types(self, tmp_path):
        opts = LoadOptions(custom_types={"ident": CustomTypeDef(base="string")})
        m = load_manifest_with_options(str(_write(tmp_path, "ident")), opts)
        assert "ident" in m.custom_types
        m2 = load_manifest_from_str(_ONESHOT.format(t="ident", extra=""), opts)
        assert "ident" in m2.custom_types

    def test_session_command_arg_type_checked(self):
        text = (
            '[tool]\nname = "s"\nversion = "1"\nbinary = "psql"\n'
            '[session]\nstartup_command = "psql"\nready_pattern = "^> $"\n'
            '[session.commands.q]\npattern = "^select .*$"\n'
            '[session.commands.q.args.t]\ntype = "nonesuch"\n'
            '[output]\nformat = "text"\n'
        )
        with pytest.raises(ValueError, match="unknown type 'nonesuch' for argument 't'"):
            load_manifest_from_str(text)

    def test_browser_command_arg_type_checked(self):
        text = (
            '[tool]\nname = "b"\nversion = "1"\n'
            '[browser]\nengine = "cdp"\n'
            '[browser.commands.go]\ndescription = "x"\n'
            '[browser.commands.go.args.u]\ntype = "weburl"\n'
            '[output]\nformat = "text"\n'
        )
        with pytest.raises(ValueError, match="unknown type 'weburl' for argument 'u'"):
            load_manifest_from_str(text)

    def test_custom_typed_default_is_validated_at_load(self, tmp_path):
        (tmp_path / "toolclad.toml").write_text('[types.ident]\nbase = "string"\npattern = "[a-z]+"\n')
        with pytest.raises(ValueError, match="default"):
            load_manifest(str(_write(tmp_path, "ident", 'default = "ABC"')))


# ---------------------------------------------------------------------------
# L4 the shipped examples, through the CLI's own discovery path
# ---------------------------------------------------------------------------


class TestExamples:
    @pytest.mark.parametrize("name", EXAMPLE_NAMES)
    def test_validate_every_example(self, name):
        path = _examples_dir() / f"{name}.clad.toml"
        result = _cli("validate", str(path))
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_nikto_custom_types_build_argv(self):
        path = _examples_dir() / "nikto_scan.clad.toml"
        result = _cli(
            "test", str(path), "--arg", "target=93.184.216.34", "--arg", "port=8080-8090",
            "--arg", "protocol=https", "--arg", "max_rate=250",
        )
        assert result.exit_code == 0, result.output
        argv = _argv_of(result.output)
        for token in ("-h", "https://93.184.216.34:8080-8090", "-Plugins", "@@ALL", "-maxrate", "250"):
            assert token in argv, (token, argv)
        # Never executed; nikto is only named in argv.
        assert argv[0] == "nikto"

    @pytest.mark.parametrize("port", ["80;id", "80abc", "80-90-100"])
    def test_nikto_port_range_is_anchored(self, port):
        path = _examples_dir() / "nikto_scan.clad.toml"
        result = _cli("test", str(path), "--arg", "target=93.184.216.34", "--arg", f"port={port}")
        assert result.exit_code == 1, result.output
        assert "FAIL" in result.output

    def test_curl_public_ip_out_of_scope(self):
        path = _examples_dir() / "curl_fetch.clad.toml"
        result = _cli("test", str(path), "--arg", "url=https://93.184.216.34/")
        assert result.exit_code == 1, result.output
        assert "not in scope" in result.output

    def test_curl_example_com_in_scope(self):
        try:
            socket.getaddrinfo("example.com", 443)
        except OSError:
            pytest.skip("example.com does not resolve (offline); block_internal needs DNS for this case")
        path = _examples_dir() / "curl_fetch.clad.toml"
        result = _cli("test", str(path), "--arg", "url=https://example.com/")
        assert result.exit_code == 0, result.output
        assert "https://example.com/" in _argv_of(result.output)

    def test_schema_of_custom_typed_example(self):
        path = _examples_dir() / "nikto_scan.clad.toml"
        result = _cli("schema", str(path))
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["name"] == "nikto_scan"


# ---------------------------------------------------------------------------
# L5 version
# ---------------------------------------------------------------------------


def test_version_matches_installed_package():
    assert toolclad.__version__ == importlib.metadata.version("toolclad")


def test_cli_version_matches_package():
    result = _cli("--version")
    assert result.exit_code == 0
    assert toolclad.__version__ in result.output
