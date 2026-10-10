"""Tests for the structural ``url`` validator, the shared host / IP egress
policy and ``{_secret:…}`` ordering in the HTTP backend.

Covers the ``url-`` vectors of the shared injection suite (asserted inline
here; the shared JSON file is read in a later wave), the scheme allowlist
and denylist, userinfo and port handling, the range table in
``toolclad.hostpolicy`` applied to ``url``, ``scope_target``, ``ip_address``
and ``cidr``, the canonical-literal parsers in front of it, and the rule
that manifest secrets are expanded before argument interpolation.

No network tool is ever executed and no request is ever made: every HTTP
manifest here runs with ``dry_run=True`` or against a stubbed ``urlopen``
that records the built request and touches no socket.
"""

from __future__ import annotations

import ipaddress
import textwrap

import pytest

from toolclad.executor import _interpolate_http, build_command_argv, execute
from toolclad.hostpolicy import (
    ALWAYS_BLOCKED_V4,
    ALWAYS_BLOCKED_V6,
    BLOCK_INTERNAL_V4,
    BLOCK_INTERNAL_V6,
    always_blocked_ip_reason,
    enforce_ip_policy,
    has_punycode_label,
    looks_like_ip_literal,
    non_public_ip_reason,
    parse_canonical_cidr,
    parse_canonical_ip,
    tld_not_all_numeric,
)
from toolclad.manifest import ArgDef, HttpDef, Manifest, ToolMeta, load_manifest
from toolclad.validator import ValidationError, _split_url_authority, validate_arg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _arg(type: str, **kwargs) -> ArgDef:  # noqa: A002
    return ArgDef(name="test", type=type, **kwargs)


def _ip(text: str):
    return ipaddress.ip_address(text)


def _rejects(arg_def: ArgDef, value: str, *needles: str) -> str:
    """Assert ``value`` is refused and every needle appears in the message."""
    with pytest.raises(ValidationError) as exc:
        validate_arg(arg_def, value)
    msg = str(exc.value)
    for needle in needles:
        assert needle in msg, f"{value!r}: expected {needle!r} in {msg!r}"
    return msg


# ---------------------------------------------------------------------------
# The url- vectors of the shared injection suite
# ---------------------------------------------------------------------------

# (id, arg fields, value, expectation). A local cross-check of the url-
# vectors in tests/injection_vectors.json; the whole file is consumed by
# test_injection_vectors.py.
_URL_VECTORS = [
    ("url-space-option-injection", {}, "https://attacker.example/ -o /root/.ssh/authorized_keys", "reject"),
    ("url-space-write-tmp", {}, "https://attacker.example/ -o /tmp/pwned", "reject"),
    ("url-secret-smuggling", {}, "https://attacker.example/?k={_secret:api_key}", "reject"),
    ("url-javascript-scheme", {}, "javascript:alert(1)", "reject"),
    ("url-file-scheme", {}, "file:///etc/passwd", "reject"),
    ("url-data-scheme", {}, "data:text/html,<script>1</script>", "reject"),
    ("url-gopher-redis", {}, "gopher://127.0.0.1:6379/_FLUSHALL", "reject"),
    ("url-dict-scheme", {}, "dict://127.0.0.1:11211/stat", "reject"),
    ("url-userinfo", {}, "http://user:pw@example.com/", "reject"),
    ("url-metacharacter", {}, "https://attacker.example/;id", "reject"),
    ("url-scheme-not-in-list", {"schemes": ["https"]}, "http://example.com/", "reject"),
    ("url-imds-always-blocked", {}, "http://169.254.169.254/latest/meta-data/", "reject"),
    ("url-docker-socket-block-internal", {"block_internal": True}, "http://127.0.0.1:2375/containers/json", "reject"),
    ("url-ipv6-loopback-block-internal", {"block_internal": True}, "http://[::1]:8080/", "reject"),
    ("url-accept", {}, "https://example.com/path", "accept"),
    ("url-accept-public-ip-block-internal", {"block_internal": True}, "https://93.184.216.34/x", "accept"),
]


class TestUrlInjectionVectors:
    @pytest.mark.parametrize(
        "vector_id,fields,value,expect",
        _URL_VECTORS,
        ids=[v[0] for v in _URL_VECTORS],
    )
    def test_vector(self, vector_id, fields, value, expect):
        arg_def = _arg("url", **fields)
        if expect == "accept":
            assert validate_arg(arg_def, value) == value
        else:
            with pytest.raises(ValidationError):
                validate_arg(arg_def, value)

    def test_every_vector_id_is_covered_once(self):
        ids = [v[0] for v in _URL_VECTORS]
        assert len(ids) == len(set(ids)) == 16


# ---------------------------------------------------------------------------
# Structural parse: scheme, denylist, userinfo, host, port
# ---------------------------------------------------------------------------

class TestUrlStructure:
    def test_requires_scheme_separator(self):
        _rejects(_arg("url"), "not-a-url", "Invalid URL", "scheme://host")
        _rejects(_arg("url"), "example.com/path", "Invalid URL")
        _rejects(_arg("url"), "http:/example.com", "Invalid URL")

    def test_default_schemes_are_http_and_https(self):
        assert validate_arg(_arg("url"), "http://example.com/") == "http://example.com/"
        assert validate_arg(_arg("url"), "https://example.com/") == "https://example.com/"
        _rejects(_arg("url"), "ftp://example.com/", "scheme 'ftp'", "not permitted", "http, https")
        _rejects(_arg("url"), "ssh://example.com/", "scheme 'ssh'", "not permitted")

    def test_schemes_list_is_honored(self):
        # The regression the shared suite pins: a manifest that allows only
        # https must refuse http.
        _rejects(_arg("url", schemes=["https"]), "http://example.com/", "scheme 'http'", "allowed: https")
        assert validate_arg(_arg("url", schemes=["https"]), "https://example.com/")
        # A listed non-default scheme is admitted as long as it is not denied.
        assert validate_arg(_arg("url", schemes=["sftp"]), "sftp://example.com/x")
        _rejects(_arg("url", schemes=["sftp"]), "https://example.com/", "allowed: sftp")

    def test_scheme_comparison_is_case_insensitive(self):
        assert validate_arg(_arg("url"), "HTTPS://Example.COM/x") == "HTTPS://Example.COM/x"
        assert validate_arg(_arg("url", schemes=["https"]), "HTTPS://example.com/")
        assert validate_arg(_arg("url", schemes=["HTTPS"]), "https://example.com/")

    @pytest.mark.parametrize(
        "scheme",
        ["javascript", "data", "file", "blob", "about", "gopher", "dict", "ftp",
         "ldap", "jar", "netdoc", "mailto", "ws", "wss"],
    )
    def test_denied_scheme_is_refused_even_when_listed(self, scheme):
        _rejects(
            _arg("url", schemes=[scheme, "https"]),
            f"{scheme}://example.com/x",
            f"scheme '{scheme}'",
            "never permitted",
        )

    def test_file_scheme_to_localhost(self):
        _rejects(_arg("url"), "file://localhost/etc/passwd", "scheme 'file'")
        _rejects(_arg("url", schemes=["file"]), "file://localhost/etc/passwd", "never permitted")

    def test_userinfo_rejected(self):
        _rejects(_arg("url"), "http://user:pw@example.com/", "userinfo")
        _rejects(_arg("url"), "http://example.com@evil.example/", "userinfo")
        _rejects(_arg("url"), "https://example.com@93.184.216.34:8080/x", "userinfo")

    def test_at_sign_after_authority_is_not_userinfo(self):
        assert validate_arg(_arg("url"), "https://example.com/@handle")
        assert validate_arg(_arg("url"), "https://example.com?u=a@b")
        assert validate_arg(_arg("url"), "https://example.com#@frag")

    def test_host_ends_at_path_query_or_fragment(self):
        assert validate_arg(_arg("url"), "https://example.com/a/b")
        assert validate_arg(_arg("url"), "https://example.com?x=1")
        assert validate_arg(_arg("url"), "https://example.com#top")
        assert validate_arg(_arg("url"), "https://example.com")

    def test_empty_host_rejected(self):
        for value in ("http://", "http:///path", "http://:80/", "http://?x=1", "http://#f"):
            _rejects(_arg("url"), value, "empty host")

    def test_explicit_port_accepted(self):
        assert validate_arg(_arg("url"), "https://example.com:8443/x") == "https://example.com:8443/x"
        assert validate_arg(_arg("url"), "http://example.com:1/")
        assert validate_arg(_arg("url"), "http://example.com:65535/")
        assert validate_arg(_arg("url"), "https://93.184.216.34:8443/x")

    @pytest.mark.parametrize(
        "value",
        [
            "https://example.com:0/x",
            "https://example.com:99999/x",
            "https://example.com:65536/x",
            "https://example.com:/x",
            "https://example.com:8a/x",
            "https://example.com:+80/x",
            "https://example.com:" + "9" * 5000 + "/x",
        ],
    )
    def test_bad_port_rejected(self, value):
        _rejects(_arg("url"), value, "port must be 1-65535")

    def test_unbracketed_ipv6_host_rejected(self):
        _rejects(_arg("url"), "http://::1/", "enclosed in brackets")
        _rejects(_arg("url"), "http://fe80::1:80/", "enclosed in brackets")

    def test_bracketed_ipv6_url_is_refused_at_the_metacharacter_stage(self):
        # `[` and `]` are shell metacharacters in every runtime, so a
        # bracketed literal never reaches the policy through validate_arg;
        # the authority splitter below is exercised directly.
        _rejects(_arg("url"), "http://[::1]:8080/", "shell metacharacters")
        _rejects(_arg("url", block_internal=True), "http://[::1]:8080/", "shell metacharacters")
        _rejects(_arg("url"), "http://[::ffff:169.254.169.254]/", "shell metacharacters")

    def test_authority_splitter_unwraps_bracketed_ipv6(self):
        assert _split_url_authority("[::1]:8080") == ("::1", 8080, ipaddress.IPv6Address("::1"))
        assert _split_url_authority("[::1]") == ("::1", None, ipaddress.IPv6Address("::1"))
        assert _split_url_authority("example.com:8080") == ("example.com", 8080, None)
        assert _split_url_authority("example.com") == ("example.com", None, None)
        assert _split_url_authority("93.184.216.34") == ("93.184.216.34", None, None)

    @pytest.mark.parametrize(
        "authority,needle",
        [
            ("[::1", "malformed bracketed IPv6"),
            ("[::1]x", "malformed bracketed IPv6"),
            ("[example]", "not a valid IPv6 literal"),
            ("[127.0.0.1]", "not a valid IPv6 literal"),
            ("[fe80::1%eth0]", "not a valid IPv6 literal"),
            ("[]", "not a valid IPv6 literal"),
            ("[::1]:", "port must be 1-65535"),
            ("[::1]:0", "port must be 1-65535"),
            ("", "empty host"),
            (":80", "empty host"),
            ("a:b:c", "enclosed in brackets"),
        ],
    )
    def test_authority_splitter_rejects_malformed_shapes(self, authority, needle):
        with pytest.raises(ValidationError, match=needle):
            _split_url_authority(authority)

    def test_bracketed_ipv6_policy_through_the_splitter(self):
        # What the policy would say for a bracketed loopback once the
        # splitter has unwrapped it.
        host, port, v6 = _split_url_authority("[::1]:8080")
        assert (host, port) == ("::1", 8080)
        with pytest.raises(ValidationError, match="IPv6 loopback ::1"):
            enforce_ip_policy("test", v6, True)
        enforce_ip_policy("test", v6, False)
        _, _, mapped = _split_url_authority("[::ffff:169.254.169.254]")
        with pytest.raises(ValidationError, match="always blocked"):
            enforce_ip_policy("test", mapped, False)

    @pytest.mark.parametrize(
        "value",
        [
            "http://", "http:///", "http://[", "http://]", "http://[]", "http://:",
            "http://a:b:c", "://", "http://" + "a" * 300 + "/", "http://..",
            "http://a..b/", "http://-a.com/", "http://a-.com/", "http://.example.com/",
            "http://example..com/", "http://" + "a" * 64 + ".com/", "http://%41/",
            "http://a b/", "http://a\tb/", "http://\x00/", "http://exa'mple.com/",
            "-http://example.com/", "HTTP://", "http://example.com:" + "1" * 10000,
        ],
    )
    def test_malformed_input_always_raises_validation_error(self, value):
        with pytest.raises(ValidationError):
            validate_arg(_arg("url"), value)


# ---------------------------------------------------------------------------
# Host policy applied to url hosts
# ---------------------------------------------------------------------------

class TestUrlHostPolicy:
    def test_imds_always_blocked_with_policy_off_and_on(self):
        for block_internal in (False, True):
            msg = _rejects(
                _arg("url", block_internal=block_internal),
                "http://169.254.169.254/latest/meta-data/",
                "always blocked",
            )
            assert msg == (
                "argument 'test' target is a link-local / cloud-metadata address "
                "(169.254.0.0/16) — always blocked"
            )
            _rejects(_arg("url", block_internal=block_internal), "http://169.254.1.1:80/", "always blocked")

    def test_block_internal_loopback(self):
        msg = _rejects(_arg("url", block_internal=True), "http://127.0.0.1/", "loopback")
        assert msg == (
            "argument 'test' target resolves to a loopback address "
            "(blocked by block_internal policy)"
        )
        _rejects(_arg("url", block_internal=True), "http://127.0.0.1:2375/containers/json", "loopback")
        _rejects(_arg("url", block_internal=True), "http://127.255.255.254/", "loopback")

    def test_block_internal_private_and_special_ranges(self):
        cases = [
            ("http://10.0.0.5/", "private"),
            ("http://172.16.0.1/", "private"),
            ("http://192.168.1.1/", "private"),
            ("http://100.64.0.1/", "carrier-grade NAT"),
            ("http://0.0.0.0/", "unspecified"),
            ("http://255.255.255.255/", "broadcast"),
            ("http://192.0.2.1/", "documentation"),
            ("http://198.18.0.1/", "benchmarking"),
            ("http://240.0.0.1/", "reserved"),
        ]
        for value, word in cases:
            _rejects(_arg("url", block_internal=True), value, word, "blocked by block_internal policy")

    def test_policy_off_admits_non_public_literals(self):
        assert validate_arg(_arg("url"), "http://127.0.0.1/") == "http://127.0.0.1/"
        assert validate_arg(_arg("url"), "http://10.0.0.5:8080/x")
        assert validate_arg(_arg("url"), "http://192.168.1.1/")

    def test_public_literal_accepted_under_block_internal(self):
        assert validate_arg(_arg("url", block_internal=True), "https://93.184.216.34/x") == "https://93.184.216.34/x"
        assert validate_arg(_arg("url", block_internal=True), "https://8.8.8.8:853/")
        # A name under block_internal is resolved (test_hardening_w4); with
        # the policy off no lookup happens and the name is accepted as is.
        assert validate_arg(_arg("url"), "https://example.com/")

    def test_punycode_host_rejected(self):
        _rejects(_arg("url"), "https://xn--example-9c.com/", "punycode")
        _rejects(_arg("url"), "https://sub.XN--example.com/", "punycode")

    @pytest.mark.parametrize(
        "value",
        ["http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://1.2.3/"],
    )
    def test_non_canonical_literal_host_rejected(self, value):
        _rejects(_arg("url"), value, "non-canonical IP literal")

    def test_non_ascii_host_rejected(self):
        _rejects(_arg("url"), "https://exаmple.com/", "must be ASCII")  # Cyrillic а

    def test_invalid_hostname_rejected(self):
        _rejects(_arg("url"), "https://exa_mple.com/", "not a valid hostname")
        _rejects(_arg("url"), "https://example.123/", "not a valid hostname")
        _rejects(_arg("url"), "https://example.com./", "not a valid hostname")

    def test_host_length_limits(self):
        _rejects(_arg("url"), "https://" + "a" * 64 + ".com/", "DNS length limits")
        _rejects(_arg("url"), "https://" + ".".join(["a" * 60] * 5) + "/", "DNS length limits")

    def test_block_internal_applies_through_a_loaded_manifest(self, tmp_path):
        p = tmp_path / "t.clad.toml"
        p.write_text(textwrap.dedent("""\
            [tool]
            name = "echo_url"
            version = "1.0.0"
            binary = "echo"

            [args.target]
            position = 1
            required = true
            type = "url"
            block_internal = true

            [command]
            exec = ["echo", "{target}"]

            [output]
            format = "json"
        """))
        m = load_manifest(str(p))
        assert m.args["target"].block_internal is True
        assert build_command_argv(m, {"target": "https://93.184.216.34/x"}) == ["echo", "https://93.184.216.34/x"]
        with pytest.raises(ValidationError, match="blocked by block_internal policy"):
            build_command_argv(m, {"target": "http://127.0.0.1/"})
        with pytest.raises(ValidationError, match="always blocked"):
            build_command_argv(m, {"target": "http://169.254.169.254/"})


# ---------------------------------------------------------------------------
# Host policy applied to scope_target
# ---------------------------------------------------------------------------

class TestScopeTargetPolicy:
    @pytest.mark.parametrize(
        "value,word",
        [
            ("10.0.0.5", "private"),
            ("192.168.1.1", "private"),
            ("0.0.0.0", "unspecified"),
            ("::1", "loopback"),
            ("fc00::1", "unique-local"),
            ("::ffff:127.0.0.1", "loopback"),
            ("127.0.0.1", "loopback"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("::", "unspecified"),
            ("2001:db8::1", "documentation"),
        ],
    )
    def test_block_internal_rejects_non_public(self, value, word):
        _rejects(_arg("scope_target", block_internal=True), value, word, "blocked by block_internal policy")
        # Off by default: the same literal is admitted.
        assert validate_arg(_arg("scope_target"), value) == value

    def test_block_internal_admits_public(self):
        for value in ("93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:93.184.216.34"):
            assert validate_arg(_arg("scope_target", block_internal=True), value) == value
        # A name under block_internal is resolved (test_hardening_w4); with
        # the policy off no lookup happens and the name is accepted as is.
        assert validate_arg(_arg("scope_target"), "example.com") == "example.com"

    @pytest.mark.parametrize("value", ["169.254.169.254", "169.254.0.1", "::ffff:169.254.169.254", "fe80::1", "febf::1"])
    def test_link_local_always_blocked(self, value):
        for block_internal in (False, True):
            _rejects(_arg("scope_target", block_internal=block_internal), value, "always blocked")

    def test_cidr_base_address_is_under_policy(self):
        _rejects(_arg("scope_target", block_internal=True), "10.0.0.0/8", "private")
        _rejects(_arg("scope_target", block_internal=True), "192.168.0.0/16", "private")
        _rejects(_arg("scope_target", block_internal=True), "2001:db8::/32", "documentation")
        _rejects(_arg("scope_target"), "169.254.0.0/16", "always blocked")
        _rejects(_arg("scope_target", block_internal=True), "169.254.0.0/16", "always blocked")
        assert validate_arg(_arg("scope_target", block_internal=True), "8.8.8.0/24") == "8.8.8.0/24"
        assert validate_arg(_arg("scope_target"), "10.0.0.0/8") == "10.0.0.0/8"
        # Host bits are still permitted, as before.
        assert validate_arg(_arg("scope_target"), "10.0.0.1/8") == "10.0.0.1/8"

    @pytest.mark.parametrize(
        "value",
        ["2130706433", "0x7f000001", "0X7F000001", "0177.0.0.1", "127.1", "1.2.3", "010.0.0.1", "1.2.3.4.5", "256.1.1.1"],
    )
    def test_non_canonical_literal_rejected(self, value):
        _rejects(_arg("scope_target"), value, "non-canonical IP literal")
        _rejects(_arg("scope_target", block_internal=True), value, "non-canonical IP literal")

    def test_all_numeric_tld_and_trailing_dot_rejected(self):
        _rejects(_arg("scope_target"), "example.123", "Invalid scope target")
        _rejects(_arg("scope_target"), "example.com.", "Invalid scope target")

    def test_zone_id_is_not_a_literal(self):
        _rejects(_arg("scope_target"), "fe80::1%eth0", "Invalid scope target")

    def test_canonical_literals_still_accepted(self):
        # A /0 range now fails the overlap test (it contains link-local
        # space, test_hardening_w4); a /1 that does not is still canonical.
        for value in ("93.184.216.34", "::ffff:93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "0.0.0.0/1"):
            assert validate_arg(_arg("scope_target"), value) == value


# ---------------------------------------------------------------------------
# Host policy applied to ip_address and cidr
# ---------------------------------------------------------------------------

class TestIpAddressPolicy:
    def test_canonical_only(self):
        for value in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1", "fe80::1%eth0", "[::1]", "1.2.3.4.5", "256.0.0.1"):
            _rejects(_arg("ip_address"), value, "Invalid IP address")
        assert validate_arg(_arg("ip_address"), "127.0.0.1") == "127.0.0.1"
        assert validate_arg(_arg("ip_address"), "::ffff:127.0.0.1") == "::ffff:127.0.0.1"

    def test_policy(self):
        _rejects(_arg("ip_address", block_internal=True), "127.0.0.1", "loopback", "blocked by block_internal policy")
        _rejects(_arg("ip_address", block_internal=True), "::1", "loopback")
        _rejects(_arg("ip_address", block_internal=True), "::ffff:10.1.2.3", "private")
        for block_internal in (False, True):
            _rejects(_arg("ip_address", block_internal=block_internal), "169.254.169.254", "always blocked")
            _rejects(_arg("ip_address", block_internal=block_internal), "::ffff:169.254.169.254", "always blocked")
            _rejects(_arg("ip_address", block_internal=block_internal), "fe80::1", "always blocked")
        assert validate_arg(_arg("ip_address", block_internal=True), "93.184.216.34") == "93.184.216.34"


class TestCidrPolicy:
    def test_canonical_only(self):
        _rejects(_arg("cidr"), "10.0.0.1", "requires '/'")
        for value in ("10.0.0.0/33", "10.0.0.0/+8", "10.0.0.0/08", "10.0.0.0/", "/8", "0x0a000000/8",
                      "10.0.0/8", "010.0.0.0/8", "::1/129", "fe80::1%eth0/64", "not/a/cidr"):
            _rejects(_arg("cidr"), value, "Invalid CIDR")
        assert validate_arg(_arg("cidr"), "10.0.0.0/8") == "10.0.0.0/8"
        # 0.0.0.0/0 is canonical but overlaps link-local space, so it is
        # refused by the policy (test_hardening_w4); 0.0.0.0/1 is not.
        assert validate_arg(_arg("cidr"), "0.0.0.0/1") == "0.0.0.0/1"
        assert validate_arg(_arg("cidr"), "2001:db8::/32") == "2001:db8::/32"

    def test_policy_on_base_address(self):
        _rejects(_arg("cidr", block_internal=True), "10.0.0.0/8", "private", "blocked by block_internal policy")
        _rejects(_arg("cidr", block_internal=True), "::1/128", "loopback")
        _rejects(_arg("cidr", block_internal=True), "2001:db8::/32", "documentation")
        for block_internal in (False, True):
            _rejects(_arg("cidr", block_internal=block_internal), "169.254.0.0/16", "always blocked")
            _rejects(_arg("cidr", block_internal=block_internal), "fe80::/10", "always blocked")
        assert validate_arg(_arg("cidr", block_internal=True), "8.8.8.0/24") == "8.8.8.0/24"


# ---------------------------------------------------------------------------
# The range table itself
# ---------------------------------------------------------------------------

class TestHostPolicyTable:
    def test_range_table_matches_policy_document(self):
        # Pin the table shape so a drift in any runtime is a visible diff.
        assert [str(r.net) for r in ALWAYS_BLOCKED_V4] == ["169.254.0.0/16"]
        assert [str(r.net) for r in ALWAYS_BLOCKED_V6] == ["fe80::/10"]
        assert [str(r.net) for r in BLOCK_INTERNAL_V4] == [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "0.0.0.0/8",
            "255.255.255.255/32",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "198.18.0.0/15",
            "240.0.0.0/4",
        ]
        assert [str(r.net) for r in BLOCK_INTERNAL_V6] == [
            "::1/128", "::/128", "fc00::/7", "fe80::/10", "2001:db8::/32",
        ]

    def test_always_blocked_tier_fires_in_both_modes(self):
        for v in ("169.254.169.254", "169.254.0.1", "169.254.255.255", "::ffff:169.254.169.254", "fe80::1", "febf::1"):
            assert always_blocked_ip_reason(_ip(v)) is not None, v
            for block_internal in (False, True):
                with pytest.raises(ValidationError, match="always blocked"):
                    enforce_ip_policy("t", _ip(v), block_internal)
        for v in ("169.253.255.255", "169.255.0.0", "fe7f::1", "fec0::1"):
            assert always_blocked_ip_reason(_ip(v)) is None, v

    @pytest.mark.parametrize(
        "value,word",
        [
            ("127.0.0.1", "loopback"), ("127.255.255.254", "loopback"),
            ("10.0.0.5", "private"), ("172.16.0.1", "private"), ("172.31.255.255", "private"), ("192.168.1.1", "private"),
            ("100.64.0.1", "carrier-grade NAT"), ("100.127.255.255", "carrier-grade NAT"),
            ("0.0.0.0", "unspecified"), ("0.1.2.3", "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("192.0.2.1", "documentation"), ("198.51.100.1", "documentation"), ("203.0.113.1", "documentation"),
            ("198.18.0.1", "benchmarking"), ("198.19.255.255", "benchmarking"),
            ("240.0.0.1", "reserved"), ("255.255.255.254", "reserved"),
            ("::1", "loopback"), ("::", "unspecified"),
            ("fc00::1", "unique-local"), ("fdff::1", "unique-local"),
            ("fe80::1", "link-local"),
            ("2001:db8::1", "documentation"), ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "documentation"),
            ("::ffff:127.0.0.1", "loopback"), ("::ffff:10.1.2.3", "private"), ("::ffff:100.64.0.1", "carrier-grade NAT"),
            ("::ffff:0.0.0.0", "unspecified"), ("::ffff:255.255.255.255", "broadcast"),
            ("::ffff:198.18.0.1", "benchmarking"), ("::ffff:240.0.0.1", "reserved"),
        ],
    )
    def test_block_internal_tier_covers_every_range(self, value, word):
        ip = _ip(value)
        reason = non_public_ip_reason(ip)
        assert reason is not None and word in reason, f"{value}: {reason}"
        if always_blocked_ip_reason(ip) is None:
            # Enforced only when the policy is on.
            with pytest.raises(ValidationError, match="blocked by block_internal policy"):
                enforce_ip_policy("t", ip, True)
            enforce_ip_policy("t", ip, False)
        else:
            # Link-local sits in both tiers; the always-blocked tier wins.
            for block_internal in (False, True):
                with pytest.raises(ValidationError, match="always blocked"):
                    enforce_ip_policy("t", ip, block_internal)

    @pytest.mark.parametrize(
        "value",
        [
            "126.255.255.255", "128.0.0.0", "9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
            "192.167.255.255", "192.169.0.0", "100.63.255.255", "100.128.0.0", "1.0.0.0", "192.0.1.255",
            "192.0.3.0", "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0", "198.17.255.255",
            "198.20.0.0", "239.255.255.255", "93.184.216.34", "8.8.8.8", "::2", "fbff::1", "fe00::1",
            "2001:db7:ffff::1", "2001:db9::1", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:93.184.216.34",
        ],
    )
    def test_block_internal_tier_range_boundaries(self, value):
        ip = _ip(value)
        assert non_public_ip_reason(ip) is None, f"{value} should be public"
        enforce_ip_policy("t", ip, True)

    def test_broadcast_is_reported_before_reserved(self):
        assert non_public_ip_reason(_ip("255.255.255.255")) == "is the broadcast address"

    def test_messages_match_the_shared_wording(self):
        assert always_blocked_ip_reason(_ip("169.254.169.254")) == (
            "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked"
        )
        assert always_blocked_ip_reason(_ip("fe80::1")) == "is an IPv6 link-local address (fe80::/10) — always blocked"
        assert non_public_ip_reason(_ip("127.0.0.1")) == "resolves to a loopback address"
        assert non_public_ip_reason(_ip("::1")) == "resolves to the IPv6 loopback ::1"
        with pytest.raises(ValidationError) as exc:
            enforce_ip_policy("u", _ip("10.0.0.1"), True)
        assert str(exc.value) == "argument 'u' target resolves to a private address (blocked by block_internal policy)"


# ---------------------------------------------------------------------------
# Parsers in front of the policy
# ---------------------------------------------------------------------------

class TestCanonicalParsers:
    def test_canonical_ip_parser_accepts_canonical_forms(self):
        assert parse_canonical_ip("127.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
        assert parse_canonical_ip("::1") == ipaddress.IPv6Address("::1")
        assert parse_canonical_ip("::ffff:127.0.0.1") == ipaddress.IPv6Address("::ffff:127.0.0.1")
        assert parse_canonical_ip("0.0.0.0") == ipaddress.IPv4Address("0.0.0.0")
        assert parse_canonical_ip("255.255.255.255") == ipaddress.IPv4Address("255.255.255.255")
        assert parse_canonical_ip("2001:DB8::1") == ipaddress.IPv6Address("2001:db8::1")

    @pytest.mark.parametrize(
        "value",
        ["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "010.0.0.1", "127.0.0.1.", "[::1]", "256.0.0.1",
         "1.2.3.4.5", "fe80::1%eth0", "::ffff:0177.0.0.1", "::ffff:127.1", "2001:db8::1/64", "1:2:3:4:5:6:7:8:9",
         "", " 127.0.0.1", "127.0.0.1 ", "+127.0.0.1", "１２７.0.0.1"],
    )
    def test_canonical_ip_parser_rejects_resolver_expansions(self, value):
        assert parse_canonical_ip(value) is None, value

    def test_canonical_cidr_parser(self):
        assert parse_canonical_cidr("10.0.0.0/8") == (ipaddress.IPv4Address("10.0.0.0"), 8)
        assert parse_canonical_cidr("10.0.0.1/8") == (ipaddress.IPv4Address("10.0.0.1"), 8)
        assert parse_canonical_cidr("0.0.0.0/0") == (ipaddress.IPv4Address("0.0.0.0"), 0)
        assert parse_canonical_cidr("2001:db8::/32") == (ipaddress.IPv6Address("2001:db8::"), 32)
        assert parse_canonical_cidr("::1/128") == (ipaddress.IPv6Address("::1"), 128)
        for value in ("10.0.0.0", "10.0.0.0/33", "::1/129", "10.0.0.0/08", "10.0.0.0/+8", "10.0.0.0/",
                      "/8", "0177.0.0.0/8", "127.1/8", "10.0.0.0/8/8", "fe80::1%eth0/64"):
            assert parse_canonical_cidr(value) is None, value

    def test_non_canonical_literal_detection(self):
        for v in ("2130706433", "0x7f000001", "0X7F000001", "0177.0.0.1", "127.1", "1.2.3"):
            assert looks_like_ip_literal(v), v
        for v in ("example.com", "localhost", "1.example", "a.1", "", ".", "１２７"):
            assert not looks_like_ip_literal(v), v

    def test_tld_not_all_numeric(self):
        for v in ("example.com", "a.b.c", "localhost", "1.example"):
            assert tld_not_all_numeric(v), v
        for v in ("example.123", "1.2.3.4", "example.com.", "", "123"):
            assert not tld_not_all_numeric(v), v

    def test_punycode_label_detection_is_case_insensitive(self):
        for v in ("xn--example-9c.com", "sub.XN--example.com", "Xn--a.b", "a.xN--b"):
            assert has_punycode_label(v), v
        for v in ("example.com", "xn-.com", "axn--b.com", "xn.com", ""):
            assert not has_punycode_label(v), v


# ---------------------------------------------------------------------------
# {_secret:…} ordering in the HTTP backend
# ---------------------------------------------------------------------------

_SECRET = "s3cr3t-value-that-must-never-leave-the-process"
_SMUGGLE = "https://attacker.example/?k={_secret:api_key}"


def _http_manifest(url: str, headers=None, body_template=None) -> Manifest:
    return Manifest(
        tool=ToolMeta(name="http_tool", version="1.0.0", binary=""),
        http=HttpDef(
            method="POST",
            url=url,
            headers=headers or {},
            body_template=body_template,
            success_status=[200],
        ),
        args={"target": ArgDef(name="target", type="string", required=True)},
    )


class TestSecretOrdering:
    def test_argument_cannot_smuggle_a_secret_into_the_url(self, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", _SECRET)
        m = _http_manifest(url="{target}")
        # HTTP arguments go through the same validation as the oneshot path,
        # so a brace-carrying value is refused before anything is built.
        with pytest.raises(ValidationError, match="metacharacters") as exc:
            execute(m, {"target": _SMUGGLE}, dry_run=True)
        assert _SECRET not in str(exc.value)

    def test_manifest_secret_still_expands_before_args(self, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", _SECRET)
        m = _http_manifest(url="https://api.example.com/{target}?k={_secret:api_key}")
        envelope = execute(m, {"target": "scan123"}, dry_run=True)
        assert envelope["command"] == f"POST https://api.example.com/scan123?k={_SECRET}"

    def test_interpolate_http_order(self, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", _SECRET)
        # Manifest-written reference: expanded.
        assert _interpolate_http("Bearer {_secret:api_key}", {"target": "x"}) == f"Bearer {_SECRET}"
        # Argument-supplied reference: left literal, never expanded.
        assert _interpolate_http("{target}", {"target": "{_secret:api_key}"}) == "{_secret:api_key}"
        assert _interpolate_http("{target}", {"target": _SMUGGLE}) == _SMUGGLE

    def test_headers_and_body_follow_the_same_order(self, monkeypatch):
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", _SECRET)
        captured = {}

        class _Resp:
            status = 200

            def read(self, n=-1):
                return b"{}"

        def fake_open(req, timeout=None):
            # Records the built request; no socket is ever opened.
            captured["req"] = req
            return _Resp()

        import toolclad.executor as executor_mod

        monkeypatch.setattr(executor_mod, "_open_url", fake_open)
        m = _http_manifest(
            url="http://127.0.0.1:9/{target}",
            headers={"X-Echo": "{target}", "Authorization": "Bearer {_secret:api_key}"},
            body_template='{"t": "{target}"}',
        )
        with pytest.raises(ValidationError, match="metacharacters"):
            execute(m, {"target": "{_secret:api_key}"})
        assert "req" not in captured  # refused before any request was built

        envelope = execute(m, {"target": "scan123"})
        assert envelope["http_status"] == 200
        req = captured["req"]
        assert req.full_url == "http://127.0.0.1:9/scan123"
        assert req.get_header("X-echo") == "scan123"
        assert req.get_header("Authorization") == f"Bearer {_SECRET}"
        assert req.data == b'{"t": "scan123"}'
        assert _SECRET not in req.full_url
        assert _SECRET not in req.data.decode()

    def test_secret_env_is_cleaned_up(self):
        # monkeypatch.setenv in the tests above restores the environment;
        # nothing from them leaks into this one.
        import os

        assert "TOOLCLAD_SECRET_API_KEY" not in os.environ
