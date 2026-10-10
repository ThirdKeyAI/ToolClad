"""Tests for the hostname half of the host policy and the egress lint.

D1 the internal-name denylist, D2 IP literals embedded in a hostname, D3
CIDR overlap with every blocked prefix, D4 DNS resolution under
``block_internal``, and D5 the egress lint as a manifest property.

No test depends on live DNS succeeding. Positive cases use literals or the
embedded forms; the resolution path uses ``no-such-host.invalid``
(``.invalid`` is reserved by RFC 2606 and never resolves) or a substituted
resolver, and the ``no_dns`` fixture proves that no lookup happens where
none must. That one ``.invalid`` lookup is the only network activity a test
may cause. No network tool is ever executed: every manifest here is only
loaded.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from toolclad import hostpolicy
from toolclad.hostpolicy import (
    INTERNAL_NAME_REASON,
    always_blocked_cidr_reason,
    embedded_ip_literal,
    internal_name_reason,
    non_public_cidr_reason,
    resolve_host_addresses,
)
from toolclad.manifest import (
    EGRESS_BINARIES,
    NETWORK_TARGET_TYPES,
    ArgDef,
    BrowserDef,
    CommandDef,
    CustomTypeDef,
    HttpDef,
    Manifest,
    ToolMeta,
    is_egress_manifest,
    load_manifest,
    validate_manifest_with_custom_types,
)
from toolclad.validator import (
    ValidationError,
    validate_arg,
    validate_arg_with_custom_types,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _arg(type: str, **kwargs) -> ArgDef:  # noqa: A002
    return ArgDef(name="target", type=type, **kwargs)


def _rejects(arg_def: ArgDef, value: str, *needles: str) -> str:
    """Assert ``value`` is refused and every needle appears in the message."""
    with pytest.raises(ValidationError) as exc:
        validate_arg(arg_def, value)
    msg = str(exc.value)
    for needle in needles:
        assert needle in msg, f"{needle!r} not in {msg!r}"
    return msg


@pytest.fixture
def no_dns(monkeypatch):
    """Fail the test if the resolver is consulted."""
    def _never(host: str):
        raise AssertionError(f"resolver consulted for {host!r}")
    monkeypatch.setattr(hostpolicy, "resolve_host_addresses", _never)


def _answers(monkeypatch, *texts: str) -> None:
    """Substitute a resolver that returns the given addresses."""
    ips = [ipaddress.ip_address(t) for t in texts]
    monkeypatch.setattr(hostpolicy, "resolve_host_addresses", lambda host: list(ips))


_INTERNAL = INTERNAL_NAME_REASON
_POLICY = "blocked by block_internal policy"
_PUBLIC = "93.184.216.34"


# ---------------------------------------------------------------------------
# D1 — internal-name denylist, unconditional
# ---------------------------------------------------------------------------

_INTERNAL_NAMES = [
    "localhost", "api.localhost", "printer.local", "metadata.google.internal",
    "db.internal", "x.home.arpa", "nas.lan", "wiki.intranet", "files.corp",
    "vault.private",
]


class TestInternalNameDenylist:
    @pytest.mark.parametrize("host", _INTERNAL_NAMES)
    def test_scope_target_refused_without_block_internal(self, host, no_dns):
        msg = _rejects(_arg("scope_target"), host, _INTERNAL)
        assert msg == f"argument 'target' target {_INTERNAL}"

    @pytest.mark.parametrize("host", _INTERNAL_NAMES)
    def test_url_host_refused_without_block_internal(self, host, no_dns):
        _rejects(_arg("url"), f"http://{host}/path", _INTERNAL)
        _rejects(_arg("url"), f"https://{host}:8443/", _INTERNAL)

    @pytest.mark.parametrize("host", ["localhost", "printer.local"])
    def test_refused_with_block_internal_too(self, host, no_dns):
        # The denylist wins before any resolution is attempted.
        _rejects(_arg("scope_target", block_internal=True), host, _INTERNAL)
        _rejects(_arg("url", block_internal=True), f"http://{host}/", _INTERNAL)

    @pytest.mark.parametrize("host", ["LOCALHOST", "Printer.LOCAL", "METADATA.GOOGLE.INTERNAL", "Db.Internal"])
    def test_comparison_is_case_insensitive(self, host, no_dns):
        _rejects(_arg("scope_target"), host, _INTERNAL)
        _rejects(_arg("url"), f"http://{host}/", _INTERNAL)

    def test_trailing_dot_form_is_refused_structurally(self, no_dns):
        # The structural hostname check refuses a trailing dot before the
        # denylist is consulted, so the message is the structural one.
        _rejects(_arg("scope_target"), "localhost.", "Invalid scope target")
        _rejects(_arg("url"), "http://localhost./", "not a valid hostname")

    def test_helper_ignores_one_trailing_dot(self):
        assert internal_name_reason("localhost") == _INTERNAL
        assert internal_name_reason("LOCALHOST.") == _INTERNAL
        assert internal_name_reason("a.b.internal.") == _INTERNAL
        assert internal_name_reason("localhost..") is None
        assert internal_name_reason("example.com") is None

    @pytest.mark.parametrize(
        "host",
        ["notlocalhost", "internal.example.com", "corp.example.com", "localhost.example.com", "lan.example.net"],
    )
    def test_suffix_match_is_on_a_label_boundary(self, host, no_dns):
        # Policy off: no resolution, and these are not internal names.
        assert validate_arg(_arg("scope_target"), host) == host
        assert validate_arg(_arg("url"), f"https://{host}/") == f"https://{host}/"


# ---------------------------------------------------------------------------
# D2 — IP literal embedded in a hostname
# ---------------------------------------------------------------------------

class TestEmbeddedIpLiteral:
    @pytest.mark.parametrize("host", ["169.254.169.254.nip.io", "169.254.169.254.xip.io", "169-254-169-254.nip.io"])
    def test_metadata_embedded_is_always_refused(self, host, no_dns):
        _rejects(_arg("scope_target"), host, "always blocked")
        _rejects(_arg("scope_target", block_internal=True), host, "always blocked")
        _rejects(_arg("url"), f"http://{host}/latest/meta-data/", "always blocked")

    def test_loopback_and_private_embedded_refused_under_block_internal(self, no_dns):
        _rejects(_arg("scope_target", block_internal=True), "127.0.0.1.nip.io", "loopback", _POLICY)
        _rejects(_arg("scope_target", block_internal=True), "10-0-0-1.nip.io", "private", _POLICY)
        _rejects(_arg("url", block_internal=True), "http://127.0.0.1.nip.io:8080/", "loopback", _POLICY)
        _rejects(_arg("url", block_internal=True), "http://10-0-0-1.sslip.io/", "private", _POLICY)
        _rejects(_arg("url", block_internal=True), "http://192.168.1.1.nip.io/", "private", _POLICY)

    def test_embedded_admitted_when_policy_off(self, no_dns):
        # Same as a literal: loopback and private are admitted unless the
        # manifest opts in to block_internal.
        assert validate_arg(_arg("scope_target"), "127.0.0.1.nip.io") == "127.0.0.1.nip.io"
        assert validate_arg(_arg("scope_target"), "10-0-0-1.nip.io") == "10-0-0-1.nip.io"

    def test_public_shape_is_not_a_refusal_and_is_not_resolved(self, no_dns):
        for host in ("93-184-216-34.example.com", "93.184.216.34.example.com"):
            assert validate_arg(_arg("scope_target", block_internal=True), host) == host
            url = f"https://{host}/x"
            assert validate_arg(_arg("url", block_internal=True), url) == url

    def test_helper_shapes(self):
        v4 = ipaddress.IPv4Address
        assert embedded_ip_literal("127.0.0.1.nip.io") == v4("127.0.0.1")
        assert embedded_ip_literal("169.254.169.254.xip.io") == v4("169.254.169.254")
        assert embedded_ip_literal("10-0-0-1.nip.io") == v4("10.0.0.1")
        assert embedded_ip_literal("010-0-0-1.nip.io") == v4("10.0.0.1")
        assert embedded_ip_literal("10-0-0-1") == v4("10.0.0.1")
        # Non-canonical dotted forms, too few or too many groups, out of
        # range: not an embedded literal.
        for host in ("0127.0.0.1.nip.io", "1.2.3.nip.io", "a.b.c.d", "256-0-0-1.nip.io",
                     "1-2-3.nip.io", "10-0-0-1-5.nip.io", "example.com", "www.1.2.3.4"):
            assert embedded_ip_literal(host) is None, host

    def test_non_matching_shape_falls_through_to_hostname_rules(self, no_dns):
        # Policy off: accepted as an ordinary name, no resolution.
        assert validate_arg(_arg("scope_target"), "256-0-0-1.nip.io") == "256-0-0-1.nip.io"


# ---------------------------------------------------------------------------
# D3 — CIDR overlap, not base address
# ---------------------------------------------------------------------------

class TestCidrOverlap:
    @pytest.mark.parametrize(
        "value,word",
        [
            ("8.0.0.0/5", "private"),           # public base, contains 10.0.0.0/8
            ("10.0.0.0/24", "private"),         # inside a blocked range
            ("172.0.0.0/8", "private"),         # contains 172.16.0.0/12
            ("192.0.0.0/8", "private"),         # contains 192.168.0.0/16
            ("100.0.0.0/8", "carrier-grade NAT"),
            ("126.0.0.0/7", "loopback"),        # 126-127
            ("198.0.0.0/8", "documentation"),   # 198.51.100.0/24 precedes 198.18.0.0/15
            ("2001:db8::/32", "documentation"),
            ("2001::/16", "documentation"),     # supernet of 2001:db8::/32
            ("fd00::/8", "unique-local"),
            ("::/120", "loopback"),             # contains ::1
        ],
    )
    def test_refused_under_block_internal(self, value, word):
        for arg_type in ("scope_target", "cidr"):
            _rejects(_arg(arg_type, block_internal=True), value, word, _POLICY)

    @pytest.mark.parametrize(
        "value",
        ["93.184.216.0/24", "8.8.8.0/24", "1.0.0.0/8", "11.0.0.0/8", "172.32.0.0/11", "2606:4700::/32", "2600::/12"],
    )
    def test_accepted_under_block_internal(self, value):
        for arg_type in ("scope_target", "cidr"):
            assert validate_arg(_arg(arg_type, block_internal=True), value) == value

    @pytest.mark.parametrize("value", ["0.0.0.0/0", "128.0.0.0/1", "169.0.0.0/8", "::/0", "fe00::/7"])
    def test_overlap_with_link_local_is_always_refused(self, value):
        for arg_type in ("scope_target", "cidr"):
            for block_internal in (False, True):
                _rejects(_arg(arg_type, block_internal=block_internal), value, "always blocked")

    def test_policy_off_admits_supernets_of_the_opt_in_ranges(self):
        for value in ("8.0.0.0/5", "0.0.0.0/1", "2001::/16"):
            assert validate_arg(_arg("scope_target"), value) == value
            assert validate_arg(_arg("cidr"), value) == value

    def test_host_bits_are_masked_before_the_overlap_test(self):
        _rejects(_arg("scope_target", block_internal=True), "10.0.0.1/8", "private")
        _rejects(_arg("cidr", block_internal=True), "8.1.2.3/5", "private")
        assert validate_arg(_arg("scope_target"), "10.0.0.1/8") == "10.0.0.1/8"

    def test_ipv4_mapped_ipv6_cidr(self):
        _rejects(_arg("cidr", block_internal=True), "::ffff:10.0.0.0/104", "private", _POLICY)
        _rejects(_arg("scope_target", block_internal=True), "::ffff:127.0.0.0/104", "loopback", _POLICY)
        # Covers every mapped IPv4 address, link-local included.
        for block_internal in (False, True):
            _rejects(_arg("cidr", block_internal=block_internal), "::ffff:0:0/96", "always blocked")
            _rejects(_arg("cidr", block_internal=block_internal), "::ffff:169.254.0.0/112", "always blocked")
        assert validate_arg(_arg("cidr", block_internal=True), "::ffff:93.184.216.0/120") == "::ffff:93.184.216.0/120"

    def test_helpers(self):
        net = ipaddress.ip_network
        assert "private" in non_public_cidr_reason(net("8.0.0.0/5"))
        assert non_public_cidr_reason(net("93.184.216.0/24")) is None
        assert always_blocked_cidr_reason(net("::/0")) is not None
        assert always_blocked_cidr_reason(net("0.0.0.0/0")) is not None
        assert always_blocked_cidr_reason(net("8.8.8.0/24")) is None
        assert always_blocked_cidr_reason(net("2606:4700::/32")) is None


# ---------------------------------------------------------------------------
# D4 — DNS resolution under block_internal
# ---------------------------------------------------------------------------

_UNRESOLVABLE = "no-such-host.invalid"
_COULD_NOT = f"could not resolve host '{_UNRESOLVABLE}' to verify it is public (block_internal)"


class TestDnsResolutionUnderBlockInternal:
    def test_unresolvable_name_is_refused(self):
        msg = _rejects(_arg("scope_target", block_internal=True), _UNRESOLVABLE, _COULD_NOT)
        assert msg == f"argument 'target' {_COULD_NOT}"
        _rejects(_arg("url", block_internal=True), f"https://{_UNRESOLVABLE}/x", _COULD_NOT)
        _rejects(_arg("url", block_internal=True), f"http://{_UNRESOLVABLE}:8080/", _COULD_NOT)

    def test_no_resolution_when_policy_off(self, no_dns):
        assert validate_arg(_arg("scope_target"), _UNRESOLVABLE) == _UNRESOLVABLE
        url = f"https://{_UNRESOLVABLE}/x"
        assert validate_arg(_arg("url"), url) == url

    def test_literals_are_never_resolved(self, no_dns):
        assert validate_arg(_arg("scope_target", block_internal=True), _PUBLIC) == _PUBLIC
        assert validate_arg(_arg("url", block_internal=True), f"https://{_PUBLIC}/") == f"https://{_PUBLIC}/"
        assert validate_arg(_arg("ip_address", block_internal=True), _PUBLIC) == _PUBLIC
        assert validate_arg(_arg("cidr", block_internal=True), "8.8.8.0/24") == "8.8.8.0/24"

    def test_internal_name_wins_before_resolution(self, no_dns):
        _rejects(_arg("scope_target", block_internal=True), "localhost", _INTERNAL)

    @pytest.mark.parametrize(
        "error",
        [socket.gaierror(-2, "Name or service not known"), OSError("resolver unavailable"), socket.timeout("slow")],
    )
    def test_resolver_error_fails_closed(self, monkeypatch, error):
        def _raise(host, port):
            raise error
        monkeypatch.setattr(hostpolicy.socket, "getaddrinfo", _raise)
        _rejects(_arg("scope_target", block_internal=True), "example.com",
                 "could not resolve host 'example.com' to verify it is public (block_internal)")

    def test_empty_answer_set_fails_closed(self, monkeypatch):
        monkeypatch.setattr(hostpolicy.socket, "getaddrinfo", lambda host, port: [])
        _rejects(_arg("url", block_internal=True), "https://example.com/", "could not resolve host 'example.com'")

    def test_every_answer_is_checked(self, monkeypatch):
        # One public answer does not launder an internal one (rebinding,
        # round-robin, or an attacker-controlled zone).
        _answers(monkeypatch, _PUBLIC, "127.0.0.1")
        _rejects(_arg("scope_target", block_internal=True), "example.com", "loopback", _POLICY)
        _answers(monkeypatch, _PUBLIC, "10.0.0.1")
        _rejects(_arg("url", block_internal=True), "https://example.com/", "private", _POLICY)
        _answers(monkeypatch, "2606:4700::1111", "fd00::1")
        _rejects(_arg("scope_target", block_internal=True), "example.com", "unique-local", _POLICY)

    def test_resolved_link_local_is_always_blocked(self, monkeypatch):
        _answers(monkeypatch, _PUBLIC, "169.254.169.254")
        _rejects(_arg("scope_target", block_internal=True), "example.com", "always blocked")
        _answers(monkeypatch, "::ffff:169.254.169.254")
        _rejects(_arg("url", block_internal=True), "https://example.com/", "always blocked")

    def test_all_public_answers_are_accepted(self, monkeypatch):
        _answers(monkeypatch, _PUBLIC, "2606:2800:220:1:248:1893:25c8:1946")
        assert validate_arg(_arg("scope_target", block_internal=True), "example.com") == "example.com"
        assert validate_arg(_arg("url", block_internal=True), "https://example.com/") == "https://example.com/"

    def test_getaddrinfo_answers_are_parsed_and_deduplicated(self, monkeypatch):
        v4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        v4_dgram = (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 0))
        mapped = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 0, 0, 0))
        zoned = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 0, 0, 2))
        monkeypatch.setattr(hostpolicy.socket, "getaddrinfo", lambda host, port: [v4, v4_dgram, mapped, zoned])
        answers = resolve_host_addresses("example.com")
        assert answers == [
            ipaddress.ip_address("127.0.0.1"),
            ipaddress.ip_address("::ffff:127.0.0.1"),
            ipaddress.ip_address("fe80::1"),
        ]
        # The loopback answer comes first in the table walk, and the zoned
        # link-local one would be caught regardless of block_internal.
        _rejects(_arg("scope_target", block_internal=True), "example.com", "loopback")
        monkeypatch.setattr(hostpolicy.socket, "getaddrinfo", lambda host, port: [zoned])
        _rejects(_arg("scope_target", block_internal=True), "example.com", "always blocked")


# ---------------------------------------------------------------------------
# D5 — egress lint as a manifest property
# ---------------------------------------------------------------------------

_LINT = (
    "argument 'target' is a network target for an egress binary but "
    "block_internal is not set; set block_internal = true to default-deny "
    "internal/SSRF targets"
)


def _doc(
    binary: str = "curl",
    arg_type: str = "url",
    flag: str = "",
    command: str = "",
    tool: str = "",
    tail: str = "",
) -> str:
    """A oneshot manifest: ``binary`` with one ``target`` argument. Nothing
    is ever executed; every manifest here is only loaded."""
    cmd = command or f'exec = ["{binary}", "{{target}}"]\n'
    return (
        f'[tool]\nname = "t"\nversion = "1.0.0"\nbinary = "{binary}"\n{tool}\n'
        f'[args.target]\nposition = 1\nrequired = true\ntype = "{arg_type}"\n{flag}\n'
        f"[command]\n{cmd}\n"
        '[output]\nformat = "text"\n'
        f"{tail}"
    )


def _load(tmp_path, text: str) -> Manifest:
    p = tmp_path / "t.clad.toml"
    p.write_text(text)
    return load_manifest(str(p))


def _refused(tmp_path, text: str, needle: str = _LINT) -> str:
    with pytest.raises(ValueError) as exc:
        _load(tmp_path, text)
    assert needle in str(exc.value), str(exc.value)
    return str(exc.value)


_FLAG = "block_internal = true\n"


class TestEgressLint:
    def test_list_is_exactly_the_shared_one(self):
        assert EGRESS_BINARIES == frozenset({
            "curl", "wget", "nmap", "nc", "ncat", "netcat", "masscan", "telnet",
            "ssh", "ping", "fping", "httpie", "http", "wfuzz", "ffuf", "hydra",
            "nikto",
        })
        assert NETWORK_TARGET_TYPES == frozenset({"scope_target", "url", "ip_address", "cidr"})

    def test_curl_url_without_flag_is_refused_at_load(self, tmp_path):
        assert _refused(tmp_path, _doc("curl", "url")) == _LINT

    def test_curl_url_with_flag_loads(self, tmp_path):
        m = _load(tmp_path, _doc("curl", "url", _FLAG))
        assert m.args["target"].block_internal is True

    def test_nmap_scope_target(self, tmp_path):
        _refused(tmp_path, _doc("nmap", "scope_target"))
        assert _load(tmp_path, _doc("nmap", "scope_target", _FLAG)).tool.binary == "nmap"

    @pytest.mark.parametrize("binary", sorted(EGRESS_BINARIES))
    def test_every_listed_binary_triggers(self, tmp_path, binary):
        _refused(tmp_path, _doc(binary, "scope_target"))
        _load(tmp_path, _doc(binary, "scope_target", _FLAG))

    @pytest.mark.parametrize("arg_type", sorted(NETWORK_TARGET_TYPES))
    def test_every_network_type_requires_the_flag(self, tmp_path, arg_type):
        _refused(tmp_path, _doc("curl", arg_type))
        _load(tmp_path, _doc("curl", arg_type, _FLAG))

    def test_non_network_type_is_not_linted(self, tmp_path):
        assert _load(tmp_path, _doc("curl", "string")).args["target"].type == "string"

    @pytest.mark.parametrize("binary", ["whois", "dig", "echo", "sort"])
    def test_non_egress_binary_does_not_require_the_flag(self, tmp_path, binary):
        m = _load(tmp_path, _doc(binary, "scope_target"))
        assert m.args["target"].block_internal is False

    def test_network_egress_flag_on_unlisted_binary_requires_it(self, tmp_path):
        _refused(tmp_path, _doc("echo", "scope_target", tool="network_egress = true\n"))
        m = _load(tmp_path, _doc("echo", "scope_target", _FLAG, tool="network_egress = true\n"))
        assert m.tool.network_egress is True

    def test_http_manifest_with_url_arg_requires_it(self, tmp_path):
        http = '[http]\nmethod = "GET"\nurl = "https://api.example.com/?u={{target}}"\n'
        doc = (
            '[tool]\nname = "h"\nversion = "1.0.0"\nbinary = ""\n'
            '[args.target]\nposition = 1\nrequired = true\ntype = "url"\n{flag}'
            + http + '[output]\nformat = "json"\n'
        )
        _refused(tmp_path, doc.format(flag=""))
        assert _load(tmp_path, doc.format(flag=_FLAG)).http is not None

    def test_http_manifest_with_string_arg_loads(self, tmp_path):
        doc = (
            '[tool]\nname = "h"\nversion = "1.0.0"\nbinary = ""\n'
            '[args.target]\nposition = 1\nrequired = true\ntype = "string"\n'
            '[http]\nmethod = "GET"\nurl = "https://api.example.com/{target}"\n'
            '[output]\nformat = "json"\n'
        )
        assert _load(tmp_path, doc).http is not None

    def test_browser_manifest_command_url_arg_requires_it(self, tmp_path):
        doc = (
            '[tool]\nname = "b"\n'
            '[browser]\nengine = "cdp"\n'
            '[browser.commands.navigate]\ndescription = "go"\n'
            '[browser.commands.navigate.args.target]\ntype = "url"\n{flag}'
            '[output]\nformat = "json"\n'
        )
        _refused(tmp_path, doc.format(flag=""))
        m = _load(tmp_path, doc.format(flag=_FLAG))
        assert m.browser.commands["navigate"].args["target"].block_internal is True

    def test_session_command_arg_under_network_egress(self, tmp_path):
        doc = (
            '[tool]\nname = "s"\n{tool}'
            '[session]\nstartup_command = "echo"\n'
            '[session.commands.scan]\npattern = "^scan .+$"\n'
            '[session.commands.scan.args.target]\ntype = "scope_target"\n{flag}'
            '[output]\nformat = "text"\n'
        )
        # A session manifest is not an egress manifest by itself.
        _load(tmp_path, doc.format(tool="", flag=""))
        _refused(tmp_path, doc.format(tool="network_egress = true\n", flag=""))
        _load(tmp_path, doc.format(tool="network_egress = true\n", flag=_FLAG))

    def test_program_is_matched_by_basename_case_insensitively(self, tmp_path):
        _refused(tmp_path, _doc("/usr/local/bin/Curl", "url"))
        _refused(tmp_path, _doc("", "url", command='exec = ["/opt/tools/nmap", "{target}"]\n'))
        _refused(tmp_path, _doc("", "url", command='exec = ["C:\\\\tools\\\\WGET", "{target}"]\n'))
        # A different basename, however similar, is not on the list.
        _load(tmp_path, _doc("curl2", "url"))
        _load(tmp_path, _doc("", "url", command='exec = ["/opt/tools/nmap-parse", "{target}"]\n'))

    def test_template_first_token_is_inspected(self, tmp_path):
        _refused(tmp_path, _doc("", "url", command='template = "curl -s {target}"\n'))
        _refused(tmp_path, _doc("", "url", command="template = \"'/usr/bin/curl' -s {target}\"\n"))
        # The lint runs before the template is compiled, so only the manifest
        # that loads emits the template deprecation warning.
        with pytest.warns(DeprecationWarning, match="template is deprecated"):
            _load(tmp_path, _doc("", "url", command='template = "whois {target}"\n'))

    def test_executor_only_manifest_is_the_authors_responsibility(self, tmp_path):
        base = (
            '[tool]\nname = "x"\n{tool}'
            '[args.target]\nposition = 1\nrequired = true\ntype = "scope_target"\n'
            '[command]\nexecutor = "/bin/true"\n'
            '[output]\nformat = "text"\n'
        )
        # The script cannot be inspected for a binary: not an egress manifest
        # unless declared.
        assert _load(tmp_path, base.format(tool="")).command.executor == "/bin/true"
        _refused(tmp_path, base.format(tool="network_egress = true\n"))

    def test_is_egress_manifest_helper(self):
        def m(**kw) -> Manifest:
            return Manifest(**kw)
        assert is_egress_manifest(m(tool=ToolMeta(binary="nmap"))) is True
        assert is_egress_manifest(m(tool=ToolMeta(network_egress=True))) is True
        assert is_egress_manifest(m(http=HttpDef(url="https://x/"))) is True
        assert is_egress_manifest(m(browser=BrowserDef())) is True
        assert is_egress_manifest(m(command=CommandDef(exec=["/usr/bin/curl"]))) is True
        assert is_egress_manifest(m(command=CommandDef(template="ping -c 1 {t}"))) is True
        assert is_egress_manifest(m(tool=ToolMeta(binary="whois"), command=CommandDef(exec=["whois"]))) is False
        assert is_egress_manifest(m(command=CommandDef(executor="/bin/true"))) is False
        assert is_egress_manifest(m()) is False


_CUSTOM_MSG = (
    "argument 'target' uses custom type 'host' as a network target; custom "
    "types cannot carry block_internal — use the built-in scope_target type"
)


def _load_opaque(tmp_path, text: str, type_name: str) -> Manifest:
    """Load with ``type_name`` declared as an opaque string custom type, so the
    lint can be exercised separately against other custom definitions."""
    from toolclad.manifest import LoadOptions, load_manifest_with_options

    p = tmp_path / "t.clad.toml"
    p.write_text(text)
    return load_manifest_with_options(
        str(p), LoadOptions(custom_types={type_name: CustomTypeDef(base="string")})
    )


class TestCustomTypeNetworkTargets:
    def test_load_refuses_custom_network_type_from_discovered_config(self, tmp_path):
        # The loader discovers toolclad.toml and runs the lint with its types.
        (tmp_path / "toolclad.toml").write_text('[types.host]\nbase = "scope_target"\n')
        with pytest.raises(ValueError) as exc:
            _load(tmp_path, _doc("nmap", "host"))
        assert str(exc.value) == _CUSTOM_MSG

    def test_manifest_lint_refuses_custom_network_type_on_egress_manifest(self, tmp_path):
        # With an opaque definition of the type the manifest loads.
        m = _load_opaque(tmp_path, _doc("nmap", "host"), "host")
        with pytest.raises(ValueError) as exc:
            validate_manifest_with_custom_types(m, {"host": CustomTypeDef(base="scope_target")})
        assert str(exc.value) == _CUSTOM_MSG

    @pytest.mark.parametrize("base", ["url", "ip_address", "cidr"])
    def test_every_network_base_is_refused(self, tmp_path, base):
        m = _load_opaque(tmp_path, _doc("curl", "host"), "host")
        with pytest.raises(ValueError, match=f"use the built-in {base} type"):
            validate_manifest_with_custom_types(m, {"host": CustomTypeDef(base=base)})

    def test_manifest_lint_passes_other_custom_types(self, tmp_path):
        m = _load_opaque(tmp_path, _doc("nmap", "ident", _FLAG), "ident")
        validate_manifest_with_custom_types(m, {"ident": CustomTypeDef(base="string", pattern="[a-z]+")})
        # An unknown custom type is not this lint's concern.
        validate_manifest_with_custom_types(m, {})

    def test_manifest_lint_is_gated_on_egress(self, tmp_path):
        m = _load_opaque(tmp_path, _doc("whois", "host"), "host")
        validate_manifest_with_custom_types(m, {"host": CustomTypeDef(base="scope_target")})

    def test_manifest_lint_still_requires_the_flag_on_built_in_types(self, tmp_path):
        m = _load(tmp_path, _doc("whois", "scope_target"))
        m.tool.network_egress = True
        with pytest.raises(ValueError) as exc:
            validate_manifest_with_custom_types(m, {})
        assert str(exc.value) == _LINT

    @pytest.mark.parametrize("base", ["scope_target", "url", "ip_address", "cidr"])
    def test_validate_arg_with_custom_types_refuses_network_base(self, base, no_dns):
        custom = {"host": CustomTypeDef(base=base)}
        with pytest.raises(ValidationError) as exc:
            validate_arg_with_custom_types(_arg("host", block_internal=True), _PUBLIC, custom)
        assert str(exc.value) == _CUSTOM_MSG.replace("scope_target", base)

    def test_validate_arg_with_custom_types_still_delegates_other_bases(self):
        custom = {"ident": CustomTypeDef(base="string", pattern="[a-z]+")}
        assert validate_arg_with_custom_types(_arg("ident"), "abc", custom) == "abc"
