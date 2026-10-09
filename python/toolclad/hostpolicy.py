"""Host / IP egress policy shared by every argument type that can carry a
literal address: ``scope_target``, ``url``, ``ip_address`` and ``cidr``.

The range table in this module is the single source of truth for the Python
runtime and mirrors, entry for entry, the table in the Rust, Go and
JavaScript runtimes so the four can be compared side by side. There are two
tiers:

* **Always blocked**, with or without ``block_internal``: the link-local
  ranges. IPv4 link-local contains the cloud-metadata endpoint
  169.254.169.254, and the blast radius of reaching it (instance-credential
  theft) is maximal. No agent tool has a legitimate reason to target these.
* **Blocked when** ``block_internal = true``: loopback, private, shared
  (carrier-grade NAT), unspecified, broadcast, documentation, benchmarking
  and reserved space, plus the IPv6 equivalents.

IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are unwrapped before the
table is consulted, so the IPv6 spelling of any IPv4 range is caught.

The parser helpers at the bottom (``parse_canonical_ip``,
``parse_canonical_cidr``, ``looks_like_ip_literal``, ``tld_not_all_numeric``,
``has_punycode_label``) sit in front of the policy: a value the resolver
would expand (``2130706433``, ``0x7f000001``, ``0177.0.0.1``, ``127.1``)
must be refused outright rather than passed through as a "hostname" the
table never sees. The stdlib ``ipaddress`` module is only handed text that
has already passed the canonical-form check, because on its own it accepts
shapes this policy must not: a zone id (``fe80::1%eth0``), an integer, and
host bits in a network when ``strict=False``.

The remaining hostname rules (internal-suffix denylist, embedded IP
literals, CIDR overlap, DNS resolution under ``block_internal``) plug into
this module in a later wave.
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple, Optional, Sequence, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class BlockedRange(NamedTuple):
    """One blocked prefix and the reason reported when a target falls in it."""

    net: IPNetwork
    reason: str


def _r(cidr: str, reason: str) -> BlockedRange:
    return BlockedRange(ipaddress.ip_network(cidr, strict=True), reason)


# IPv4 ranges blocked regardless of `block_internal`.
ALWAYS_BLOCKED_V4: Tuple[BlockedRange, ...] = (
    _r(
        "169.254.0.0/16",
        "is a link-local / cloud-metadata address (169.254.0.0/16) — always blocked",
    ),
)

# IPv6 ranges blocked regardless of `block_internal`.
ALWAYS_BLOCKED_V6: Tuple[BlockedRange, ...] = (
    _r("fe80::/10", "is an IPv6 link-local address (fe80::/10) — always blocked"),
)

# IPv4 ranges blocked when `block_internal = true`. Entries are tested in
# order, so the broadcast address (which also lies inside 240.0.0.0/4) is
# reported as broadcast, not as reserved.
BLOCK_INTERNAL_V4: Tuple[BlockedRange, ...] = (
    _r("127.0.0.0/8", "resolves to a loopback address"),
    _r("10.0.0.0/8", "resolves to a private address"),
    _r("172.16.0.0/12", "resolves to a private address"),
    _r("192.168.0.0/16", "resolves to a private address"),
    _r(
        "100.64.0.0/10",
        "resolves to a shared / carrier-grade NAT address (100.64.0.0/10)",
    ),
    _r("0.0.0.0/8", "is in the unspecified range (0.0.0.0/8)"),
    _r("255.255.255.255/32", "is the broadcast address"),
    _r("192.0.2.0/24", "is a documentation-range address"),
    _r("198.51.100.0/24", "is a documentation-range address"),
    _r("203.0.113.0/24", "is a documentation-range address"),
    _r("198.18.0.0/15", "is a benchmarking-range address (198.18.0.0/15)"),
    _r("240.0.0.0/4", "is a reserved address (240.0.0.0/4)"),
)

# IPv6 ranges blocked when `block_internal = true`. Link-local appears here
# as well as in the always-blocked tier so the table matches the policy as
# written; in practice the always-blocked check fires first.
BLOCK_INTERNAL_V6: Tuple[BlockedRange, ...] = (
    _r("::1/128", "resolves to the IPv6 loopback ::1"),
    _r("::/128", "is the IPv6 unspecified address ::"),
    _r("fc00::/7", "is an IPv6 unique-local address (fc00::/7)"),
    _r("fe80::/10", "is an IPv6 link-local address (fe80::/10)"),
    _r("2001:db8::/32", "is an IPv6 documentation-range address (2001:db8::/32)"),
)


def _first_match(table: Sequence[BlockedRange], ip: IPAddress) -> Optional[str]:
    """The reason of the first table entry containing ``ip``, if any."""
    for entry in table:
        if ip in entry.net:
            return entry.reason
    return None


def _unwrap_v4(ip: IPAddress) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 view of ``ip``: the address itself, or the embedded address
    of an IPv4-mapped IPv6 literal (``::ffff:a.b.c.d``). ``None`` for every
    other IPv6."""
    if isinstance(ip, ipaddress.IPv4Address):
        return ip
    return ip.ipv4_mapped


def always_blocked_ip_reason(ip: IPAddress) -> Optional[str]:
    """Reason if ``ip`` must be blocked regardless of policy: link-local
    (169.254.0.0/16, fe80::/10), which includes the cloud-metadata endpoint
    169.254.169.254. IPv4-mapped IPv6 is unwrapped first."""
    v4 = _unwrap_v4(ip)
    if v4 is not None:
        return _first_match(ALWAYS_BLOCKED_V4, v4)
    return _first_match(ALWAYS_BLOCKED_V6, ip)


def non_public_ip_reason(ip: IPAddress) -> Optional[str]:
    """Reason if ``ip`` is a non-public address that the opt-in
    ``block_internal`` policy blocks: loopback, private, shared,
    unspecified, broadcast, documentation, benchmarking, reserved, and the
    IPv6 equivalents. IPv4-mapped IPv6 is unwrapped so ``::ffff:127.0.0.1``
    is caught."""
    v4 = _unwrap_v4(ip)
    if v4 is not None:
        return _first_match(BLOCK_INTERNAL_V4, v4)
    return _first_match(BLOCK_INTERNAL_V6, ip)


def enforce_ip_policy(name: str, ip: IPAddress, block_internal: bool) -> None:
    """Enforce the egress policy for a literal (or resolved) target IP on
    behalf of argument ``name``: link-local / metadata is always blocked;
    the remaining non-public ranges are blocked only under the opt-in
    ``block_internal`` policy. Raises ``ValidationError``."""
    # Deferred: toolclad.validator imports this module at load.
    from toolclad.validator import ValidationError

    reason = always_blocked_ip_reason(ip)
    if reason is not None:
        raise ValidationError(f"argument '{name}' target {reason}")
    if block_internal:
        reason = non_public_ip_reason(ip)
        if reason is not None:
            raise ValidationError(
                f"argument '{name}' target {reason} (blocked by block_internal policy)"
            )


# ---------------------------------------------------------------------------
# Canonical-form parsers that sit in front of the policy
# ---------------------------------------------------------------------------

_ASCII_DIGITS_RE = re.compile(r"[0-9]+")

# Four decimal octets of 1-3 digits with no leading zero (a bare `0` is the
# only octet that may start with one). The 0-255 bound is checked after the
# match because a regex alternation for it would obscure the shape.
_IPV4_OCTET = r"(?:0|[1-9][0-9]{0,2})"
_CANONICAL_IPV4_RE = re.compile(rf"{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}")

# A CIDR prefix length: decimal digits, no sign, no leading zero.
_PREFIX_LEN_RE = re.compile(r"0|[1-9][0-9]{0,2}")


def _all_ascii_digits(s: str) -> bool:
    return _ASCII_DIGITS_RE.fullmatch(s) is not None


def _parse_canonical_ipv4(val: str) -> Optional[ipaddress.IPv4Address]:
    if _CANONICAL_IPV4_RE.fullmatch(val) is None:
        return None
    if any(int(octet) > 255 for octet in val.split(".")):
        return None
    return ipaddress.IPv4Address(val)


def _parse_canonical_ipv6(val: str) -> Optional[ipaddress.IPv6Address]:
    # Standard textual IPv6 only: hex groups, at most one `::`, and an
    # optional trailing dotted-quad that must itself be canonical. No zone
    # id, brackets or prefix length.
    if ":" not in val or not val.isascii() or any(c in val for c in "%[]/"):
        return None
    if "." in val:
        embedded = val.rsplit(":", 1)[1]
        if _parse_canonical_ipv4(embedded) is None:
            return None
    try:
        return ipaddress.IPv6Address(val)
    except ValueError:
        return None


def parse_canonical_ip(val: str) -> Optional[IPAddress]:
    """Parse only canonical IP text: dotted-quad IPv4 with decimal octets
    and no leading zeros, or standard IPv6 without a zone id. Integer
    (``2130706433``), hex (``0x7f000001``), octal (``0177.0.0.1``) and
    shorthand (``127.1``) encodings — all of which a libc resolver would
    expand to 127.0.0.1 — return ``None`` and are caught by
    ``looks_like_ip_literal`` instead."""
    v4 = _parse_canonical_ipv4(val)
    if v4 is not None:
        return v4
    return _parse_canonical_ipv6(val)


def parse_canonical_cidr(val: str) -> Optional[Tuple[IPAddress, int]]:
    """Parse only canonical CIDR text: a canonical address (see
    ``parse_canonical_ip``) followed by ``/`` and a decimal prefix length in
    range for that address family. Returns ``(base_address, prefix_len)``
    with the base address exactly as written (host bits are permitted, as in
    the other runtimes); the policy is applied to that base address."""
    base_text, sep, prefix_text = val.partition("/")
    if not sep:
        return None
    base = parse_canonical_ip(base_text)
    if base is None or _PREFIX_LEN_RE.fullmatch(prefix_text) is None:
        return None
    prefix_len = int(prefix_text)
    if prefix_len > base.max_prefixlen:
        return None
    return base, prefix_len


def looks_like_ip_literal(val: str) -> bool:
    """True if ``val`` is an attempt at an IP literal in a non-canonical
    encoding: a ``0x…`` hex form, or every dot-separated label is all ASCII
    digits (integer / dotted-decimal / octal / shorthand). A libc resolver
    would expand any of these to an address, so they must never pass as a
    hostname. Canonical IPs are handled by ``parse_canonical_ip`` first and
    never reach here."""
    if val[:2].lower() == "0x":
        return True
    return all(label != "" and _all_ascii_digits(label) for label in val.split("."))


def tld_not_all_numeric(val: str) -> bool:
    """True if the rightmost DNS label is non-empty and not entirely
    numeric. A real TLD is never all digits (RFC 3696 §2), so this rejects
    e.g. ``example.123``, dotted-decimal IPs that slipped past the literal
    parser, and a trailing-dot form whose last label is empty."""
    tld = val.rsplit(".", 1)[-1]
    return tld != "" and not _all_ascii_digits(tld)


def has_punycode_label(host: str) -> bool:
    """True if any DNS label in ``host`` is an A-label (``xn--…``).
    Comparison is case-insensitive per IDNA: ``XN--``, ``Xn--``, ``xN--``
    all count. Punycode is rejected everywhere because a homoglyph domain
    supplied in its ASCII form would otherwise satisfy an ASCII-only
    hostname check."""
    return any(
        len(label) >= 4 and label[:4].lower() == "xn--" for label in host.split(".")
    )
