"""Scope enforcement for arguments that declare ``scope_check = true``.

A project lists the targets it may touch in ``scope/scope.toml``::

    [scope]
    allowed_domains = ["example.com", "*.example.com"]
    allowed_cidrs   = ["10.0.1.0/24"]
    blocked_domains = []
    blocked_cidrs   = []

Discovery order (:func:`discover_scope`):

1. the path in ``TOOLCLAD_SCOPE_FILE`` (absolute or relative to the cwd);
   if it is set but cannot be read, that is an error, never a fallback;
2. ``scope/scope.toml`` searched upward from the manifest's directory (or
   from the cwd when the manifest did not come from a file), stopping at the
   filesystem root.

Matching (:func:`check_scope`), applied to the host of a ``url`` and to the
value itself for ``scope_target``, ``ip_address`` and ``cidr``:

* blocked rules are evaluated first and always win;
* ``"example.com"`` matches that host exactly, case-insensitively;
  ``"*.example.com"`` matches a strict subdomain at any depth, never the apex
  and never a bare string suffix such as ``evil-example.com``;
* an IP matches a CIDR rule when the range contains it; a CIDR subject
  matches an allowed range only when it is fully contained in it, and is
  refused by a blocked range it overlaps at all;
* no match is a refusal, and ``scope_check`` with no scope file is a refusal
  (fail closed). A file whose allowed lists are empty puts nothing in scope.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence, Tuple, Union

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from toolclad.hostpolicy import IPAddress, IPNetwork, parse_canonical_cidr, parse_canonical_ip

SCOPE_FILE_ENV = "TOOLCLAD_SCOPE_FILE"

# Argument types on which `scope_check = true` is honored.
SCOPE_CHECK_TYPES = frozenset({"scope_target", "url", "ip_address", "cidr"})

_SCOPE_KEYS = frozenset({"allowed_domains", "allowed_cidrs", "blocked_domains", "blocked_cidrs"})

# A domain rule: lowercase DNS labels, optionally behind one leading `*.`.
_DOMAIN_RULE_RE = re.compile(r"(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*")

NOT_FOUND_MESSAGE = (
    "scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)"
)


class ScopeError(ValueError):
    """Raised when a scope file cannot be read or is malformed."""


@dataclass
class ScopeDef:
    """A parsed scope file. CIDR rules are stored as networks with host bits
    masked off."""

    allowed_domains: List[str] = field(default_factory=list)
    allowed_cidrs: List[IPNetwork] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    blocked_cidrs: List[IPNetwork] = field(default_factory=list)
    source_path: str = ""


def _parse_domain_rules(key: str, value: Any, origin: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f"scope file {origin}: 'scope.{key}' must be a list of strings")
    for rule in value:
        if _DOMAIN_RULE_RE.fullmatch(rule) is None:
            raise ScopeError(
                f"scope file {origin}: invalid domain rule '{rule}' in scope.{key} "
                "(lowercase [a-z0-9.-] labels with an optional leading '*.')"
            )
    return list(value)


def _parse_cidr_rules(key: str, value: Any, origin: str) -> List[IPNetwork]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f"scope file {origin}: 'scope.{key}' must be a list of strings")
    nets: List[IPNetwork] = []
    for rule in value:
        parsed = parse_canonical_cidr(rule)
        if parsed is None:
            raise ScopeError(f"scope file {origin}: invalid CIDR '{rule}' in scope.{key}")
        nets.append(ipaddress.ip_network(f"{parsed[0]}/{parsed[1]}", strict=False))
    return nets


def parse_scope(data: Mapping[str, Any], origin: str = "<string>") -> ScopeDef:
    """Build a :class:`ScopeDef` from parsed TOML. Unknown keys, a malformed
    CIDR and a malformed domain rule each raise :class:`ScopeError`."""
    unknown = sorted(k for k in data if k != "scope")
    section = data.get("scope", {})
    if not isinstance(section, dict):
        raise ScopeError(f"scope file {origin}: [scope] must be a table")
    unknown += sorted(f"scope.{k}" for k in section if k not in _SCOPE_KEYS)
    if unknown:
        raise ScopeError(
            "; ".join(f"unknown key '{k}' in scope file {origin}" for k in unknown)
        )
    return ScopeDef(
        allowed_domains=_parse_domain_rules(
            "allowed_domains", section.get("allowed_domains", []), origin
        ),
        allowed_cidrs=_parse_cidr_rules("allowed_cidrs", section.get("allowed_cidrs", []), origin),
        blocked_domains=_parse_domain_rules(
            "blocked_domains", section.get("blocked_domains", []), origin
        ),
        blocked_cidrs=_parse_cidr_rules("blocked_cidrs", section.get("blocked_cidrs", []), origin),
        source_path=origin,
    )


def load_scope_file(path: Union[str, os.PathLike]) -> ScopeDef:
    """Read and parse a scope file. Raises :class:`ScopeError` when it cannot
    be read, is not valid TOML, or fails the rules of :func:`parse_scope`."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except OSError as exc:
        raise ScopeError(f"cannot read scope file {path}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ScopeError(f"scope file {path} is not valid TOML: {exc}") from exc
    return parse_scope(data, str(path))


def discover_scope(manifest_dir: Optional[Union[str, os.PathLike]] = None) -> Optional[ScopeDef]:
    """Find and load the scope file for a manifest in ``manifest_dir``
    (``None`` or empty: the cwd). Returns ``None`` when no file exists.
    A set but unreadable ``TOOLCLAD_SCOPE_FILE`` raises :class:`ScopeError`."""
    env = os.environ.get(SCOPE_FILE_ENV)
    if env:
        return load_scope_file(env)
    start = Path(manifest_dir) if manifest_dir else Path.cwd()
    for directory in (start.resolve(), *start.resolve().parents):
        candidate = directory / "scope" / "scope.toml"
        if candidate.is_file():
            return load_scope_file(candidate)
    return None


_UNSET = object()


def manifest_scope(manifest: Any) -> Optional[ScopeDef]:
    """The scope for a loaded manifest, discovered at most once and cached on
    it. Discovery runs only when some argument declares ``scope_check``; a
    manifest that never asks for scope never touches the filesystem (and a
    broken ``TOOLCLAD_SCOPE_FILE`` does not affect it)."""
    cached = getattr(manifest, "_scope_cache", _UNSET)
    if cached is not _UNSET:
        return cached
    from toolclad.manifest import _iter_args

    scope: Optional[ScopeDef] = None
    if any(arg.scope_check for arg in _iter_args(manifest)):
        source = getattr(manifest, "source_path", "")
        scope = discover_scope(os.path.dirname(source) if source else None)
    object.__setattr__(manifest, "_scope_cache", scope)
    return scope


# ---------------------------------------------------------------------------
# Matchers
# ---------------------------------------------------------------------------


def _unwrap(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _as_address(ip: Union[str, IPAddress]) -> Optional[IPAddress]:
    return parse_canonical_ip(ip) if isinstance(ip, str) else ip


def _as_network(cidr: Union[str, IPNetwork]) -> Optional[IPNetwork]:
    if not isinstance(cidr, str):
        return cidr
    parsed = parse_canonical_cidr(cidr)
    if parsed is None:
        return None
    return ipaddress.ip_network(f"{parsed[0]}/{parsed[1]}", strict=False)


def ip_in_cidr(ip: Union[str, IPAddress], cidr: Union[str, IPNetwork]) -> bool:
    """True when ``ip`` lies in ``cidr``. Either may be text (canonical form
    only) or an ``ipaddress`` object; an IPv4-mapped IPv6 address is compared
    as its IPv4 address. Unparseable input returns False."""
    addr, net = _as_address(ip), _as_network(cidr)
    if addr is None or net is None:
        return False
    addr = _unwrap(addr)
    return addr.version == net.version and addr in net


def cidr_within(inner: Union[str, IPNetwork], outer: Union[str, IPNetwork]) -> bool:
    """True when the range ``inner`` is fully contained in ``outer``."""
    a, b = _as_network(inner), _as_network(outer)
    return a is not None and b is not None and a.version == b.version and a.subnet_of(b)


def _cidr_overlaps(a: IPNetwork, b: IPNetwork) -> bool:
    return a.version == b.version and a.overlaps(b)


def host_matches_rule(host: str, pattern: str) -> bool:
    """Domain-rule match: exact (case-insensitive), or ``*.suffix`` for a
    strict subdomain at any depth on a label boundary."""
    host, pattern = host.lower(), pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    return host == pattern


def _subject(value: str) -> Tuple[str, Union[IPAddress, IPNetwork, str]]:
    ip = parse_canonical_ip(value)
    if ip is not None:
        return "ip", _unwrap(ip)
    net = _as_network(value)
    if net is not None:
        return "cidr", net
    return "host", value


def in_scope(subject: str, scope: ScopeDef) -> bool:
    """True when ``subject`` (a host, IP or CIDR as text) is in scope."""
    kind, val = _subject(subject)
    if kind == "host":
        assert isinstance(val, str)
        if any(host_matches_rule(val, r) for r in scope.blocked_domains):
            return False
        return any(host_matches_rule(val, r) for r in scope.allowed_domains)
    if kind == "ip":
        if any(ip_in_cidr(val, n) for n in scope.blocked_cidrs):  # type: ignore[arg-type]
            return False
        return any(ip_in_cidr(val, n) for n in scope.allowed_cidrs)  # type: ignore[arg-type]
    if any(_cidr_overlaps(val, n) for n in scope.blocked_cidrs):  # type: ignore[arg-type]
        return False
    return any(cidr_within(val, n) for n in scope.allowed_cidrs)  # type: ignore[arg-type]


def check_scope(name: str, subject: str, scope: Optional[ScopeDef], display: Optional[str] = None) -> None:
    """Refuse ``subject`` for argument ``name`` unless it is in ``scope``.
    ``scope=None`` is the fail-closed refusal. ``display`` is the value named
    in the error (the full URL for a url argument). Raises ``ValidationError``."""
    from toolclad.validator import ValidationError

    if scope is None:
        raise ValidationError(f"argument '{name}' {NOT_FOUND_MESSAGE}")
    if not in_scope(subject, scope):
        raise ValidationError(
            f"argument '{name}' target '{display if display is not None else subject}' "
            "is not in scope"
        )


def url_host_in_scope(url: str, allowed_hosts: Sequence[str]) -> bool:
    """True when ``url`` validates as a ``url`` argument and its host is in a
    scope whose ``allowed_domains`` is ``allowed_hosts``."""
    from toolclad.manifest import ArgDef
    from toolclad.validator import ValidationError, validate_arg_in

    scope = ScopeDef(allowed_domains=list(allowed_hosts))
    try:
        validate_arg_in(ArgDef(name="url", type="url", scope_check=True), url, False, scope)
    except ValidationError:
        return False
    return True
