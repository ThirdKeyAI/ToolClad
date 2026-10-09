"""Argument type validation for ToolClad manifests."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from toolclad.hostpolicy import (
    enforce_cidr_policy,
    enforce_hostname_policy,
    enforce_ip_policy,
    has_punycode_label,
    looks_like_ip_literal,
    parse_canonical_cidr,
    parse_canonical_ip,
    tld_not_all_numeric,
)
from toolclad.manifest import NETWORK_TARGET_TYPES, ArgDef

# Shell metacharacters that indicate injection attempts.
SHELL_METACHARACTERS = set(";|&$`(){}[]<>!\n\r")

# Regex for a valid hostname label.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)


class ValidationError(Exception):
    """Raised when an argument value fails validation."""


# Types whose value is passed through as text and therefore get the full
# string-derived hygiene rules (NUL, control characters, quotes/backslash,
# whitespace, leading dash) before any type-specific parsing.
STRING_DERIVED_TYPES = frozenset(
    {"string", "path", "credential_file", "regex_match", "url", "scope_target",
     "duration", "msf_options"}
)

# Numeric types get the leading-dash rule on the *output* value, after range
# checking and clamping, so `-5` with `clamp` and `min = 1` yields `1`.
NUMERIC_TYPES = frozenset({"integer", "number", "port"})

def _check_injection(value: str) -> None:
    """Reject values containing shell metacharacters."""
    found = set(value) & SHELL_METACHARACTERS
    if found:
        chars = ", ".join(sorted(repr(c) for c in found))
        raise ValidationError(
            f"Injection check failed: value contains shell metacharacters: {chars}"
        )


def _check_leading_dash(arg_def: ArgDef, value: str) -> None:
    """Reject a value that an invoked binary could read as an option."""
    if value[:1] in ("-", "+") and not arg_def.allow_leading_dash:
        raise ValidationError(
            "must not start with '-' or '+' (set allow_leading_dash = true to permit)"
        )


def _check_hygiene(arg_def: ArgDef, value: str, exec_mode: bool) -> None:
    """String-derived value hygiene, in the normative order.

    NUL is checked by the caller for every type. Control characters (every
    C0 including tab, newline and carriage return, DEL, and the C1 range)
    are rejected unconditionally. ``msf_options`` is exempt from the
    whitespace rule only (the ASCII space is its ``KEY VALUE`` separator).
    ``allow_whitespace`` is honored only in exec mode (a manifest that
    declared ``exec`` directly, never a template compiled to exec) and even
    then permits only the ASCII space U+0020; a non-breaking or ideographic
    space is a homoglyph, not a separator. A ``url`` never contains
    whitespace, whatever the opt-in says.
    """
    for c in value:
        code = ord(c)
        if code < 0x20 or 0x7F <= code <= 0x9F:
            raise ValidationError("must not contain control characters")
    if "\\" in value and arg_def.type == "scope_target":
        raise ValidationError(
            f"scope_target must not contain backslash escape sequences: {value!r}"
        )
    if "'" in value or '"' in value or "\\" in value:
        raise ValidationError("must not contain quote or backslash characters")
    if any(c.isspace() for c in value):
        space_ok = arg_def.type == "msf_options" or (
            arg_def.allow_whitespace and exec_mode and arg_def.type != "url"
        )
        if not space_ok or any(c.isspace() and c != " " for c in value):
            raise ValidationError("must not contain whitespace")
    _check_leading_dash(arg_def, value)


def _anchor_pattern(pattern: str) -> str:
    """Anchor a manifest pattern as ``^(?:<pat>)\\Z``.

    One leading ``^`` and one trailing unescaped ``$`` are stripped first.
    ``\\Z`` rather than ``$`` so a trailing newline cannot match.
    """
    if pattern.startswith("^"):
        pattern = pattern[1:]
    if pattern.endswith("$"):
        trailing_backslashes = len(pattern) - 1 - len(pattern[:-1].rstrip("\\"))
        if trailing_backslashes % 2 == 0:
            pattern = pattern[:-1]
    return r"^(?:" + pattern + r")\Z"


def _matches_pattern(pattern: str, value: str) -> bool:
    """Full-match ``value`` against the anchored form of ``pattern``."""
    try:
        return re.match(_anchor_pattern(pattern), value) is not None
    except re.error as exc:
        raise ValidationError(f"Invalid pattern {pattern!r}: {exc}")


def _validate_string(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    if arg_def.pattern:
        if not _matches_pattern(arg_def.pattern, value):
            raise ValidationError(
                f"Value '{value}' does not match pattern: {arg_def.pattern}"
            )
    return value


def _validate_integer(arg_def: ArgDef, value: str) -> str:
    try:
        num = int(value)
    except (ValueError, TypeError):
        raise ValidationError(f"Expected integer, got: {value!r}")

    if arg_def.min is not None or arg_def.max is not None:
        lo = arg_def.min if arg_def.min is not None else num
        hi = arg_def.max if arg_def.max is not None else num
        if arg_def.clamp:
            num = max(lo, min(hi, num))
        else:
            if num < lo:
                raise ValidationError(f"Value {num} is below minimum {lo}")
            if num > hi:
                raise ValidationError(f"Value {num} is above maximum {hi}")
    return str(num)


def _validate_number(arg_def: ArgDef, value: str) -> str:
    import math
    try:
        num = float(value)
    except (ValueError, TypeError):
        raise ValidationError(f"Expected number, got: {value!r}")
    if not math.isfinite(num):
        raise ValidationError(
            f"Number must be finite (no NaN or infinity), got: {value!r}"
        )

    lo = arg_def.min_float
    if lo is None and arg_def.min is not None:
        lo = float(arg_def.min)
    hi = arg_def.max_float
    if hi is None and arg_def.max is not None:
        hi = float(arg_def.max)

    if lo is not None or hi is not None:
        bound_lo = lo if lo is not None else num
        bound_hi = hi if hi is not None else num
        if arg_def.clamp:
            num = max(bound_lo, min(bound_hi, num))
        else:
            if num < bound_lo:
                raise ValidationError(f"Value {num} is below minimum {bound_lo}")
            if num > bound_hi:
                raise ValidationError(f"Value {num} is above maximum {bound_hi}")
    return str(num)


def _validate_port(arg_def: ArgDef, value: str) -> str:
    try:
        port = int(value)
    except (ValueError, TypeError):
        raise ValidationError(f"Expected port number, got: {value!r}")
    if port < 1 or port > 65535:
        raise ValidationError(f"Port {port} out of range 1-65535")
    return str(port)


def _validate_boolean(arg_def: ArgDef, value: str) -> str:
    lower = str(value).lower()
    if lower not in ("true", "false"):
        raise ValidationError(
            f"Expected 'true' or 'false', got: {value!r}"
        )
    return lower


def _validate_enum(arg_def: ArgDef, value: str) -> str:
    if not arg_def.allowed:
        raise ValidationError("Enum type requires 'allowed' list in arg definition")
    if value not in arg_def.allowed:
        raise ValidationError(
            f"Value '{value}' not in allowed values: {arg_def.allowed}"
        )
    return value


# ---------------------------------------------------------------------------
# Network-typed values: scope_target, url, ip_address, cidr
#
# Every literal address, CIDR range and hostname goes through
# ``toolclad.hostpolicy`` — the range table, the overlap test for ranges, the
# canonical-literal parsers, the punycode rule, the internal-name denylist,
# the embedded-literal rule and DNS resolution under ``block_internal`` — so
# the policy can be compared side by side with the other runtimes.
# ---------------------------------------------------------------------------

def _is_valid_hostname(value: str) -> bool:
    """Structural hostname check: RFC 1035 labels, the 253-octet cap, and a
    rightmost label that is not all digits (a real TLD never is, RFC 3696
    §2 — which also rejects dotted-decimal IPs that slipped past the literal
    parser and the trailing-dot form)."""
    return (
        len(value) <= 253
        and bool(_HOSTNAME_RE.match(value))
        and tld_not_all_numeric(value)
    )


def _is_valid_ip(value: str) -> bool:
    """Check if value is a canonical IPv4 or IPv6 address."""
    return parse_canonical_ip(value) is not None


def _is_valid_cidr(value: str) -> bool:
    """Check if value is canonical CIDR notation."""
    return parse_canonical_cidr(value) is not None


# RFC 1035 §2.3.4 caps a fully-qualified domain name at 253 octets.
# IPv6 textual form maxes out at 45 chars. We use 253 as the upper bound
# for any scope_target shape — hostnames, IPv4, IPv6, and CIDRs all fit
# well below it, and rejecting anything longer is defense-in-depth
# against buffer-pathological payloads.
_SCOPE_TARGET_MAX_LEN = 253


def _validate_scope_target(arg_def: ArgDef, value: str) -> str:
    # Scope validation rules (aligned across Rust, Python, JS, Go):
    # 1. Reject shell metacharacters  2. Block * and ? wildcards
    # 3. Surface specific failure modes (traversal, slashes, escapes, IDN) before
    #    falling through to the generic regex catch-all.
    # 4. Accept valid IPv4, IPv6, CIDR, or hostname.
    if not value:
        raise ValidationError("scope_target must not be empty")
    if value != value.strip():
        # RFC 1035 / RFC 5891 don't permit terminal whitespace in hostname
        # labels. Reject explicitly so silent CLI trimming can't mask
        # malformed input.
        raise ValidationError(
            f"scope_target must not contain leading or trailing whitespace: {value!r}"
        )
    if len(value) > _SCOPE_TARGET_MAX_LEN:
        raise ValidationError(
            f"scope_target exceeds {_SCOPE_TARGET_MAX_LEN}-character limit "
            f"(RFC 1035 §2.3.4): length={len(value)}"
        )
    _check_injection(value)
    if "*" in value or "?" in value:
        raise ValidationError(f"Wildcard targets are not allowed: {value!r}")

    if "../" in value or "..\\" in value or "/.." in value:
        raise ValidationError(
            f"scope_target must not contain path traversal sequences: {value!r}"
        )
    if "/" in value and not _is_valid_cidr(value) and not _is_valid_ip(value):
        raise ValidationError(
            f"scope_target must not contain '/' "
            f"(use CIDR notation for ranges): {value!r}"
        )
    if "\\" in value:
        raise ValidationError(
            f"scope_target must not contain backslash escape sequences: {value!r}"
        )
    if not value.isascii():
        raise ValidationError(
            f"scope_target must be ASCII (non-ASCII hostnames including IDN "
            f"homoglyphs are rejected; gate IDN registration upstream if needed): {value!r}"
        )
    # Defense-in-depth against IDN homoglyph bypass via punycode.
    if has_punycode_label(value):
        raise ValidationError(
            f"scope_target must not contain punycode (xn--) labels — IDN/IDNA "
            f"hostnames are rejected to prevent homoglyph bypass; gate IDN "
            f"registration upstream if needed: {value!r}"
        )

    # Canonical IP literals only (see hostpolicy.parse_canonical_ip): the
    # egress policy is applied to the literal address.
    ip = parse_canonical_ip(value)
    if ip is not None:
        enforce_ip_policy(arg_def.name, ip, arg_def.block_internal)
        return value

    # CIDR ranges: the whole range is tested for overlap with each blocked
    # prefix, so a supernet of a blocked range is refused too.
    cidr = parse_canonical_cidr(value)
    if cidr is not None:
        enforce_cidr_policy(arg_def.name, cidr[0], cidr[1], arg_def.block_internal)
        return value

    # A non-canonical IP-literal encoding must not slip through as a
    # "hostname": a downstream resolver would expand it to an address. No
    # legitimate hostname is all-numeric labels or a 0x-prefixed hex literal.
    if looks_like_ip_literal(value):
        raise ValidationError(
            "scope_target looks like a non-canonical IP literal; use "
            f"dotted-quad IPv4 or standard IPv6: {value!r}"
        )

    if not _is_valid_hostname(value):
        raise ValidationError(
            f"Invalid scope target: {value!r} "
            "(must be a valid IP, CIDR, or hostname)"
        )
    # The structural check above has already refused the trailing-dot form,
    # so the name policy compares exactly what a resolver would see: the
    # internal-name denylist, an embedded IP literal, then DNS resolution
    # under block_internal.
    enforce_hostname_policy(arg_def.name, value, arg_def.block_internal)
    return value


# Schemes a url argument may use when the manifest does not set `schemes`.
_DEFAULT_URL_SCHEMES = ("http", "https")

# Never permitted, even when a manifest lists one in `schemes`: each either
# executes content, reads local files, or speaks a protocol that can be
# driven at an internal service by a crafted URL.
_DENIED_URL_SCHEMES = frozenset({
    "javascript", "data", "file", "blob", "about", "gopher", "dict", "ftp",
    "ldap", "jar", "netdoc", "mailto", "ws", "wss",
})

# A URL port: plain decimal digits only (int() would also accept a sign,
# surrounding whitespace and non-ASCII digits), short enough to convert.
_URL_PORT_RE = re.compile(r"[0-9]{1,5}")


def _split_url_authority(
    authority: str,
) -> Tuple[str, Optional[int], Optional[ipaddress.IPv6Address]]:
    """Split a URL authority into ``(host, port, bracketed_v6)``.

    ``authority`` is everything between ``://`` and the first ``/``, ``?``
    or ``#``, with userinfo already refused. A bracketed IPv6 literal is
    unwrapped and must be canonical; an unbracketed one is ambiguous with a
    port and refused. A written port must be 1-65535 in plain decimal
    digits. Every malformed shape raises ``ValidationError``.
    """
    bracketed_v6: Optional[ipaddress.IPv6Address] = None
    port_text: Optional[str] = None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise ValidationError("URL has a malformed bracketed IPv6 host")
        host = authority[1:close]
        tail = authority[close + 1:]
        if tail:
            if not tail.startswith(":"):
                raise ValidationError("URL has a malformed bracketed IPv6 host")
            port_text = tail[1:]
        parsed = parse_canonical_ip(host)
        if not isinstance(parsed, ipaddress.IPv6Address):
            raise ValidationError("URL bracketed host is not a valid IPv6 literal")
        bracketed_v6 = parsed
    else:
        head, sep, tail = authority.rpartition(":")
        if sep:
            host, port_text = head, tail
        else:
            host = authority

    if not host:
        raise ValidationError("URL has an empty host")
    if bracketed_v6 is None and ":" in host:
        raise ValidationError("URL IPv6 host must be enclosed in brackets")

    port: Optional[int] = None
    if port_text is not None:
        if _URL_PORT_RE.fullmatch(port_text) is None or not 1 <= int(port_text) <= 65535:
            raise ValidationError("URL port must be 1-65535")
        port = int(port_text)
    return host, port, bracketed_v6


def _validate_url(arg_def: ArgDef, value: str) -> str:
    """The ``url`` validator, in order: the string-derived hygiene has
    already run (whitespace is never admitted for a url, opt-in or not);
    then the shell-metacharacter blocklist, which rejects ``{`` and ``}``
    and therefore any ``{_secret:…}`` reference; then a structural parse —
    ``scheme://``, the scheme allowlist, the scheme denylist, no userinfo,
    host extraction with an optional port — and finally the host policy of
    ``toolclad.hostpolicy``.

    This is deliberately not a WHATWG / RFC 3986 normalizer (``urlparse``
    accepts any scheme and tolerates spaces). The fetcher downstream will
    parse the value again with its own rules, so anything a human reviewer
    of the manifest could misread is refused here rather than normalized
    away.
    """
    _check_injection(value)

    # Step 2: scheme://rest.
    scheme, sep, rest = value.partition("://")
    if not sep:
        raise ValidationError(f"Invalid URL: {value!r} (expected scheme://host)")
    scheme = scheme.lower()

    # Step 3: allowlist — the manifest's `schemes` when set, else http/https.
    allowed = [str(s).lower() for s in arg_def.schemes] or list(_DEFAULT_URL_SCHEMES)
    if scheme not in allowed:
        raise ValidationError(
            f"URL scheme '{scheme}' is not permitted (allowed: {', '.join(allowed)})"
        )

    # Step 4: explicit denial, even when a manifest lists the scheme.
    if scheme in _DENIED_URL_SCHEMES:
        raise ValidationError(
            f"URL scheme '{scheme}' is never permitted for a url argument"
        )

    # Step 5: the authority ends at the first '/', '?' or '#'. An '@' before
    # that is userinfo, which hides the real host from a reviewer.
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority:
        raise ValidationError("URL must not contain userinfo (user:pass@host)")

    # Step 6: host and optional port.
    host, _port, bracketed_v6 = _split_url_authority(authority)

    # Step 7: host policy — the same checks as scope_target, since curl and
    # wget-style fetchers are the prime SSRF vector.
    if has_punycode_label(host):
        raise ValidationError("URL host must not contain punycode (xn--) labels")
    ip = bracketed_v6 if bracketed_v6 is not None else parse_canonical_ip(host)
    if ip is not None:
        enforce_ip_policy(arg_def.name, ip, arg_def.block_internal)
    else:
        if not host.isascii():
            raise ValidationError(
                "URL host must be ASCII (IDN hostnames are rejected to prevent "
                "homoglyph bypass)"
            )
        if looks_like_ip_literal(host):
            raise ValidationError(
                "URL host looks like a non-canonical IP literal; use dotted-quad "
                f"IPv4 or a hostname: {host!r}"
            )
        if len(host) > _SCOPE_TARGET_MAX_LEN or any(
            len(label) > 63 for label in host.split(".")
        ):
            raise ValidationError("URL host exceeds DNS length limits (RFC 1035 §2.3.4)")
        if not _is_valid_hostname(host):
            raise ValidationError(
                f"URL host is not a valid hostname or IP literal: {host!r}"
            )
        # Trailing dot already refused above; the name policy (internal-name
        # denylist, embedded IP literal, DNS resolution under block_internal)
        # sees the host exactly as the fetcher would.
        enforce_hostname_policy(arg_def.name, host, arg_def.block_internal)

    # Step 8 — SCOPE HOOK: when arg_def.scope_check is set, the scope checker
    # (a later wave) is consulted here with `host`. Not implemented yet; the
    # flag is parsed and carried so manifests can already declare it.
    return value


def _validate_path(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    # Block absolute paths
    if value.startswith("/") or (len(value) >= 2 and value[1] == ":"):
        raise ValidationError(f"Path must be relative, not absolute: {value}")
    if ".." in value.split("/") or ".." in value.split("\\"):
        raise ValidationError(f"Path traversal detected in: {value!r}")
    return value


def _validate_ip_address(arg_def: ArgDef, value: str) -> str:
    """A canonical IPv4 or IPv6 literal, under the same egress policy as
    every other address-carrying type: link-local is always refused, the
    rest of the non-public table under ``block_internal``."""
    ip = parse_canonical_ip(value)
    if ip is None:
        raise ValidationError(f"Invalid IP address: {value!r}")
    enforce_ip_policy(arg_def.name, ip, arg_def.block_internal)
    return value


def _validate_cidr(arg_def: ArgDef, value: str) -> str:
    if "/" not in value:
        raise ValidationError(f"CIDR notation requires '/': {value!r}")
    parsed = parse_canonical_cidr(value)
    if parsed is None:
        raise ValidationError(f"Invalid CIDR: {value!r}")
    # The whole range is tested for overlap with each blocked prefix, not
    # just the base address as written.
    enforce_cidr_policy(arg_def.name, parsed[0], parsed[1], arg_def.block_internal)
    return value


def _validate_msf_options(arg_def: ArgDef, value: str) -> str:
    import re as _re
    key_re = _re.compile(r'^[A-Z][A-Z0-9_]*$')
    # Don't use _check_injection on the whole value since ; is a valid delimiter
    metachar_no_semi = set("|&$`(){}[]<>!\n\r")
    for pair in value.split(';'):
        pair = pair.strip()
        if not pair:
            continue
        parts = pair.split(' ', 1)
        if len(parts) != 2:
            raise ValidationError(f"msf_options: invalid pair '{pair}' (expected 'KEY VALUE')")
        key, val = parts
        if not key_re.match(key):
            raise ValidationError(f"msf_options: invalid key '{key}' (must be uppercase alphanumeric)")
        found = set(val) & metachar_no_semi
        if found:
            chars = ", ".join(sorted(repr(c) for c in found))
            raise ValidationError(f"msf_options: value contains disallowed characters: {chars}")
    return value


def _validate_credential_file(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    if value.startswith("/") or (len(value) >= 2 and value[1] == ":"):
        raise ValidationError(f"Credential file must be a relative path: {value}")
    if ".." in value.split("/") or ".." in value.split("\\"):
        raise ValidationError(f"Path traversal detected: {value}")
    import os
    if not os.path.exists(value):
        raise ValidationError(f"Credential file not found: {value}")
    if not os.path.isfile(value):
        raise ValidationError(f"Not a file: {value}")
    return value


def _validate_duration(arg_def: ArgDef, value: str) -> str:
    import re as _re
    # Plain integer seconds
    try:
        int(value)
        return value
    except ValueError:
        pass
    # Duration with suffix
    if not _re.match(r'^(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?$', value) or value == '':
        raise ValidationError(f"Invalid duration: {value!r} (e.g. '30', '5m', '2h', '1h30m', '500ms')")
    return value


def _validate_regex_match(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    if not arg_def.pattern:
        raise ValidationError("regex_match type requires a 'pattern' field")
    if not _matches_pattern(arg_def.pattern, value):
        raise ValidationError(f"Value {value!r} does not match required pattern: {arg_def.pattern}")
    return value


# Registry of type handlers.
_TYPE_HANDLERS = {
    "string": _validate_string,
    "integer": _validate_integer,
    "number": _validate_number,
    "port": _validate_port,
    "boolean": _validate_boolean,
    "enum": _validate_enum,
    "scope_target": _validate_scope_target,
    "url": _validate_url,
    "path": _validate_path,
    "ip_address": _validate_ip_address,
    "cidr": _validate_cidr,
    "msf_options": _validate_msf_options,
    "credential_file": _validate_credential_file,
    "duration": _validate_duration,
    "regex_match": _validate_regex_match,
}

SUPPORTED_TYPES: List[str] = sorted(_TYPE_HANDLERS.keys())


def _run_validation(arg_def: ArgDef, str_value: str, exec_mode: bool) -> str:
    """Apply hygiene, the type handler, and the numeric leading-dash rule."""
    handler = _TYPE_HANDLERS.get(arg_def.type)
    if handler is None:
        raise ValidationError(f"Unknown type: {arg_def.type!r}")
    if "\0" in str_value:
        raise ValidationError("must not contain NUL bytes")
    if arg_def.type in STRING_DERIVED_TYPES:
        _check_hygiene(arg_def, str_value, exec_mode)
    result = handler(arg_def, str_value)
    if arg_def.type in NUMERIC_TYPES:
        _check_leading_dash(arg_def, result)
    return result


def validate_arg_mode(arg_def: ArgDef, value: Any, exec_mode: bool) -> str:
    """Validate a value against an argument definition and return the cleaned value.

    Args:
        arg_def: The argument definition from the manifest.
        value: The raw value to validate (will be converted to str).
        exec_mode: True only when the manifest declared ``command.exec``
            directly. This is the sole mode in which ``allow_whitespace``
            is honored; a template compiled to exec is still strict.

    Returns:
        The cleaned, validated string value.

    Raises:
        ValidationError: If the value fails validation.
    """
    return _run_validation(arg_def, str(value), exec_mode)


def validate_arg(arg_def: ArgDef, value: Any) -> str:
    """Validate a value in strict (template) mode: whitespace is always rejected.

    Equivalent to ``validate_arg_mode(arg_def, value, exec_mode=False)``.
    """
    return validate_arg_mode(arg_def, value, exec_mode=False)


def validate_arg_with_custom_types_mode(
    arg_def: ArgDef,
    value: Any,
    custom_types: Dict[str, "CustomTypeDef"],
    exec_mode: bool,
) -> str:
    """Validate using custom type definitions.

    If the arg type matches a custom type, create a synthetic ArgDef
    from the custom type and delegate to the base type validator. The
    custom type's ``pattern`` is anchored exactly like a built-in one.

    A custom type whose base is a network target type (``scope_target``,
    ``url``, ``ip_address``, ``cidr``) is refused outright: the synthetic
    definition cannot carry ``block_internal``, so the author's flag would
    be silently dropped. Network targets use the built-in types.
    """
    from toolclad.manifest import CustomTypeDef  # avoid circular import  # noqa: F811

    if arg_def.type in custom_types:
        custom = custom_types[arg_def.type]
        if custom.base not in _TYPE_HANDLERS:
            raise ValidationError(f"Custom type '{arg_def.type}' has invalid base type '{custom.base}'")
        if custom.base in NETWORK_TARGET_TYPES:
            raise ValidationError(
                f"argument '{arg_def.name}' uses custom type '{arg_def.type}' as a "
                f"network target; custom types cannot carry block_internal — use "
                f"the built-in {custom.base} type"
            )

        # Create synthetic ArgDef with custom type constraints merged
        synthetic = ArgDef(
            name=arg_def.name,
            position=arg_def.position,
            required=arg_def.required,
            type=custom.base,
            description=arg_def.description,
            default=arg_def.default,
            allowed=custom.allowed or arg_def.allowed,
            pattern=custom.pattern or arg_def.pattern,
            min=custom.min if custom.min is not None else arg_def.min,
            max=custom.max if custom.max is not None else arg_def.max,
            min_float=custom.min_float if custom.min_float is not None else arg_def.min_float,
            max_float=custom.max_float if custom.max_float is not None else arg_def.max_float,
            clamp=arg_def.clamp,
            sanitize=arg_def.sanitize,
            schemes=arg_def.schemes,
            scope_check=arg_def.scope_check,
            allow_leading_dash=arg_def.allow_leading_dash,
            allow_whitespace=arg_def.allow_whitespace,
        )
        return _run_validation(synthetic, str(value), exec_mode)

    # Not a custom type, use standard validation
    return validate_arg_mode(arg_def, value, exec_mode)


def validate_arg_with_custom_types(
    arg_def: ArgDef,
    value: Any,
    custom_types: Dict[str, "CustomTypeDef"],
) -> str:
    """Strict-mode form of ``validate_arg_with_custom_types_mode``."""
    return validate_arg_with_custom_types_mode(arg_def, value, custom_types, exec_mode=False)
