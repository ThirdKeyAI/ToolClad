"""Argument type validation for ToolClad manifests."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from toolclad.manifest import ArgDef

# Shell metacharacters that indicate injection attempts.
SHELL_METACHARACTERS = set(";|&$`(){}[]<>!\n\r")

# Regex for a valid hostname label.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)


class ValidationError(Exception):
    """Raised when an argument value fails validation."""


def _check_injection(value: str) -> None:
    """Reject values containing shell metacharacters."""
    found = set(value) & SHELL_METACHARACTERS
    if found:
        chars = ", ".join(sorted(repr(c) for c in found))
        raise ValidationError(
            f"Injection check failed: value contains shell metacharacters: {chars}"
        )


def _validate_string(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    if arg_def.pattern:
        if not re.match(arg_def.pattern, value):
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


def _is_valid_hostname(value: str) -> bool:
    """Check if value looks like a valid hostname (not IP, not CIDR)."""
    return bool(_HOSTNAME_RE.match(value)) and len(value) <= 253


def _is_valid_ip(value: str) -> bool:
    """Check if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_cidr(value: str) -> bool:
    """Check if value is valid CIDR notation."""
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _has_punycode_label(host: str) -> bool:
    """Returns True if any DNS label in `host` is an A-label (case-insensitive xn--)."""
    for label in host.split("."):
        if len(label) >= 4 and label[:4].lower() == "xn--":
            return True
    return False


def _validate_scope_target(arg_def: ArgDef, value: str) -> str:
    # Scope validation rules (aligned across Rust, Python, JS, Go):
    # 1. Reject shell metacharacters  2. Block * and ? wildcards
    # 3. Surface specific failure modes (traversal, slashes, escapes, IDN) before
    #    falling through to the generic regex catch-all.
    # 4. Accept valid IPv4, IPv6, CIDR, or hostname.
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
    if _has_punycode_label(value):
        raise ValidationError(
            f"scope_target must not contain punycode (xn--) labels — IDN/IDNA "
            f"hostnames are rejected to prevent homoglyph bypass; gate IDN "
            f"registration upstream if needed: {value!r}"
        )

    if not (_is_valid_ip(value) or _is_valid_cidr(value) or _is_valid_hostname(value)):
        raise ValidationError(
            f"Invalid scope target: {value!r} "
            "(must be a valid IP, CIDR, or hostname)"
        )
    return value


def _validate_url(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Invalid URL: {value!r}")
    if arg_def.schemes and parsed.scheme not in arg_def.schemes:
        raise ValidationError(
            f"URL scheme '{parsed.scheme}' not in allowed schemes: {arg_def.schemes}"
        )
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
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError(f"Invalid IP address: {value!r}")
    return value


def _validate_cidr(arg_def: ArgDef, value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValidationError(f"Invalid CIDR: {value!r}")
    if "/" not in value:
        raise ValidationError(f"CIDR notation requires '/': {value!r}")
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
    if not re.match(arg_def.pattern, value):
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


def validate_arg(arg_def: ArgDef, value: Any) -> str:
    """Validate a value against an argument definition and return the cleaned value.

    Args:
        arg_def: The argument definition from the manifest.
        value: The raw value to validate (will be converted to str).

    Returns:
        The cleaned, validated string value.

    Raises:
        ValidationError: If the value fails validation.
    """
    str_value = str(value)

    handler = _TYPE_HANDLERS.get(arg_def.type)
    if handler is None:
        raise ValidationError(f"Unknown type: {arg_def.type!r}")

    return handler(arg_def, str_value)


def validate_arg_with_custom_types(
    arg_def: ArgDef,
    value: Any,
    custom_types: Dict[str, "CustomTypeDef"],
) -> str:
    """Validate using custom type definitions.

    If the arg type matches a custom type, create a synthetic ArgDef
    from the custom type and delegate to the base type validator.
    """
    from toolclad.manifest import CustomTypeDef  # avoid circular import  # noqa: F811

    if arg_def.type in custom_types:
        custom = custom_types[arg_def.type]
        handler = _TYPE_HANDLERS.get(custom.base)
        if handler is None:
            raise ValidationError(f"Custom type '{arg_def.type}' has invalid base type '{custom.base}'")

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
        )
        return handler(synthetic, str(value))

    # Not a custom type, use standard validation
    return validate_arg(arg_def, value)
