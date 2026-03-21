"""Argument type validation for ToolClad manifests."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, List
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


def _validate_scope_target(arg_def: ArgDef, value: str) -> str:
    _check_injection(value)
    # Block wildcard targets.
    if "*" in value or "?" in value:
        raise ValidationError(f"Wildcard targets are not allowed: {value!r}")
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


# Registry of type handlers.
_TYPE_HANDLERS = {
    "string": _validate_string,
    "integer": _validate_integer,
    "port": _validate_port,
    "boolean": _validate_boolean,
    "enum": _validate_enum,
    "scope_target": _validate_scope_target,
    "url": _validate_url,
    "path": _validate_path,
    "ip_address": _validate_ip_address,
    "cidr": _validate_cidr,
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
