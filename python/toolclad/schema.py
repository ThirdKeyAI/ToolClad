"""A small JSON-Schema subset validator for ``[output.schema]``.

No dependency: the runtime must check parsed output against the declared
schema every time, so validation cannot depend on an optional package being
installed. Supported keywords:

``type`` (a name or a list of names among ``object array string number
integer boolean null``), ``properties``, ``required``,
``additionalProperties`` (boolean only), ``items`` (a single sub-schema),
``enum``, ``minimum`` / ``maximum`` (inclusive), ``minLength`` /
``maxLength`` (code points) and ``pattern`` (anchored as ``^(?:pat)\\Z``,
like every other pattern in ToolClad). Unknown keywords are ignored.

Errors carry a JSON-pointer path: ``/hosts/0/port: expected integer, got
string``. The document root renders as ``/``. The first failure in document
order is reported.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from toolclad.validator import _anchor_pattern

__all__ = ["SchemaError", "validate_schema", "schema_error"]


class SchemaError(Exception):
    """A value does not satisfy the schema. ``str()`` is ``<path>: <message>``."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path or "/"
        self.message = message
        super().__init__(f"{self.path}: {message}")


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _matches_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "number":
        return _is_number(value)
    if name == "integer":
        # A number with no fractional part: 30.0 from a float-typed parser
        # is an integer, as in JSON Schema.
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and value.is_integer()
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    return False


def _deep_equal(a: Any, b: Any) -> bool:
    # JSON equality: true is not 1, and 1 equals 1.0.
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number(a) and _is_number(b):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_deep_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_deep_equal(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _check(value: Any, schema: Any, path: List[str]) -> None:
    if not isinstance(schema, dict):
        return

    def fail(message: str) -> None:
        raise SchemaError("".join("/" + p for p in path), message)

    if "type" in schema:
        wanted = schema["type"]
        names = wanted if isinstance(wanted, list) else [wanted]
        if not any(isinstance(n, str) and _matches_type(value, n) for n in names):
            expected = " or ".join(str(n) for n in names)
            fail(f"expected {expected}, got {_type_name(value)}")

    if "enum" in schema and isinstance(schema["enum"], list):
        if not any(_deep_equal(value, member) for member in schema["enum"]):
            fail("value is not one of the allowed enum values")

    if _is_number(value):
        minimum = schema.get("minimum")
        if _is_number(minimum) and value < minimum:
            fail(f"{value} is less than the minimum {minimum}")
        maximum = schema.get("maximum")
        if _is_number(maximum) and value > maximum:
            fail(f"{value} is greater than the maximum {maximum}")

    if isinstance(value, str):
        min_len = schema.get("minLength")
        if _is_number(min_len) and len(value) < min_len:
            fail(f"string is shorter than minLength {min_len}")
        max_len = schema.get("maxLength")
        if _is_number(max_len) and len(value) > max_len:
            fail(f"string is longer than maxLength {max_len}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                ok = re.match(_anchor_pattern(pattern), value) is not None
            except re.error as exc:
                fail(f"invalid pattern {pattern!r}: {exc}")
            if not ok:
                fail(f"string does not match pattern {pattern!r}")

    if isinstance(value, dict):
        props = schema.get("properties")
        props = props if isinstance(props, dict) else {}
        required = schema.get("required")
        if isinstance(required, list):
            for name in required:
                if isinstance(name, str) and name not in value:
                    fail(f"missing required property '{name}'")
        additional = schema.get("additionalProperties")
        for key, item in value.items():
            if key in props:
                _check(item, props[key], path + [_escape(str(key))])
            elif additional is False:
                raise SchemaError(
                    "".join("/" + p for p in path + [_escape(str(key))]),
                    "additional property is not allowed",
                )

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _check(item, schema["items"], path + [str(index)])


def validate_schema(value: Any, schema: Any) -> None:
    """Validate ``value`` against ``schema``.

    Raises:
        SchemaError: On the first failure in document order.
    """
    _check(value, schema, [])


def schema_error(value: Any, schema: Any) -> Optional[str]:
    """``"<path>: <message>"`` for the first failure, or None when valid."""
    try:
        validate_schema(value, schema)
    except SchemaError as exc:
        return str(exc)
    return None
