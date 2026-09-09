"""Literal text must retain its UTF-8 bytes through direct and custom validation."""
import json
from pathlib import Path
import pytest
from toolclad.manifest import ArgDef, CustomTypeDef
from toolclad.validator import ValidationError, validate_arg, validate_arg_with_custom_types

VECTORS = json.loads((Path(__file__).parents[2] / "tests/literal_text_vectors.json").read_text())["cases"]

@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
@pytest.mark.parametrize("custom", [False, True])
def test_literal_text(case, custom):
    value = case["value"] * case["repeat"]
    definition = ArgDef(name="value", type="literal_text", required=True, pattern=case["pattern"])
    def check():
        if custom:
            definition.type = "source_text"
            return validate_arg_with_custom_types(definition, value, {"source_text": CustomTypeDef(base="literal_text", pattern=case["pattern"])})
        return validate_arg(definition, value)
    if case["error"]:
        with pytest.raises(ValidationError): check()
    else:
        assert check() == value

@pytest.mark.parametrize("value", ["\ud800", "\udfff", 1, False, b"text", {}, [], None])
def test_literal_text_requires_utf8_string(value):
    with pytest.raises(ValidationError):
        validate_arg(ArgDef(type="literal_text"), value)
    with pytest.raises(ValidationError):
        validate_arg_with_custom_types(ArgDef(type="source_text"), value, {"source_text": CustomTypeDef(base="literal_text")})

@pytest.mark.parametrize("value", [None, 1, False, {}, []])
def test_literal_text_contract_does_not_coerce_supplied_values(value):
    from toolclad.manifest import Manifest
    from toolclad.contracts import validate_arguments
    manifest = Manifest(args={"content": ArgDef(type="literal_text", default="fallback")})
    with pytest.raises(ValidationError):
        validate_arguments(manifest, {"content": value})
