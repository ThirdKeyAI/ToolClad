"""Portable relative paths retain spelling and share credential validation."""
import json
from pathlib import Path
import pytest
from toolclad.manifest import ArgDef, CustomTypeDef
from toolclad.validator import ValidationError, validate_arg, validate_arg_with_custom_types

CASES = json.loads((Path(__file__).parents[2] / "tests/path_vectors.json").read_text())["cases"]

@pytest.mark.parametrize("kind", ["path", "credential_file"])
@pytest.mark.parametrize("custom", [False, True])
def test_path_vectors(tmp_path, monkeypatch, kind, custom):
    monkeypatch.chdir(tmp_path)
    for case in CASES:
        if not case["error"]:
            file = Path(case["value"])
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("synthetic fixture")
    for case in CASES:
        definition = ArgDef(type="relative_file" if custom else kind)
        def check():
            if custom:
                return validate_arg_with_custom_types(definition, case["value"], {"relative_file": CustomTypeDef(base=kind)})
            return validate_arg(definition, case["value"])
        if case["error"]:
            with pytest.raises(ValidationError): check()
        else:
            assert check() == case["value"]
    if kind == "credential_file":
        for value in ("data", "missing.txt"):
            with pytest.raises(ValidationError): validate_arg(ArgDef(type=kind), value)
