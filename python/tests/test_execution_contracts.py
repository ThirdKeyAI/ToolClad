"""Shared execution contract vectors, exercised through public builders."""
import json
import shlex
from pathlib import Path
import pytest
from toolclad.manifest import load_manifest
from toolclad.executor import build_command
from toolclad.validator import ValidationError

VECTORS = json.loads((Path(__file__).parents[2] / "tests/execution_vectors.json").read_text())["cases"]

@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_execution_vector(case, tmp_path):
    path = tmp_path / "fixture.clad.toml"
    path.write_text(case["manifest"])
    manifest = load_manifest(str(path))
    if case["error"]:
        with pytest.raises((ValueError, RuntimeError, ValidationError)):
            build_command(manifest, case["args"])
    else:
        assert shlex.split(build_command(manifest, case["args"])) == case["expected_argv"]

@pytest.mark.parametrize("bounds,value,expected", [({"max_float": 10.0}, "99", "10.0"), ({"min_float": 10.0}, "1", "10.0")])
def test_number_clamp_with_one_bound(bounds, value, expected):
    from toolclad.manifest import ArgDef
    from toolclad.validator import validate_arg
    assert validate_arg(ArgDef(type="number", clamp=True, **bounds), value) == expected
