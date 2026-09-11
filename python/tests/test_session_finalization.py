"""Shared manifest vectors must preserve explicit session finalization authority."""
import json
from pathlib import Path
import pytest
from toolclad.manifest import load_manifest

CASES = json.loads((Path(__file__).resolve().parents[2] / 'tests/session_finalization_vectors.json').read_text())


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['name'])
def test_session_finalization_contract(case, tmp_path):
    path = tmp_path / 'terminal.clad.toml'
    path.write_text(case['manifest'])
    if case['expected'] is None:
        with pytest.raises(ValueError):
            load_manifest(str(path))
    else:
        manifest = load_manifest(str(path))
        assert manifest.session.commands['finish'].finalize is case['expected']
