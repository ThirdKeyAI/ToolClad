"""The shared negative suite: every vector in ``tests/injection_vectors.json``
at the repository root, with the verdict the file states.

The file is shared by all four runtimes and is never edited to suit one of
them; a mismatch here means this runtime is wrong. Vectors are deterministic
and the resolver is replaced so that no vector can cause a DNS lookup.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from toolclad import hostpolicy
from toolclad.manifest import ArgDef, load_manifest_from_str
from toolclad.validator import ValidationError, validate_arg

VECTORS_FILE = Path(__file__).resolve().parents[2] / "tests" / "injection_vectors.json"

_ARG_FIELDS = {f.name for f in dataclasses.fields(ArgDef)}


def _load_vectors() -> dict:
    if not VECTORS_FILE.is_file():
        pytest.skip(
            f"{VECTORS_FILE} not found: the shared vectors live in the repository, "
            "not in a published package"
        )
    return json.loads(VECTORS_FILE.read_text(encoding="utf-8"))


def _arg_def(spec: dict) -> ArgDef:
    unknown = set(spec) - _ARG_FIELDS
    assert not unknown, f"vector uses argument keys this runtime does not model: {sorted(unknown)}"
    return ArgDef(name="arg", **spec)


def _arg_verdict(vector: dict) -> str:
    try:
        validate_arg(_arg_def(vector["arg"]), vector["value"])
    except ValidationError:
        return "reject"
    return "accept"


def _manifest_verdict(vector: dict) -> str:
    try:
        load_manifest_from_str(vector["manifest"])
    except ValueError:  # includes tomllib.TOMLDecodeError
        return "reject"
    return "accept"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_injection_vectors(monkeypatch, capsys):
    def _no_dns(host: str):
        raise AssertionError(f"a vector consulted the resolver for {host!r}")

    monkeypatch.setattr(hostpolicy, "resolve_host_addresses", _no_dns)
    data = _load_vectors()

    failures = []
    executed = 0
    for vector in data["arg_vectors"]:
        got = _arg_verdict(vector)
        executed += 1
        if got != vector["expect"]:
            failures.append(
                f"arg vector {vector['id']}: expected {vector['expect']}, got {got} "
                f"(value={vector['value']!r}; {vector.get('note', '')})"
            )
    for vector in data["manifest_vectors"]:
        got = _manifest_verdict(vector)
        executed += 1
        if got != vector["expect"]:
            failures.append(
                f"manifest vector {vector['id']}: expected {vector['expect']}, got {got} "
                f"({vector.get('note', '')})"
            )

    assert executed > 0, "no vectors were executed"
    with capsys.disabled():
        print(
            f"\ninjection_vectors.json: executed {executed} vectors "
            f"({len(data['arg_vectors'])} argument, {len(data['manifest_vectors'])} manifest)"
        )
    assert not failures, "\n".join(failures)
