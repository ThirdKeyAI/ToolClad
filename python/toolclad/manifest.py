"""Manifest loading and dataclasses for .clad.toml files."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class CedarDef:
    """Cedar policy integration metadata."""

    resource: str = ""
    action: str = ""


@dataclass
class EvidenceDef:
    """Evidence capture configuration."""

    output_dir: str = ""
    capture: bool = False
    hash: str = "sha256"


@dataclass
class SchemaPinDef:
    """SchemaPin integration metadata."""

    public_key_url: str = ""
    schema_hash_algorithm: str = "sha256"


@dataclass
class ToolMeta:
    """Top-level [tool] section metadata."""

    name: str = ""
    version: str = ""
    binary: str = ""
    description: str = ""
    timeout_seconds: int = 60
    risk_tier: str = "low"
    human_approval: bool = False
    cedar: CedarDef = field(default_factory=CedarDef)
    evidence: EvidenceDef = field(default_factory=EvidenceDef)
    schemapin: Optional[SchemaPinDef] = None


@dataclass
class ArgDef:
    """Definition of a single tool argument from [args.*]."""

    name: str = ""
    position: int = 0
    required: bool = False
    type: str = "string"
    description: str = ""
    default: Any = None
    allowed: List[str] = field(default_factory=list)
    pattern: str = ""
    min: Optional[int] = None
    max: Optional[int] = None
    clamp: bool = False
    sanitize: List[str] = field(default_factory=list)
    schemes: List[str] = field(default_factory=list)
    scope_check: bool = False


@dataclass
class ConditionalDef:
    """A conditional command fragment from [command.conditionals.*]."""

    name: str = ""
    when: str = ""
    template: str = ""


@dataclass
class CommandDef:
    """The [command] section: template, mappings, conditionals, or executor."""

    template: str = ""
    executor: str = ""
    defaults: Dict[str, Any] = field(default_factory=dict)
    mappings: Dict[str, Dict[str, str]] = field(default_factory=dict)
    conditionals: Dict[str, ConditionalDef] = field(default_factory=dict)


@dataclass
class OutputDef:
    """The [output] section: format, parser, envelope, schema."""

    format: str = "text"
    parser: str = ""
    envelope: bool = True
    schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Manifest:
    """Complete parsed .clad.toml manifest."""

    tool: ToolMeta = field(default_factory=ToolMeta)
    args: Dict[str, ArgDef] = field(default_factory=dict)
    command: CommandDef = field(default_factory=CommandDef)
    output: OutputDef = field(default_factory=OutputDef)
    source_path: str = ""

    @property
    def args_sorted(self) -> List[ArgDef]:
        """Return args sorted by position."""
        return sorted(self.args.values(), key=lambda a: a.position)

    @property
    def required_args(self) -> List[ArgDef]:
        """Return only required args, sorted by position."""
        return [a for a in self.args_sorted if a.required]


def _parse_cedar(data: Dict[str, Any]) -> CedarDef:
    return CedarDef(
        resource=data.get("resource", ""),
        action=data.get("action", ""),
    )


def _parse_evidence(data: Dict[str, Any]) -> EvidenceDef:
    return EvidenceDef(
        output_dir=data.get("output_dir", ""),
        capture=data.get("capture", False),
        hash=data.get("hash", "sha256"),
    )


def _parse_schemapin(data: Dict[str, Any]) -> SchemaPinDef:
    return SchemaPinDef(
        public_key_url=data.get("public_key_url", ""),
        schema_hash_algorithm=data.get("schema_hash_algorithm", "sha256"),
    )


def _parse_tool(data: Dict[str, Any]) -> ToolMeta:
    meta = ToolMeta(
        name=data.get("name", ""),
        version=data.get("version", ""),
        binary=data.get("binary", ""),
        description=data.get("description", ""),
        timeout_seconds=data.get("timeout_seconds", 60),
        risk_tier=data.get("risk_tier", "low"),
        human_approval=data.get("human_approval", False),
    )
    if "cedar" in data:
        meta.cedar = _parse_cedar(data["cedar"])
    if "evidence" in data:
        meta.evidence = _parse_evidence(data["evidence"])
    if "schemapin" in data:
        meta.schemapin = _parse_schemapin(data["schemapin"])
    return meta


def _parse_arg(name: str, data: Dict[str, Any]) -> ArgDef:
    return ArgDef(
        name=name,
        position=data.get("position", 0),
        required=data.get("required", False),
        type=data.get("type", "string"),
        description=data.get("description", ""),
        default=data.get("default"),
        allowed=data.get("allowed", []),
        pattern=data.get("pattern", ""),
        min=data.get("min"),
        max=data.get("max"),
        clamp=data.get("clamp", False),
        sanitize=data.get("sanitize", []),
        schemes=data.get("schemes", []),
        scope_check=data.get("scope_check", False),
    )


def _parse_command(data: Dict[str, Any]) -> CommandDef:
    conditionals: Dict[str, ConditionalDef] = {}
    for cond_name, cond_data in data.get("conditionals", {}).items():
        conditionals[cond_name] = ConditionalDef(
            name=cond_name,
            when=cond_data.get("when", ""),
            template=cond_data.get("template", ""),
        )
    return CommandDef(
        template=data.get("template", ""),
        executor=data.get("executor", ""),
        defaults=data.get("defaults", {}),
        mappings=data.get("mappings", {}),
        conditionals=conditionals,
    )


def _parse_output(data: Dict[str, Any]) -> OutputDef:
    return OutputDef(
        format=data.get("format", "text"),
        parser=data.get("parser", ""),
        envelope=data.get("envelope", True),
        schema=data.get("schema", {}),
    )


def load_manifest(path: str) -> Manifest:
    """Parse a .clad.toml file and return a Manifest.

    Args:
        path: Filesystem path to the .clad.toml file.

    Returns:
        A fully populated Manifest dataclass.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If required sections are missing.
        tomllib.TOMLDecodeError: If the file is not valid TOML.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")

    with open(file_path, "rb") as f:
        data = tomllib.load(f)

    if "tool" not in data:
        raise ValueError(f"Manifest {path} is missing required [tool] section")

    manifest = Manifest(source_path=str(file_path.resolve()))

    manifest.tool = _parse_tool(data["tool"])

    if "args" in data:
        for arg_name, arg_data in data["args"].items():
            manifest.args[arg_name] = _parse_arg(arg_name, arg_data)

    if "command" in data:
        manifest.command = _parse_command(data["command"])

    if "output" in data:
        manifest.output = _parse_output(data["output"])

    return manifest
