"""CLI entry point for ToolClad."""

from __future__ import annotations

import json
import sys
from typing import Dict, List, Optional, Tuple

import click

from toolclad.executor import build_command, execute
from toolclad.manifest import Manifest, load_manifest
from toolclad.validator import ValidationError


def _parse_args(arg_pairs: Tuple[str, ...]) -> Dict[str, str]:
    """Parse key=value pairs from --arg options."""
    result: Dict[str, str] = {}
    for pair in arg_pairs:
        if "=" not in pair:
            raise click.BadParameter(
                f"Expected key=value format, got: {pair!r}"
            )
        key, _, value = pair.partition("=")
        result[key.strip()] = value.strip()
    return result


@click.group()
@click.version_option(package_name="toolclad")
def main() -> None:
    """ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes."""


@main.command()
@click.argument("manifest_path", type=click.Path(exists=True))
def validate(manifest_path: str) -> None:
    """Parse and validate a .clad.toml manifest."""
    try:
        manifest = load_manifest(manifest_path)
    except (ValueError, FileNotFoundError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)

    click.echo(f"Manifest:     {manifest.source_path}")
    click.echo(f"Tool:         {manifest.tool.name} v{manifest.tool.version}")
    click.echo(f"Binary:       {manifest.tool.binary}")
    click.echo(f"Description:  {manifest.tool.description}")
    click.echo(f"Risk tier:    {manifest.tool.risk_tier}")
    click.echo(f"Timeout:      {manifest.tool.timeout_seconds}s")
    click.echo(f"Arguments:    {len(manifest.args)}")
    for arg in manifest.args_sorted:
        req = "required" if arg.required else "optional"
        click.echo(f"  {arg.name}: {arg.type} ({req})")
    if manifest.command.template:
        click.echo(f"Template:     {manifest.command.template}")
    elif manifest.command.executor:
        click.echo(f"Executor:     {manifest.command.executor}")
    click.echo(f"Output:       {manifest.output.format}")
    click.echo()
    click.echo("OK")


@main.command()
@click.argument("manifest_path", type=click.Path(exists=True))
@click.option("--arg", "-a", "arg_pairs", multiple=True, help="Argument as key=value")
def run(manifest_path: str, arg_pairs: Tuple[str, ...]) -> None:
    """Execute a tool through its .clad.toml manifest."""
    try:
        manifest = load_manifest(manifest_path)
        args = _parse_args(arg_pairs)
        envelope = execute(manifest, args)
    except (ValueError, FileNotFoundError, ValidationError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)

    click.echo(json.dumps(envelope, indent=2))


def _mcp_type_and_constraints(arg) -> Tuple[str, dict]:
    """Return (json_schema_type, extra_constraints) for an arg."""
    t = arg.type
    extra: dict = {}
    if t == "integer":
        return "integer", extra
    if t == "port":
        extra = {"minimum": 1, "maximum": 65535}
        return "integer", extra
    if t == "boolean":
        return "boolean", extra
    if t == "ip_address":
        extra["format"] = "ipv4"
    elif t == "cidr":
        if not arg.pattern:
            extra["pattern"] = r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
    elif t == "url":
        extra["format"] = "uri"
    elif t == "duration":
        if not arg.pattern:
            extra["pattern"] = r"^(\d+|(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?)$"
    return "string", extra


@main.command()
@click.argument("manifest_path", type=click.Path(exists=True))
def schema(manifest_path: str) -> None:
    """Output MCP JSON schema for a manifest."""
    try:
        manifest = load_manifest(manifest_path)
    except (ValueError, FileNotFoundError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)

    # Build inputSchema from args.
    properties: Dict[str, dict] = {}
    required: List[str] = []
    for arg in manifest.args_sorted:
        json_type, extra = _mcp_type_and_constraints(arg)
        prop: dict = {"type": json_type, "description": arg.description}
        prop.update(extra)
        if arg.allowed:
            prop["enum"] = arg.allowed
        if arg.default is not None:
            prop["default"] = arg.default
        properties[arg.name] = prop
        if arg.required:
            required.append(arg.name)

    input_schema = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    # Build outputSchema: wrap results schema in envelope if configured.
    output_schema: dict = {}
    if manifest.output.envelope:
        output_schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["success", "error"]},
                "scan_id": {"type": "string"},
                "tool": {"type": "string"},
                "command": {"type": "string"},
                "duration_ms": {"type": "integer"},
                "timestamp": {"type": "string", "format": "date-time"},
                "output_file": {"type": "string"},
                "output_hash": {"type": "string"},
                "exit_code": {"type": "integer"},
                "stderr": {"type": "string"},
                "results": manifest.output.schema or {"type": "object"},
            },
        }
    elif manifest.output.schema:
        output_schema = manifest.output.schema

    mcp_tool = {
        "name": manifest.tool.name,
        "description": manifest.tool.description,
        "inputSchema": input_schema,
    }
    if output_schema:
        mcp_tool["outputSchema"] = output_schema

    click.echo(json.dumps(mcp_tool, indent=2))


@main.command()
@click.argument("manifest_path", type=click.Path(exists=True))
@click.option("--arg", "-a", "arg_pairs", multiple=True, help="Argument as key=value")
def test(manifest_path: str, arg_pairs: Tuple[str, ...]) -> None:
    """Dry-run a tool invocation: validate args and show the constructed command."""
    try:
        manifest = load_manifest(manifest_path)
        args = _parse_args(arg_pairs)

        # Validate each arg individually for nice reporting.
        from toolclad.validator import validate_arg

        click.echo(f"  Manifest:  {manifest.source_path}")
        click.echo(f"  Arguments:")
        for arg_name, arg_def in manifest.args.items():
            if arg_name in args:
                try:
                    cleaned = validate_arg(arg_def, args[arg_name])
                    click.echo(f"    {arg_name}={cleaned} ({arg_def.type}: OK)")
                except ValidationError as ve:
                    click.echo(f"    {arg_name}={args[arg_name]} ({arg_def.type}: FAIL - {ve})")
                    sys.exit(1)
            elif arg_def.default is not None:
                click.echo(f"    {arg_name}={arg_def.default} (default)")
            elif arg_def.required:
                click.echo(f"    {arg_name}=??? (MISSING - required)")
                sys.exit(1)

        command = build_command(manifest, args)
        click.echo(f"  Command:   {command}")
        if manifest.tool.cedar.resource:
            click.echo(
                f"  Cedar:     {manifest.tool.cedar.resource} / "
                f"{manifest.tool.cedar.action}"
            )
        click.echo(f"  Timeout:   {manifest.tool.timeout_seconds}s")
        click.echo()
        click.echo("  [dry run -- command not executed]")

    except (ValueError, FileNotFoundError, ValidationError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
