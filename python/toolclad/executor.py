"""Command construction and execution for ToolClad manifests."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from toolclad.manifest import Manifest
from toolclad.validator import ValidationError, validate_arg


def _generate_scan_id() -> str:
    """Generate a unique scan ID: unix_timestamp-short_uuid."""
    ts = int(time.time())
    short = uuid.uuid4().hex[:5]
    return f"{ts}-{short}"


def _evaluate_condition(when: str, resolved: Dict[str, str]) -> bool:
    """Evaluate a simple conditional expression against resolved args.

    Supports:
        - ``name != ''``  /  ``name == ''``
        - ``name != 0``   /  ``name == 0``
        - Compound with ``and`` / ``or``
    """
    # Split on ` and ` / ` or ` (single level, no nesting).
    if " and " in when:
        parts = when.split(" and ")
        return all(_evaluate_single(p.strip(), resolved) for p in parts)
    if " or " in when:
        parts = when.split(" or ")
        return any(_evaluate_single(p.strip(), resolved) for p in parts)
    return _evaluate_single(when.strip(), resolved)


def _evaluate_single(expr: str, resolved: Dict[str, str]) -> bool:
    """Evaluate a single comparison expression."""
    for op in ("!=", "=="):
        if op in expr:
            lhs, rhs = expr.split(op, 1)
            lhs = lhs.strip()
            rhs = rhs.strip().strip("'\"")
            lhs_val = resolved.get(lhs, "")
            if op == "!=":
                return lhs_val != rhs
            return lhs_val == rhs
    return False


def build_command(manifest: Manifest, args: Dict[str, str]) -> str:
    """Build the final command string from a manifest and validated arguments.

    This resolves argument values, applies defaults, expands mappings and
    conditionals, and performs template interpolation.

    Args:
        manifest: The parsed manifest.
        args: Mapping of argument name to raw string value.

    Returns:
        The fully interpolated command string.

    Raises:
        ValidationError: If a required argument is missing or validation fails.
        ValueError: If the manifest uses an executor (not a template).
    """
    if manifest.command.executor:
        raise ValueError(
            f"Manifest '{manifest.tool.name}' uses a custom executor "
            f"({manifest.command.executor}); cannot build a template command."
        )

    # --- Validate and resolve all args ---
    resolved: Dict[str, str] = {}

    for arg_name, arg_def in manifest.args.items():
        if arg_name in args:
            resolved[arg_name] = validate_arg(arg_def, args[arg_name])
        elif arg_def.default is not None:
            resolved[arg_name] = str(arg_def.default)
        elif arg_def.required:
            raise ValidationError(
                f"Missing required argument: '{arg_name}'"
            )
        else:
            resolved[arg_name] = ""

    # Apply command defaults for template variables not in args.
    for key, val in manifest.command.defaults.items():
        if key not in resolved:
            resolved[key] = str(val)

    # --- Executor-injected variables ---
    scan_id = _generate_scan_id()
    evidence_dir = os.environ.get("TOOLCLAD_EVIDENCE_DIR", "/tmp/toolclad-evidence")
    tool_name = manifest.tool.name

    output_dir = evidence_dir
    if manifest.tool.evidence.output_dir:
        output_dir = manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )

    ext_map = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt", "jsonl": "jsonl"}
    ext = ext_map.get(manifest.output.format, "txt")
    output_file = os.path.join(output_dir, f"scan.{ext}")

    resolved["_scan_id"] = scan_id
    resolved["_evidence_dir"] = evidence_dir
    resolved["_output_file"] = output_file

    # --- Resolve mappings ---
    for map_arg, mapping_table in manifest.command.mappings.items():
        arg_value = resolved.get(map_arg, "")
        mapped = mapping_table.get(arg_value, "")
        # Convention: {_<arg_name>_flags} or detect from template.
        resolved[f"_{map_arg}_flags"] = mapped
        # Also support the bare {_scan_flags} shorthand.
        resolved["_scan_flags"] = mapped

    # --- Resolve conditionals ---
    for cond_name, cond_def in manifest.command.conditionals.items():
        if _evaluate_condition(cond_def.when, resolved):
            fragment = cond_def.template
            # Interpolate any {placeholders} in the conditional fragment.
            fragment = _interpolate(fragment, resolved)
            resolved[f"_{cond_name}"] = fragment
        else:
            resolved[f"_{cond_name}"] = ""

    # --- Interpolate the main template ---
    command = _interpolate(manifest.command.template, resolved)

    # Collapse multiple spaces into one and strip.
    command = re.sub(r"\s+", " ", command).strip()
    return command


def _interpolate(template: str, values: Dict[str, str]) -> str:
    """Replace {placeholder} tokens with values from the dict."""
    def replacer(match: re.Match) -> str:  # type: ignore[type-arg]
        key = match.group(1)
        return values.get(key, match.group(0))

    return re.sub(r"\{(\w+)\}", replacer, template)


def _hash_file(path: str, algorithm: str = "sha256") -> str:
    """Compute the hex digest of a file."""
    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"
    except FileNotFoundError:
        return ""


def execute(
    manifest: Manifest,
    args: Dict[str, str],
    *,
    dry_run: bool = False,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate arguments, build and run the command, and return an evidence envelope.

    Args:
        manifest: The parsed manifest.
        args: Mapping of argument name to raw string value.
        dry_run: If True, build the command but do not execute it.
        timeout: Override for the manifest's timeout_seconds.

    Returns:
        An evidence envelope dict with status, scan_id, tool, command,
        duration_ms, timestamp, output_file, output_hash, and results.
    """
    scan_id = _generate_scan_id()
    tool_name = manifest.tool.name
    effective_timeout = timeout or manifest.tool.timeout_seconds

    # Build command (also validates args).
    command = build_command(manifest, args)

    envelope: Dict[str, Any] = {
        "status": "success",
        "scan_id": scan_id,
        "tool": tool_name,
        "command": command,
        "duration_ms": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_file": "",
        "output_hash": "",
        "results": {},
    }

    if dry_run:
        envelope["status"] = "dry_run"
        return envelope

    # Ensure evidence output directory exists.
    evidence_dir = os.environ.get("TOOLCLAD_EVIDENCE_DIR", "/tmp/toolclad-evidence")
    if manifest.tool.evidence.output_dir:
        out_dir = manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )
    else:
        out_dir = os.path.join(evidence_dir, f"{scan_id}-{tool_name}")
    os.makedirs(out_dir, exist_ok=True)

    ext_map = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt", "jsonl": "jsonl"}
    ext = ext_map.get(manifest.output.format, "txt")
    output_file = os.path.join(out_dir, f"scan.{ext}")
    envelope["output_file"] = output_file

    # Execute.
    start = time.monotonic()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms

        # Write captured stdout to evidence file.
        with open(output_file, "w") as f:
            f.write(result.stdout)

        if manifest.tool.evidence.capture:
            envelope["output_hash"] = _hash_file(
                output_file, manifest.tool.evidence.hash
            )

        if result.returncode != 0:
            envelope["status"] = "error"
            envelope["results"] = {
                "returncode": result.returncode,
                "stderr": result.stderr,
                "raw_output": result.stdout,
            }
        else:
            envelope["results"] = {"raw_output": result.stdout}

    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "timeout"
        envelope["results"] = {
            "error": f"Command timed out after {effective_timeout}s"
        }
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "error"
        envelope["results"] = {"error": str(exc)}

    return envelope
