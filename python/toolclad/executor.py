"""Command construction and execution for ToolClad manifests."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shlex
import signal
import subprocess
import time
import urllib.error
import urllib.request
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

    SECURITY: This evaluator uses a closed-vocabulary parser.
    Never use eval() or equivalent dynamic code execution for conditions.
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


def inject_template_vars(template: str) -> str:
    """Replace {_secret:name} with TOOLCLAD_SECRET_{NAME} env var."""

    def replacer(match: re.Match) -> str:  # type: ignore[type-arg]
        name = match.group(1)
        env_key = f"TOOLCLAD_SECRET_{name.upper()}"
        val = os.environ.get(env_key)
        if val is None:
            raise RuntimeError(f"Secret '{name}' not found (set {env_key})")
        return val

    return re.sub(r"\{_secret:([a-zA-Z0-9_]+)\}", replacer, template)


def _parse_output(manifest: Manifest, raw: str) -> dict:
    """Parse raw output according to manifest output format/parser."""
    parser = manifest.output.parser or f"builtin:{manifest.output.format}"

    if parser == "builtin:json":
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"JSON parse failed: {e}")

    elif parser == "builtin:jsonl":
        lines = [l for l in raw.strip().splitlines() if l.strip()]
        try:
            return [json.loads(l) for l in lines]
        except json.JSONDecodeError as e:
            raise RuntimeError(f"JSONL parse failed: {e}")

    elif parser == "builtin:csv":
        reader = csv.DictReader(io.StringIO(raw))
        return list(reader)

    elif parser == "builtin:xml":
        # Return raw — full XML->JSON conversion is out of scope for reference impl
        return {"raw_output": raw}

    else:  # builtin:text or custom
        return {"raw_output": raw}


def _validate_output_schema(manifest: Manifest, parsed: Any) -> None:
    """Validate parsed output against manifest output schema, if jsonschema is available."""
    if not manifest.output.schema:
        return
    try:
        import jsonschema
        jsonschema.validate(instance=parsed, schema=manifest.output.schema)
    except ImportError:
        pass  # jsonschema not installed, skip validation
    except jsonschema.ValidationError as e:
        raise RuntimeError(f"Output schema validation failed: {e.message}")


def _interpolate_http(template: str, args: Dict[str, str]) -> str:
    """Interpolate arg placeholders then resolve secret references."""
    result = _interpolate(template, args)
    return inject_template_vars(result)


def _execute_http(
    manifest: Manifest,
    args: Dict[str, str],
    *,
    dry_run: bool = False,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute an HTTP-based manifest using urllib.request (no extra deps)."""
    http = manifest.http
    assert http is not None

    scan_id = _generate_scan_id()
    effective_timeout = timeout or manifest.tool.timeout_seconds

    # Interpolate URL, headers, and body with args + secrets.
    url = _interpolate_http(http.url, args)
    headers = {k: _interpolate_http(v, args) for k, v in http.headers.items()}
    body: Optional[bytes] = None
    if http.body_template is not None:
        # JSON-escape values to prevent injection into JSON body
        escaped_args = {k: json.dumps(v)[1:-1] for k, v in args.items()}  # strip quotes from json.dumps
        body_str = _interpolate(http.body_template, escaped_args)
        body_str = inject_template_vars(body_str)
        body = body_str.encode("utf-8")

    envelope: Dict[str, Any] = {
        "status": "success",
        "scan_id": scan_id,
        "tool": manifest.tool.name,
        "command": f"{http.method} {url}",
        "duration_ms": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_file": "",
        "output_hash": "",
        "http_status": 0,
        "results": {},
    }

    if dry_run:
        envelope["status"] = "dry_run"
        return envelope

    start = time.monotonic()
    try:
        req = urllib.request.Request(
            url, data=body, headers=headers, method=http.method
        )
        resp = urllib.request.urlopen(req, timeout=effective_timeout)
        status_code = resp.status
        resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        resp_body = exc.read().decode("utf-8", errors="replace")
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "error"
        envelope["results"] = {"error": str(exc)}
        return envelope

    elapsed_ms = int((time.monotonic() - start) * 1000)
    envelope["duration_ms"] = elapsed_ms
    envelope["http_status"] = status_code

    if http.error_status and status_code in http.error_status:
        envelope["status"] = "error"
    elif http.success_status and status_code not in http.success_status:
        envelope["status"] = "error"

    envelope["results"] = {"raw_output": resp_body}
    return envelope


def _execute_mcp_proxy(
    manifest: Manifest,
    args: Dict[str, str],
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Build a delegation envelope for an MCP proxy manifest."""
    mcp = manifest.mcp
    assert mcp is not None

    scan_id = _generate_scan_id()

    # Map args through field_map.
    mapped_args: Dict[str, str] = {}
    for src, dst in mcp.field_map.items():
        if src in args:
            mapped_args[dst] = args[src]

    # Pass through any args not in the field_map.
    for k, v in args.items():
        if k not in mcp.field_map:
            mapped_args[k] = v

    envelope: Dict[str, Any] = {
        "status": "delegation_preview",
        "scan_id": scan_id,
        "tool": manifest.tool.name,
        "command": f"mcp://{mcp.server}/{mcp.tool}",
        "duration_ms": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_file": "",
        "output_hash": "",
        "mcp_server": mcp.server,
        "mcp_tool": mcp.tool,
        "mcp_args": mapped_args,
        "results": {},
    }

    if dry_run:
        envelope["status"] = "dry_run"

    return envelope


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
    # Dispatch to HTTP or MCP execution if applicable.
    if manifest.http is not None:
        return _execute_http(manifest, args, dry_run=dry_run, timeout=timeout)
    if manifest.mcp is not None:
        return _execute_mcp_proxy(manifest, args, dry_run=dry_run)

    if manifest.session is not None:
        raise RuntimeError(
            "session mode is parsed but not yet executable in the reference implementation "
            "— use the Symbiont runtime for session execution"
        )
    if manifest.browser is not None:
        raise RuntimeError(
            "browser mode is parsed but not yet executable in the reference implementation "
            "— use the Symbiont runtime for browser execution"
        )

    # Handle custom executor escape hatch.
    if manifest.command.executor:
        # Validate args manually since build_command() isn't called for executor mode
        validated_args: Dict[str, str] = {}
        for arg_name, arg_def in manifest.args.items():
            if arg_name in args:
                validated_args[arg_name] = validate_arg(arg_def, args[arg_name])
            elif arg_def.default is not None:
                validated_args[arg_name] = str(arg_def.default)
            elif arg_def.required:
                raise ValidationError(f"Missing required argument: '{arg_name}'")

        scan_id = _generate_scan_id()
        effective_timeout = timeout or manifest.tool.timeout_seconds

        env = os.environ.copy()
        for k, v in validated_args.items():
            env[f"TOOLCLAD_ARG_{k.upper()}"] = str(v)
        env["TOOLCLAD_SCAN_ID"] = scan_id
        env["TOOLCLAD_TOOL_NAME"] = manifest.tool.name

        envelope: Dict[str, Any] = {
            "status": "success",
            "scan_id": scan_id,
            "tool": manifest.tool.name,
            "command": f"{manifest.command.executor} (custom executor)",
            "duration_ms": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output_file": "",
            "output_hash": "",
            "results": {},
        }

        if dry_run:
            envelope["status"] = "dry_run"
            return envelope

        start = time.monotonic()
        proc = None
        try:
            proc = subprocess.Popen(
                [manifest.command.executor],
                env=env,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setpgrp,
            )
            stdout, stderr = proc.communicate(timeout=effective_timeout)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            envelope["duration_ms"] = elapsed_ms
            envelope["exit_code"] = proc.returncode
            envelope["stderr"] = stderr

            if proc.returncode != 0:
                envelope["status"] = "error"
                envelope["results"] = {"returncode": proc.returncode, "stderr": stderr, "raw_output": stdout}
            else:
                try:
                    parsed = _parse_output(manifest, stdout)
                    envelope["results"] = parsed if isinstance(parsed, dict) else {"parsed_output": parsed}
                except RuntimeError:
                    envelope["results"] = {"raw_output": stdout}
        except subprocess.TimeoutExpired:
            if proc is not None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait()
            elapsed_ms = int((time.monotonic() - start) * 1000)
            envelope["duration_ms"] = elapsed_ms
            envelope["status"] = "timeout"
            envelope["exit_code"] = -1
            envelope["results"] = {"error": f"Custom executor timed out after {effective_timeout}s"}

        return envelope

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

    # Execute using array-based invocation to avoid shell interpretation.
    args_list = shlex.split(command)
    start = time.monotonic()
    proc = None
    try:
        proc = subprocess.Popen(
            args_list,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setpgrp,
        )
        stdout, stderr = proc.communicate(timeout=effective_timeout)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["exit_code"] = proc.returncode
        envelope["stderr"] = stderr

        # Write captured stdout to evidence file.
        with open(output_file, "w") as f:
            f.write(stdout)

        if manifest.tool.evidence.capture:
            envelope["output_hash"] = _hash_file(
                output_file, manifest.tool.evidence.hash
            )

        if proc.returncode != 0:
            envelope["status"] = "error"
            envelope["results"] = {
                "returncode": proc.returncode,
                "stderr": stderr,
                "raw_output": stdout,
            }
        else:
            try:
                parsed = _parse_output(manifest, stdout)
                envelope["results"] = parsed if isinstance(parsed, dict) else {"parsed_output": parsed}
                _validate_output_schema(manifest, parsed)
            except RuntimeError:
                envelope["results"] = {"raw_output": stdout}

    except subprocess.TimeoutExpired:
        # Kill the entire process group to reap child processes.
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.wait()
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "timeout"
        envelope["exit_code"] = -1
        envelope["stderr"] = ""
        envelope["results"] = {
            "error": f"Command timed out after {effective_timeout}s"
        }
    except Exception as exc:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "error"
        envelope["exit_code"] = -1
        envelope["stderr"] = str(exc)
        envelope["results"] = {"error": str(exc)}

    return envelope
