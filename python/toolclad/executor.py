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
import selectors
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from toolclad.manifest import Manifest
from toolclad.validator import ValidationError, validate_arg
from toolclad.contracts import (
    validate_arguments, check_execution, child_environment, template_argv,
    http_url, http_template, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
)


def _communicate_bounded(proc, timeout):
    """Drain both pipes under a deadline and clean up the original process group."""
    deadline = time.monotonic() + timeout
    buffers = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
    def stop_group():
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            selector.register(proc.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(proc.args, timeout)
                if proc.poll() is not None:
                    stop_group()
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.fd]
                    if len(buffer) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError("Process output exceeds 4 MiB per stream")
                    buffer.extend(chunk)
            proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        return tuple(bytes(value).decode("utf-8", errors="replace") for value in buffers.values())
    finally:
        stop_group()
        proc.stdout.close()
        proc.stderr.close()
        proc.wait(timeout=1)


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


def _resolve_vars(manifest: Manifest, args: Dict[str, str]) -> tuple:
    """Validate arguments and resolve all template variables into a single context."""
    resolved = validate_arguments(manifest, args)
    present = set(resolved)
    for name in manifest.args:
        resolved.setdefault(name, "")
    for key, val in manifest.command.defaults.items():
        resolved.setdefault(key, str(val))

    scan_id = _generate_scan_id()
    evidence_dir = os.environ.get("TOOLCLAD_EVIDENCE_DIR", os.path.join(tempfile.gettempdir(), "toolclad-evidence"))

    output_dir = os.path.join(evidence_dir, f"{scan_id}-{manifest.tool.name}")
    if manifest.tool.evidence.output_dir:
        output_dir = manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )

    ext_map = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt", "jsonl": "jsonl"}
    out_format = manifest.output.format if manifest.output else "text"
    ext = ext_map.get(out_format, "txt")
    output_file = os.path.join(output_dir, f"scan.{ext}")

    resolved["_scan_id"] = scan_id
    resolved["_evidence_dir"] = evidence_dir
    resolved["_output_file"] = output_file

    for map_arg, mapping_table in manifest.command.mappings.items():
        arg_value = resolved.get(map_arg, "")
        mapped = mapping_table.get(arg_value, "")
        resolved[f"_{map_arg}_flags"] = mapped
        resolved[f"_{map_arg}"] = mapped
        if map_arg.endswith("_type"):
            resolved[f"_{map_arg[:-5]}_flags"] = mapped

    for cond_name, cond_def in manifest.command.conditionals.items():
        if _evaluate_condition(cond_def.when, resolved):
            fragment = cond_def.template
            fragment = _interpolate(fragment, resolved)
            resolved[f"_{cond_name}"] = fragment
        else:
            resolved[f"_{cond_name}"] = ""

    return resolved, present


def build_command_argv(manifest: Manifest, args: Dict[str, str]) -> list:
    """Build an argv list from the manifest's exec array and validated arguments.

    Each element in exec is interpolated independently, preserving argument
    boundaries. This avoids the template->string->split round-trip that breaks
    when argument values contain spaces or quote characters.

    Args:
        manifest: The parsed manifest.
        args: Mapping of argument name to raw string value.

    Returns:
        A list of strings ready for subprocess execution.

    Raises:
        ValidationError: If a required argument is missing or validation fails.
        ValueError: If the manifest has no exec array.
    """
    if not manifest.command.exec:
        raise ValueError(
            f"Manifest '{manifest.tool.name}' has no exec array."
        )

    resolved, present = _resolve_vars(manifest, args)

    argv = [_interpolate(element, resolved) for element in manifest.command.exec]

    if not argv or not argv[0]:
        raise ValueError("exec array produced empty argv")

    return argv


def build_command(manifest: Manifest, args: Dict[str, str]) -> str:
    """Build the final command string from a manifest template and validated arguments.

    This resolves argument values, applies defaults, expands mappings and
    conditionals, and performs template interpolation.

    For new manifests, prefer build_command_argv with the exec array format.

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

    resolved, present = _resolve_vars(manifest, args)

    return shlex.join(_command_argv(manifest, resolved, present))


def _command_argv(manifest, resolved, present):
    fragments = {}
    for name, table in manifest.command.mappings.items():
        fragment = table.get(resolved.get(name, ""), "")
        fragments[f"_{name}_flags"] = fragments[f"_{name}"] = fragment
        if name.endswith("_type"):
            fragments[f"_{name[:-5]}_flags"] = fragment
    for name, cond in manifest.command.conditionals.items():
        fragments[f"_{name}"] = cond.template if _evaluate_condition(cond.when, resolved) else ""
    if manifest.command.exec:
        return [_interpolate(v, resolved) for v in manifest.command.exec]
    return template_argv(manifest.command.template, resolved, fragments, present)


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


def _xml_element_to_dict(elem) -> dict:
    """Convert an XML element to a dict recursively."""
    result = {}
    # Attributes
    for k, v in elem.attrib.items():
        result[f"@{k}"] = v
    # Text content
    if elem.text and elem.text.strip():
        result["#text"] = elem.text.strip()
    # Child elements
    children: Dict[str, Any] = {}
    for child in elem:
        child_dict = _xml_element_to_dict(child)
        tag = child.tag
        if tag in children:
            if not isinstance(children[tag], list):
                children[tag] = [children[tag]]
            children[tag].append(child_dict)
        else:
            children[tag] = child_dict
    result.update(children)
    return result


def _parse_xml_to_json(raw: str) -> dict:
    """Parse XML string to a JSON-compatible dict."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(raw)
    return {root.tag: _xml_element_to_dict(root)}


def _parse_csv(raw: str) -> list:
    """Parse CSV with auto-delimiter detection and type inference."""
    # Auto-detect delimiter
    first_line = raw.split('\n', 1)[0]
    if '\t' in first_line:
        delimiter = '\t'
    elif '|' in first_line and ',' not in first_line:
        delimiter = '|'
    else:
        delimiter = ','

    reader = csv.DictReader(io.StringIO(raw), delimiter=delimiter)
    rows = []
    for row in reader:
        typed_row: Dict[str, Any] = {}
        for k, v in row.items():
            if v is None:
                typed_row[k] = None
                continue
            v = v.strip()
            # Type inference
            if v.lower() in ('true', 'false'):
                typed_row[k] = v.lower() == 'true'
            else:
                try:
                    typed_row[k] = int(v)
                except ValueError:
                    try:
                        typed_row[k] = float(v)
                    except ValueError:
                        typed_row[k] = v
        rows.append(typed_row)
    return rows


def _parse_output(manifest: Manifest, raw: str) -> dict:
    """Parse raw output according to manifest output format/parser."""
    if manifest.output is None:
        return {"raw_output": raw}
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
        return _parse_csv(raw)

    elif parser == "builtin:xml":
        try:
            return _parse_xml_to_json(raw)
        except Exception:
            return {"raw_output": raw}

    else:  # builtin:text or custom
        return {"raw_output": raw}


def _validate_output_schema(manifest: Manifest, parsed: Any) -> None:
    """Validate parsed output against manifest output schema, if jsonschema is available."""
    if manifest.output is None or not manifest.output.schema:
        return
    try:
        import jsonschema
        jsonschema.validate(instance=parsed, schema=manifest.output.schema)
    except ImportError:
        pass  # jsonschema not installed, skip validation
    except jsonschema.ValidationError as e:
        raise RuntimeError(f"Output schema validation failed: {e.message}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_response(response):
    with response:
        content = response.read(MAX_RESPONSE_BYTES + 1)
    if len(content) > MAX_RESPONSE_BYTES:
        raise ValueError("HTTP response exceeds 4 MiB")
    return content.decode("utf-8", errors="replace")


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

    args = validate_arguments(manifest, args)
    check_execution(manifest, dry_run)
    url = http_url(http.url, args)
    headers = {k: http_template(v, args, dry_run=dry_run) for k, v in http.headers.items()}
    body = None
    if http.body_template is not None:
        body = http_template(http.body_template, args, dry_run=dry_run, json_string=True).encode()
    if len(body or b"") + sum(len(k.encode()) + len(v.encode()) for k, v in headers.items()) + len(url.encode()) > MAX_REQUEST_BYTES:
        raise ValueError("HTTP request exceeds 1 MiB")

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
        resp = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open(req, timeout=effective_timeout)
        status_code = resp.status
        resp_body = _read_response(resp)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        resp_body = _read_response(exc)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        envelope["duration_ms"] = elapsed_ms
        envelope["status"] = "error"
        envelope["results"] = {"error": str(exc)}
        return envelope

    elapsed_ms = int((time.monotonic() - start) * 1000)
    envelope["duration_ms"] = elapsed_ms
    envelope["http_status"] = status_code

    is_success = (status_code in http.success_status if http.success_status else 200 <= status_code < 300)
    if status_code in http.error_status:
        is_success = False

    if not is_success:
        if 400 <= status_code < 500:
            envelope["status"] = f"client_error (HTTP {status_code})"
        elif 500 <= status_code < 600:
            envelope["status"] = f"server_error (HTTP {status_code})"
        else:
            envelope["status"] = f"error (HTTP {status_code})"

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
    args = validate_arguments(manifest, args)
    check_execution(manifest, dry_run)
    if timeout is not None and not 1 <= timeout <= manifest.tool.timeout_seconds:
        raise ValueError("Timeout override must be positive and cannot extend the manifest deadline")
    if dry_run and manifest.tool.dispatch == "callback":
        return {"status": "dry_run", "command": "callback (embedding runtime required)", "results": {}}
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
        validated_args = args

        scan_id = _generate_scan_id()
        effective_timeout = timeout or manifest.tool.timeout_seconds

        env = child_environment()
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
                start_new_session=True,
            stdin=subprocess.DEVNULL,
            )
            stdout, stderr = _communicate_bounded(proc, effective_timeout)
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
                except RuntimeError as exc:
                    envelope["status"] = "error"
                    envelope["parser_error"] = str(exc)
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

    resolved, present = _resolve_vars(manifest, args)
    scan_id = resolved["_scan_id"]
    tool_name = manifest.tool.name
    effective_timeout = timeout or manifest.tool.timeout_seconds
    args_list = _command_argv(manifest, resolved, present)
    command = shlex.join(args_list)

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

    output_file = resolved["_output_file"]
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    envelope["output_file"] = output_file
    start = time.monotonic()
    proc = None
    try:
        proc = subprocess.Popen(
            args_list,
            env=child_environment(),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
        )
        stdout, stderr = _communicate_bounded(proc, effective_timeout)
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
            except RuntimeError as exc:
                envelope["status"] = "error"
                envelope["parser_error"] = str(exc)
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
