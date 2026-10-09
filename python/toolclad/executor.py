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
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from toolclad.manifest import Manifest
from toolclad.validator import ValidationError, validate_arg, validate_arg_mode

# Variables the executor injects into every command context.
INJECTED_VARS: Tuple[str, ...] = ("_scan_id", "_output_file", "_evidence_dir")

# One left-to-right pass over a token: `{{` and `}}` are escapes for literal
# braces and are consumed before `{name}` can match, so `%{{http_code}}` is
# never read as a placeholder named `http_code`.
_PLACEHOLDER_RE = re.compile(r"\{\{|\}\}|\{(\w+)\}")
# A token that is exactly one placeholder (used with fullmatch).
_SOLE_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")

_TEMPLATE_DEPRECATION = (
    "[command] template is deprecated and will be removed in the next minor "
    "release; use exec = [...]"
)


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


def tokenize_template(s: str) -> List[str]:
    """Split a trusted manifest template into argv tokens.

    POSIX-like: single and double quotes group text, a backslash outside
    single quotes escapes the next character, and unquoted whitespace
    separates tokens. This runs on manifest text only; substituted values are
    never re-split.

    A ``{`` inside quotes is rejected unless it starts a ``{{`` escape, so a
    placeholder can only ever be a whole, unquoted token.

    Raises:
        ValueError: On a placeholder inside quotes, an unbalanced quote, or a
            trailing backslash.
    """
    tokens: List[str] = []
    cur: List[str] = []
    started = False
    in_single = False
    in_double = False
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and not in_single:
            if i + 1 >= n:
                raise ValueError("trailing backslash in command template")
            cur.append(s[i + 1])
            started = True
            i += 2
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            started = True
        elif c == '"' and not in_single:
            in_double = not in_double
            started = True
        elif c == "{" and (in_single or in_double):
            if s[i + 1 : i + 2] == "{":
                cur.append("{{")
                started = True
                i += 2
                continue
            raise ValueError(
                f"command template places a placeholder inside quotes at offset {i}; "
                "placeholders must be whole, unquoted tokens (use exec = [...])"
            )
        elif c.isspace() and not in_single and not in_double:
            if started:
                tokens.append("".join(cur))
                cur = []
                started = False
        else:
            cur.append(c)
            started = True
        i += 1
    if in_single or in_double:
        raise ValueError("unbalanced quote in command template")
    if started:
        tokens.append("".join(cur))
    return tokens


def _placeholder_names(text: str) -> List[str]:
    """Placeholder names in ``text`` in order, skipping ``{{``/``}}`` escapes."""
    return [m.group(1) for m in _PLACEHOLDER_RE.finditer(text) if m.group(1)]


def _sole_placeholder(token: str) -> Optional[str]:
    """Return the name when ``token`` is exactly ``{name}``, else None."""
    m = _SOLE_PLACEHOLDER_RE.fullmatch(token)
    return m.group(1) if m else None


def _single_var_names(manifest: Manifest) -> Set[str]:
    names: Set[str] = set(manifest.args)
    names.update(manifest.command.defaults)
    names.update(INJECTED_VARS)
    return names


def _trusted_var_names(manifest: Manifest) -> Set[str]:
    cmd = manifest.command
    names = {f"_{arg}_flags" for arg in cmd.mappings}
    names.update(f"_{cond}" for cond in cmd.conditionals)
    return names


def _check_placeholders(manifest: Manifest) -> None:
    """Load-time check: every placeholder must name a known variable.

    Known names are declared args, ``[command.defaults]`` keys,
    ``_<arg>_flags`` for mapped args, ``_<cond>`` for declared conditionals,
    and the injected ``_scan_id`` / ``_output_file`` / ``_evidence_dir``.
    A multi-token variable must be a whole token: ``x{_flags}`` is rejected
    because splicing a token vector into literal text would re-join it.
    """
    single = _single_var_names(manifest)
    trusted = _trusted_var_names(manifest)

    def scan(tokens: List[str], where: str) -> None:
        for token in tokens:
            sole = _sole_placeholder(token)
            for name in _placeholder_names(token):
                if name in trusted:
                    if sole != name:
                        raise ValueError(
                            f"placeholder '{{{name}}}' expands to multiple tokens and "
                            f"must be a whole token in {where}"
                        )
                    continue
                if name not in single:
                    raise ValueError(f"unresolved placeholder '{{{name}}}' in {where}")

    cmd = manifest.command
    scan(cmd.exec, "command")
    if cmd.template and cmd.exec_was_declared:
        # exec takes precedence and the template is display-only, but it may
        # still only reference declared names.
        for name in _placeholder_names(cmd.template):
            if name not in single and name not in trusted:
                raise ValueError(f"unresolved placeholder '{{{name}}}' in command")
    for cond_name, cond in cmd.conditionals.items():
        scan(cond.tokens, f"command (conditional '{cond_name}')")


def _check_mappings(manifest: Manifest) -> None:
    """Load-time check: an enum's mapping table must cover every allowed value.

    A missing case would otherwise surface only when that value is used. An
    author who wants "this value adds no flags" maps it to ``""``.
    """
    for map_arg, table in manifest.command.mappings.items():
        arg_def = manifest.args.get(map_arg)
        if arg_def is None or arg_def.type != "enum":
            continue
        missing = [str(v) for v in arg_def.allowed if str(v) not in table]
        if missing:
            raise ValueError(
                f"[command.mappings.{map_arg}] is missing entries for enum values: "
                + ", ".join(repr(v) for v in missing)
                + ' (map a value to "" to mean no flags)'
            )


def compile_command(manifest: Manifest, *, warn: bool = True) -> None:
    """Compile ``[command]`` to its canonical exec form and check it.

    Idempotent. When ``template`` is set and ``exec`` is empty, the template
    is tokenized into ``exec`` (``exec_was_declared`` stays False so the
    manifest remains in strict template mode). Every conditional template is
    tokenized into ``ConditionalDef.tokens``. ``end_of_options``, every
    placeholder, and enum mapping coverage are validated.

    Args:
        manifest: The manifest to compile in place.
        warn: Emit the template deprecation warning (once per load).

    Raises:
        ValueError: On a malformed template, a bad ``end_of_options`` value,
            or an unresolved placeholder.
    """
    cmd = manifest.command
    if cmd.end_of_options not in ("", "--"):
        raise ValueError(
            f'[command] end_of_options must be "--" when set, got {cmd.end_of_options!r}'
        )
    if cmd.template and not cmd.exec:
        cmd.exec = tokenize_template(cmd.template)
        cmd.exec_was_declared = False
        if warn:
            warnings.warn(_TEMPLATE_DEPRECATION, DeprecationWarning, stacklevel=2)
            sys.stderr.write(f"warning: {_TEMPLATE_DEPRECATION}\n")
    for cond_name, cond in cmd.conditionals.items():
        try:
            cond.tokens = tokenize_template(cond.template)
        except ValueError as exc:
            raise ValueError(f"[command.conditionals.{cond_name}] {exc}") from exc
    _check_placeholders(manifest)
    _check_mappings(manifest)


def _expand_tokens(
    tokens: List[str],
    single: Dict[str, str],
    trusted: Dict[str, List[str]],
    user_args: Set[str],
) -> List[Tuple[str, bool]]:
    """Substitute one token list into argv pieces.

    A token that is exactly ``{name}`` naming a trusted multi-token variable
    splices that variable's tokens. Any other token has every ``{name}``
    replaced textually inside that one token (``{{``/``}}`` become literal
    braces) and is never split; a token that was exactly one placeholder
    resolving to the empty string is dropped.

    Returns:
        ``(argv_token, from_user_arg)`` pairs; ``from_user_arg`` is True for
        a token produced from a sole placeholder naming a declared arg.
    """
    out: List[Tuple[str, bool]] = []
    for token in tokens:
        name = _sole_placeholder(token)
        if name is not None:
            if name in trusted:
                out.extend((t, False) for t in trusted[name])
                continue
            if name not in single:
                raise ValueError(f"unresolved placeholder '{{{name}}}' in command")
            value = single[name]
            if value == "":
                continue
            out.append((value, name in user_args))
            continue

        def replace(m: re.Match) -> str:  # type: ignore[type-arg]
            text = m.group(0)
            if text == "{{":
                return "{"
            if text == "}}":
                return "}"
            key = m.group(1)
            if key in single:
                return single[key]
            if key in trusted:
                raise ValueError(
                    f"placeholder '{{{key}}}' expands to multiple tokens and "
                    "must be a whole token in command"
                )
            raise ValueError(f"unresolved placeholder '{{{key}}}' in command")

        out.append((_PLACEHOLDER_RE.sub(replace, token), False))
    return out


def _check_declared_args(manifest: Manifest, args: Dict[str, str]) -> None:
    """Refuse a supplied argument name that ``[args]`` does not declare.

    An undeclared name never reaches the command, but dropping it silently
    hides the gap between what the caller asked for and what ran.
    """
    unknown = sorted(name for name in args if name not in manifest.args)
    if not unknown:
        return
    declared = ", ".join(a.name for a in manifest.args_sorted) or "none"
    raise ValidationError(
        "; ".join(
            f"unknown argument '{name}' (declared arguments: {declared})"
            for name in unknown
        )
    )


def _resolve_context(
    manifest: Manifest, args: Dict[str, str]
) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Validate arguments and build the two substitution maps.

    Returns:
        ``(single, trusted)``: single-token variables (validated args,
        ``[command.defaults]``, injected executor variables) and trusted
        multi-token variables (``_<arg>_flags`` from mappings, ``_<cond>``
        from conditionals), each already split into argv tokens.
    """
    _check_declared_args(manifest, args)
    exec_mode = manifest.command.exec_was_declared
    single: Dict[str, str] = {}
    absent: Set[str] = set()

    for arg_name, arg_def in manifest.args.items():
        if arg_name in args:
            single[arg_name] = validate_arg_mode(arg_def, args[arg_name], exec_mode)
        elif arg_def.default is not None:
            single[arg_name] = str(arg_def.default)
        elif arg_def.required:
            raise ValidationError(
                f"Missing required argument: '{arg_name}'"
            )
        else:
            single[arg_name] = ""
            absent.add(arg_name)

    for key, val in manifest.command.defaults.items():
        if key not in single:
            single[key] = str(val)

    scan_id = _generate_scan_id()
    evidence_dir = os.environ.get("TOOLCLAD_EVIDENCE_DIR", os.path.join(tempfile.gettempdir(), "toolclad-evidence"))

    output_dir = evidence_dir
    if manifest.tool.evidence.output_dir:
        output_dir = manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )

    ext_map = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt", "jsonl": "jsonl"}
    out_format = manifest.output.format if manifest.output else "text"
    ext = ext_map.get(out_format, "txt")
    output_file = os.path.join(output_dir, f"scan.{ext}")

    single["_scan_id"] = scan_id
    single["_evidence_dir"] = evidence_dir
    single["_output_file"] = output_file

    # Mapping values come from the manifest, so splitting them is safe. A
    # present value with no table entry is an error (never an empty splice);
    # an absent optional argument contributes nothing.
    trusted: Dict[str, List[str]] = {}
    for map_arg, mapping_table in manifest.command.mappings.items():
        if map_arg in absent or map_arg not in single:
            trusted[f"_{map_arg}_flags"] = []
            continue
        arg_value = single[map_arg]
        if arg_value not in mapping_table:
            raise ValidationError(
                f"no mapping for argument '{map_arg}' value '{arg_value}' "
                f"in [command.mappings.{map_arg}]"
            )
        trusted[f"_{map_arg}_flags"] = tokenize_template(str(mapping_table[arg_value]))

    user_args = set(manifest.args)
    for cond_name, cond_def in manifest.command.conditionals.items():
        if _evaluate_condition(cond_def.when, single):
            expanded = _expand_tokens(cond_def.tokens, single, trusted, user_args)
            trusted[f"_{cond_name}"] = [t for t, _ in expanded]
        else:
            trusted[f"_{cond_name}"] = []

    return single, trusted


def build_command_argv(manifest: Manifest, args: Dict[str, str]) -> List[str]:
    """Build the argv list from a manifest and raw argument values.

    The manifest is compiled to its exec form if needed, every argument is
    validated, and each exec token is substituted independently so argument
    boundaries are preserved: a value is always exactly one argv element.
    When ``end_of_options = "--"`` is set, a literal ``--`` is inserted once,
    immediately before the first argv element produced from a top-level exec
    token that was solely a declared-arg placeholder.

    Args:
        manifest: The parsed manifest.
        args: Mapping of argument name to raw string value.

    Returns:
        A list of strings ready for subprocess execution.

    Raises:
        ValidationError: If a required argument is missing, validation fails,
            or a mapped argument's value has no entry in its mapping table.
        ValueError: If the manifest uses a custom executor, has no command,
            or references an unresolved placeholder.
    """
    if manifest.command.executor:
        raise ValueError(
            f"Manifest '{manifest.tool.name}' uses a custom executor "
            f"({manifest.command.executor}); cannot build a template command."
        )

    compile_command(manifest, warn=False)
    if not manifest.command.exec:
        raise ValueError(
            f"Manifest '{manifest.tool.name}' has no exec array or command template."
        )

    single, trusted = _resolve_context(manifest, args)
    expanded = _expand_tokens(manifest.command.exec, single, trusted, set(manifest.args))

    argv: List[str] = []
    insert_end_of_options = manifest.command.end_of_options == "--"
    for token, from_user_arg in expanded:
        if insert_end_of_options and from_user_arg:
            argv.append("--")
            insert_end_of_options = False
        argv.append(token)

    if not argv or not argv[0]:
        raise ValueError("exec array produced empty argv")

    return argv


def build_command(manifest: Manifest, args: Dict[str, str]) -> str:
    """Build the command as a display string.

    This is ``build_command_argv`` rendered with ``shlex.join``; it exists for
    envelopes and dry-run output. Nothing is ever executed from this string.

    Raises:
        ValidationError: If a required argument is missing or validation fails.
        ValueError: If the manifest uses a custom executor or has no command.
    """
    return shlex.join(build_command_argv(manifest, args))


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


def _interpolate_http(template: str, args: Dict[str, str]) -> str:
    """Resolve ``{_secret:…}`` on the manifest template, then interpolate args.

    Secrets are expanded first so an argument value can never introduce a
    secret reference of its own: by the time arguments are substituted,
    every ``{_secret:name}`` the manifest wrote has already been replaced
    and nothing expands them again. A ``{_secret:…}`` arriving inside an
    argument therefore stays literal.
    """
    return _interpolate(inject_template_vars(template), args)


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
    _check_declared_args(manifest, args)

    scan_id = _generate_scan_id()
    effective_timeout = timeout or manifest.tool.timeout_seconds

    # Manifest secrets first, then args (see _interpolate_http): an
    # argument can never carry a secret reference into the request.
    url = _interpolate_http(http.url, args)
    headers = {k: _interpolate_http(v, args) for k, v in http.headers.items()}
    body: Optional[bytes] = None
    if http.body_template is not None:
        # JSON-escape values to prevent injection into JSON body
        escaped_args = {k: json.dumps(v)[1:-1] for k, v in args.items()}  # strip quotes from json.dumps
        body_str = _interpolate(inject_template_vars(http.body_template), escaped_args)
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

    is_success = True
    if http.error_status and status_code in http.error_status:
        is_success = False
    elif http.success_status and status_code not in http.success_status:
        is_success = False
    elif not http.success_status and not http.error_status:
        is_success = 200 <= status_code < 300

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
        _check_declared_args(manifest, args)
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

    # Build argv from the compiled exec form; values are never re-split.
    args_list = build_command_argv(manifest, args)
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

    # Ensure evidence output directory exists.
    evidence_dir = os.environ.get("TOOLCLAD_EVIDENCE_DIR", os.path.join(tempfile.gettempdir(), "toolclad-evidence"))
    if manifest.tool.evidence.output_dir:
        out_dir = manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )
    else:
        out_dir = os.path.join(evidence_dir, f"{scan_id}-{tool_name}")
    os.makedirs(out_dir, exist_ok=True)

    ext_map = {"xml": "xml", "json": "json", "csv": "csv", "text": "txt", "jsonl": "jsonl"}
    out_format = manifest.output.format if manifest.output else "text"
    ext = ext_map.get(out_format, "txt")
    output_file = os.path.join(out_dir, f"scan.{ext}")
    envelope["output_file"] = output_file
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
