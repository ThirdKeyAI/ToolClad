"""Command construction and execution for ToolClad manifests."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import warnings

try:  # POSIX only; the spawn path requires it.
    import resource
except ImportError:  # pragma: no cover - non-POSIX platforms
    resource = None  # type: ignore[assignment]
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from toolclad.manifest import LimitsDef, Manifest, _command_basename, _default_text
from toolclad.scope import manifest_scope
from toolclad.validator import ValidationError, validate_arg_in

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


# The child's PATH. Fixed, never inherited: an inherited PATH is how a renamed
# binary placed earlier in the search order wins.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Parent variables copied into the child environment, only when set.
_PASSTHROUGH_ENV: Tuple[str, ...] = ("HOME", "LANG", "LC_ALL", "TZ", "TERM")

# Basenames refused as argv[0] unless ``[tool] allow_interpreter = true``.
INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
    "env", "eval", "xargs", "python", "python2", "python3", "perl", "ruby",
    "node", "deno", "bun", "lua", "php", "awk",
})

# Default child resource limits (W6 item 8). RLIMIT_AS and RLIMIT_CPU are set
# only when ``[tool.limits]`` declares them: an address-space cap breaks tools
# that reserve large virtual mappings.
_DEFAULT_NOFILE = 1024
_DEFAULT_FSIZE = 1 << 30

_DEFAULT_KILL_GRACE_MS = 2000

_EXT_MAP = {"xml": "xml", "json": "json", "csv": "csv", "jsonl": "jsonl"}


def _generate_scan_id() -> str:
    """Generate a scan ID: ``<unix_seconds>-<32 hex chars>`` (128 random bits)."""
    return f"{int(time.time())}-{secrets.token_hex(16)}"


def child_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Build a child environment from the allowlist.

    ``PATH`` is the fixed :data:`SAFE_PATH`; ``HOME``, ``LANG``, ``LC_ALL``,
    ``TZ`` and ``TERM`` are copied from the parent when set; ``extra`` (the
    executor hatch variables) is added. Nothing else is inherited, and any
    ``TOOLCLAD_SECRET*`` name is removed unconditionally so a future change
    to the allowlist cannot hand a secret to a child.
    """
    env: Dict[str, str] = {"PATH": SAFE_PATH}
    for name in _PASSTHROUGH_ENV:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    if extra:
        env.update(extra)
    for name in list(env):
        if name.upper().startswith("TOOLCLAD_SECRET"):
            del env[name]
    return env


def resolve_binary(program: str) -> str:
    """Resolve ``program`` to an absolute path against :data:`SAFE_PATH`.

    A name containing a path separator is used as given.

    Raises:
        RuntimeError: When the name is not an executable file on the path.
    """
    if os.sep in program or "/" in program:
        return program
    for directory in SAFE_PATH.split(":"):
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError(f"cannot resolve binary '{program}' on PATH {SAFE_PATH}")


def _kill_grace_seconds() -> float:
    """``TOOLCLAD_KILL_GRACE_MS`` as seconds; invalid or negative -> 2000 ms."""
    raw = os.environ.get("TOOLCLAD_KILL_GRACE_MS", "").strip()
    ms = int(raw) if re.fullmatch(r"[0-9]+", raw) else _DEFAULT_KILL_GRACE_MS
    return ms / 1000.0


def _evidence_root() -> str:
    """``TOOLCLAD_EVIDENCE_DIR``, else ``<tmpdir>/toolclad-evidence``."""
    return os.environ.get("TOOLCLAD_EVIDENCE_DIR") or os.path.join(
        tempfile.gettempdir(), "toolclad-evidence"
    )


def _output_dir(manifest: Manifest, evidence_dir: str, scan_id: str) -> str:
    """The per-call output directory (W6 item 9)."""
    if manifest.tool.evidence.output_dir:
        return manifest.tool.evidence.output_dir.format(
            evidence_dir=evidence_dir, scan_id=scan_id
        )
    return os.path.join(evidence_dir, f"{scan_id}-{manifest.tool.name}")


def _output_file(manifest: Manifest, output_dir: str) -> str:
    """``<output dir>/scan.<ext>``; ``ext`` from ``output.format``, else txt."""
    out_format = manifest.output.format if manifest.output else "text"
    return os.path.join(output_dir, f"scan.{_EXT_MAP.get(out_format, 'txt')}")


def _make_private_dir(path: str) -> None:
    """Create ``path`` (and parents) and force mode 0700.

    The umask may mask the ``makedirs`` mode, hence the explicit chmod. A
    directory owned by another user (a pre-planted directory or symlink in a
    shared temp directory) is refused.
    """
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.stat(path)
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise RuntimeError(f"refusing evidence directory '{path}': not owned by the current user")
    os.chmod(path, 0o700)


def _write_private_file(path: str, data: str) -> None:
    """Create ``path`` mode 0600 and write ``data``.

    ``O_EXCL | O_NOFOLLOW``: an existing file or a pre-planted symlink is
    refused rather than overwritten or followed.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def _rlimit_plan(limits: LimitsDef) -> List[Tuple[int, int]]:
    """The ``(resource, value)`` pairs the pre-exec hook applies."""
    if resource is None:  # pragma: no cover - non-POSIX platforms
        return []
    plan = [
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_FSIZE, limits.fsize_bytes if limits.fsize_bytes is not None else _DEFAULT_FSIZE),
        (resource.RLIMIT_NOFILE, limits.nofile if limits.nofile is not None else _DEFAULT_NOFILE),
    ]
    # RLIMIT_NPROC only when declared: Linux counts it against every task the
    # user owns, not the tool's own tree, so any fixed default stops a
    # threaded tool from starting a thread on a busy host.
    if limits.nproc is not None:
        plan.append((resource.RLIMIT_NPROC, limits.nproc))
    if limits.address_space_bytes is not None:
        plan.append((resource.RLIMIT_AS, limits.address_space_bytes))
    if limits.cpu_seconds is not None:
        plan.append((resource.RLIMIT_CPU, limits.cpu_seconds))
    return plan


def _make_preexec(limits: LimitsDef):
    """The child pre-exec hook: own process group, umask 0077, rlimits.

    Runs in the forked child before exec; the rlimit plan is computed in the
    parent so the hook does as little as possible. A limit above the
    inherited hard limit is clamped to it.
    """
    plan = _rlimit_plan(limits)

    def hook() -> None:
        os.setpgrp()
        os.umask(0o077)
        for res, value in plan:
            _soft, hard = resource.getrlimit(res)
            if hard != resource.RLIM_INFINITY and value > hard:
                value = hard
            resource.setrlimit(res, (value, value))

    return hook


def _signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _run_process(
    argv: List[str],
    *,
    env: Dict[str, str],
    cwd: str,
    timeout: float,
    limits: LimitsDef,
) -> Tuple[int, str, str, bool]:
    """Spawn ``argv`` with the hardened settings and wait for it.

    stdin is ``/dev/null``, the environment is ``env`` (from
    :func:`child_env`), the working directory is ``cwd``, and the pre-exec
    hook puts the child in its own process group with umask 0077 and rlimits.

    Returns:
        ``(returncode, stdout, stderr, timed_out)``. On timeout the return
        code is -1 and the output collected before the kill is kept.
    """
    argv = [resolve_binary(argv[0])] + list(argv[1:])
    proc = subprocess.Popen(
        argv,
        env=env,
        cwd=cwd,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=False,
        preexec_fn=_make_preexec(limits),
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout or "", stderr or "", False
    except subprocess.TimeoutExpired:
        pass
    except BaseException:
        _signal_group(proc.pid, signal.SIGKILL)
        proc.wait()
        raise

    # Deadline: SIGTERM to the process group, a grace period, then SIGKILL to
    # the group. The hook made the child a group leader, so pgid == pid.
    # A descendant that calls setsid() leaves the group and escapes this in
    # every language: this is cleanup, not containment. Escape-proof cleanup
    # needs a cgroup, which is out of scope here.
    grace = _kill_grace_seconds()
    pgid = proc.pid
    _signal_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    # The leader may have exited on SIGTERM while other members ignored it;
    # SIGKILL takes the rest of the group either way.
    _signal_group(pgid, signal.SIGKILL)
    proc.wait()

    # Collect what the child wrote before the kill. A descendant outside the
    # group may still hold the pipes open, so this read is bounded too.
    try:
        stdout, stderr = proc.communicate(timeout=max(grace, 0.5))
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = _partial_text(exc.stdout), _partial_text(exc.stderr)
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
    return -1, stdout or "", stderr or "", True


def _partial_text(data: Any) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _check_argv0(manifest: Manifest) -> None:
    """Load-time checks on ``argv[0]`` of an exec/template command.

    The basename must match ``tool.binary`` when it is set, and an
    interpreter is refused unless ``allow_interpreter = true``. Skipped for
    ``dispatch = "callback"`` and for manifests with no exec command.
    """
    cmd = manifest.command
    if manifest.tool.dispatch == "callback":
        return
    # The executor escape hatch is exempt from the basename rule (it is a
    # wrapper by definition) but not from the interpreter denylist:
    # ``executor = "/bin/sh"`` turns argument values into shell input.
    if cmd.executor:
        if not manifest.tool.allow_interpreter and _command_basename(cmd.executor) in INTERPRETERS:
            raise ValueError(
                f"command argv[0] '{cmd.executor}' is an interpreter; "
                "set allow_interpreter = true to permit it"
            )
        return
    if not cmd.exec:
        return
    argv0 = cmd.exec[0]
    binary = manifest.tool.binary
    if binary and os.path.basename(argv0) != os.path.basename(binary):
        raise ValueError(f"command argv[0] '{argv0}' does not match tool.binary '{binary}'")
    if not manifest.tool.allow_interpreter and _command_basename(argv0) in INTERPRETERS:
        raise ValueError(
            f"command argv[0] '{argv0}' is an interpreter; "
            "set allow_interpreter = true to permit it"
        )


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
    _check_argv0(manifest)


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


def _validate_call_args(
    manifest: Manifest, args: Dict[str, str], exec_mode: bool
) -> Tuple[Dict[str, str], Set[str]]:
    """Validate every declared argument for one call, on every backend.

    A supplied value and a manifest default both go through the full rule
    set, scope included (the scope file is discovered once per manifest).
    Returns ``(values, absent)`` where ``absent`` names the optional
    arguments that were neither supplied nor defaulted.
    """
    _check_declared_args(manifest, args)
    scope = manifest_scope(manifest)
    values: Dict[str, str] = {}
    absent: Set[str] = set()
    for arg_name, arg_def in manifest.args.items():
        if arg_name in args:
            values[arg_name] = validate_arg_in(arg_def, args[arg_name], exec_mode, scope)
        elif arg_def.default is not None:
            values[arg_name] = validate_arg_in(
                arg_def, _default_text(arg_def.default), exec_mode, scope
            )
        elif arg_def.required:
            raise ValidationError(f"Missing required argument: '{arg_name}'")
        else:
            absent.add(arg_name)
    return values, absent


def _resolve_context(
    manifest: Manifest, args: Dict[str, str], scan_id: Optional[str] = None
) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Validate arguments and build the two substitution maps.

    Returns:
        ``(single, trusted)``: single-token variables (validated args,
        ``[command.defaults]``, injected executor variables) and trusted
        multi-token variables (``_<arg>_flags`` from mappings, ``_<cond>``
        from conditionals), each already split into argv tokens.
    """
    single, absent = _validate_call_args(
        manifest, args, manifest.command.exec_was_declared
    )
    for arg_name in absent:
        single[arg_name] = ""

    for key, val in manifest.command.defaults.items():
        if key not in single:
            single[key] = str(val)

    if scan_id is None:
        scan_id = _generate_scan_id()
    evidence_dir = _evidence_root()
    output_file = _output_file(manifest, _output_dir(manifest, evidence_dir, scan_id))

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


def build_command_argv(
    manifest: Manifest, args: Dict[str, str], *, scan_id: Optional[str] = None
) -> List[str]:
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
        scan_id: The scan id behind ``{_scan_id}`` and ``{_output_file}``;
            a fresh one is generated when omitted.

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

    single, trusted = _resolve_context(manifest, args, scan_id)
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


def load_secrets_file() -> Dict[str, str]:
    """Read the TOML file named by ``TOOLCLAD_SECRETS_FILE``, if set.

    Top-level ``name = "value"`` pairs; names are matched case-insensitively.
    The file is refused when it is readable by group or others, which is what
    makes it a better home for a secret than an environment variable.

    Returns:
        A mapping of lowercased name to value; empty when the variable is unset.

    Raises:
        RuntimeError: On a group/other-readable file, an unreadable or
            malformed file, or a non-string value.
    """
    path = os.environ.get("TOOLCLAD_SECRETS_FILE")
    if not path:
        return {}
    from toolclad.manifest import tomllib

    try:
        with open(path, "rb") as f:
            mode = stat.S_IMODE(os.fstat(f.fileno()).st_mode)
            if mode & 0o077:
                raise RuntimeError(
                    f"TOOLCLAD_SECRETS_FILE '{path}' is readable by group or others "
                    f"(mode {mode:04o}); chmod 600 it"
                )
            data = tomllib.load(f)
    except OSError as exc:
        raise RuntimeError(f"cannot read TOOLCLAD_SECRETS_FILE '{path}': {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"TOOLCLAD_SECRETS_FILE '{path}' is not valid TOML: {exc}") from exc
    out: Dict[str, str] = {}
    for name, value in data.items():
        if not isinstance(value, str):
            raise RuntimeError(
                f"TOOLCLAD_SECRETS_FILE '{path}': secret '{name}' must be a string"
            )
        out[name.lower()] = value
    return out


def inject_template_vars(template: str, secrets_map: Optional[Dict[str, str]] = None) -> str:
    """Replace ``{_secret:name}`` with its value.

    The value comes from ``secrets_map`` (the loaded ``TOOLCLAD_SECRETS_FILE``,
    which wins) or else the ``TOOLCLAD_SECRET_<NAME>`` environment variable.
    When ``secrets_map`` is None the file is read here; callers expanding
    several templates load it once with :func:`load_secrets_file` and pass it.
    A missing secret is an error.
    """
    if secrets_map is None:
        secrets_map = load_secrets_file() if "{_secret:" in template else {}

    def replacer(match: re.Match) -> str:  # type: ignore[type-arg]
        name = match.group(1)
        if name.lower() in secrets_map:
            return secrets_map[name.lower()]
        env_key = f"TOOLCLAD_SECRET_{name.upper()}"
        val = os.environ.get(env_key)
        if val is None:
            raise RuntimeError(
                f"Secret '{name}' not found (set {env_key} or add it to TOOLCLAD_SECRETS_FILE)"
            )
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


def _interpolate_http(
    template: str, args: Dict[str, str], secrets_map: Optional[Dict[str, str]] = None
) -> str:
    """Resolve ``{_secret:…}`` on the manifest template, then interpolate args.

    Secrets are expanded first so an argument value can never introduce a
    secret reference of its own: by the time arguments are substituted,
    every ``{_secret:name}`` the manifest wrote has already been replaced
    and nothing expands them again. A ``{_secret:…}`` arriving inside an
    argument therefore stays literal.
    """
    return _interpolate(inject_template_vars(template, secrets_map), args)


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
    # The same validation as the oneshot path (strict mode): only validated
    # values are ever interpolated into the URL, headers or body.
    args, absent = _validate_call_args(manifest, args, False)
    for arg_name in absent:
        args[arg_name] = ""

    scan_id = _generate_scan_id()
    effective_timeout = timeout or manifest.tool.timeout_seconds

    # Manifest secrets first, then args (see _interpolate_http): an
    # argument can never carry a secret reference into the request.
    # The secrets file is read once per call, not once per placeholder.
    secrets_map = load_secrets_file()
    url = _interpolate_http(http.url, args, secrets_map)
    headers = {k: _interpolate_http(v, args, secrets_map) for k, v in http.headers.items()}
    body: Optional[bytes] = None
    if http.body_template is not None:
        # JSON-escape values to prevent injection into JSON body
        escaped_args = {k: json.dumps(v)[1:-1] for k, v in args.items()}  # strip quotes from json.dumps
        body_str = _interpolate(
            inject_template_vars(http.body_template, secrets_map), escaped_args
        )
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
    # Every argument is validated (scope included) and forwarded in its
    # validated form. An undeclared name is refused, as on every other
    # backend: the manifest, not the remote server, is the contract.
    _check_declared_args(manifest, args)
    validated, absent = _validate_call_args(manifest, args, False)
    args = {k: v for k, v in validated.items() if k not in absent}

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
        return _execute_custom(manifest, args, dry_run=dry_run, timeout=timeout)

    scan_id = _generate_scan_id()
    tool_name = manifest.tool.name
    effective_timeout = timeout or manifest.tool.timeout_seconds

    # Build argv from the compiled exec form; values are never re-split. The
    # same scan id backs {_scan_id}/{_output_file} and the envelope.
    args_list = build_command_argv(manifest, args, scan_id=scan_id)
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

    evidence_dir = _evidence_root()
    out_dir = _output_dir(manifest, evidence_dir, scan_id)
    output_file = _output_file(manifest, out_dir)
    envelope["output_file"] = output_file
    start = time.monotonic()
    work_dir = ""
    try:
        work_dir = _prepare_dirs(evidence_dir, out_dir, scan_id)
        if os.path.lexists(output_file):
            raise RuntimeError(f"refusing to run: evidence file '{output_file}' already exists")
        returncode, stdout, stderr, timed_out = _run_process(
            args_list,
            env=child_env(),
            cwd=work_dir,
            timeout=effective_timeout,
            limits=manifest.tool.limits,
        )
        envelope["duration_ms"] = int((time.monotonic() - start) * 1000)
        envelope["exit_code"] = returncode
        envelope["stderr"] = stderr

        if timed_out:
            envelope["status"] = "timeout"
            envelope["results"] = {
                "error": f"Command timed out after {effective_timeout}s",
                "raw_output": stdout,
            }
            return envelope

        # Evidence: when the tool wrote {_output_file} itself, keep its file;
        # otherwise record captured stdout. Either way nothing is followed
        # through a symlink or overwritten.
        if os.path.islink(output_file):
            raise RuntimeError(f"refusing evidence file '{output_file}': it is a symlink")
        if not os.path.lexists(output_file):
            _write_private_file(output_file, stdout)

        if manifest.tool.evidence.capture:
            envelope["output_hash"] = _hash_file(
                output_file, manifest.tool.evidence.hash
            )

        if returncode != 0:
            envelope["status"] = "error"
            envelope["results"] = {
                "returncode": returncode,
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
    except Exception as exc:
        envelope["duration_ms"] = int((time.monotonic() - start) * 1000)
        envelope["status"] = "error"
        envelope["exit_code"] = -1
        envelope["stderr"] = str(exc)
        envelope["results"] = {"error": str(exc)}
    finally:
        _remove_if_empty(work_dir)

    return envelope


def _prepare_dirs(evidence_dir: str, out_dir: str, scan_id: str) -> str:
    """Create the evidence root, the output directory and the per-call
    scratch directory, all mode 0700. Returns the scratch directory, which
    becomes the child's working directory."""
    _make_private_dir(evidence_dir)
    _make_private_dir(out_dir)
    work_dir = os.path.join(evidence_dir, f"{scan_id}-work")
    os.mkdir(work_dir, 0o700)
    os.chmod(work_dir, 0o700)
    return work_dir


def _remove_if_empty(path: str) -> None:
    """Remove the scratch directory unless the tool left files in it (those
    are evidence)."""
    if not path:
        return
    try:
        os.rmdir(path)
    except OSError:
        pass


def _execute_custom(
    manifest: Manifest,
    args: Dict[str, str],
    *,
    dry_run: bool = False,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the ``command.executor`` escape hatch.

    The script receives validated arguments as ``TOOLCLAD_ARG_<NAME>`` plus
    ``TOOLCLAD_SCAN_ID``, ``TOOLCLAD_TOOL_NAME``, ``TOOLCLAD_EVIDENCE_DIR``
    and ``TOOLCLAD_OUTPUT_DIR`` on top of the allowlisted environment;
    secrets are never passed.
    """
    validated_args, _absent = _validate_call_args(manifest, args, False)

    scan_id = _generate_scan_id()
    effective_timeout = timeout or manifest.tool.timeout_seconds
    evidence_dir = _evidence_root()
    out_dir = _output_dir(manifest, evidence_dir, scan_id)

    extra = {f"TOOLCLAD_ARG_{k.upper()}": str(v) for k, v in validated_args.items()}
    extra["TOOLCLAD_SCAN_ID"] = scan_id
    extra["TOOLCLAD_TOOL_NAME"] = manifest.tool.name
    extra["TOOLCLAD_EVIDENCE_DIR"] = evidence_dir
    extra["TOOLCLAD_OUTPUT_DIR"] = out_dir

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
    work_dir = ""
    try:
        work_dir = _prepare_dirs(evidence_dir, out_dir, scan_id)
        returncode, stdout, stderr, timed_out = _run_process(
            [manifest.command.executor],
            env=child_env(extra),
            cwd=work_dir,
            timeout=effective_timeout,
            limits=manifest.tool.limits,
        )
        envelope["duration_ms"] = int((time.monotonic() - start) * 1000)
        envelope["exit_code"] = returncode
        envelope["stderr"] = stderr

        if timed_out:
            envelope["status"] = "timeout"
            envelope["results"] = {
                "error": f"Custom executor timed out after {effective_timeout}s",
                "raw_output": stdout,
            }
        elif returncode != 0:
            envelope["status"] = "error"
            envelope["results"] = {"returncode": returncode, "stderr": stderr, "raw_output": stdout}
        else:
            try:
                parsed = _parse_output(manifest, stdout)
                envelope["results"] = parsed if isinstance(parsed, dict) else {"parsed_output": parsed}
            except RuntimeError:
                envelope["results"] = {"raw_output": stdout}
    except Exception as exc:
        envelope["duration_ms"] = int((time.monotonic() - start) * 1000)
        envelope["status"] = "error"
        envelope["exit_code"] = -1
        envelope["stderr"] = str(exc)
        envelope["results"] = {"error": str(exc)}
    finally:
        _remove_if_empty(work_dir)

    return envelope
