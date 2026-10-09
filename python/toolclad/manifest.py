"""Manifest loading and dataclasses for .clad.toml files."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterator, List, Mapping, Optional, Tuple

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
    screenshots: bool = False


@dataclass
class LimitsDef:
    """Resource limits for the spawned process from [tool.limits].

    Every field is optional; ``None`` means no limit is requested.
    """

    nproc: Optional[int] = None
    nofile: Optional[int] = None
    fsize_bytes: Optional[int] = None
    address_space_bytes: Optional[int] = None
    cpu_seconds: Optional[int] = None


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
    # Dispatch mode: "exec" (default) runs an execution backend; "callback"
    # declares the manifest as validator-only — no [output] or backend
    # required. Useful for in-process embeddings where ToolClad is the
    # typed-argument fence and dispatch happens elsewhere.
    dispatch: str = "exec"
    # Backend mode: "oneshot" | "session" | "browser". Advisory: when the
    # manifest omits it, the loader derives it from which backend section is
    # present.
    mode: str = "oneshot"
    # The tool reaches the network. Declaring it makes the egress lint apply.
    network_egress: bool = False
    # Permit an interpreter (sh, python, ...) as argv[0].
    allow_interpreter: bool = False
    cedar: CedarDef = field(default_factory=CedarDef)
    evidence: EvidenceDef = field(default_factory=EvidenceDef)
    limits: LimitsDef = field(default_factory=LimitsDef)


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
    # Float bounds for `number` type. Fall back to min/max cast to float when unset.
    min_float: Optional[float] = None
    max_float: Optional[float] = None
    clamp: bool = False
    sanitize: List[str] = field(default_factory=list)
    schemes: List[str] = field(default_factory=list)
    scope_check: bool = False
    # Refuse internal, private and link-local targets (loopback, RFC 1918,
    # cloud metadata, ...) for network-typed arguments.
    block_internal: bool = False
    # Permit a value starting with '-' or '+'. Off by default so a value can
    # never be read as an option by the invoked binary.
    allow_leading_dash: bool = False
    # Permit whitespace inside a value. Honored only when the manifest
    # declared `exec` directly (CommandDef.exec_was_declared); a compiled
    # template stays strict.
    allow_whitespace: bool = False


@dataclass
class ConditionalDef:
    """A conditional command fragment from [command.conditionals.*]."""

    name: str = ""
    when: str = ""
    template: str = ""
    # `template` tokenized at load; placeholders are substituted per token at
    # resolve time and the result is spliced in for `{_<name>}`.
    tokens: List[str] = field(default_factory=list)


@dataclass
class CommandDef:
    """The [command] section: template/exec, mappings, conditionals, or executor.

    Supports two invocation forms:
    - ``exec = ["cmd", "arg1", "{placeholder}"]`` — preferred, shell-free array execution
    - ``template = "cmd arg1 {placeholder}"`` — deprecated; tokenized at load
      into ``exec`` (the manifest text is split, substituted values never are)

    When both are present, ``exec`` takes precedence and ``template`` is kept
    for display only.
    """

    template: str = ""
    exec: List[str] = field(default_factory=list)
    executor: str = ""
    defaults: Dict[str, Any] = field(default_factory=dict)
    mappings: Dict[str, Dict[str, str]] = field(default_factory=dict)
    conditionals: Dict[str, ConditionalDef] = field(default_factory=dict)
    # Only "--" is accepted. When set, a literal "--" is inserted once before
    # the first argv element produced from a sole declared-arg placeholder.
    end_of_options: str = ""
    # True when the manifest declared `exec` directly. A template compiled to
    # exec leaves this False, which keeps `allow_whitespace` disabled.
    exec_was_declared: bool = False


@dataclass
class OutputDef:
    """The [output] section: format, parser, envelope, schema."""

    format: str = "text"
    parser: str = ""
    envelope: bool = True
    schema: Dict[str, Any] = field(default_factory=dict)
    # Upper bound on captured stdout, in bytes.
    max_bytes: int = 8_388_608


@dataclass
class HttpDef:
    """HTTP execution definition from [http] section."""

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: Optional[str] = None
    success_status: List[int] = field(default_factory=list)
    error_status: List[int] = field(default_factory=list)


@dataclass
class McpProxyDef:
    """MCP proxy delegation definition from [mcp] section."""

    server: str = ""
    tool: str = ""
    field_map: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionInteractionDef:
    """Interaction constraints for session mode."""

    input_sanitize: List[str] = field(default_factory=list)
    output_max_bytes: int = 1_048_576
    output_wait_ms: int = 2000


@dataclass
class SessionCommandDef:
    """A command definition within a session."""

    pattern: str = ""
    description: str = ""
    risk_tier: str = "low"
    human_approval: bool = False
    extract_target: bool = False
    args: Dict[str, ArgDef] = field(default_factory=dict)


@dataclass
class SessionChildDetectionDef:
    """Detection of a nested interactive child from [session.child_detection]."""

    pattern: str = ""
    type: str = ""
    manifest: str = ""


@dataclass
class SessionDef:
    """Session mode definition from [session] section."""

    startup_command: str = ""
    ready_pattern: str = ""
    startup_timeout_seconds: int = 30
    idle_timeout_seconds: int = 300
    session_timeout_seconds: int = 1800
    max_interactions: int = 100
    interaction: Optional[SessionInteractionDef] = None
    commands: Dict[str, SessionCommandDef] = field(default_factory=dict)
    child_detection: Optional[SessionChildDetectionDef] = None


@dataclass
class BrowserScopeDef:
    """Domain scoping for browser mode."""

    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    allow_external: bool = False


@dataclass
class BrowserCommandDef:
    """A command definition within a browser session."""

    description: str = ""
    risk_tier: str = "low"
    human_approval: bool = False
    args: Dict[str, ArgDef] = field(default_factory=dict)


@dataclass
class BrowserStateDef:
    """State tracking fields for browser mode."""

    fields: List[str] = field(default_factory=list)


@dataclass
class BrowserDefaultsDef:
    """Per-command defaults for browser mode from [browser.defaults]."""

    extract_mode: str = ""


@dataclass
class BrowserDef:
    """Browser mode definition from [browser] section."""

    engine: str = "cdp"
    headless: bool = True
    connect: str = "launch"
    extract_mode: str = "accessibility_tree"
    startup_timeout_seconds: int = 10
    session_timeout_seconds: int = 600
    idle_timeout_seconds: int = 120
    max_interactions: int = 200
    scope: Optional[BrowserScopeDef] = None
    commands: Dict[str, BrowserCommandDef] = field(default_factory=dict)
    state: Optional[BrowserStateDef] = None
    defaults: Optional[BrowserDefaultsDef] = None


@dataclass
class Manifest:
    """Complete parsed .clad.toml manifest."""

    tool: ToolMeta = field(default_factory=ToolMeta)
    args: Dict[str, ArgDef] = field(default_factory=dict)
    command: CommandDef = field(default_factory=CommandDef)
    # Output is required for execution-mode manifests; optional when
    # tool.dispatch == "callback" (validator-only embeddings).
    output: Optional[OutputDef] = None
    http: Optional[HttpDef] = None
    mcp: Optional[McpProxyDef] = None
    session: Optional[SessionDef] = None
    browser: Optional[BrowserDef] = None
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
        screenshots=bool(data.get("screenshots", False)),
    )


def _parse_limits(data: Dict[str, Any]) -> LimitsDef:
    return LimitsDef(
        nproc=data.get("nproc"),
        nofile=data.get("nofile"),
        fsize_bytes=data.get("fsize_bytes"),
        address_space_bytes=data.get("address_space_bytes"),
        cpu_seconds=data.get("cpu_seconds"),
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
        dispatch=data.get("dispatch", "exec"),
        # Left empty when absent; the loader derives it from the backend.
        mode=str(data.get("mode", "")),
        network_egress=bool(data.get("network_egress", False)),
        allow_interpreter=bool(data.get("allow_interpreter", False)),
    )
    if "cedar" in data:
        meta.cedar = _parse_cedar(data["cedar"])
    if "evidence" in data:
        meta.evidence = _parse_evidence(data["evidence"])
    if "limits" in data:
        meta.limits = _parse_limits(data["limits"])
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
        min_float=data.get("min_float"),
        max_float=data.get("max_float"),
        clamp=data.get("clamp", False),
        sanitize=data.get("sanitize", []),
        schemes=data.get("schemes", []),
        scope_check=data.get("scope_check", False),
        block_internal=bool(data.get("block_internal", False)),
        allow_leading_dash=bool(data.get("allow_leading_dash", False)),
        allow_whitespace=bool(data.get("allow_whitespace", False)),
    )


def _parse_command(data: Dict[str, Any]) -> CommandDef:
    conditionals: Dict[str, ConditionalDef] = {}
    for cond_name, cond_data in data.get("conditionals", {}).items():
        conditionals[cond_name] = ConditionalDef(
            name=cond_name,
            when=cond_data.get("when", ""),
            template=cond_data.get("template", ""),
        )
    exec_list = data.get("exec", [])
    if not isinstance(exec_list, list) or not all(isinstance(e, str) for e in exec_list):
        raise ValueError("[command] exec must be an array of strings")
    template = data.get("template", "")
    if not isinstance(template, str):
        raise ValueError("[command] template must be a string")
    return CommandDef(
        template=template,
        exec=list(exec_list),
        executor=data.get("executor", ""),
        defaults=data.get("defaults", {}),
        mappings=data.get("mappings", {}),
        conditionals=conditionals,
        end_of_options=str(data.get("end_of_options", "")),
        exec_was_declared=bool(exec_list),
    )


def _parse_output(data: Dict[str, Any]) -> OutputDef:
    return OutputDef(
        format=data.get("format", "text"),
        parser=data.get("parser", ""),
        envelope=data.get("envelope", True),
        schema=data.get("schema", {}),
        max_bytes=data.get("max_bytes", 8_388_608),
    )


def _parse_http(data: Dict[str, Any]) -> HttpDef:
    return HttpDef(
        method=data.get("method", "GET"),
        url=data.get("url", ""),
        headers=data.get("headers", {}),
        body_template=data.get("body_template"),
        success_status=data.get("success_status", []),
        error_status=data.get("error_status", []),
    )


def _parse_mcp(data: Dict[str, Any]) -> McpProxyDef:
    return McpProxyDef(
        server=data.get("server", ""),
        tool=data.get("tool", ""),
        field_map=data.get("field_map", {}),
    )


def _parse_session_interaction(data: Dict[str, Any]) -> SessionInteractionDef:
    return SessionInteractionDef(
        input_sanitize=data.get("input_sanitize", []),
        output_max_bytes=data.get("output_max_bytes", 1_048_576),
        output_wait_ms=data.get("output_wait_ms", 2000),
    )


def _parse_session_command(data: Dict[str, Any]) -> SessionCommandDef:
    args: Dict[str, ArgDef] = {}
    for arg_name, arg_data in data.get("args", {}).items():
        args[arg_name] = _parse_arg(arg_name, arg_data)
    return SessionCommandDef(
        pattern=data.get("pattern", ""),
        description=data.get("description", ""),
        risk_tier=data.get("risk_tier", "low"),
        human_approval=data.get("human_approval", False),
        extract_target=data.get("extract_target", False),
        args=args,
    )


def _parse_session_child_detection(data: Dict[str, Any]) -> SessionChildDetectionDef:
    return SessionChildDetectionDef(
        pattern=data.get("pattern", ""),
        type=data.get("type", ""),
        manifest=data.get("manifest", ""),
    )


def _parse_session(data: Dict[str, Any]) -> SessionDef:
    session = SessionDef(
        startup_command=data.get("startup_command", ""),
        ready_pattern=data.get("ready_pattern", ""),
        startup_timeout_seconds=data.get("startup_timeout_seconds", 30),
        idle_timeout_seconds=data.get("idle_timeout_seconds", 300),
        session_timeout_seconds=data.get("session_timeout_seconds", 1800),
        max_interactions=data.get("max_interactions", 100),
    )
    if "interaction" in data:
        session.interaction = _parse_session_interaction(data["interaction"])
    commands: Dict[str, SessionCommandDef] = {}
    if "commands" in data:
        for cmd_name, cmd_data in data["commands"].items():
            commands[cmd_name] = _parse_session_command(cmd_data)
    session.commands = commands
    if "child_detection" in data:
        session.child_detection = _parse_session_child_detection(data["child_detection"])
    return session


def _parse_browser_scope(data: Dict[str, Any]) -> BrowserScopeDef:
    return BrowserScopeDef(
        allowed_domains=data.get("allowed_domains", []),
        blocked_domains=data.get("blocked_domains", []),
        allow_external=data.get("allow_external", False),
    )


def _parse_browser_command(data: Dict[str, Any]) -> BrowserCommandDef:
    args: Dict[str, ArgDef] = {}
    for arg_name, arg_data in data.get("args", {}).items():
        args[arg_name] = _parse_arg(arg_name, arg_data)
    return BrowserCommandDef(
        description=data.get("description", ""),
        risk_tier=data.get("risk_tier", "low"),
        human_approval=data.get("human_approval", False),
        args=args,
    )


def _parse_browser_state(data: Dict[str, Any]) -> BrowserStateDef:
    return BrowserStateDef(
        fields=data.get("fields", []),
    )


def _parse_browser_defaults(data: Dict[str, Any]) -> BrowserDefaultsDef:
    return BrowserDefaultsDef(
        extract_mode=data.get("extract_mode", ""),
    )


def _parse_browser(data: Dict[str, Any]) -> BrowserDef:
    browser = BrowserDef(
        engine=data.get("engine", "cdp"),
        headless=data.get("headless", True),
        connect=data.get("connect", "launch"),
        extract_mode=data.get("extract_mode", "accessibility_tree"),
        startup_timeout_seconds=data.get("startup_timeout_seconds", 10),
        session_timeout_seconds=data.get("session_timeout_seconds", 600),
        idle_timeout_seconds=data.get("idle_timeout_seconds", 120),
        max_interactions=data.get("max_interactions", 200),
    )
    if "scope" in data:
        browser.scope = _parse_browser_scope(data["scope"])
    commands: Dict[str, BrowserCommandDef] = {}
    if "commands" in data:
        for cmd_name, cmd_data in data["commands"].items():
            commands[cmd_name] = _parse_browser_command(cmd_data)
    browser.commands = commands
    if "state" in data:
        browser.state = _parse_browser_state(data["state"])
    if "defaults" in data:
        browser.defaults = _parse_browser_defaults(data["defaults"])
    return browser


@dataclass
class CustomTypeDef:
    """Custom type definition from toolclad.toml."""

    base: str = ""
    allowed: List[str] = field(default_factory=list)
    pattern: str = ""
    min: Optional[int] = None
    max: Optional[int] = None
    min_float: Optional[float] = None
    max_float: Optional[float] = None


def load_custom_types(path: str) -> Dict[str, CustomTypeDef]:
    """Load custom type definitions from a toolclad.toml file.

    Returns a dict mapping type name to CustomTypeDef.
    """
    file_path = Path(path)
    if not file_path.exists():
        return {}

    with open(file_path, "rb") as f:
        data = tomllib.load(f)

    types = {}
    for name, tdef in data.get("types", {}).items():
        types[name] = CustomTypeDef(
            base=tdef.get("base", ""),
            allowed=tdef.get("allowed", []),
            pattern=tdef.get("pattern", ""),
            min=tdef.get("min"),
            max=tdef.get("max"),
            min_float=tdef.get("min_float"),
            max_float=tdef.get("max_float"),
        )
    return types


# ---------------------------------------------------------------------------
# Manifest key allowlist
# ---------------------------------------------------------------------------
#
# One entry per section, in the order of the normative key table shared by
# every ToolClad runtime. ``<n>`` stands for an author-chosen name (an
# argument, conditional or command) whose *contents* are checked against that
# entry. A key that is not listed is refused at load with
# ``unknown key '<section>.<key>' in manifest``; the ``validate`` CLI's
# ``--allow-unknown-keys`` downgrades that to a warning on stderr. Library
# loading is always strict.

_ARG_KEYS: FrozenSet[str] = frozenset({
    "position", "required", "type", "description", "default", "allowed",
    "pattern", "sanitize", "min", "max", "min_float", "max_float", "clamp",
    "schemes", "scope_check", "block_internal", "allow_leading_dash",
    "allow_whitespace",
})

MANIFEST_KEYS: Dict[str, FrozenSet[str]] = {
    # Top-level sections.
    "": frozenset({
        "tool", "args", "command", "output", "http", "mcp", "session",
        "browser",
    }),
    "tool": frozenset({
        "name", "version", "binary", "description", "timeout_seconds",
        "risk_tier", "human_approval", "dispatch", "mode", "network_egress",
        "allow_interpreter", "cedar", "evidence", "limits",
    }),
    "tool.cedar": frozenset({"resource", "action"}),
    "tool.evidence": frozenset({"output_dir", "capture", "hash", "screenshots"}),
    "tool.limits": frozenset({
        "nproc", "nofile", "fsize_bytes", "address_space_bytes", "cpu_seconds",
    }),
    "args.<n>": _ARG_KEYS,
    "command": frozenset({
        "template", "exec", "executor", "defaults", "mappings", "conditionals",
        "end_of_options",
    }),
    "command.conditionals.<n>": frozenset({"when", "template"}),
    "output": frozenset({"format", "parser", "envelope", "schema", "max_bytes"}),
    "http": frozenset({
        "method", "url", "headers", "body_template", "success_status",
        "error_status",
    }),
    "mcp": frozenset({"server", "tool", "field_map"}),
    "session": frozenset({
        "startup_command", "ready_pattern", "startup_timeout_seconds",
        "idle_timeout_seconds", "session_timeout_seconds", "max_interactions",
        "interaction", "commands", "child_detection",
    }),
    "session.interaction": frozenset({
        "input_sanitize", "output_max_bytes", "output_wait_ms",
    }),
    "session.commands.<n>": frozenset({
        "pattern", "description", "risk_tier", "human_approval",
        "extract_target", "args",
    }),
    "session.commands.<n>.args.<n>": _ARG_KEYS,
    "session.child_detection": frozenset({"pattern", "type", "manifest"}),
    "browser": frozenset({
        "engine", "headless", "connect", "extract_mode",
        "startup_timeout_seconds", "session_timeout_seconds",
        "idle_timeout_seconds", "max_interactions", "scope", "commands",
        "state", "defaults",
    }),
    "browser.defaults": frozenset({"extract_mode"}),
    "browser.scope": frozenset({
        "allowed_domains", "blocked_domains", "allow_external",
    }),
    "browser.commands.<n>": frozenset({
        "description", "risk_tier", "human_approval", "args",
    }),
    "browser.commands.<n>.args.<n>": _ARG_KEYS,
    "browser.state": frozenset({"fields"}),
}

# Tables whose keys are chosen by the manifest author; they are never
# descended into. ``[command.defaults]`` names variables, ``[command.mappings]``
# names arguments and their values, ``[http.headers]`` names header fields,
# ``[mcp.field_map]`` names remote fields and ``[output.schema]`` is JSON
# Schema.
_OPEN_TABLES: FrozenSet[str] = frozenset({
    "command.defaults", "command.mappings", "http.headers", "mcp.field_map",
    "output.schema",
})

_MODES: Tuple[str, ...] = ("oneshot", "session", "browser")


def _walk_keys(
    table: Mapping[str, Any], path: str = "", spec: str = ""
) -> Iterator[Tuple[str, str, str, bool]]:
    """Yield ``(spec, dotted_path, key, known)`` for every key in ``table``.

    ``spec`` is the ``MANIFEST_KEYS`` entry the key was checked against and
    ``dotted_path`` its concrete location (``args.target.block_internal``).
    Only known, closed tables are descended into.
    """
    allowed = MANIFEST_KEYS[spec]
    for key, value in table.items():
        full = f"{path}.{key}" if path else key
        known = key in allowed
        yield spec, full, key, known
        if not known or not isinstance(value, dict):
            continue
        child = f"{spec}.{key}" if spec else key
        if child in _OPEN_TABLES:
            continue
        if f"{child}.<n>" in MANIFEST_KEYS:
            for name, entry in value.items():
                if isinstance(entry, dict):
                    yield from _walk_keys(entry, f"{full}.{name}", f"{child}.<n>")
        elif child in MANIFEST_KEYS:
            yield from _walk_keys(value, full, child)


def find_unknown_keys(data: Mapping[str, Any]) -> List[str]:
    """Return every key of a parsed manifest that ``MANIFEST_KEYS`` does not
    list, as sorted dotted paths (``tool.tiemout_seconds``)."""
    return sorted(path for _, path, _, known in _walk_keys(data) if not known)


@dataclass(frozen=True)
class LoadOptions:
    """Options for :func:`load_manifest_with_options`.

    ``allow_unknown_keys`` backs the ``validate`` CLI's ``--allow-unknown-keys``
    flag: an unknown manifest key is reported as a warning on stderr instead of
    failing the load. It is the only relaxation the loader offers;
    :func:`load_manifest` is always strict.
    """

    allow_unknown_keys: bool = False


def load_manifest(path: str) -> Manifest:
    """Parse a .clad.toml file and return a Manifest (strict).

    Same as :func:`load_manifest_with_options` with default options: an
    unknown key anywhere in the manifest is a load error.

    Args:
        path: Filesystem path to the .clad.toml file.

    Returns:
        A fully populated Manifest dataclass.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the manifest contains a key the allowlist does not
            know, required sections are missing, ``tool.mode`` is not one of
            ``oneshot`` / ``session`` / ``browser``, a command template is
            malformed (placeholder inside quotes, unbalanced quote), a
            placeholder names no declared variable, or ``end_of_options`` is
            not ``"--"``.
        tomllib.TOMLDecodeError: If the file is not valid TOML.
    """
    return load_manifest_with_options(path, LoadOptions())


def load_manifest_with_options(
    path: str, options: Optional[LoadOptions] = None
) -> Manifest:
    """Parse a .clad.toml file and return a Manifest.

    Args:
        path: Filesystem path to the .clad.toml file.
        options: Loader options; ``None`` means strict (the default).

    Returns:
        A fully populated Manifest dataclass.

    Raises:
        See :func:`load_manifest`. With ``options.allow_unknown_keys`` set,
        unknown keys are printed as warnings instead of raised.
    """
    options = options or LoadOptions()
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")

    with open(file_path, "rb") as f:
        data = tomllib.load(f)

    unknown = find_unknown_keys(data)
    if unknown:
        messages = [f"unknown key '{key}' in manifest" for key in unknown]
        if not options.allow_unknown_keys:
            raise ValueError("; ".join(messages))
        for message in messages:
            sys.stderr.write(f"warning: {message}\n")

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

    if "http" in data:
        manifest.http = _parse_http(data["http"])

    if "mcp" in data:
        manifest.mcp = _parse_mcp(data["mcp"])

    if "session" in data:
        manifest.session = _parse_session(data["session"])

    if "browser" in data:
        manifest.browser = _parse_browser(data["browser"])

    if "mode" not in data["tool"]:
        manifest.tool.mode = _derive_mode(manifest)

    _validate_manifest(manifest)
    _compile_command(manifest)
    return manifest


def _derive_mode(manifest: Manifest) -> str:
    """Backend mode implied by which backend section is present."""
    if manifest.session is not None:
        return "session"
    if manifest.browser is not None:
        return "browser"
    return "oneshot"


def _compile_command(manifest: Manifest) -> None:
    """Tokenize a legacy template into exec and check every placeholder.

    Emits the template deprecation warning once per load. Deferred import:
    the executor module imports this one.
    """
    from toolclad.executor import compile_command

    compile_command(manifest, warn=True)


def _validate_manifest(manifest: Manifest) -> None:
    """Cross-section consistency checks. Mirrors the Rust validator."""
    valid_dispatch = ("exec", "callback")
    if manifest.tool.dispatch not in valid_dispatch:
        raise ValueError(
            f"invalid dispatch '{manifest.tool.dispatch}', must be one of: "
            f"{', '.join(valid_dispatch)}"
        )

    if manifest.tool.mode not in _MODES:
        raise ValueError(
            f"invalid mode '{manifest.tool.mode}', must be one of: "
            f"{', '.join(_MODES)}"
        )

    is_callback = manifest.tool.dispatch == "callback"
    if not is_callback:
        cmd = manifest.command
        has_backend = bool(
            cmd.template
            or cmd.exec
            or cmd.executor
            or manifest.http
            or manifest.mcp
            or manifest.session
            or manifest.browser
        )
        if not has_backend:
            raise ValueError(
                "manifest must define at least one execution backend: "
                "[command] template/executor, [http], [mcp], [session], or [browser] "
                "(or set tool.dispatch = \"callback\" for validator-only manifests)"
            )
        if manifest.output is None:
            raise ValueError(
                "manifest is missing [output] block "
                "(or set tool.dispatch = \"callback\" for validator-only manifests)"
            )
