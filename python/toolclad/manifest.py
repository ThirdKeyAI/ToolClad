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
    """The [command] section: template/exec, mappings, conditionals, or executor.

    Supports two invocation forms:
    - ``exec = ["cmd", "arg1", "{placeholder}"]`` — preferred, shell-free array execution
    - ``template = "cmd arg1 {placeholder}"`` — legacy string template (split via shlex)

    When both are present, ``exec`` takes precedence.
    """

    template: str = ""
    exec: List[str] = field(default_factory=list)
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


@dataclass
class Manifest:
    """Complete parsed .clad.toml manifest."""

    tool: ToolMeta = field(default_factory=ToolMeta)
    args: Dict[str, ArgDef] = field(default_factory=dict)
    command: CommandDef = field(default_factory=CommandDef)
    output: OutputDef = field(default_factory=OutputDef)
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
        exec=data.get("exec", []),
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
    return browser


@dataclass
class CustomTypeDef:
    """Custom type definition from toolclad.toml."""

    base: str = ""
    allowed: List[str] = field(default_factory=list)
    pattern: str = ""
    min: Optional[int] = None
    max: Optional[int] = None


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
        )
    return types


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

    if "http" in data:
        manifest.http = _parse_http(data["http"])

    if "mcp" in data:
        manifest.mcp = _parse_mcp(data["mcp"])

    if "session" in data:
        manifest.session = _parse_session(data["session"])

    if "browser" in data:
        manifest.browser = _parse_browser(data["browser"])

    return manifest
