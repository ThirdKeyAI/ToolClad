"""ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes."""

__version__ = "0.6.1"

from toolclad.manifest import (
    Manifest,
    HttpDef,
    McpProxyDef,
    SessionDef,
    SessionCommandDef,
    SessionInteractionDef,
    BrowserDef,
    BrowserCommandDef,
    BrowserScopeDef,
    BrowserStateDef,
    load_manifest,
)
from toolclad.validator import validate_arg
from toolclad.executor import build_command, execute, inject_template_vars

__all__ = [
    "Manifest",
    "HttpDef",
    "McpProxyDef",
    "SessionDef",
    "SessionCommandDef",
    "SessionInteractionDef",
    "BrowserDef",
    "BrowserCommandDef",
    "BrowserScopeDef",
    "BrowserStateDef",
    "load_manifest",
    "validate_arg",
    "build_command",
    "execute",
    "inject_template_vars",
]
