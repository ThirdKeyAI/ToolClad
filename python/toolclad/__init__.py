"""ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes."""

__version__ = "0.5.0"

from toolclad.manifest import Manifest, HttpDef, McpProxyDef, load_manifest
from toolclad.validator import validate_arg
from toolclad.executor import build_command, execute, inject_template_vars

__all__ = [
    "Manifest",
    "HttpDef",
    "McpProxyDef",
    "load_manifest",
    "validate_arg",
    "build_command",
    "execute",
    "inject_template_vars",
]
