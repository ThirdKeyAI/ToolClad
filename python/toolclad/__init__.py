"""ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes."""

__version__ = "0.1.0"

from toolclad.manifest import Manifest, load_manifest
from toolclad.validator import validate_arg
from toolclad.executor import build_command, execute

__all__ = [
    "Manifest",
    "load_manifest",
    "validate_arg",
    "build_command",
    "execute",
]
