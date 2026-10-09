"""ToolClad: Declarative Tool Interface Contracts for Agentic Runtimes."""

__version__ = "0.6.1"

from toolclad.manifest import (
    MANIFEST_KEYS,
    LoadOptions,
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
    find_unknown_keys,
    load_manifest,
    load_manifest_with_options,
)
from toolclad.validator import (
    ValidationError,
    validate_arg,
    validate_arg_mode,
    validate_arg_with_custom_types,
    validate_arg_with_custom_types_mode,
)
from toolclad.executor import (
    build_command,
    build_command_argv,
    compile_command,
    execute,
    inject_template_vars,
    tokenize_template,
)

__all__ = [
    "MANIFEST_KEYS",
    "LoadOptions",
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
    "find_unknown_keys",
    "load_manifest",
    "load_manifest_with_options",
    "ValidationError",
    "validate_arg",
    "validate_arg_mode",
    "validate_arg_with_custom_types",
    "validate_arg_with_custom_types_mode",
    "build_command",
    "build_command_argv",
    "compile_command",
    "execute",
    "inject_template_vars",
    "tokenize_template",
]
