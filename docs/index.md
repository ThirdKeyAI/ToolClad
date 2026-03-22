# ToolClad

**Declarative tool interface contracts for agentic runtimes.**

ToolClad is the tool execution layer of the [ThirdKey](https://thirdkey.ai) trust stack: [SchemaPin](https://schemapin.org) (tool integrity) / [AgentPin](https://agentpin.org) (agent identity) / **ToolClad** (tool contracts) / [Symbiont](https://symbiont.dev) (runtime).

**Version**: 0.5.1 | **Status**: Release Candidate | **License**: MIT (spec), Apache 2.0 (Symbiont integration)

---

## What ToolClad Does

ToolClad is a manifest format (`.clad.toml`) that replaces wrapper scripts, MCP tool schemas, and execution wiring with a single declarative file. One manifest defines everything: typed parameters, command construction, output parsing, and policy metadata.

A ToolClad manifest answers four questions:

1. **What can this tool accept?** Typed parameters with validation constraints (enums, ranges, regex, scope checks, injection sanitization).
2. **How do you invoke it?** A command template, HTTP request, MCP server call, PTY session, or browser engine action. The LLM never generates raw invocation details.
3. **What does it produce?** Output format, parsing rules, and a mandatory output schema that normalizes raw output into structured JSON.
4. **What is the interaction model?** Three execution modes with five backends share a common governance layer.

## Key Features

- **14 typed validators** -- 10 core + 4 extended types with shell injection sanitization on all string-based types
- **Five execution backends** -- Shell command, HTTP API, MCP proxy, PTY session, CDP browser
- **Command templates** -- `{arg_name}` interpolation with mappings, conditionals, and defaults; no `sh -c`
- **MCP schema generation** -- Auto-generate `inputSchema` + `outputSchema` from manifest declarations
- **Evidence envelopes** -- Structured JSON with scan_id, timestamps, exit_code, output_hash (SHA-256)
- **Cedar policy integration** -- Manifests declare Cedar resource/action for policy evaluation
- **SchemaPin signing** -- `.clad.toml` files are signed directly as first-class artifacts
- **Output parsers** -- builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text, custom scripts
- **Session mode** -- Per-interaction ORGA gating on interactive CLIs (psql, msfconsole, redis-cli)
- **Browser mode** -- Governed headless or live browser sessions via CDP with URL scope enforcement

## Three Execution Modes

| Mode | Backend | Use Case |
|------|---------|----------|
| **Oneshot** | Shell (`[command]`), HTTP (`[http]`), MCP proxy (`[mcp]`) | Single command/request, get result |
| **Session** | PTY (pseudo-terminal) | Interactive CLIs: psql, msfconsole, redis-cli, gdb |
| **Browser** | CDP (Chrome DevTools Protocol) | Headless or live browser automation |

All three modes share a common governance layer: typed parameters, argument validation, Cedar policy evaluation, scope enforcement, output schema validation, evidence capture, and audit trail.

## Quick Example

```toml
# tools/whois_lookup.clad.toml
[tool]
name = "whois_lookup"
version = "1.0.0"
binary = "whois"
description = "WHOIS domain/IP registration lookup"
timeout_seconds = 30
risk_tier = "low"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[args.target]
position = 1
required = true
type = "scope_target"
description = "Domain name or IP address to query"

[command]
template = "whois {target}"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw WHOIS registration data"
```

The agent fills typed parameters. The executor validates, constructs the command, executes with timeout, and returns structured JSON. The agent never sees or generates a shell command.

## Why ToolClad?

ToolClad inverts the security model of sandbox-based approaches:

| | Sandbox (deny-list) | ToolClad (allow-list) |
|---|---|---|
| **Flow** | LLM generates command &#8594; sandbox intercepts &#8594; allow/deny | LLM fills typed parameters &#8594; executor validates &#8594; constructs command from template |
| **What the agent sees** | A shell | Typed fields with constraints |
| **Dangerous actions** | Possible but intercepted (gaps exist) | Cannot be expressed (interface does not permit it) |
| **Static analysis** | Not possible | Inspect manifest to determine all possible invocations |
| **Policy integration** | Post-hoc | Cedar policies reference manifest-declared properties |

The dangerous action cannot be expressed because the interface does not permit it.

## Reference Implementations

| Language | Directory | Package |
|----------|-----------|---------|
| Rust | `rust/` | [crates.io/crates/toolclad](https://crates.io/crates/toolclad) |
| Python | `python/` | [pypi.org/project/toolclad](https://pypi.org/project/toolclad/) |
| JavaScript | `js/` | [npmjs.com/package/toolclad](https://www.npmjs.com/package/toolclad) |
| Go | `go/` | `go install ./cmd/toolclad` |

All four implementations parse the same `.clad.toml` format, validate arguments with the same type system, and produce interoperable evidence envelopes.

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Install, create, validate, and run your first manifest |
| [Manifest Format](manifest-format.md) | Complete `.clad.toml` reference for every section |
| [Type System](type-system.md) | All 14 built-in types with validation rules and examples |
| [Command Construction](command-construction.md) | Templates, mappings, conditionals, array-based execution |
| [HTTP and MCP Backends](http-mcp-backends.md) | HTTP API tools and governed MCP proxy passthrough |
| [Session Mode](session-mode.md) | PTY sessions with per-interaction governance |

## Links

- [GitHub](https://github.com/ThirdKeyAI/ToolClad)
- [Design Specification](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md)
