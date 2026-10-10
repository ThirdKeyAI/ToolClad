# ToolClad

**Declarative tool interface contracts for agentic runtimes.**

ToolClad is the tool execution layer of the [ThirdKey](https://thirdkey.ai) trust stack: [SchemaPin](https://schemapin.org) (tool integrity) / [AgentPin](https://agentpin.org) (agent identity) / **ToolClad** (tool contracts) / [Symbiont](https://symbiont.dev) (runtime).

**Version**: 0.6.2 | **Status**: Release Candidate | **License**: MIT (spec), Apache 2.0 (Symbiont integration)

---

## What ToolClad Does

ToolClad is a manifest format (`.clad.toml`) that replaces wrapper scripts, MCP tool schemas, and execution wiring with a single declarative file. One manifest defines everything: typed parameters, command construction, output parsing, and policy metadata.

A ToolClad manifest answers four questions:

1. **What can this tool accept?** Typed parameters with validation constraints (enums, ranges, regex, scope checks, injection sanitization).
2. **How do you invoke it?** An `exec` argv array or an HTTP request (executed by the reference runtimes), or an MCP server call, PTY session, or browser engine action (parsed and validated here, executed by a hosting runtime). The LLM never generates raw invocation details.
3. **What does it produce?** Output format, parsing rules, and a mandatory output schema that normalizes raw output into structured JSON.
4. **What is the interaction model?** Two executing backends plus three parsed-only contracts share a common governance layer.

## Key Features

- **15 built-in type validators** -- all with shell injection sanitization, NUL/control-character/quote/whitespace/leading-dash rejection and a host/IP policy (`block_internal`), plus custom types via `toolclad.toml`
- **Two executing backends** -- Shell command (`[command]`) and HTTP API (`[http]`). MCP proxy, PTY session and CDP browser manifests are parsed and validated but are not executable by the reference runtimes
- **Command construction** -- `exec` array (canonical) with mappings, conditionals, defaults, brace escapes and `end_of_options`; the deprecated `template` string is compiled to `exec` at load; no `sh -c`
- **Strict loading** -- unknown manifest keys are refused at load
- **Policy gate** -- deny-by-default for `human_approval = true` and `risk_tier` `high`/`critical`; Cedar evaluation is external
- **MCP schema generation** -- Auto-generate `inputSchema` + `outputSchema` from manifest declarations
- **Evidence envelopes** -- Structured JSON with scan_id, timestamps, exit_code, output_hash (SHA-256)
- **Cedar policy integration** -- Manifests declare Cedar resource/action for policy evaluation
- **SchemaPin signing** -- `.clad.toml` files are signed directly as first-class artifacts
- **Output parsers** -- builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text; fail-closed schema validation; custom parser scripts are refused at load
- **Session mode** -- Per-interaction ORGA gating contract for interactive CLIs (psql, msfconsole, redis-cli); parsed and validated by the reference runtimes, executed by a hosting runtime
- **Browser mode** -- Governed headless or live browser session contract via CDP with URL scope enforcement; parsed and validated by the reference runtimes, executed by a hosting runtime

## Execution Modes

| Mode | Backend | Reference runtimes | Use Case |
|------|---------|--------------------|----------|
| **Oneshot** | Shell (`[command]`), HTTP (`[http]`) | Executed | Single command/request, get result |
| **Oneshot** | MCP proxy (`[mcp]`) | Parsed and validated; `execute` returns a `delegation_preview` envelope, no upstream call | Govern a third-party MCP tool |
| **Session** | PTY (pseudo-terminal) | Parsed and validated only; `execute` is refused | Interactive CLIs: psql, msfconsole, redis-cli, gdb |
| **Browser** | CDP (Chrome DevTools Protocol) | Parsed and validated only; `execute` is refused | Headless or live browser automation |

All modes share a common governance layer: typed parameters, argument validation, policy gating, scope enforcement, output schema validation, evidence capture, and audit trail. Session and browser execution is provided by a hosting runtime such as Symbiont, not by the reference CLIs or libraries in this repository.

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
exec = ["whois", "{target}"]

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw WHOIS registration data"
```

The agent fills typed parameters. The executor validates, constructs the argv, executes with timeout, and returns structured JSON. The agent never generates a shell command; the evidence envelope reports the declared command with placeholders intact, so executor-injected paths and expanded secrets never reach the agent (the human-facing `toolclad test` dry run shows the resolved argv).

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
| [Type System](type-system.md) | All 15 built-in types with validation rules and examples |
| [Command Construction](command-construction.md) | Templates, mappings, conditionals, array-based execution |
| [HTTP and MCP Backends](http-mcp-backends.md) | HTTP API tools and governed MCP proxy passthrough |
| [Session Mode](session-mode.md) | PTY session contract with per-interaction governance (parsed, not executed, by the reference runtimes) |
| [Browser Mode](browser-mode.md) | CDP browser session contract (parsed, not executed, by the reference runtimes) |
| [Security Model](security-model.md) | Value hygiene, spawn hardening, policy gate, scope enforcement, output caps |
| [Output & Evidence](output-evidence.md) | Parsers, fail-closed schema validation, evidence envelopes |
| [CLI Reference](cli-reference.md) | `validate`, `run`, `test`, `schema` and their flags |
| [API Reference](api-reference.md) | Library entry points in Rust, Python, JavaScript, and Go |
| [SchemaPin v1.4 Features](schemapin-v1.4-features.md) | Sign with TTL, schema-version + previous-hash lineage, and `_schemapin.{domain}` DNS TXT cross-verification |

## Links

- [GitHub](https://github.com/ThirdKeyAI/ToolClad)
- [Design Specification](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md)
