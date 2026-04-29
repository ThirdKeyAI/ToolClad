# AGENTS.md

<!-- agents-md:auto-start -->
<!-- This section describes the ToolClad project for agent discovery. -->

## Project

| Field | Value |
|-------|-------|
| Name | ToolClad |
| Description | Declarative CLI tool interface contracts for agentic runtimes |
| Version | 0.6.1 |
| License | MIT (spec), Apache 2.0 (Symbiont integration) |
| Repository | https://github.com/ThirdKeyAI/ToolClad |

## Capabilities

ToolClad provides:

- **Manifest parsing** — Load and validate `.clad.toml` tool interface contracts (oneshot, session, browser modes)
- **Argument validation** — 15 built-in type validators (incl. `number` and ASCII-strict `scope_target` with IDN/punycode rejection) with shell injection sanitization, plus custom types via `toolclad.toml`
- **Dispatch modes** — `tool.dispatch = "exec"` (default) runs an execution backend; `dispatch = "callback"` is a validator-only embedding for in-process tool dispatch (no `[output]`/backend required)
- **Five execution backends** — Shell command, HTTP API, MCP proxy, PTY session, CDP/Playwright browser
- **HTTP backend** — REST/GraphQL API tools with `{_secret:name}` template variable injection
- **MCP proxy backend** — Governed passthrough to upstream MCP servers with field mapping
- **Command construction** — Template interpolation with mappings, conditionals, and defaults
- **Tool execution** — Direct argv dispatch, process group kill on timeout, SHA-256 evidence hashing
- **Output parsers** — builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text, custom scripts
- **MCP schema generation** — Auto-generate inputSchema + outputSchema for LLM tool use
- **Evidence envelopes** — Structured JSON with scan_id, timestamps, exit_code, stderr, output_hash

## Available Tools

ToolClad is a framework for defining tools, not a tool itself. It provides a CLI (`toolclad`) with these commands:

| Command | Description |
|---------|-------------|
| `toolclad validate <manifest>` | Parse and validate a `.clad.toml` manifest |
| `toolclad run <manifest> --arg k=v` | Execute a tool with validated arguments |
| `toolclad test <manifest> --arg k=v` | Dry-run: validate and show command without executing |
| `toolclad schema <manifest>` | Output MCP-compatible JSON Schema |

## Reference Implementations

| Language | Directory | Package |
|----------|-----------|---------|
| Rust | `rust/` | [crates.io/crates/toolclad](https://crates.io/crates/toolclad) |
| Python | `python/` | `pip install -e .` |
| JavaScript | `js/` | `npm install` |
| Go | `go/` | `go install ./cmd/toolclad` |

## Integration Points

- **Symbiont**: Auto-discovered from `tools/` directory, registered as MCP tools in the ORGA reasoning loop
- **Cedar**: Manifests declare `[tool.cedar]` resource/action for policy evaluation
- **SchemaPin**: Manifests can include `[tool.schemapin]` for cryptographic verification
- **MCP**: `inputSchema` and `outputSchema` auto-generated for any MCP-compatible runtime

## Security Model

ToolClad uses an **allow-list** approach: the LLM fills typed parameters constrained by the manifest. The executor validates and constructs the command. The LLM never generates or sees shell commands.

All string-based types reject shell metacharacters by default: `;|&$\`(){}[]<>!`

## Example Manifests

See `examples/` for ready-to-use manifests:
- `whois_lookup.clad.toml` — Simple text tool
- `nmap_scan.clad.toml` — Scanner with enum mappings
- `dig_lookup.clad.toml` — DNS queries
- `curl_fetch.clad.toml` — HTTP requests with scope checking

<!-- agents-md:auto-end -->
