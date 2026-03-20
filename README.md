# ToolClad

Declarative tool interface contracts for agentic runtimes.

ToolClad is a manifest format (`.clad.toml`) that defines the complete behavioral contract for a CLI tool: typed parameters, validation rules, command construction, output parsing, and policy metadata. A single manifest replaces wrapper scripts, MCP tool schemas, and execution wiring.

## The Problem

Every team building agentic systems writes custom glue code per tool: argument sanitization, timeout enforcement, output parsing, evidence capture, Cedar mappings, DSL capabilities, and policies. That's 7 steps per tool. It doesn't scale.

## The Solution

```toml
# tools/whois_lookup.clad.toml
[tool]
name = "whois_lookup"
version = "1.0.0"
binary = "whois"
description = "WHOIS domain/IP registration lookup"
timeout_seconds = 30
risk_tier = "low"

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
```

The agent fills typed parameters. The executor validates, constructs the command from the template, executes with timeout, and returns structured JSON. The agent never sees or generates a shell command.

## Security Model

ToolClad inverts the sandbox approach:

- **Sandbox**: LLM generates command -> sandbox intercepts -> allow/deny (deny-list)
- **ToolClad**: LLM fills typed parameters -> policy gate -> executor validates -> constructs command from template (allow-list)

The dangerous action cannot be expressed because the interface doesn't permit it.

## Reference Implementations

| Language | Directory | CLI | Status |
|----------|-----------|-----|--------|
| **Rust** | `rust/` | `cargo run -- validate manifest.clad.toml` | Complete |
| **Python** | `python/` | `toolclad validate manifest.clad.toml` | Complete |
| **JavaScript** | `js/` | `npx toolclad validate manifest.clad.toml` | Complete |
| **Go** | `go/` | `go run ./cmd/toolclad validate manifest.clad.toml` | Complete |

Each implementation provides:

- **Manifest parsing** -- load and validate `.clad.toml` files
- **Argument validation** -- 10 core types with injection sanitization
- **Command construction** -- template interpolation with mappings and conditionals
- **Execution** -- run with timeout, capture output, SHA-256 evidence hashing
- **MCP schema generation** -- auto-generate JSON Schema for LLM tool use
- **CLI** -- `validate`, `run`, `schema`, `test` (dry run) subcommands

## Quick Start

```bash
# Rust
cd rust && cargo run -- test ../examples/whois_lookup.clad.toml --arg target=example.com

# Python
cd python && pip install -e . && toolclad test ../examples/whois_lookup.clad.toml --arg target=example.com

# JavaScript
cd js && npm install && node src/cli.js test ../examples/whois_lookup.clad.toml --arg target=example.com

# Go
cd go && go run ./cmd/toolclad test ../examples/whois_lookup.clad.toml --arg target=example.com
```

## Type System

| Type | Validates | Examples |
|------|-----------|---------|
| `string` | Non-empty, injection-safe | General text |
| `integer` | Numeric, optional min/max with clamping | Thread counts |
| `port` | 1-65535 | Network ports |
| `boolean` | Exactly "true" or "false" | Feature flags |
| `enum` | Value in declared `allowed` list | Scan types |
| `scope_target` | Injection-safe + no wildcards | IPs, CIDRs, hostnames |
| `url` | Valid URL, optional scheme restriction | Web targets |
| `path` | No traversal (`../`) | File paths |
| `ip_address` | Valid IPv4 or IPv6 | Addresses |
| `cidr` | Valid CIDR notation | Network ranges |

All types reject shell metacharacters by default.

## Symbiont Integration

ToolClad is the `tools/` directory convention for [Symbiont](https://symbiont.dev). The runtime auto-discovers `.clad.toml` files, registers them as MCP tools, and wires them into the ORGA reasoning loop with Cedar policy evaluation.

See [TOOLCLAD_DESIGN_SPEC.md](TOOLCLAD_DESIGN_SPEC.md) for the full specification.

## License

- Protocol specification (manifest format, type system, evidence envelope): **MIT**
- Symbiont integration (Cedar gating, ORGA enforcement, scope enforcement): **Apache 2.0**
