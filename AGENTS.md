# AGENTS.md

<!-- agents-md:auto-start -->
<!-- This section describes the ToolClad project for agent discovery. -->

## Project

| Field | Value |
|-------|-------|
| Name | ToolClad |
| Description | Declarative CLI tool interface contracts for agentic runtimes |
| Version | 0.6.2 |
| License | MIT (spec), Apache 2.0 (Symbiont integration) |
| Repository | https://github.com/ThirdKeyAI/ToolClad |

## Capabilities

ToolClad provides:

- **Manifest parsing** — Load and validate `.clad.toml` tool interface contracts. Unknown keys are refused at load (`validate --allow-unknown-keys` downgrades them to warnings). Session and browser manifests parse and validate but are not executable by the reference runtimes.
- **Argument validation** — 15 built-in type validators (incl. `number` and ASCII-strict `scope_target` with IDN/punycode rejection) with shell injection sanitization, NUL/control-character/quote/whitespace/leading-dash rejection, anchored `pattern`s, and `block_internal` host/IP policy; plus custom types via `toolclad.toml` (discovered by walking up from the manifest's directory)
- **Dispatch modes** — `tool.dispatch = "exec"` (default) runs an execution backend; `dispatch = "callback"` is a validator-only embedding for in-process tool dispatch (no `[output]`/backend required)
- **Two executing backends** — Shell command (`[command]`) and HTTP API (`[http]`). MCP proxy (`[mcp]`), PTY session (`[session]`) and CDP/Playwright browser (`[browser]`) manifests are **parsed and validated but not executable** by the reference runtimes: `[mcp]` returns a `delegation_preview` envelope (field-mapped arguments, no upstream call) and `[session]`/`[browser]` are refused at execution with a "parsed but not yet executable" error.
- **HTTP backend** — REST/GraphQL API tools with `{_secret:name}` template variable injection (expanded before argument interpolation), percent-encoded URL values, JSON-escaped body values, redirects not followed, unexpanded template in the envelope's `command`
- **MCP proxy manifests** — Field mapping to upstream parameter names and a `delegation_preview` envelope; the upstream MCP call is left to a hosting runtime
- **Command construction** — `exec` argv arrays (canonical) with mappings (`_<arg>_flags`), conditionals (`_<cond>`), defaults, `{{`/`}}` brace escapes and `end_of_options = "--"`; the deprecated `template` string is tokenized into `exec` at load with a warning
- **Tool execution** — Direct argv dispatch, cleared child environment (secrets never passed), interpreter denylist, `SIGTERM` to the process group then `SIGKILL` after `TOOLCLAD_KILL_GRACE_MS` (default 2000 ms), SHA-256 evidence hashing
- **Policy gate** — `human_approval = true` and `risk_tier` `high`/`critical` are denied by default; `run --approve` or an explicit gate is required. Cedar evaluation is external.
- **Scope enforcement** — `scope_check = true` arguments checked against `scope/scope.toml` (`TOOLCLAD_SCOPE_FILE` or found by walking up from the manifest); fail-closed when no scope file is reachable
- **Output parsers** — builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text; custom parser scripts are refused at load
- **Output validation** — `[output] max_bytes` cap (default 8 MiB, sets `output_truncated`), XML `<!DOCTYPE`/`<!ENTITY` refused, fail-closed `[output.schema]` validation (status `schema_error`, raw output preserved)
- **MCP schema generation** — Auto-generate inputSchema + outputSchema for LLM tool use
- **Evidence envelopes** — Structured JSON with scan_id, timestamps, exit_code, stderr, output_hash

## Available Tools

ToolClad is a framework for defining tools, not a tool itself. It provides a CLI (`toolclad`) with these commands:

| Command | Description |
|---------|-------------|
| `toolclad validate <manifest>` | Parse and validate a `.clad.toml` manifest (`--allow-unknown-keys` downgrades unknown keys to warnings) |
| `toolclad run <manifest> --arg k=v` | Execute a tool with validated arguments (`--approve` switches the policy gate to allow-all) |
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
- **SchemaPin**: `.clad.toml` files are signed directly with `schemapin-sign` (no `[tool.schemapin]` section needed). v1.4-alpha additive options recommended for production: `--expires-in` (TTL), `--schema-version "$TOOL_VERSION"` (semver tag), `--previous-hash $PREV` (lineage chain), and a `_schemapin.{vendor-domain}` TXT record for second-channel cross-verification.
- **MCP**: `inputSchema` and `outputSchema` auto-generated for any MCP-compatible runtime

## Security Model

ToolClad uses an **allow-list** approach: the LLM fills typed parameters constrained by the manifest. The executor validates and constructs the argv. The LLM never generates shell commands; the evidence envelope reports the declared command with placeholders intact on every backend, so executor-injected paths and expanded secrets never reach the agent (the `toolclad test` dry run shows the resolved argv for the operator).

All string-derived types reject shell metacharacters by default (`;|&$\`(){}[]<>!`), plus NUL (every type, `enum` included), control characters, quotes and backslashes, whitespace (unless `allow_whitespace = true` in `exec` mode) and a leading `-`/`+` (unless `allow_leading_dash = true`). Every `pattern` is anchored to the whole value.

Network-target arguments (`scope_target`, `url`, `ip_address`, `cidr`) always refuse link-local and cloud-metadata ranges and internal name suffixes; `block_internal = true` extends that to loopback, private, CGNAT, documentation and reserved ranges and resolves hostnames fail-closed. Manifests that set `network_egress = true`, dispatch a known egress binary, or use `[http]`/`[browser]` must set `block_internal = true` on every such argument.

## Example Manifests

See `examples/` for ready-to-use manifests:
- `whois_lookup.clad.toml` — Simple text tool
- `nmap_scan.clad.toml` — Scanner with enum mappings and `block_internal`
- `dig_lookup.clad.toml` — DNS queries
- `curl_fetch.clad.toml` — HTTP requests with scope checking, `allow_whitespace`, and brace escapes
- `nikto_scan.clad.toml` — Custom types from `toolclad.toml` and `human_approval` gating

<!-- agents-md:auto-end -->
