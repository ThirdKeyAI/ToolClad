# ToolClad

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19957595.svg)](https://doi.org/10.5281/zenodo.19957595)

Declarative tool interface contracts for agentic runtimes.

ToolClad is a manifest format (`.clad.toml`) that defines the complete behavioral contract for a tool: typed parameters, validation rules, invocation mechanism, output parsing, and policy metadata. Two executing backends share a common governance layer:

- **Shell command** (`[command]`, default): a single CLI invocation dispatched via `execve`
- **HTTP API** (`[http]`): a single HTTP request constructed from the manifest

Three further manifest kinds are **parsed and validated but not executable by the reference runtimes** in this repository:

- **MCP proxy** (`[mcp]`): arguments are validated and field-mapped, and `execute` returns a `delegation_preview` envelope; no upstream MCP call is made
- **PTY session** (`[session]`) and **CDP browser** (`[browser]`): `validate` and `schema` work, but `execute` is refused with `session mode is parsed but not yet executable in the reference implementation` (and the equivalent message for browser mode). Executing these contracts is the job of a hosting runtime such as Symbiont.

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
exec = ["whois", "{target}"]

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
```

The agent fills typed parameters. The executor validates, constructs the argv, executes with timeout, and returns structured JSON. The agent never generates a shell command; the evidence envelope reports the argv that was run (for HTTP tools, the unexpanded URL template, so secrets never reach the agent). The `[command]` section is optional for HTTP-only or MCP-only manifests.

### Array-Based Command Construction

`exec` is the canonical invocation form. Each element is exactly one argv entry, dispatched straight to `execve`; substituted values are never re-split and there is no shell:

```toml
[command]
exec = ["curl", "-s", "-S", "-X", "{method}", "{_header_flags}", "{url}"]
```

A placeholder must be a whole, unquoted token. `{{` and `}}` are escapes for literal braces (so `"\\n%{{http_code}}"` reaches curl as `\n%{http_code}`). The legacy `template` string form is **deprecated**: it is still accepted, but it is tokenized into the same `exec` array at load time, prints a deprecation warning, and will be removed in the next minor release. Argument values may contain whitespace only when the argument sets `allow_whitespace = true`, and that opt-in is honored only for manifests that declare `exec` directly. See [Command Construction](https://docs.toolclad.org/command-construction/) for details.

## Security Model

ToolClad inverts the sandbox approach:

- **Sandbox**: LLM generates command -> sandbox intercepts -> allow/deny (deny-list)
- **ToolClad**: LLM fills typed parameters -> policy gate -> executor validates -> constructs command from template (allow-list)

The dangerous action cannot be expressed because the interface doesn't permit it.

### Security Features

- **Shell injection prevention**: All string-derived types reject shell metacharacters (`;|&$\`(){}[]<>!`), NUL, control characters, quotes and backslashes, whitespace (unless `allow_whitespace = true` in `exec` mode) and a leading `-`/`+` (unless `allow_leading_dash = true`). NUL is rejected for every type, `enum` included.
- **Array-based execution**: Commands dispatched via direct `execve` (no `sh -c` shell interpretation); substituted values are never re-split
- **Process group isolation**: Tools spawned in a new PGID; on timeout the executor sends `SIGTERM` to the group, waits `TOOLCLAD_KILL_GRACE_MS` (default 2000 ms), then sends `SIGKILL` to the group. `timeout_seconds = 0` is refused at load.
- **Hardened spawn path**: child environment rebuilt from a fixed allowlist (secrets are never passed), `argv[0]` resolved against a fixed `PATH`, shell and script interpreters refused unless `allow_interpreter = true`, stdin from `/dev/null`, a 0700 per-invocation scratch directory as cwd
- **Policy gate**: `human_approval = true` and `risk_tier` `high`/`critical` are denied by default; `--approve` (or an explicit gate in library use) is required to run them. Cedar evaluation stays external.
- **Absolute path blocking**: `path` type rejects `/etc/shadow`, `C:\...` style paths and any `..` path component
- **Host and IP policy**: link-local and cloud-metadata ranges are always blocked; `block_internal = true` additionally blocks loopback, private, CGNAT, documentation and reserved ranges, internal name suffixes, embedded-IP hostnames, and resolves hostnames (fail-closed). Manifests that dispatch a known egress binary, set `network_egress = true`, or use `[http]`/`[browser]` must set `block_internal = true` on every network-target argument.
- **Fail-closed scope enforcement**: `scope_check = true` with no reachable `scope/scope.toml` is a refusal, not a pass
- **Unknown manifest keys refused at load**: every section is checked against a fixed key allowlist (`validate --allow-unknown-keys` is the only escape hatch)
- **HTTP hardening**: secrets are expanded before argument interpolation, URL values are percent-encoded, body values are JSON-escaped, redirects are not followed (`redirect_blocked`), and the envelope's `command` holds the unexpanded template
- **Platform-aware evidence directories**: evidence root at `TOOLCLAD_EVIDENCE_DIR` or `<tmpdir>/toolclad-evidence`, created mode 0700; output files opened `O_NOFOLLOW | O_EXCL | O_CREAT` mode 0600
- **Fail-closed output**: stdout and stderr capped by `[output] max_bytes` (default 8 MiB, sets `output_truncated`), XML containing `<!DOCTYPE`/`<!ENTITY` refused, schema violations yield status `schema_error`, custom parser scripts refused at load
- **HTTP error semantics**: 4xx responses map to `client_error`, 5xx to `server_error`, 3xx to `redirect_blocked` in evidence envelopes
- **No eval**: Conditional evaluators use closed-vocabulary parsers, never dynamic code execution

### Scope Enforcement

Any argument of type `scope_target`, `url`, `ip_address`, or `cidr` that sets `scope_check = true` is checked against the project scope file before the command is built. `scope_target` alone is only a shape check; allowlisting requires `scope_check = true`.

```toml
# scope/scope.toml
[scope]
allowed_domains = ["example.com", "*.example.com"]
allowed_cidrs   = ["10.0.1.0/24"]
blocked_domains = []
blocked_cidrs   = []
```

- **Discovery**: `TOOLCLAD_SCOPE_FILE` if set, otherwise `scope/scope.toml` searched upward from the manifest's directory (or the cwd when loading from a string). Unknown keys in the scope file are refused.
- **Fail-closed**: `scope_check = true` with no scope file reachable is refused (`scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)`).
- **Blocked before allowed**: blocked rules are evaluated first and always win.
- **Domain rules**: an exact rule matches the host case-insensitively; `*.example.com` matches strict subdomains at any depth (`app.example.com`, `deep.sub.example.com`) but not the apex `example.com` and not `evil-example.com`. For `url` arguments the host is extracted first.
- **CIDR rules**: an IP matches when it is contained in an allowed range; a CIDR argument matches only when it is **fully contained** in an allowed range.
- No match: `target '<value>' is not in scope`.

## Packages

Install from your language's package registry:

```bash
cargo install toolclad        # Rust / crates.io
pip install toolclad           # Python / PyPI
npm install toolclad           # JavaScript / npm
```

| Language | Registry | Package |
|----------|----------|---------|
| **Rust** | [crates.io](https://crates.io/crates/toolclad) | `cargo install toolclad` |
| **Python** | [PyPI](https://pypi.org/project/toolclad/) | `pip install toolclad` |
| **JavaScript** | [npm](https://www.npmjs.com/package/toolclad) | `npm install toolclad` |
| **Go** | Source | `go install ./go/cmd/toolclad` |

## Reference Implementations

Each implementation provides:

- **Manifest parsing** -- load and validate `.clad.toml` files; unknown keys are refused at load. Session and browser manifests parse and validate but are not executable.
- **15 built-in type validators** -- all with injection sanitization, plus custom types via `toolclad.toml` (discovered by walking up from the manifest's directory)
- **Command construction** -- `exec` argv arrays with mappings, conditionals, defaults; deprecated `template` strings are compiled to `exec` at load
- **Execution** -- shell and HTTP backends: direct argv dispatch, hardened child environment, SIGTERM-then-SIGKILL process group kill on timeout, policy gate, SHA-256 evidence hashing
- **Output parsers** -- builtin:json, builtin:xml, builtin:csv, builtin:jsonl, builtin:text (custom parser scripts are refused at load)
- **Output schema validation** -- fail-closed validation of parsed results against `[output.schema]` (status `schema_error` on violation)
- **MCP schema generation** -- rich inputSchema + outputSchema with format/pattern constraints for LLM tool use
- **Evidence envelopes** -- structured JSON with scan_id, timestamps, exit_code, stderr, output_hash
- **CLI** -- `validate` (`--allow-unknown-keys`), `run` (`--approve`), `schema`, `test` (dry run) subcommands

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

### Core Types

| Type | Validates | Examples |
|------|-----------|---------|
| `string` | Injection-safe, optional anchored regex `pattern` | General text |
| `integer` | `^[+-]?\d+$`, optional `min`/`max` with `clamp` | Thread counts |
| `number` | Float, optional `min_float`/`max_float` with `clamp`; rejects NaN/inf | Confidence scores, ratios |
| `port` | `^\d+$` in 1-65535 | Network ports |
| `boolean` | `true` or `false` (case-insensitive, normalized to lowercase) | Feature flags |
| `enum` | Value in declared `allowed` list | Scan types |
| `scope_target` | Injection-safe, ASCII-only, IDN/punycode rejected, no wildcards/traversal, canonical IP/CIDR (IPv4 + IPv6)/hostname; `block_internal`, `scope_check` | Targets |
| `url` | `scheme://host[:port]/...` with `http`/`https` by default (`schemes` to override; dangerous schemes always refused), no userinfo, host/IP policy; `block_internal`, `scope_check` | Web targets |
| `path` | No `..` component, no absolute paths | File paths |
| `ip_address` | Canonical IPv4 or IPv6 literal; `block_internal`, `scope_check` | Addresses |
| `cidr` | Valid CIDR notation (IPv4 + IPv6); `block_internal` (overlap check), `scope_check` | Network ranges |

### Extended Types

| Type | Validates | Use Case |
|------|-----------|----------|
| `msf_options` | Semicolon-delimited `set KEY VALUE` pairs (whitespace allowed as the separator) | Metasploit options |
| `credential_file` | Relative path + must exist | Username/password lists |
| `duration` | `^\d+$` or `h`/`m`/`s`/`ms` components (`30`, `5m`, `2h`, `1h30m`) | Timeout overrides |
| `regex_match` | Matches declared anchored `pattern` (required) | Module paths |

### Value Hygiene

Every string-derived type (`string`, `path`, `credential_file`, `regex_match`, `url`, `scope_target`, `duration`, `msf_options`) is checked, in order, before any type-specific parsing:

1. NUL bytes are rejected (for every type, including `enum`)
2. Control characters (U+0000-U+001F, U+007F) are rejected
3. `'`, `"` and `\` are rejected
4. Any Unicode whitespace is rejected unless the argument sets `allow_whitespace = true` **and** the manifest declares `command.exec` directly (`msf_options` is exempt because the space is its `KEY VALUE` separator)
5. A leading `-` or `+` is rejected unless the argument sets `allow_leading_dash = true`

Numeric types apply the leading-dash rule to the output value after clamping, so `-5` with `clamp = true` and `min = 1` yields `1`, while `-1` with no bounds is rejected unless `allow_leading_dash = true`. Every `pattern` is anchored (`^(?:pat)$`) so it must match the whole value.

### Custom Types

Define reusable types in `toolclad.toml` at the project root:

```toml
[types.service_protocol]
base = "enum"
allowed = ["ssh", "ftp", "http", "https", "smb", "rdp"]

[types.severity_level]
base = "enum"
allowed = ["info", "low", "medium", "high", "critical"]
```

Reference in manifests: `type = "service_protocol"`

The CLIs discover `toolclad.toml` by walking up from the manifest's directory and pass the custom types into validation and load-time type checking. Custom types cannot carry `block_internal` or `scope_check`, so an argument that names a network target must use the built-in `scope_target`, `url`, `ip_address`, or `cidr` type; a custom type whose base is one of those still counts as a network target for the egress lint.

### Dispatch Modes

`tool.dispatch` selects the execution model:

- `"exec"` (default) — manifest must declare a backend (`[command]`, `[http]`,
  `[mcp]`, `[session]`, or `[browser]`) and an `[output]` block. The reference
  runtimes execute `[command]` and `[http]`; `[mcp]` yields a
  `delegation_preview` envelope and `[session]`/`[browser]` are refused at
  execution (see above).
- `"callback"` — validator-only embedding. Backend and `[output]` are
  optional; in-process code dispatches the validated arguments however it
  likes. Useful when ToolClad is just the typed-argument fence and execution
  happens elsewhere (e.g. a runtime that maps tool calls to native functions).

```toml
[tool]
name = "store_knowledge"
dispatch = "callback"

[args.confidence]
type = "number"
min_float = 0.0
max_float = 1.0
required = true
```

### Tool-Level Hardening Keys

| Key | Default | Effect |
|-----|---------|--------|
| `[tool] network_egress` | `false` | Declares that the tool reaches the network. When `true` (or when the binary is a known egress tool such as `curl`, `nmap`, `ssh`, or the manifest uses `[http]`/`[browser]`), every `scope_target`/`url`/`ip_address`/`cidr` argument must set `block_internal = true` or the manifest is refused at load. |
| `[tool] allow_interpreter` | `false` | Permits `argv[0]` to be a shell or script interpreter (`sh`, `bash`, `python3`, `node`, `perl`, `env`, `xargs`, ...). Refused at load otherwise. |
| `[tool] mode` | derived | `oneshot`, `session`, or `browser`. Advisory only; derived from the backend section when absent. |
| `[tool] human_approval` | `false` | The default policy gate denies execution; requires `--approve` or an approving gate. |
| `[tool.limits]` | unset | `nproc`, `nofile`, `fsize_bytes`, `address_space_bytes`, `cpu_seconds`. Applied as child rlimits by the Rust and Python runtimes; Go and JS cannot set child rlimits portably and skip them. |
| `[command] end_of_options` | unset | Only `"--"` is accepted; inserts a literal `--` before the first user-argument token. |
| `[output] max_bytes` | `8388608` | Cap on captured stdout and stderr; overflow sets `output_truncated`. |

## Output Handling

### Built-in Parsers

| Parser | Use Case |
|--------|----------|
| `builtin:json` | Tools with native JSON output |
| `builtin:xml` | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Spreadsheet exports, log files |
| `builtin:jsonl` | Nuclei, streaming tools |
| `builtin:text` | Simple unstructured output (default) |

### Custom Parsers (Not Supported)

The reference runtimes accept only the `builtin:*` parser names above. A `parser` value naming a script (for example `parser = "scripts/parse.py"`) is refused at load with `custom output parsers are not supported by the reference runtimes`.

### Output Limits and Schema Validation

- `[output] max_bytes` (default `8388608`, 8 MiB) caps stdout and stderr separately; on overflow capture stops and the envelope gets `"output_truncated": true` without changing the status.
- XML input containing `<!DOCTYPE` or `<!ENTITY` (case-insensitive) is refused before parsing.
- Parsed output is validated against `[output.schema]` with a bundled JSON-Schema subset validator. Validation is fail-closed: a violation sets `status` to `schema_error`, replaces `results` with `{"schema_error": "<path>: <message>"}`, and preserves the raw output under `results.raw_output`.

### Evidence Envelope

Every execution returns a structured envelope:

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "nmap_scan",
  "command": "nmap -sT -sV --max-rate 1000 10.0.1.0/24",
  "duration_ms": 4523,
  "timestamp": "2026-03-20T12:00:00Z",
  "exit_code": 0,
  "stderr": "",
  "output_hash": "sha256:a1b2c3...",
  "results": { "hosts": [...] }
}
```

On error, `exit_code` and `stderr` are included so LLM agents can self-correct. Possible `status` values are `success`, `error`, `timeout` (partial output preserved), `schema_error`, `client_error`, `server_error`, `redirect_blocked` (HTTP), and `delegation_preview` (MCP proxy). For HTTP tools `command` holds `"<METHOD> <url as written in the manifest>"`, never the expanded URL.

## Symbiont Integration

ToolClad is the `tools/` directory convention for [Symbiont](https://symbiont.dev):

- Runtime auto-discovers `.clad.toml` files at startup
- Registers each tool as an MCP tool in the ORGA reasoning loop
- Cedar policy evaluation using manifest-declared `[tool.cedar]` resource/action
- Scope enforcement against `scope/scope.toml` (the same fail-closed rules described under [Scope Enforcement](#scope-enforcement))
- Cedar policy auto-generation from manifest `risk_tier`
- Hot-reload in development mode
- `symbi tools list/validate/test/schema/init` CLI

```bash
symbi tools list                    # show discovered tools
symbi tools test nmap_scan --arg target=10.0.1.0/24 --arg scan_type=service
symbi tools schema nmap_scan        # output MCP JSON Schema
symbi tools init my_scanner         # scaffold new manifest
```

## SchemaPin Integration

SchemaPin signs `.clad.toml` files directly as first-class artifacts:

```bash
schemapin-sign tools/nmap_scan.clad.toml
```

The signature covers the entire behavioral contract. If anyone tampers with a command template, validation rule, scope constraint, or output schema, the hash changes and verification fails.

For production manifests, opt into the SchemaPin v1.4-alpha hardening — TTL-bounded signatures, lineage chains tied to `[tool] version`, and DNS TXT cross-verification at `_schemapin.{vendor-domain}`:

```bash
TOOL_VERSION=$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' tools/nmap_scan.clad.toml)
schemapin-sign tools/nmap_scan.clad.toml \
    --expires-in 6mo \
    --schema-version "$TOOL_VERSION" \
    --previous-hash "$(jq -r '.skill_hash' tools/nmap_scan.clad.toml.sig.prior 2>/dev/null || true)"
```

All three flags are additive optional — v1.3 verifiers ignore them; v1.4 verifiers gain a degraded-not-failed expiration signal, opt-in chain enforcement against rug-pull substitutions, and a second-channel trust anchor independent of HTTPS hosting. See [SchemaPin v1.4 Features in ToolClad](https://github.com/ThirdKeyAI/ToolClad/blob/main/docs/schemapin-v1.4-features.md) for the full operational guide.

See [TOOLCLAD_DESIGN_SPEC.md](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md) for the full specification.

## License

- Protocol specification (manifest format, type system, evidence envelope): **MIT**
- Symbiont integration (Cedar gating, ORGA enforcement, scope enforcement): **Apache 2.0**
