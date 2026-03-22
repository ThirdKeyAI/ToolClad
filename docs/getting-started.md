# Getting Started

Create, validate, and run your first ToolClad manifest in under 5 minutes.

## Install

=== "Rust"

    ```bash
    cargo install toolclad
    ```

=== "Python"

    ```bash
    pip install toolclad
    ```

=== "JavaScript"

    ```bash
    npm install -g toolclad
    ```

=== "Go"

    ```bash
    go install github.com/ThirdKeyAI/ToolClad/go/cmd/toolclad@latest
    ```

## Create Your First Manifest

Create a `tools/` directory and write `tools/whois_lookup.clad.toml`:

```toml
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

What this manifest declares:

- **`[tool]`**: Name, binary, timeout, risk tier. Identifies the tool for MCP registration and policy evaluation.
- **`[tool.cedar]`**: Cedar resource and action for authorization.
- **`[args.target]`**: Required `scope_target` -- validates the value is a valid IP, CIDR, or hostname and blocks shell injection characters.
- **`[command]`**: Template string. The executor interpolates validated args and dispatches via `execve` -- no shell interpretation.
- **`[output]`**: Text format, wrapped in a structured evidence envelope with SHA-256 hash.

## Validate

Check that the manifest is well-formed:

```bash
toolclad validate tools/whois_lookup.clad.toml
```

Output:

```
tools/whois_lookup.clad.toml is valid
  Tool: whois_lookup v1.0.0
  Args: target (scope_target, required)
  Command: whois {target}
```

Validation checks required fields, type definitions, template references, and output schema structure.

## Dry Run

Test command construction without executing:

```bash
toolclad test tools/whois_lookup.clad.toml \
  --arg target=example.com
```

Output:

```
--- Dry Run ---
Tool:    whois_lookup
Command: whois example.com
Args:
  target = "example.com"  (scope_target: OK)
Cedar:   PenTest::ScanTarget / execute_tool
Timeout: 30s

[dry run -- command not executed]
```

The `test` subcommand validates arguments, resolves mappings and conditionals, and prints the constructed command. Nothing is executed.

## Execute

Run the tool for real:

```bash
toolclad run tools/whois_lookup.clad.toml \
  --arg target=example.com
```

Output (evidence envelope):

```json
{
  "status": "success",
  "scan_id": "1711929600-12345",
  "tool": "whois_lookup",
  "command": "whois example.com",
  "duration_ms": 892,
  "timestamp": "2026-03-22T12:00:00Z",
  "exit_code": 0,
  "stderr": "",
  "output_hash": "sha256:a1b2c3...",
  "results": {
    "raw_output": "Domain Name: EXAMPLE.COM\nRegistrar: RESERVED-Internet Assigned Numbers Authority\n..."
  }
}
```

Every execution returns a structured JSON envelope with timing, exit code, output hash, and parsed results.

## Generate MCP Schema

Export the manifest as an MCP tool definition for LLM consumption:

```bash
toolclad schema tools/whois_lookup.clad.toml
```

Output:

```json
{
  "name": "whois_lookup",
  "description": "WHOIS domain/IP registration lookup",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Domain name or IP address to query"
      }
    },
    "required": ["target"]
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "raw_output": {
        "type": "string",
        "description": "Raw WHOIS registration data"
      }
    }
  }
}
```

The LLM sees `inputSchema` to know what parameters to provide and `outputSchema` to know what data it will receive -- it never sees or constructs the actual `whois` command.

## What Happens on Invalid Input

```bash
toolclad run tools/whois_lookup.clad.toml --arg target="example.com; rm -rf /"
```

```
Error: Argument validation failed
  target: injection characters detected (;) in scope_target value
```

Shell metacharacters (`` ; | & $ ` ( ) { } [ ] < > ! \n \r ``) are rejected by default on all string-based types. The command is never constructed, let alone executed.

## A More Complex Example

Create `tools/dig_lookup.clad.toml` with an enum argument and default value:

```toml
[tool]
name = "dig_lookup"
version = "1.0.0"
binary = "dig"
description = "DNS record lookup"
timeout_seconds = 15
risk_tier = "low"

[tool.cedar]
resource = "Tool::DnsLookup"
action = "execute_tool"

[args.target]
position = 1
required = true
type = "scope_target"
description = "Domain name to query"

[args.record_type]
position = 2
required = false
type = "enum"
allowed = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "ANY"]
default = "A"
description = "DNS record type"

[command]
template = "dig +short {target} {record_type}"

[output]
format = "text"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "DNS query results"
```

Test it:

```bash
toolclad test tools/dig_lookup.clad.toml \
  --arg target=example.com \
  --arg record_type=MX
```

```
--- Dry Run ---
Tool:    dig_lookup
Command: dig +short example.com MX
Args:
  target      = "example.com"  (scope_target: OK)
  record_type = "MX"           (enum: OK, in allowed list)
```

The `record_type` enum constrains the agent to only the 10 declared values. Providing an unlisted value like `"AXFR"` is rejected at validation time.

## CLI Commands Summary

| Command | Description |
|---------|-------------|
| `toolclad validate <manifest>` | Parse and validate a `.clad.toml` manifest |
| `toolclad run <manifest> --arg k=v` | Execute a tool with validated arguments |
| `toolclad test <manifest> --arg k=v` | Dry-run: validate and show command without executing |
| `toolclad schema <manifest>` | Output MCP-compatible JSON Schema |

## Next Steps

- [Manifest Format](manifest-format.md) -- full reference for every section
- [Type System](type-system.md) -- all 14 types with validation rules
- [Command Construction](command-construction.md) -- templates, mappings, conditionals
- [HTTP and MCP Backends](http-mcp-backends.md) -- wrap HTTP APIs and MCP server tools
- [Session Mode](session-mode.md) -- govern interactive CLI tools
