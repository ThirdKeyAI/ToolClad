---
title: API Reference
description: Library API reference for Rust, Python, JavaScript, and Go
---

# API Reference

ToolClad provides library APIs in four languages. Each implementation supports manifest parsing, argument validation, command construction, execution, and MCP schema generation.

## Rust

**Crate**: [`toolclad`](https://crates.io/crates/toolclad)

### Functions

#### `load_manifest(path) -> Result<Manifest>`

Load and parse a `.clad.toml` manifest from a file path.

```rust
let manifest = toolclad::load_manifest("tools/nmap_scan.clad.toml")?;
println!("Tool: {} v{}", manifest.tool.name, manifest.tool.version);
```

#### `parse_manifest(toml_str) -> Result<Manifest>`

Parse a manifest from a TOML string (useful for testing or embedded manifests).

```rust
let toml = std::fs::read_to_string("tools/whois_lookup.clad.toml")?;
let manifest = toolclad::parse_manifest(&toml)?;
```

#### `generate_mcp_schema(manifest) -> Value`

Generate an MCP-compatible JSON Schema from a manifest, including both `inputSchema` (from `[args]`) and `outputSchema` (from `[output.schema]`).

```rust
let manifest = toolclad::load_manifest("tools/nmap_scan.clad.toml")?;
let schema = toolclad::generate_mcp_schema(&manifest);
println!("{}", serde_json::to_string_pretty(&schema)?);
```

#### `validator::validate_arg(name, def, value) -> Result<()>`

Validate a single argument value against its type definition. Returns `Ok(())` if valid, or an error describing the validation failure.

```rust
use toolclad::types::ArgDef;

let def = ArgDef {
    type_name: "enum".to_string(),
    allowed: Some(vec!["ping".into(), "service".into()]),
    required: true,
    position: 1,
    ..Default::default()
};

assert!(toolclad::validator::validate_arg("scan_type", &def, "ping").is_ok());
assert!(toolclad::validator::validate_arg("scan_type", &def, "exploit").is_err());
```

#### `executor::build_command(manifest, args) -> Result<Vec<String>>`

Construct the command argument array from a manifest and validated arguments. Does not execute. Returns the argv array that would be passed to `execve`.

```rust
use std::collections::HashMap;

let manifest = toolclad::load_manifest("tools/nmap_scan.clad.toml")?;
let mut args = HashMap::new();
args.insert("target".into(), "10.0.1.0/24".into());
args.insert("scan_type".into(), "service".into());

let cmd = toolclad::executor::build_command(&manifest, &args)?;
// ["nmap", "-sT", "-sV", "--version-intensity", "5", "--max-rate", "1000", ...]
```

#### `executor::execute(manifest, args) -> Result<EvidenceEnvelope>`

Validate arguments, construct the command, execute with timeout, parse output, and return the evidence envelope.

```rust
use std::collections::HashMap;

let manifest = toolclad::load_manifest("tools/whois_lookup.clad.toml")?;
let mut args = HashMap::new();
args.insert("target".into(), "example.com".into());

let result = toolclad::executor::execute(&manifest, &args)?;
println!("Status: {}, Duration: {}ms", result.status, result.duration_ms);
```

#### `executor::dry_run(manifest, args) -> Result<DryRunResult>`

Validate arguments and construct the command without executing. Returns the command that would be run plus validation details.

```rust
let manifest = toolclad::load_manifest("tools/nmap_scan.clad.toml")?;
let mut args = HashMap::new();
args.insert("target".into(), "10.0.1.0/24".into());
args.insert("scan_type".into(), "service".into());

let result = toolclad::executor::dry_run(&manifest, &args)?;
println!("Would run: {}", result.command.join(" "));
```

### Types

#### `Manifest`

Top-level manifest structure containing all sections.

| Field | Type | Description |
|-------|------|-------------|
| `tool` | `ToolMeta` | Tool metadata (`[tool]` section) |
| `args` | `HashMap<String, ArgDef>` | Parameter definitions (`[args.*]`) |
| `command` | `Option<CommandDef>` | Command template (`[command]`) |
| `http` | `Option<HttpDef>` | HTTP backend (`[http]`) |
| `mcp` | `Option<McpProxyDef>` | MCP proxy backend (`[mcp]`) |
| `session` | `Option<SessionDef>` | Session configuration (`[session]`) |
| `browser` | `Option<BrowserDef>` | Browser configuration (`[browser]`) |
| `output` | `OutputDef` | Output configuration (`[output]`) |

#### `ToolMeta`

Tool metadata from the `[tool]` section.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Tool identifier |
| `version` | `String` | Tool version |
| `binary` | `Option<String>` | Executable path (oneshot/session) |
| `mode` | `Option<String>` | `"oneshot"` (default), `"session"`, or `"browser"` |
| `description` | `String` | Human-readable description |
| `timeout_seconds` | `u64` | Execution timeout |
| `risk_tier` | `String` | `"low"`, `"medium"`, `"high"`, or `"critical"` |

#### `ArgDef`

Parameter definition from `[args.*]`.

| Field | Type | Description |
|-------|------|-------------|
| `type_name` | `String` | Type identifier (e.g., `"string"`, `"enum"`, `"scope_target"`) |
| `position` | `usize` | Positional order |
| `required` | `bool` | Whether the argument is mandatory |
| `default` | `Option<String>` | Default value |
| `allowed` | `Option<Vec<String>>` | Allowed values (for `enum` type) |
| `pattern` | `Option<String>` | Regex pattern constraint |
| `min` | `Option<i64>` | Minimum value (for `integer` type) |
| `max` | `Option<i64>` | Maximum value (for `integer` type) |
| `clamp` | `bool` | Clamp out-of-range values instead of rejecting |
| `description` | `String` | Human-readable description |

#### `EvidenceEnvelope`

Execution result with metadata.

| Field | Type | Description |
|-------|------|-------------|
| `status` | `String` | `"success"` or `"error"` |
| `scan_id` | `String` | Unique invocation identifier |
| `tool` | `String` | Tool name |
| `command` | `String` | Constructed command string |
| `duration_ms` | `u64` | Execution time in milliseconds |
| `timestamp` | `String` | ISO 8601 timestamp |
| `exit_code` | `i32` | Process exit code |
| `stderr` | `String` | Standard error output |
| `output_hash` | `String` | SHA-256 hash of raw output |
| `results` | `Value` | Parsed and validated output |

---

## Python

**Package**: [`toolclad`](https://pypi.org/project/toolclad/)

### Functions

#### `load_manifest(path) -> Manifest`

Load and parse a `.clad.toml` manifest.

```python
from toolclad import load_manifest

manifest = load_manifest("tools/nmap_scan.clad.toml")
print(f"Tool: {manifest.tool.name} v{manifest.tool.version}")
```

#### `validate_arg(arg_def, value) -> None`

Validate a value against an argument definition. Raises `ValueError` on failure.

```python
from toolclad import validate_arg
from toolclad.manifest import ArgDef

arg_def = ArgDef(
    type_name="enum",
    allowed=["ping", "service", "version"],
    required=True,
    position=1,
)

validate_arg(arg_def, "ping")      # OK
validate_arg(arg_def, "exploit")   # raises ValueError
```

#### `build_command(manifest, args) -> list[str]`

Construct the command argument array without executing.

```python
from toolclad import load_manifest, build_command

manifest = load_manifest("tools/nmap_scan.clad.toml")
cmd = build_command(manifest, {"target": "10.0.1.0/24", "scan_type": "service"})
print(cmd)  # ["nmap", "-sT", "-sV", ...]
```

#### `execute(manifest, args) -> dict`

Validate, construct, execute, parse, and return the evidence envelope.

```python
from toolclad import load_manifest, execute

manifest = load_manifest("tools/whois_lookup.clad.toml")
result = execute(manifest, {"target": "example.com"})
print(f"Status: {result['status']}, Duration: {result['duration_ms']}ms")
```

### Dataclass Types

| Class | Description |
|-------|-------------|
| `Manifest` | Top-level manifest with `tool`, `args`, `command`, `http`, `mcp`, `session`, `browser`, `output` |
| `ToolMeta` | Tool metadata (`name`, `version`, `binary`, `mode`, `description`, `timeout_seconds`, `risk_tier`) |
| `ArgDef` | Parameter definition (`type_name`, `position`, `required`, `default`, `allowed`, `pattern`, `min`, `max`) |
| `HttpDef` | HTTP backend (`method`, `url`, `headers`, `body_template`, `success_status`, `error_status`) |
| `McpProxyDef` | MCP proxy backend (`server`, `tool`, `field_map`) |
| `SessionDef` | Session configuration (`startup_command`, `ready_pattern`, `commands`, timeouts) |
| `BrowserDef` | Browser configuration (`engine`, `connect`, `extract_mode`, `scope`, `commands`) |

---

## JavaScript

**Package**: [`toolclad`](https://www.npmjs.com/package/toolclad)

### Functions

#### `loadManifest(path) -> Manifest`

Load and parse a `.clad.toml` manifest.

```javascript
import { loadManifest } from "toolclad";

const manifest = loadManifest("tools/nmap_scan.clad.toml");
console.log(`Tool: ${manifest.tool.name} v${manifest.tool.version}`);
```

#### `validateArg(argDef, value) -> void`

Validate a value against an argument definition. Throws on failure.

```javascript
import { validateArg } from "toolclad";

const argDef = {
  type_name: "enum",
  allowed: ["ping", "service", "version"],
  required: true,
  position: 1,
};

validateArg(argDef, "ping");     // OK
validateArg(argDef, "exploit");  // throws Error
```

#### `buildCommand(manifest, args) -> string[]`

Construct the command argument array without executing.

```javascript
import { loadManifest, buildCommand } from "toolclad";

const manifest = loadManifest("tools/nmap_scan.clad.toml");
const cmd = buildCommand(manifest, { target: "10.0.1.0/24", scan_type: "service" });
// ["nmap", "-sT", "-sV", ...]
```

#### `execute(manifest, args) -> object`

Validate, construct, execute, parse, and return the evidence envelope.

```javascript
import { loadManifest, execute } from "toolclad";

const manifest = loadManifest("tools/whois_lookup.clad.toml");
const result = await execute(manifest, { target: "example.com" });
console.log(`Status: ${result.status}, Duration: ${result.duration_ms}ms`);
```

#### `generateMcpSchema(manifest) -> object`

Generate an MCP-compatible JSON Schema.

```javascript
import { loadManifest, generateMcpSchema } from "toolclad";

const manifest = loadManifest("tools/nmap_scan.clad.toml");
const schema = generateMcpSchema(manifest);
console.log(JSON.stringify(schema, null, 2));
```

#### `executeHttp(manifest, args) -> object`

Execute an HTTP backend tool. Constructs the request from `[http]`, sends it, and returns the evidence envelope.

```javascript
import { loadManifest, executeHttp } from "toolclad";

const manifest = loadManifest("tools/slack_post_message.clad.toml");
const result = await executeHttp(manifest, { channel: "C01234", message: "hello" });
```

#### `executeMcp(manifest, args) -> object`

Execute an MCP proxy tool. Validates arguments, maps fields, forwards to the upstream MCP server, and returns the evidence envelope.

```javascript
import { loadManifest, executeMcp } from "toolclad";

const manifest = loadManifest("tools/github_create_issue.clad.toml");
const result = await executeMcp(manifest, { repo: "org/repo", title: "Bug report" });
```

---

## Go

**Module**: `github.com/ThirdKeyAI/ToolClad/go`

### `manifest` package

#### `manifest.LoadManifest(path) -> (*Manifest, error)`

Load and parse a `.clad.toml` manifest.

```go
package main

import (
    "fmt"
    "github.com/ThirdKeyAI/ToolClad/go/pkg/manifest"
)

func main() {
    m, err := manifest.LoadManifest("tools/nmap_scan.clad.toml")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Tool: %s v%s\n", m.Tool.Name, m.Tool.Version)
}
```

### `validator` package

#### `validator.ValidateArg(def ArgDef, value string) -> error`

Validate a value against an argument definition.

```go
import "github.com/ThirdKeyAI/ToolClad/go/pkg/validator"

err := validator.ValidateArg(argDef, "ping")
if err != nil {
    fmt.Printf("Validation failed: %s\n", err)
}
```

### `executor` package

#### `executor.BuildCommand(manifest, args) -> ([]string, error)`

Construct the command argument array without executing.

```go
import "github.com/ThirdKeyAI/ToolClad/go/pkg/executor"

args := map[string]string{
    "target":    "10.0.1.0/24",
    "scan_type": "service",
}
cmd, err := executor.BuildCommand(m, args)
// ["nmap", "-sT", "-sV", ...]
```

#### `executor.Execute(manifest, args) -> (*EvidenceEnvelope, error)`

Validate, construct, execute, parse, and return the evidence envelope.

```go
import "github.com/ThirdKeyAI/ToolClad/go/pkg/executor"

args := map[string]string{"target": "example.com"}
result, err := executor.Execute(m, args)
if err != nil {
    panic(err)
}
fmt.Printf("Status: %s, Duration: %dms\n", result.Status, result.DurationMs)
```
