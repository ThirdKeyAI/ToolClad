# Manifest Format

Complete reference for the `.clad.toml` manifest format. Every section is annotated with field types, defaults, and examples.

---

## `[tool]` -- Tool Metadata

```toml
[tool]
name = "nmap_scan"              # Required. Unique tool identifier.
version = "1.0.0"              # Required. Semver, tracks CLI tool version.
binary = "nmap"                # Binary name or path. Required for oneshot shell.
description = "Network port scanning and service detection"  # Required.
mode = "oneshot"               # "oneshot" (default) | "session" | "browser"
timeout_seconds = 600          # Execution timeout. Default: 60.
risk_tier = "low"              # "low" | "medium" | "high". Informs Cedar policies.
human_approval = false         # Require human approval before execution. Default: false.
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Unique tool identifier, used for MCP registration |
| `version` | string | yes | -- | Semver version of the underlying CLI tool |
| `binary` | string | yes (oneshot shell) | -- | Binary name or path to the executable |
| `description` | string | yes | -- | Human-readable description (included in MCP schema) |
| `mode` | string | no | `"oneshot"` | Execution mode: `"oneshot"`, `"session"`, or `"browser"` |
| `timeout_seconds` | integer | no | `60` | Maximum execution time before process kill |
| `risk_tier` | string | no | `"low"` | Risk level for Cedar policy decisions |
| `human_approval` | boolean | no | `false` | Require human approval before any execution |

## `[tool.cedar]` -- Cedar Policy Metadata

```toml
[tool.cedar]
resource = "PenTest::ScanTarget"   # Cedar resource type for authorization
action = "execute_tool"            # Cedar action
```

The ORGA Gate builds the Cedar authorization request from these fields plus runtime context (agent identity, phase, environment). Cedar policies in `policies/` reference `resource.tool_name` to match against specific tools.

## `[tool.evidence]` -- Evidence Capture

```toml
[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-nmap"  # Evidence output path template
capture = true                                 # Capture raw output to file. Default: true.
hash = "sha256"                                # Hash algorithm for output_hash. Default: "sha256".
```

When `capture = true`, the executor writes the raw tool output to `output_dir` and includes the SHA-256 hash in the evidence envelope for tamper detection.

## `[tool.schemapin]` -- SchemaPin Verification

SchemaPin signs `.clad.toml` files directly as first-class artifacts. No `[tool.schemapin]` section is needed in the manifest. The manifest stays clean.

Signing (tool vendor):

```bash
schemapin-sign tools/nmap_scan.clad.toml
```

The signature and hash are published in the vendor's `.well-known/schemapin.json` discovery document. Verification happens at the runtime level, not the manifest level. See the [Design Specification](https://github.com/ThirdKeyAI/ToolClad/blob/main/TOOLCLAD_DESIGN_SPEC.md) for the full verification flow.

### SchemaPin v1.4 (alpha) — Lifecycle, Lineage, DNS

The signing command supports three additive optional features from SchemaPin v1.4-alpha. None of them require manifest changes — they are options on `schemapin-sign`. Recommended for any production manifest:

```bash
# Versioned release with TTL + lineage
schemapin-sign tools/nmap_scan.clad.toml \
    --expires-in 6mo \
    --schema-version "$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' tools/nmap_scan.clad.toml)" \
    --previous-hash "$(jq -r '.skill_hash' tools/nmap_scan.clad.toml.sig.prior 2>/dev/null || true)"
```

What each flag does:

- `--expires-in 6mo` — adds an `expires_at` field. Verifiers past the expiry emit a `signature_expired` warning rather than failing. Forces re-signing on a cadence; surfaces stale tooling for policy gating.
- `--schema-version "$TOOL_VERSION"` — embeds the manifest's `[tool] version` semver into the signature. Surfaced on `VerificationResult.schema_version` for runtime version policy.
- `--previous-hash "$PREV_HASH"` — claims this signature is the legitimate successor of the prior one. Pair with `verify_chain` at the runtime layer to fail closed on rug-pull substitutions.

Vendors SHOULD also publish a `_schemapin.{vendor-domain}` TXT record pointing at the same key fingerprint as `.well-known/schemapin.json` — runtimes that adopt DNS TXT cross-verification then fail closed on mismatches between the HTTPS hosting channel and the DNS channel.

See [SchemaPin v1.4 features in ToolClad](schemapin-v1.4-features.md) for the full operational guide and per-language verifier examples.

## `[args.*]` -- Parameter Definitions

Each parameter is a TOML table under `[args]`:

```toml
[args.target]
position = 1              # Positional index in the command template
required = true            # Is this parameter mandatory?
type = "scope_target"      # One of 14 built-in types or a custom type
description = "Target CIDR, IP, or hostname"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect"]
description = "Type of scan to perform"

[args.threads]
position = 3
required = false
type = "integer"
min = 1                    # Minimum value (integer type)
max = 64                   # Maximum value (integer type)
clamp = true               # Clamp to range instead of rejecting. Default: false.
default = 4                # Default value when not provided

[args.module_path]
type = "string"
pattern = "^(exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"  # Regex validation
sanitize = ["injection"]   # Explicit injection sanitization

[args.target_url]
type = "url"
schemes = ["http", "https"]   # Allowed URL schemes
scope_check = true             # Extract host for scope validation

[args.wordlist]
type = "path"              # No traversal (../), no absolute paths
required = false
```

### Arg Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `position` | integer | Positional index for template ordering |
| `required` | boolean | Mandatory parameter. Default: `false` |
| `type` | string | Built-in type name or custom type. See [Type System](type-system.md) |
| `description` | string | Human-readable description (included in MCP schema) |
| `default` | any | Default value when parameter is not provided |
| `allowed` | array | Valid values for `enum` type |
| `pattern` | string | Regex constraint for `string` and `regex_match` types |
| `sanitize` | array | Sanitization rules: `["injection"]` |
| `min` | number | Minimum for `integer` type |
| `max` | number | Maximum for `integer` type |
| `clamp` | boolean | Clamp to range instead of rejecting. Default: `false` |
| `schemes` | array | Allowed URL schemes for `url` type |
| `scope_check` | boolean | Enable scope validation for `url` type |

### Mappings in Args

When an `enum` arg has a corresponding entry in `[command.mappings]`, the enum value is translated to CLI flags at command construction time. See [Command Construction](command-construction.md) for details.

## `[command]` -- Shell Command Construction

```toml
[command]
template = "nmap {_scan_flags} --max-rate {max_rate} -oX {_output_file} {extra_flags} {target}"
```

Use `template` for most tools. Use `executor` when invocation logic exceeds what templates can express.

```toml
[command]
executor = "scripts/tool-wrappers/msf-wrapper.sh"  # Escape hatch (replaces template)
```

See [Command Construction](command-construction.md) for details on mappings, conditionals, defaults, and the escape hatch.

### `[command.defaults]`

```toml
[command.defaults]
max_rate = 1000            # Default value for template variable {max_rate}
```

### `[command.mappings.*]`

```toml
[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV --version-intensity 5"
syn = "-sS --top-ports 1000"
```

Maps enum values to CLI flag strings. The mapped result is available as `{_scan_type_flags}` (or `{_scan_flags}` by convention) in the template.

### `[command.conditionals]`

```toml
[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
```

Include template fragments only when conditions are met. See [Command Construction](command-construction.md) for the full `when` expression syntax.

## `[http]` -- HTTP Request Backend

```toml
[http]
method = "POST"
url = "https://slack.com/api/chat.postMessage"
headers = { "Authorization" = "Bearer {_secret:slack_token}", "Content-Type" = "application/json" }
body_template = '{"channel": "{channel}", "text": "{message}"}'
success_status = [200]
error_status = [400, 401, 403, 404, 429]
```

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD |
| `url` | string | URL template with `{arg_name}` and `{_secret:name}` placeholders |
| `headers` | table | Header key-value pairs with template variable support |
| `body_template` | string | Request body template with `{arg_name}` interpolation |
| `success_status` | array | HTTP status codes that indicate success |
| `error_status` | array | HTTP status codes that indicate error |

See [HTTP and MCP Backends](http-mcp-backends.md) for details.

## `[mcp]` -- MCP Proxy Backend

```toml
[mcp]
server = "github-mcp"           # Named MCP server from symbiont.toml
tool = "create_issue"           # Upstream tool name

[mcp.field_map]
repo = "repository"             # ToolClad arg name -> upstream param name
labels = "label_names"
```

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | Named MCP server connection from `symbiont.toml` |
| `tool` | string | Upstream MCP tool name to invoke |
| `field_map` | table | Argument name mapping: ToolClad name to upstream name |

Unmapped fields pass through with the same name. See [HTTP and MCP Backends](http-mcp-backends.md) for details.

## `[output]` -- Output Handling

```toml
[output]
format = "xml"                             # "text" | "json" | "xml" | "csv" | "jsonl"
parser = "builtin:xml"                     # Built-in or custom parser script path
envelope = true                            # Wrap in evidence envelope. Default: true.
```

### Built-in Parsers

| Parser | Produces | Use Case |
|--------|----------|----------|
| `builtin:json` | Pass-through | Tools with native JSON output |
| `builtin:xml` | JSON conversion | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Array of objects | Spreadsheets, log files |
| `builtin:jsonl` | Array of objects | Nuclei, streaming tools |
| `builtin:text` | `{ "raw_output": "..." }` | Unstructured text (default) |

### Custom Parsers

```toml
[output]
parser = "scripts/parse-outputs/parse-nmap-xml.py"
```

Custom parsers receive the raw output file path as `argv[1]` and emit JSON to stdout. The parser's output is validated against the declared `[output.schema]` before it reaches the agent.

## `[output.schema]` -- Output Schema (Mandatory)

Every manifest must declare the expected shape of parsed results. The schema is JSON Schema-compatible and maps directly to MCP `outputSchema`.

```toml
[output.schema]
type = "object"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"

[output.schema.properties.hosts.items.properties.ip]
type = "string"

[output.schema.properties.hosts.items.properties.ports]
type = "array"

[output.schema.properties.hosts.items.properties.ports.items.properties.port]
type = "integer"

[output.schema.properties.hosts.items.properties.ports.items.properties.service]
type = "string"
```

For simple tools:

```toml
[output.schema]
type = "object"

[output.schema.properties.raw_output]
type = "string"
description = "Raw command output text"
```

The schema serves two purposes:

1. **MCP `outputSchema` generation** -- the LLM sees what data shape it will receive before proposing a tool call
2. **Parser output validation** -- the executor validates parsed results against the schema, rejecting malformed output before it reaches the agent

## `[session]` -- CLI Session Mode

```toml
[session]
startup_command = "msfconsole -q -x 'color false'"
ready_pattern = "^msf[0-9].*> $"
startup_timeout_seconds = 30
idle_timeout_seconds = 300
session_timeout_seconds = 1800
max_interactions = 100

[session.interaction]
input_sanitize = ["injection"]
output_max_bytes = 1048576
output_wait_ms = 2000

[session.commands.use_module]
pattern = "^use (exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"
description = "Load a Metasploit module"
risk_tier = "medium"

[session.commands.run]
pattern = "^(run|exploit)$"
description = "Execute the loaded module"
risk_tier = "high"
human_approval = true
```

See [Session Mode](session-mode.md) for the full reference.

## `[browser]` -- Browser Mode

```toml
[browser]
engine = "cdp-direct"
connect = "launch"               # "launch" = spawn headless | "live" = attach to Chrome
headless = true
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 200

[browser.defaults]
extract_mode = "accessibility_tree"    # "accessibility_tree" | "html" | "text"

[browser.scope]
allowed_domains = ["*.example.com", "docs.example.com"]
blocked_domains = ["*.evil.com"]
allow_external = false

[browser.commands.navigate]
description = "Navigate a tab to a URL"
risk_tier = "medium"
args.url = { type = "url", schemes = ["https"], scope_check = true }

[browser.commands.click]
description = "Click an element by CSS selector"
risk_tier = "low"
args.selector = { type = "string", pattern = "^[a-zA-Z0-9_.#\\[\\]=\"' >:()-]+$" }

[browser.commands.submit_form]
description = "Submit a form"
risk_tier = "high"
human_approval = true
args.selector = { type = "string" }
```

## `[tool.scope]` -- Scope Targets

Any parameter with type `scope_target`, `url` (with `scope_check = true`), `cidr`, or `ip_address` is automatically validated against the project scope definition (`scope/scope.toml`). The scope check runs after Cedar authorization but before command execution.

## Complete Annotated Example

```toml
# tools/nmap_scan.clad.toml -- Full manifest with all sections

[tool]
name = "nmap_scan"
version = "1.0.0"
binary = "nmap"
description = "Network port scanning and service detection"
timeout_seconds = 600
risk_tier = "low"

[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"

[tool.evidence]
output_dir = "{evidence_dir}/{scan_id}-nmap"
capture = true
hash = "sha256"

# --- Parameters ---

[args.target]
position = 1
required = true
type = "scope_target"
description = "Target CIDR, IP, or hostname"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect", "aggressive", "vuln_script"]
description = "Type of scan to perform"

[args.extra_flags]
position = 3
required = false
type = "string"
sanitize = ["injection"]
default = ""
description = "Additional nmap flags"

# --- Command Construction ---

[command]
template = "nmap {_scan_flags} --max-rate {max_rate} -oX {_output_file} --no-stylesheet -v {extra_flags} {target}"

[command.defaults]
max_rate = 1000

[command.mappings.scan_type]
ping = "-sn -PE"
service = "-sT -sV --version-intensity 5"
version = "-sV --version-all --top-ports 1000"
syn = "-sS --top-ports 1000"
os_detect = "-sS -O --osscan-guess"
aggressive = "-A -T4 --top-ports 10000"
vuln_script = "-sV --script=vuln --script-timeout 60s"

# --- Output ---

[output]
format = "xml"
parser = "builtin:xml"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.hosts]
type = "array"
description = "Discovered hosts with open ports and services"

[output.schema.properties.hosts.items.properties.ip]
type = "string"

[output.schema.properties.hosts.items.properties.ports]
type = "array"

[output.schema.properties.hosts.items.properties.ports.items.properties.port]
type = "integer"

[output.schema.properties.hosts.items.properties.ports.items.properties.protocol]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.service]
type = "string"

[output.schema.properties.hosts.items.properties.ports.items.properties.version]
type = "string"
```
