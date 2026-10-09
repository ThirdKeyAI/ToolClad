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
mode = "oneshot"               # "oneshot" | "session" | "browser". Advisory; derived when absent.
timeout_seconds = 600          # Execution timeout. Default: 60. Must be > 0.
risk_tier = "low"              # "low" | "medium" | "high" | "critical". high/critical are gated.
human_approval = false         # Gated by the default policy gate when true. Default: false.
network_egress = true          # Tool reaches the network: network-target args must set block_internal.
allow_interpreter = false      # Permit sh/bash/python3/node/... as argv[0]. Default: false.
dispatch = "exec"              # "exec" (default) | "callback" (validator-only embedding)
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Unique tool identifier, used for MCP registration |
| `version` | string | yes | -- | Semver version of the underlying CLI tool |
| `binary` | string | yes (oneshot shell) | -- | Binary name or path. When set with an `exec`/`template` command, its basename must equal the basename of `argv[0]` or the manifest is refused |
| `description` | string | yes | -- | Human-readable description (included in MCP schema) |
| `mode` | string | no | derived | `"oneshot"`, `"session"`, or `"browser"`. Advisory only; derived from which backend section is present when absent |
| `timeout_seconds` | integer | no | `60` | Maximum execution time before the `SIGTERM`/`SIGKILL` process-group kill. `0` is refused at load (`timeout_seconds must be greater than zero`) |
| `risk_tier` | string | no | `"low"` | `"low"`, `"medium"`, `"high"`, or `"critical"`. `high` and `critical` are denied by the default policy gate (`risk_tier '<t>' requires explicit approval`) unless `--approve` or an approving gate is supplied |
| `human_approval` | boolean | no | `false` | When `true`, the default policy gate denies execution (`manifest requires human approval (human_approval = true)`); `--approve` or an approving gate is required |
| `network_egress` | boolean | no | `false` | Declares that the tool reaches the network. When `true`, every argument of type `scope_target`, `url`, `ip_address`, `cidr`, or a custom type based on one of those must set `block_internal = true`, or the manifest is refused at load. The same lint applies automatically when `tool.binary`, `exec[0]`, or the template's first token is a known egress binary (`curl`, `wget`, `nmap`, `nc`, `ncat`, `netcat`, `masscan`, `telnet`, `ssh`, `ping`, `fping`, `httpie`, `http`, `wfuzz`, `ffuf`, `hydra`, `nikto`) and to every `[http]` and `[browser]` manifest |
| `allow_interpreter` | boolean | no | `false` | Permits `argv[0]`'s basename to be `sh`, `bash`, `zsh`, `dash`, `ksh`, `csh`, `tcsh`, `fish`, `ash`, `busybox`, `env`, `eval`, `xargs`, `python`, `python2`, `python3`, `perl`, `ruby`, `node`, `deno`, `bun`, `lua`, `php`, or `awk`. Refused at load otherwise |
| `dispatch` | string | no | `"exec"` | `"exec"` runs a backend; `"callback"` is a validator-only embedding with no backend or `[output]` required |

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

When `capture = true`, the executor writes the raw tool output to `output_dir` and includes the SHA-256 hash in the evidence envelope for tamper detection. `screenshots` is accepted for browser manifests.

## `[tool.limits]` -- Child Resource Limits

```toml
[tool.limits]
nproc = 4096                   # RLIMIT_NPROC. Default: unset (not applied).
nofile = 1024                  # RLIMIT_NOFILE. Default: 1024.
fsize_bytes = 1073741824       # RLIMIT_FSIZE. Default: 1 GiB.
address_space_bytes = 2147483648   # RLIMIT_AS. Only applied when declared.
cpu_seconds = 600              # RLIMIT_CPU. Only applied when declared.
```

The **Rust and Python** runtimes apply these as rlimits on the child via a pre-exec hook (together with `RLIMIT_CORE = 0` and a 0077 umask). **Go and JavaScript cannot set child rlimits portably and skip this section**; the keys are still parsed and validated there, but deployments on those runtimes must enforce limits externally (cgroups, container limits, or `ulimit` in the hosting process).

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
type = "scope_target"      # One of 15 built-in types or a custom type
block_internal = true      # Refuse loopback/private/metadata targets; resolve hostnames fail-closed
scope_check = true         # Allowlist against scope/scope.toml (fail-closed when no file is found)
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
schemes = ["http", "https"]   # Allowed URL schemes (default); dangerous schemes are always refused
block_internal = true          # Required when the tool fetches the URL
scope_check = true             # Extract host for scope validation

[args.headers]
type = "string"
allow_whitespace = true        # Permit spaces; honored only when [command] declares exec = [...]
default = ""

[args.offset]
type = "integer"
allow_leading_dash = true      # Permit a negative value (otherwise a leading - or + is refused)

[args.wordlist]
type = "path"              # No `..` component, no absolute paths
required = false
```

### Arg Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `position` | integer | Positional index for template ordering |
| `required` | boolean | Mandatory parameter. Default: `false` |
| `type` | string | Built-in type name or custom type. See [Type System](type-system.md) |
| `description` | string | Human-readable description (included in MCP schema) |
| `default` | any scalar | Default value when parameter is not provided |
| `allowed` | array | Valid values for `enum` type |
| `pattern` | string | Regex constraint for `string` and `regex_match` types. Anchored: compiled as `^(?:pattern)$` |
| `sanitize` | array | Sanitization rules: `["injection"]` |
| `min` | integer | Minimum for `integer` type |
| `max` | integer | Maximum for `integer` type |
| `min_float` | number | Minimum for `number` type |
| `max_float` | number | Maximum for `number` type |
| `clamp` | boolean | Clamp to range instead of rejecting (`integer`, `number`). Default: `false` |
| `schemes` | array | Allowed URL schemes for `url` type. Default: `["http", "https"]`. `javascript`, `data`, `file`, `blob`, `about`, `gopher`, `dict`, `ftp`, `ldap`, `jar`, `netdoc`, `mailto`, `ws`, `wss` are refused even if listed |
| `scope_check` | boolean | Check the value (host for `url`) against `scope/scope.toml`; applies to `scope_target`, `url`, `ip_address`, `cidr`. Fail-closed. Default: `false` |
| `block_internal` | boolean | Block loopback, private, CGNAT, documentation, and reserved ranges and resolve hostnames fail-closed; applies to `scope_target`, `url`, `ip_address`, `cidr`. Link-local and internal names are blocked regardless. Mandatory on egress tools. Default: `false` |
| `allow_whitespace` | boolean | Permit whitespace in a string-derived value. Honored only when `[command]` declares `exec` directly; never for `url`. Default: `false` |
| `allow_leading_dash` | boolean | Permit a value (or numeric result) that starts with `-` or `+`. Default: `false` |

Any other key under `[args.<name>]` is refused at load.

### Mappings in Args

When an `enum` arg has a corresponding entry in `[command.mappings]`, the enum value is translated to CLI flags at command construction time. See [Command Construction](command-construction.md) for details.

## `[command]` -- Shell Command Construction

```toml
[command]
exec = ["nmap", "{_scan_type_flags}", "--max-rate", "{max_rate}", "-oX", "{_output_file}", "{target}"]
end_of_options = "--"          # Optional. Only "--" is accepted.
```

`exec` is the canonical form: one argv element per entry, placeholders as whole unquoted tokens, `{{`/`}}` for literal braces, values never re-split. Use `executor` when invocation logic exceeds what `exec` can express.

```toml
[command]
executor = "scripts/tool-wrappers/msf-wrapper.sh"  # Escape hatch (replaces exec)
```

| Field | Type | Description |
|-------|------|-------------|
| `exec` | array | Canonical argv array |
| `template` | string | **Deprecated.** Tokenized into `exec` at load with a warning; a placeholder inside quotes or unbalanced quotes rejects the manifest. Will be removed in the next minor release |
| `executor` | string | Escape-hatch script; receives `TOOLCLAD_ARG_*` and friends in an otherwise cleared environment |
| `end_of_options` | string | Only `"--"`. Inserts a literal `--` before the first user-argument token |
| `defaults` | table | Open map of default values for placeholders |
| `mappings` | table | Open map of `[command.mappings.<arg>]` tables |
| `conditionals` | table | `[command.conditionals.<name>]` entries with `when` and `template` |

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

Maps enum values to CLI flag strings. The mapped result is available as `{_scan_type_flags}` -- the variable is always `_<arg_name>_flags`; no other alias is recognized. The mapped string is tokenized (it is manifest-controlled) and spliced into the argv where the placeholder appears.

### `[command.conditionals]`

```toml
[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
username_file = { when = "username_file != ''", template = "-L {username_file}" }
single_user = { when = "username != '' and username_file == ''", template = "-l {username}" }
```

Include template fragments only when conditions are met. Each conditional is exposed as `{_<name>}` (`{_service_port}` above) and its `template` is tokenized at load with the same rules as `[command].template`. See [Command Construction](command-construction.md) for the full `when` expression syntax.

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

`{_secret:name}` references are expanded on these templates before any argument is interpolated; URL values are percent-encoded, body values are JSON-escaped, redirects are not followed, and the envelope's `command` holds the unexpanded `url`. `[http]` manifests are treated as `network_egress = true`, so every network-target argument must set `block_internal = true`. See [HTTP and MCP Backends](http-mcp-backends.md) for details.

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

> **Parsed, not executed.** The reference runtimes validate `[mcp]` manifests and return a `delegation_preview` envelope (field-mapped arguments, no upstream call). Forwarding to the MCP server is the job of a hosting runtime.

## `[output]` -- Output Handling

```toml
[output]
format = "xml"                             # "text" | "json" | "xml" | "csv" | "jsonl"
parser = "builtin:xml"                     # builtin:* only; anything else is refused at load
envelope = true                            # Wrap in evidence envelope. Default: true.
max_bytes = 8388608                        # Cap on stdout and stderr (each). Default: 8 MiB.
```

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Output format hint |
| `parser` | string | One of the `builtin:*` names below. A script path is refused at load (`custom output parsers are not supported by the reference runtimes`) |
| `envelope` | boolean | Wrap results in an evidence envelope. Default: `true` |
| `schema` | table | Mandatory output schema (see below) |
| `max_bytes` | integer | Cap on captured stdout and stderr, each. Overflow stops capture and sets `output_truncated: true`. Default: `8388608` |

### Built-in Parsers

| Parser | Produces | Use Case |
|--------|----------|----------|
| `builtin:json` | Pass-through | Tools with native JSON output |
| `builtin:xml` | JSON conversion | nmap, Nessus, OWASP ZAP |
| `builtin:csv` | Array of objects | Spreadsheets, log files |
| `builtin:jsonl` | Array of objects | Nuclei, streaming tools |
| `builtin:text` | `{ "raw_output": "..." }` | Unstructured text (default) |

### Custom Parsers (Not Supported)

A `parser` value that is not one of the `builtin:*` names above -- for example `parser = "scripts/parse-outputs/parse-nmap-xml.py"` -- is **refused at load** by the reference runtimes. There is no mechanism for an external script to run in the output pipeline. `builtin:xml` additionally refuses input containing `<!DOCTYPE` or `<!ENTITY`.

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
2. **Parser output validation** -- the executor validates parsed results against the schema with a bundled JSON-Schema subset validator (`type`, `properties`, `required`, `items`, `additionalProperties` as a boolean, `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `pattern`; unknown keywords are ignored). Validation is fail-closed: a violation sets the envelope status to `schema_error`, replaces `results` with `{"schema_error": "<path>: <message>"}`, and preserves the raw output under `results.raw_output`

## `[session]` -- CLI Session Mode

> **Parsed, not executed.** The reference runtimes load and validate `[session]` manifests (and serve `validate`/`schema` for them) but refuse `execute` with `session mode is parsed but not yet executable in the reference implementation`. Execution is provided by a hosting runtime.

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

> **Parsed, not executed.** The reference runtimes load and validate `[browser]` manifests but refuse `execute` with `browser mode is parsed but not yet executable in the reference implementation`. They do enforce the egress lint at load: `[browser]` manifests count as `network_egress = true`, so every network-target command argument must set `block_internal = true`.

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
args.url = { type = "url", schemes = ["https"], block_internal = true, scope_check = true }

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

## Scope Enforcement

There is no `[tool.scope]` section; a manifest containing one is refused as an unknown key. Scope enforcement is declared per argument: any parameter of type `scope_target`, `url`, `ip_address`, or `cidr` that sets `scope_check = true` is validated against the project scope file during argument validation, before the command is built. Without `scope_check = true` no allowlisting happens -- `scope_target` by itself is only a shape check.

```toml
# scope/scope.toml
[scope]
allowed_cidrs   = ["10.0.1.0/24"]
allowed_domains = ["example.com", "*.example.com"]
blocked_cidrs   = []
blocked_domains = []
```

The file is found via `TOOLCLAD_SCOPE_FILE`, or by searching for `scope/scope.toml` upward from the manifest's directory. Unknown keys in the scope file are refused. If `scope_check = true` and no file is reachable, the value is **rejected** (fail-closed). Blocked rules win over allowed rules; `*.example.com` matches strict subdomains at any depth but not the apex or `evil-example.com`; an IP must be contained in an allowed CIDR and a CIDR value must be fully contained. See [Security Model: Scope Enforcement](security-model.md#scope-enforcement).

## Unknown Keys

Every parser refuses keys it does not know, at load, with `unknown key '<section>.<key>' in manifest`. `toolclad validate --allow-unknown-keys` downgrades this to a printed warning; library loading is always strict. The complete allowlist:

```
[tool]            name version binary description timeout_seconds risk_tier
                  human_approval dispatch mode network_egress allow_interpreter
                  cedar evidence limits
[tool.cedar]      resource action
[tool.evidence]   output_dir capture hash screenshots
[tool.limits]     nproc nofile fsize_bytes address_space_bytes cpu_seconds
[args.<n>]        position required type description default allowed pattern
                  sanitize min max min_float max_float clamp schemes
                  scope_check block_internal allow_leading_dash allow_whitespace
[command]         template exec executor defaults mappings conditionals
                  end_of_options
[command.conditionals.<n>]  when template
[output]          format parser envelope schema max_bytes
[http]            method url headers body_template success_status error_status
[mcp]             server tool field_map
[session]         startup_command ready_pattern startup_timeout_seconds
                  idle_timeout_seconds session_timeout_seconds max_interactions
                  interaction commands child_detection
[session.interaction]  input_sanitize output_max_bytes output_wait_ms
[session.commands.<n>] pattern description risk_tier human_approval
                  extract_target args
[session.child_detection]  pattern type manifest
[browser]         engine headless connect extract_mode startup_timeout_seconds
                  session_timeout_seconds idle_timeout_seconds max_interactions
                  scope commands state defaults
[browser.defaults]     extract_mode
[browser.scope]        allowed_domains blocked_domains allow_external
[browser.commands.<n>] description risk_tier human_approval args
[browser.state]        fields
```

`[args.*].default` accepts any scalar. `[command.defaults]` and `[command.mappings]` are open maps whose keys are user-chosen names. `[output.schema]` is JSON Schema and is not key-checked.

## Complete Annotated Example

```toml
# tools/nmap_scan.clad.toml -- Full manifest with all sections
#
# There is deliberately no free-form flag parameter. An argument whose value is
# interpolated as nmap options is an option-injection channel; every supported
# invocation is an entry in [command.mappings.scan_type] instead.

[tool]
name = "nmap_scan"
version = "1.0.0"
binary = "nmap"
description = "Network port scanning and service detection"
timeout_seconds = 600
risk_tier = "low"
network_egress = true

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
# nmap connects to this target: default-deny internal/SSRF ranges. Under
# block_internal a hostname must resolve to a public address, and a CIDR must
# not overlap a blocked range.
block_internal = true
description = "Target CIDR, IP, or hostname"

[args.scan_type]
position = 2
required = true
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect", "aggressive", "vuln_script"]
description = "Type of scan to perform"

# --- Command Construction ---
#
# Array form: every element is one argv entry, dispatched straight to execve.
# {_scan_type_flags} is the only multi-token placeholder; its value comes from
# the mapping table below, which is manifest-controlled, not agent-supplied.

[command]
exec = [
    "nmap",
    "{_scan_type_flags}",
    "--max-rate", "{max_rate}",
    "-oX", "{_output_file}",
    "--no-stylesheet",
    "-v",
    "{target}",
]

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
max_bytes = 8388608

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
