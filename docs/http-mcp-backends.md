# HTTP & MCP Backends

ToolClad oneshot mode declares three backends: shell commands (`[command]`), HTTP requests (`[http]`), and MCP proxy calls (`[mcp]`). All three share the same governance layer: argument validation, policy gating, output schema validation, and evidence envelopes. The backend determines how the request is dispatched.

> **Which backends the reference runtimes execute.** `[command]` and `[http]` are executed. `[mcp]` manifests are **parsed and validated but not executable**: the reference runtimes validate the arguments, apply `field_map`, and return a `delegation_preview` envelope without contacting any MCP server. Forwarding the call upstream is the job of a hosting runtime such as Symbiont.

## HTTP Backend

HTTP API tools use an `[http]` section instead of `[command]`. The executor constructs an HTTP request from the manifest, executes it, and wraps the response in a standard evidence envelope.

### HTTP Manifest Example

```toml
# tools/slack_post_message.clad.toml
[tool]
name = "slack_post_message"
version = "1.0.0"
description = "Post a message to a Slack channel"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Comms::SlackChannel"
action = "post_message"

[args.channel]
type = "string"
required = true
pattern = "^[A-Z0-9]+$"
description = "Slack channel ID"

[args.message]
type = "string"
required = true
sanitize = ["injection"]
description = "Message text to post"

[http]
method = "POST"
url = "https://slack.com/api/chat.postMessage"
headers = { "Authorization" = "Bearer {_secret:slack_token}", "Content-Type" = "application/json" }
body_template = '{"channel": "{channel}", "text": "{message}"}'
success_status = [200]
error_status = [400, 401, 403, 404, 429]

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.ok]
type = "boolean"
description = "Whether the API call succeeded"

[output.schema.properties.ts]
type = "string"
description = "Message timestamp (Slack message ID)"
```

### `[http]` Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `url` | string | URL template with `{arg}` and `{_secret:name}` placeholders |
| `headers` | table | Header key-value pairs, supports `{_secret:name}` |
| `body_template` | string | Request body template with `{arg}` placeholders |
| `success_status` | array | HTTP status codes that indicate success |
| `error_status` | array | HTTP status codes that indicate known errors |

### HTTP Request Construction

The executor follows this sequence:

1. Expand `{_secret:name}` references **on the manifest template first** -- in `url`, every `headers` value, and `body_template`. Because this happens before any argument is interpolated, an argument value can never introduce a secret reference (the `url` validator also rejects `{` and `}` outright).
2. Interpolate `{arg_name}` placeholders with validated parameter values. Values placed in the URL are percent-encoded (path segments with the path set, query values with the query set); values placed in `body_template` are JSON-escaped.
3. Set method, headers, and body
4. Execute with `timeout_seconds`. Redirects are **not** followed: a 3xx response is surfaced as `status: "redirect_blocked"`.
5. Check response status against `success_status` / `error_status`
6. Parse the response body with the declared parser, subject to `[output] max_bytes`
7. Validate against `[output.schema]` (fail-closed: a violation yields `status: "schema_error"` with the raw body preserved)
8. Wrap in an evidence envelope. The envelope's `command` holds the **unexpanded** template (`"<METHOD> <http.url as written in the manifest>"`), never the expanded URL, so secrets never reach the agent or the evidence store.

`[http]` manifests are treated as `network_egress = true`: every `url`, `scope_target`, `ip_address`, or `cidr` argument must set `block_internal = true` or the manifest is refused at load.

### Secrets Injection

The `{_secret:name}` syntax references secrets that are resolved at invocation time. Secrets never appear in the manifest, MCP schema, or LLM context.

```toml
[http]
url = "https://api.example.com/v1/{endpoint}?key={_secret:api_key}"
headers = { "Authorization" = "Bearer {_secret:bearer_token}" }
```

Resolution order in the reference runtimes:

1. The file named by `TOOLCLAD_SECRETS_FILE` (preferred): a TOML file with `name = "value"` entries at top level. Its permissions are checked and it is rejected if group- or other-readable. When present, the file wins.
2. The `TOOLCLAD_SECRET_<NAME>` environment variable of the runtime's own process.

A missing secret is a hard error. Secrets are never placed in a child process environment (`TOOLCLAD_SECRET_*` is stripped from every spawn), never appear in the envelope's `command`, and -- because expansion happens before argument interpolation -- can never be referenced from an argument value. A hosting runtime such as Symbiont may substitute its own secret store (Vault/OpenBao); that integration is outside the reference runtimes.

The agent proposes `slack_post_message(channel="C01234", message="hello")`. The executor injects the bearer token from the secret store. The agent never sees the token.

### Status Code Validation

```toml
success_status = [200, 201]
error_status = [400, 401, 403, 404, 429]
```

- Status in `success_status`: parse response, return results.
- Status in `error_status`: return error envelope with status code and response body for agent self-correction.
- Status not in either list: return error envelope with "unexpected status code" message.
- Any 3xx: redirects are not followed; the envelope status is `redirect_blocked`.
- 4xx responses are classified `client_error` and 5xx `server_error` in the envelope.

### HTTP GET Example

```toml
# tools/ip_lookup.clad.toml
[tool]
name = "ip_lookup"
version = "1.0.0"
description = "Look up geolocation data for an IP address"
timeout_seconds = 10
risk_tier = "low"

[args.ip]
type = "ip_address"
required = true
# [http] manifests are network egress: block_internal is mandatory at load.
block_internal = true
description = "IP address to look up"

[http]
method = "GET"
url = "https://ipapi.co/{ip}/json/"     # {ip} is percent-encoded as a path segment
success_status = [200]
error_status = [429]

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.city]
type = "string"

[output.schema.properties.region]
type = "string"

[output.schema.properties.country_name]
type = "string"

[output.schema.properties.org]
type = "string"
description = "ISP or organization"
```

---

## MCP Proxy Backend

> **Not executable by the reference runtimes.** An `[mcp]` manifest loads, validates, and produces an MCP schema, but `execute` returns a `delegation_preview` envelope containing the upstream server name, tool name, and the field-mapped arguments. No MCP server is contacted. Steps 4-6 of the execution flow below are performed by a hosting runtime, not by the reference CLIs or libraries.

The MCP proxy backend wraps an existing MCP server tool in a ToolClad manifest. The manifest applies stricter validation and policy gating on top of the upstream tool's permissive schema.

### Why Proxy MCP Tools?

MCP tools from marketplaces and third-party servers have permissive JSON Schemas. A GitHub MCP tool might accept any string for a repository name. A database MCP tool might accept any SQL query.

The ToolClad manifest constrains these inputs with the full type system (regex patterns, enums, scope checks) and subjects every invocation to Cedar policy evaluation. Instead of trusting a marketplace MCP tool's self-declared schema, you wrap it in a `.clad.toml` that defines the contract *you* trust.

```
Without proxy:  Agent -> MCP Server (permissive schema, no Cedar)
With proxy:     Agent -> ToolClad (strict types, Cedar) -> MCP Server
```

### MCP Proxy Manifest Example

```toml
# tools/github_create_issue.clad.toml
[tool]
name = "github_create_issue"
version = "1.0.0"
description = "Create a GitHub issue in an allowed repository"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Dev::GitHubRepo"
action = "create_issue"

[mcp]
server = "github-mcp"
tool = "create_issue"

[args.repo]
type = "string"
required = true
pattern = "^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$"
description = "Repository in owner/repo format"

[args.title]
type = "string"
required = true
sanitize = ["injection"]
description = "Issue title"

[args.body]
type = "string"
required = false
description = "Issue body (markdown)"

[args.labels]
type = "string"
required = false
pattern = "^[a-zA-Z0-9_, -]+$"
description = "Comma-separated label names"

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.number]
type = "integer"
description = "Created issue number"

[output.schema.properties.url]
type = "string"
description = "URL of the created issue"

[output.schema.properties.state]
type = "string"
description = "Issue state (open)"
```

### `[mcp]` Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | Named MCP server connection from `symbiont.toml` |
| `tool` | string | Upstream MCP tool name to invoke |
| `field_map` | table | Optional: map ToolClad arg names to upstream param names |

The `server` field references a named MCP server in the runtime configuration:

```toml
# symbiont.toml
[mcp.servers.github-mcp]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${vault:github/api-token}" }
```

### Field Mapping

When ToolClad argument names differ from the upstream MCP tool's parameter names:

```toml
[mcp]
server = "github-mcp"
tool = "create_issue"

[mcp.field_map]
repo = "repository"       # ToolClad "repo" -> upstream "repository"
labels = "label_names"     # ToolClad "labels" -> upstream "label_names"
```

Unmapped fields pass through with the same name. This decouples the ToolClad contract from the upstream tool's naming conventions. You can rename parameters to be clearer for the agent without changing the upstream tool.

### MCP Proxy Execution Flow

1. ToolClad validates all arguments against the manifest's type system (stricter than upstream)
2. The policy gate runs (`human_approval` / `risk_tier` deny-by-default); Cedar evaluation, e.g. "this agent can only create issues in `ThirdKeyAI/*` repos", is external to the reference runtimes
3. Executor maps validated arguments to the upstream tool's expected names via `field_map` and -- in the reference runtimes -- returns a `delegation_preview` envelope here
4. *(hosting runtime)* Forwards the call to the MCP server referenced by `server`
5. *(hosting runtime)* Response is parsed and validated against `[output.schema]`
6. *(hosting runtime)* Wrapped in evidence envelope with audit trail

### Proxy for Database MCP

```toml
# tools/db_query.clad.toml -- Govern a database MCP tool
[tool]
name = "db_read_query"
version = "1.0.0"
description = "Execute a read-only SQL query"
timeout_seconds = 30
risk_tier = "medium"

[tool.cedar]
resource = "Data::Database"
action = "read_query"

[mcp]
server = "postgres-mcp"
tool = "query"

[args.sql]
type = "string"
required = true
pattern = "^SELECT\\s"
sanitize = ["injection"]
description = "SQL SELECT query (read-only)"

[args.database]
type = "enum"
required = true
allowed = ["analytics", "reporting", "staging"]
description = "Target database"

[mcp.field_map]
sql = "query"
database = "db_name"

[output]
format = "json"
parser = "builtin:json"
envelope = true

[output.schema]
type = "object"

[output.schema.properties.rows]
type = "array"
description = "Query result rows"

[output.schema.properties.row_count]
type = "integer"
```

The upstream `postgres-mcp` tool accepts any query string. The ToolClad manifest constrains it to `SELECT` statements only, limits which databases can be targeted, and gates every invocation through Cedar.

## Shared Guarantees

What the reference runtimes enforce for each backend:

| Guarantee | Shell | HTTP | MCP Proxy |
|-----------|-------|------|-----------|
| Argument validation | Yes | Yes | Yes |
| Policy gate (`human_approval`, `risk_tier`) | Yes | Yes | Yes |
| Cedar policy evaluation | External | External | External |
| Scope enforcement (`scope_check`) | Yes | Yes | Yes |
| Egress lint (`block_internal` required) | When `network_egress` / egress binary | Always | No |
| Output schema validation (fail-closed) | Yes | Yes | Not applicable (no upstream response) |
| Output cap (`max_bytes`) | Yes | Yes | Not applicable |
| Timeout enforcement | Yes | Yes | Not applicable |
| Evidence envelope | Yes | Yes | `delegation_preview` only |

The backend is an implementation detail of dispatch; argument validation and the policy gate are the same for all three.
