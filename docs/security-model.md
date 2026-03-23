---
title: Security Model
description: ToolClad security architecture and trust chain
---

# Security Model

ToolClad inverts the security model of sandbox-based approaches. Instead of letting an LLM generate arbitrary commands and intercepting dangerous ones, ToolClad constrains the LLM to fill typed parameters that are validated against a manifest. The dangerous action cannot be expressed because the interface does not permit it.

## Allow-List vs Deny-List

| Approach | Model | Weakness |
|----------|-------|----------|
| **Sandbox** (deny-list) | LLM generates command -> sandbox intercepts -> allow/deny | Deny-lists have gaps by definition. Novel attack patterns bypass rules. |
| **ToolClad** (allow-list) | LLM fills typed parameters -> policy gate -> executor validates -> constructs command | Only declared operations are possible. The attack surface is the manifest. |

The sandbox approach requires the security layer to understand every possible dangerous command. ToolClad requires the manifest author to declare every *permitted* command. The allow-list is finite and auditable.

## Shell Injection Prevention

All string-based types reject shell metacharacters by default:

```
; | & $ ` ( ) { } [ ] < > ! \n \r
```

This is not optional sanitization -- it is the type system's default behavior. Any value containing these characters is rejected before it reaches command construction. The `sanitize = ["injection"]` annotation is the default for string types; it does not need to be declared explicitly.

Newline (`\n`) and carriage return (`\r`) are blocked across all string-based types. These prevent:

- Command injection via newline splitting (`arg1\nmalicious_command`)
- Header injection in HTTP backends
- Log injection in evidence transcripts

## Array-Based Execution

ToolClad never invokes `sh -c` with a command string. Commands are dispatched via direct `execve` with an argument array:

```
# What ToolClad does (safe):
execve("/usr/bin/nmap", ["nmap", "-sT", "-sV", "--max-rate", "1000", "10.0.1.0/24"])

# What ToolClad never does (unsafe):
sh -c "nmap -sT -sV --max-rate 1000 10.0.1.0/24"
```

Array-based execution means that even if a metacharacter somehow passed validation (it cannot, but defense in depth), the shell would never interpret it. There is no shell.

## HTTP Body JSON-Escaping

When values are interpolated into HTTP body templates (`[http].body_template`), they are JSON-escaped before substitution. This prevents injection attacks where an agent-supplied value could break out of a JSON string field and alter the structure of the request body. Quotes, backslashes, newlines, and control characters are all escaped.

## Platform-Aware Evidence Directories

Evidence output directories use platform-appropriate temporary directories (`/tmp` on Linux/macOS, `%TEMP%` on Windows) when no explicit `output_dir` is configured. This ensures evidence capture works correctly across operating systems without hardcoded paths.

## HTTP Error Semantics

HTTP backend responses are classified by status code:

- **2xx**: `success` status in the evidence envelope
- **4xx**: `client_error` status -- the request was malformed or unauthorized
- **5xx**: `server_error` status -- the upstream service failed

This classification gives LLM agents actionable error semantics for self-correction.

## Process Group Kill

Tools are spawned in a new process group (PGID). When a timeout fires, the executor kills the entire process group, not just the top-level process. This prevents:

- Zombie child processes that outlive the timeout
- Background processes spawned by the tool that continue running
- Resource leaks from tools that fork internally

## Absolute Path Blocking

The `path` type rejects:

- Path traversal: `../`, `..\\`
- Absolute paths: `/etc/shadow`, `C:\Windows\System32`
- Null bytes: `\0`

Paths are constrained to relative locations within the project directory. A tool cannot read or write outside its intended scope.

## Scope Enforcement

Parameters with type `scope_target`, `url` (with `scope_check = true`), `cidr`, or `ip_address` are automatically validated against the project's scope definition.

Scope enforcement supports:

- **IP addresses**: Exact match against allowed IPs
- **CIDR ranges**: Membership check against allowed networks
- **Domain names**: Pattern matching against allowed domains
- **URL hosts**: Host extraction and domain matching

The scope check runs in the executor, after Cedar authorization but before command execution. This is defense in depth: even if a Cedar policy bug allows an out-of-scope target, the type system catches it.

For browser mode, URL scope enforcement extends to navigation, redirects, and link clicks. See [Browser Mode](browser-mode.md) for details.

## Cedar Policy Integration

The `[tool.cedar]` section declares the Cedar resource and action for the tool:

```toml
[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"
```

The runtime's Gate phase builds a Cedar authorization request from the manifest metadata plus the agent's runtime context (phase, environment, agent identity). Cedar policies in `policies/` evaluate this request and produce `ALLOW`, `DENY`, or `PENDING` (for human approval).

### Automatic Policy Generation

Because the manifest declares the tool's risk tier, parameter types, and Cedar resource, the runtime can generate baseline Cedar policies:

```cedar
# Auto-generated from nmap_scan.clad.toml (risk_tier = "low")
permit (
    principal,
    action == PenTest::Action::"execute_tool",
    resource
)
when {
    resource.tool_name == "nmap_scan"
};
```

Teams then refine the generated policies with phase restrictions, environment constraints, and human approval gates.

### Session and Browser Cedar Context

For session and browser modes, Cedar policies receive additional context:

- `resource.session_state` -- current state of the interactive tool
- `resource.interaction_count` -- number of interactions so far
- `resource.command` -- the specific session/browser command being invoked
- `resource.page_state.*` -- browser page state (URL, domain, forms, auth status)

This enables state-aware and time-aware governance on interactive tools.

## SchemaPin Integration

[SchemaPin](https://schemapin.org) signs `.clad.toml` files directly as first-class artifacts:

```bash
schemapin-sign tools/nmap_scan.clad.toml
```

The signature covers the entire behavioral contract. If anyone tampers with a command template, validation rule, scope constraint, output schema, or session command pattern, the hash changes and verification fails.

### Verification Flow

1. Runtime loads `nmap_scan.clad.toml` from `tools/`
2. Runtime hashes the manifest content (SHA-256)
3. Runtime looks up the tool's provider domain (from `toolclad.toml` or `symbiont.toml`)
4. Runtime fetches `.well-known/schemapin.json` from the provider domain
5. Runtime verifies the hash against the published signature using SchemaPin's TOFU pinning
6. If verification fails, the manifest is rejected and the tool is not registered

No `[tool.schemapin]` section is needed in the manifest. The manifest stays clean. SchemaPin uses its existing `.well-known/schemapin.json` discovery infrastructure.

### What the Signature Protects

The signature covers more than an MCP JSON Schema would:

| Protected | MCP Schema Only | ToolClad Manifest |
|-----------|----------------|-------------------|
| Parameter names and types | Yes | Yes |
| Validation rules (regex, ranges) | No | Yes |
| Command template | No | Yes |
| Scope constraints | No | Yes |
| Session command patterns | No | Yes |
| Browser scope domains | No | Yes |
| Output schema | Partial | Yes |
| Risk tier and Cedar mappings | No | Yes |

## No-Eval Guarantee

Conditional evaluators in `[command.conditionals]` use closed-vocabulary parsers:

```toml
[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
```

The `when` expression supports only:

- Variable references (declared parameter names)
- Comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`)
- Logical operators (`and`, `or`)
- String literals and numeric literals

There is no `eval()`, no expression language, no dynamic code execution. The parser recognizes a fixed grammar and rejects anything outside it. This prevents any form of code injection through conditional expressions.

## Static Analysis

Because ToolClad manifests are declarative, you can determine what any tool can possibly do before it ever runs:

- **Parameter space**: Enumerable for enum types, bounded for numeric types, regex-constrained for string types
- **Command shape**: The template defines the exact command structure; only placeholder values vary
- **Risk profile**: Declared risk tier, Cedar resource/action, human approval requirements
- **Scope constraints**: Which targets and domains the tool can reach
- **Output shape**: The exact JSON structure the tool will produce

This enables formal verification: you can prove properties about valid invocations without executing anything.

## The Trust Chain

```
SchemaPin verifies the manifest has not been modified
  -> The manifest constrains what the tool can accept
    -> Cedar authorizes whether this invocation is allowed
      -> The executor validates arguments against manifest types
        -> The executor constructs and runs the command
          -> Each layer trusts the one before it
```

Each layer in the chain has a single responsibility:

1. **SchemaPin**: Integrity -- the manifest is authentic and unmodified
2. **Manifest**: Interface -- only declared operations with typed parameters
3. **Cedar**: Authorization -- this agent, in this context, is allowed to invoke this tool
4. **Executor**: Validation -- all parameter values satisfy their type constraints
5. **Runtime**: Execution -- array-based dispatch with timeout and process isolation
