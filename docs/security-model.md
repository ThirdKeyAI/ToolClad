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
; | & $ ` ( ) { } [ ] < > !
```

This is not optional sanitization -- it is the type system's default behavior. Any value containing these characters is rejected before it reaches command construction. The `sanitize = ["injection"]` annotation is the default for string types; it does not need to be declared explicitly.

### Value Hygiene

Beyond the metacharacter list, every *string-derived* type (`string`, `path`, `credential_file`, `regex_match`, `url`, `scope_target`, `duration`, `msf_options`) is checked, in this order, before any type-specific parsing:

1. **NUL** -- a value containing `\0` is rejected (`must not contain NUL bytes`). This rule applies to **every** type, `enum` included.
2. **Control characters** -- any C0 control character (U+0000-U+001F, so `\n`, `\r`, and `\t` are all covered) and U+007F are rejected (`must not contain control characters`).
3. **Quotes and backslash** -- `'`, `"`, and `\` are rejected (`must not contain quote or backslash characters`).
4. **Whitespace** -- any Unicode whitespace is rejected (`must not contain whitespace`) unless the argument sets `allow_whitespace = true` **and** the manifest declares `command.exec` directly. A `template` that was compiled to `exec` at load is still template mode, where whitespace is always rejected. `msf_options` is exempt from this rule because the space is its `KEY VALUE` separator; `url` is never exempt.
5. **Leading dash** -- a value starting with `-` or `+` is rejected (`must not start with '-' or '+' (set allow_leading_dash = true to permit)`) unless the argument sets `allow_leading_dash = true`. This is what stops an argument value from being read as an option by the tool.

Numeric types (`integer`, `number`, `port`) apply the leading-dash rule to the **output** value after range-checking or clamping: `-1` with no bounds is rejected, `-5` with `clamp = true` and `min = 1` yields `1` and passes, and `allow_leading_dash = true` permits a negative result. `enum` values come from the manifest's `allowed` list and are exempt from rules 2-5.

Every `pattern` (on `[args.*]` and on custom types) is anchored before use: one leading `^` and one trailing `$` are stripped if present and the pattern is compiled as `^(?:pat)$` (Python uses `^(?:pat)\Z` with `re.match`, so a trailing newline cannot slip through). A pattern therefore always describes the whole value, never a substring.

These rules prevent:

- Command injection via newline splitting (`arg1\nmalicious_command`)
- Argument splitting and option injection (`-iL /etc/passwd`, `--script=...`)
- Header injection in HTTP backends
- Log injection in evidence transcripts

A shared negative suite, `tests/injection_vectors.json`, is run by all four runtimes so that every `reject` vector is rejected everywhere.

## Unknown Manifest Keys

Every parser refuses keys it does not know, at load, with `unknown key '<section>.<key>' in manifest`. A typo such as `block_internall = true` therefore cannot silently disable a control. The only escape hatch is `toolclad validate --allow-unknown-keys`, which downgrades unknown keys to a printed warning; library loading is always strict. The complete key allowlist is listed in [Manifest Format](manifest-format.md#unknown-keys).

## Array-Based Execution

ToolClad never invokes `sh -c` with a command string. Commands are dispatched via direct `execve` with an argument array. The canonical `exec` form declares the argv directly. The deprecated `template` form is tokenized **at load time**, on the trusted manifest string only, into the same array; substituted argument values are never re-split, a placeholder must be a whole unquoted token (a `{` inside quotes rejects the manifest), and the only placeholders that expand to more than one token (`_<arg>_flags` mappings and `_<cond>` conditionals) draw their text from the manifest, not from the agent:

```
# exec format (preferred) — maps directly to execve:
exec = ["nmap", "-sT", "-sV", "--max-rate", "1000", "10.0.1.0/24"]

# What ToolClad never does (unsafe):
sh -c "nmap -sT -sV --max-rate 1000 10.0.1.0/24"
```

Array-based execution means that even if a metacharacter somehow passed validation (it cannot, but defense in depth), the shell would never interpret it. There is no shell. `[command] end_of_options = "--"` adds one more layer for tools that honor it: a literal `--` is inserted before the first user-argument token.

## Spawn-Path Hardening

Every oneshot spawn, including the `executor` escape hatch, goes through the same hardened path:

- **Environment**: the child's environment is cleared and rebuilt from an allowlist -- `PATH` fixed to `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, plus `HOME`, `LANG`, `LC_ALL`, `TZ`, and `TERM` copied from the parent if set. For the `command.executor` escape hatch only, `TOOLCLAD_ARG_*`, `TOOLCLAD_SCAN_ID`, `TOOLCLAD_TOOL_NAME`, `TOOLCLAD_EVIDENCE_DIR`, and `TOOLCLAD_OUTPUT_DIR` are added. `TOOLCLAD_SECRET_*` is **never** passed to a child.
- **Secrets**: `{_secret:name}` resolves from the file named by `TOOLCLAD_SECRETS_FILE` (TOML, `name = "value"` at top level; rejected if group- or other-readable) or, failing that, from `TOOLCLAD_SECRET_<NAME>` in the runtime's own environment. The file wins over the variable. A missing secret is a hard error.
- **Binary resolution**: `argv[0]` is resolved to an absolute path against the fixed `PATH` above at spawn time (or used as-is if it already contains a path separator); failure is an execution error. At load, when `tool.binary` is set and the command form is `exec`/`template`, the basename of `argv[0]` must equal the basename of `tool.binary`.
- **Interpreter denylist**: `argv[0]`'s basename may not be `sh`, `bash`, `zsh`, `dash`, `ksh`, `csh`, `tcsh`, `fish`, `ash`, `busybox`, `env`, `eval`, `xargs`, `python`, `python2`, `python3`, `perl`, `ruby`, `node`, `deno`, `bun`, `lua`, `php`, or `awk` unless the manifest sets `[tool] allow_interpreter = true`. This is a load-time check.
- **stdin**: always `/dev/null`.
- **cwd**: a per-invocation scratch directory created mode 0700 under the evidence root (`<evidence_root>/<scan_id>-work`), removed after the run if empty.
- **umask**: 0077 for the child where the language offers a pre-exec hook (Rust, Python).
- **rlimits**: the Rust and Python runtimes set `RLIMIT_CORE = 0`, `RLIMIT_FSIZE = 1 GiB`, `RLIMIT_NOFILE = 1024` on the child, plus `RLIMIT_NPROC`, `RLIMIT_AS` and `RLIMIT_CPU` when `[tool.limits]` declares `nproc` / `address_space_bytes` / `cpu_seconds` (`nofile` and `fsize_bytes` override the defaults). `RLIMIT_NPROC` has no default because Linux counts it against every task the user owns, not the tool's own process tree, so any fixed value stops threaded tools on a busy host. **Go and JavaScript cannot set child rlimits portably and skip this step.** Deployments on those runtimes that need resource limits must apply them outside ToolClad (cgroups, a container runtime, or `ulimit` in the hosting process).

## HTTP Backend Hardening

- **Secrets before arguments**: `{_secret:name}` is expanded on the manifest template (`url`, every `headers` value, `body_template`) *before* any `{arg}` is interpolated, so an argument value can never introduce a secret reference. The `url` validator additionally rejects `{` and `}`.
- **Percent-encoded URL interpolation**: values placed in `http.url` are percent-encoded with each language's standard encoder -- path segments with the path set, query values with the query set.
- **JSON-escaped bodies**: values interpolated into `body_template` are JSON-escaped before substitution. Quotes, backslashes, newlines, and control characters are all escaped, so a value cannot break out of a JSON string field and alter the request body.
- **No redirects**: redirects are never followed. A 3xx response is surfaced as `status: "redirect_blocked"`.
- **Unexpanded `command`**: the envelope's `command` holds `"<METHOD> <http.url as written in the manifest>"`, never the expanded URL, so secrets never reach the agent or the evidence store.
- **Egress lint**: `[http]` manifests are treated as `network_egress = true`, so every network-target argument must set `block_internal = true`.

## Evidence Directories and Files

The evidence root is `TOOLCLAD_EVIDENCE_DIR` when set, otherwise `<tmpdir>/toolclad-evidence` using the platform's temporary directory (`/tmp` on Linux/macOS, `%TEMP%` on Windows). It is created once, mode 0700. Scan ids carry 128 bits of entropy. Raw output files are opened with `O_NOFOLLOW | O_EXCL | O_CREAT` and mode 0600 (the JavaScript runtime uses the `wx` flag plus an `lstat` symlink check), so a pre-planted symlink cannot redirect evidence writes.

## HTTP Error Semantics

HTTP backend responses are classified by status code:

- **2xx**: `success` status in the evidence envelope
- **3xx**: `redirect_blocked` status -- redirects are not followed
- **4xx**: `client_error` status -- the request was malformed or unauthorized
- **5xx**: `server_error` status -- the upstream service failed

This classification gives LLM agents actionable error semantics for self-correction.

## Process Group Kill

Tools are spawned in a new process group (PGID). When `timeout_seconds` is exceeded, the executor sends `SIGTERM` to the entire process group, waits a grace period of `TOOLCLAD_KILL_GRACE_MS` milliseconds (default 2000), then sends `SIGKILL` to the group. Output captured before the kill is returned in the envelope with `status: "timeout"`. `timeout_seconds = 0` is refused at load (`timeout_seconds must be greater than zero`); the default is 60. Killing the whole group prevents:

- Zombie child processes that outlive the timeout
- Background processes spawned by the tool that continue running
- Resource leaks from tools that fork internally

## Absolute Path Blocking

The `path` type rejects:

- Path traversal: any `..` path component, so `../x`, `foo/..`, and a bare `..` are all rejected
- Absolute paths: `/etc/shadow`, `C:\Windows\System32`

NUL bytes are not a `path`-specific rule: the validator rejects `\0` in a value of **every** type (see [Value Hygiene](#value-hygiene)). Paths are constrained to relative locations within the project directory. A tool cannot read or write outside its intended scope.

## Host and IP Policy

Network-target types (`scope_target`, `url` hosts, `ip_address`, `cidr`) share one range table in all four runtimes:

- **Always blocked**, regardless of any manifest setting: IPv4 link-local `169.254.0.0/16` (which includes the cloud metadata address `169.254.169.254`), IPv6 link-local `fe80::/10`, and the IPv4-mapped IPv6 forms of both. Also always blocked: the internal-name denylist -- exact `localhost` or any host ending in `.localhost`, `.local`, `.internal`, `.home.arpa`, `.lan`, `.intranet`, `.corp`, `.private`, or exactly `metadata.google.internal` (`resolves to an internal name — always blocked`).
- **Blocked when `block_internal = true`**: IPv4 loopback `127.0.0.0/8`, private `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`, unspecified `0.0.0.0/8`, broadcast `255.255.255.255`, documentation `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, benchmarking `198.18.0.0/15`, reserved `240.0.0.0/4`; IPv6 loopback `::1`, unspecified `::`, unique-local `fc00::/7`, documentation `2001:db8::/32`; and the IPv4-mapped IPv6 forms of all of these.
- **Hostnames** are examined before any lookup: punycode (`xn--`) labels and non-canonical IP literal encodings (`0x...`, all-numeric labels, octal or shorthand forms) are rejected; a hostname whose first four labels form a dotted quad (`127.0.0.1.nip.io`, `169.254.169.254.xip.io`) or a leading dashed quad (`10-0-0-1.nip.io`) is treated as that IP.
- **DNS under `block_internal`**: a hostname is resolved and **every** A/AAAA answer is checked against the table; resolution failure is a rejection (`could not resolve host '<h>' to verify it is public (block_internal)`). The synchronous JavaScript `validateArg` cannot resolve names and refuses a hostname under `block_internal`; use `validateArgAsync`.
- **CIDR values** are tested for **overlap** with each blocked range, not just their base address, so `8.0.0.0/5` fails under `block_internal` because it overlaps `10.0.0.0/8`.
- **Egress lint**: when `[tool] network_egress = true`, when the dispatched binary is a known egress tool (`curl`, `wget`, `nmap`, `nc`, `ncat`, `netcat`, `masscan`, `telnet`, `ssh`, `ping`, `fping`, `httpie`, `http`, `wfuzz`, `ffuf`, `hydra`, `nikto`), or when the manifest uses `[http]` or `[browser]`, every argument of type `scope_target`, `url`, `ip_address`, `cidr`, or a custom type based on one of those must set `block_internal = true`, or the manifest is refused at load.

See [Type System](type-system.md#host-and-ip-policy-block_internal) for the per-type details.

## Scope Enforcement

Scope enforcement is opt-in per argument and fail-closed. An argument of type `scope_target`, `url`, `ip_address`, or `cidr` that sets `scope_check = true` is checked against the project scope file during validation, before the command is built. **`scope_target` alone is only a shape check** -- it guarantees the value is a well-formed IP, CIDR, or hostname. Allowlisting against the project scope requires `scope_check = true`.

### Scope File

```toml
# scope/scope.toml
[scope]
allowed_cidrs   = ["10.0.1.0/24"]
allowed_domains = ["example.com", "*.example.com"]
blocked_cidrs   = []
blocked_domains = []
```

Unknown keys in the scope file are refused, exactly as in manifests.

Discovery order:

1. The path in the `TOOLCLAD_SCOPE_FILE` environment variable (absolute or relative).
2. `scope/scope.toml`, searched upward from the manifest's directory (or from the current working directory when a manifest is loaded from a string), stopping at the filesystem root.

### Semantics

- **Fail-closed**: if `scope_check = true` and no scope file is reachable, the value is rejected -- `scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)`. There is no implicit "allow everything" when the file is missing.
- **Checked value**: the host for `url` arguments (extracted after scheme, userinfo, and port handling); the value itself for the other types.
- **Blocked before allowed**: blocked rules are evaluated first and always win.
- **Domain rules**: an exact rule matches when it equals the host, case-insensitively. A wildcard rule `*.suffix` matches when the host ends with `.suffix` -- a strict subdomain at any depth. `*.example.com` matches `app.example.com` and `deep.sub.example.com` but **not** the apex `example.com` and **not** `evil-example.com`. To allow the apex, list it explicitly, as the repository's starter `scope/scope.toml` does.
- **IP values** match when contained in an allowed CIDR.
- **CIDR values** match only when **fully contained** in an allowed CIDR; a range that merely overlaps an allowed range is out of scope.
- **No match**: `target '<value>' is not in scope`.

The check is defense in depth alongside external authorization: even if a policy bug allows an out-of-scope target, the type system catches it. The repository ships `tests/scope_vectors.json`, which all four runtimes must pass.

For browser mode, a hosting runtime extends URL scope enforcement to navigation, redirects, and link clicks via `[browser.scope]`. The reference runtimes parse `[browser.scope]` but do not execute browser sessions; see [Browser Mode](browser-mode.md).

## Policy Gate

Every `execute` call passes through a policy gate before anything is spawned:

```
GateDecision = Allow | Deny(reason)
Gate         = fn(&Manifest, &validated_args) -> GateDecision
```

The default gate **denies** when `tool.human_approval = true` (`manifest requires human approval (human_approval = true)`) or when `tool.risk_tier` is `high` or `critical` (`risk_tier '<t>' requires explicit approval`), and allows otherwise. A denied call returns or raises a structured error whose message starts with `policy gate denied: `. Nothing is executed on denial.

- The CLIs expose `run --approve`, which switches to an allow-all gate for that invocation.
- Library callers can supply their own gate (`execute_with_gate` in Rust, `ExecuteWithGate` in Go, `execute(..., gate=...)` in Python, `execute(manifest, args, { gate })` in JavaScript) to integrate an approval workflow or a policy engine. See [API Reference](api-reference.md).
- **Cedar evaluation is external.** The reference runtimes do not evaluate Cedar policies; `[tool.cedar]` is metadata for a hosting runtime's policy engine, which can be plugged in through the gate seam.

## Output Caps and Fail-Closed Schema Validation

- `[output] max_bytes` (default `8388608`, 8 MiB) caps stdout and stderr independently. On overflow, capture stops and the envelope carries `"output_truncated": true`; the status is unaffected.
- XML output containing `<!DOCTYPE` or `<!ENTITY` (case-insensitive) is refused before parsing, closing entity-expansion attacks.
- Parsed output is validated against `[output.schema]` by a bundled JSON-Schema subset validator (no external dependency) supporting `type`, `properties`, `required`, `items`, `additionalProperties` (boolean), `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, and `pattern`; unknown keywords are ignored.
- Validation is **fail-closed**: a violation sets `status` to `schema_error`, replaces `results` with `{"schema_error": "<path>: <message>"}`, and preserves the raw output under `results.raw_output`. Malformed output never reaches the agent as if it were valid.
- A `parser` value that is not one of the `builtin:*` names is refused at load (`custom output parsers are not supported by the reference runtimes`); there is no path for an external script to run in the output pipeline.

## Cedar Policy Integration

The `[tool.cedar]` section declares the Cedar resource and action for the tool:

```toml
[tool.cedar]
resource = "PenTest::ScanTarget"
action = "execute_tool"
```

A hosting runtime's Gate phase builds a Cedar authorization request from the manifest metadata plus the agent's runtime context (phase, environment, agent identity). Cedar policies in `policies/` evaluate this request and produce `ALLOW`, `DENY`, or `PENDING` (for human approval). The reference runtimes do not evaluate Cedar themselves; they ship the deny-by-default [policy gate](#policy-gate) above and a gate seam through which a hosting runtime wires Cedar in.

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

### SchemaPin v1.4 Hardening (alpha)

SchemaPin v1.4-alpha (released 2026-04-30 / 2026-05-01) adds three additive optional fields and one cross-channel verification mechanism that ToolClad publishers SHOULD adopt for defense-in-depth. None of them require manifest changes — they are signing-time options on `schemapin-sign`.

| Feature | What it adds | ToolClad use |
|---------|-------------|--------------|
| **Signature expiration** (`expires_at`) | Optional RFC 3339 TTL on the signature. Past the expiry, verifiers degrade (warn) rather than fail. | Sign with a 6-month TTL; runtime policy can refuse `risk_tier = "high"` tools whose signature is stale. |
| **Schema version binding** (`schema_version` + `previous_hash`) | Optional semver tag plus a hash chain to the prior signed version. Defends against rug-pull substitutions. | Set `schema_version` to your manifest's `[tool] version`. Set `previous_hash` to the prior release's `skill_hash`. |
| **DNS TXT cross-verification** (`_schemapin.{vendor-domain}`) | Optional second-channel trust signal independent of HTTPS hosting. | Publish the TXT record alongside `.well-known/schemapin.json`. A divergence between the two indicates compromise of one channel. |

Recommended sign command for a versioned ToolClad release:

```bash
# Read [tool] version from the manifest (semver string already required)
TOOL_VERSION=$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' tools/nmap_scan.clad.toml)

# For the first release of a tool: no previous_hash
schemapin-sign tools/nmap_scan.clad.toml \
    --expires-in 6mo \
    --schema-version "$TOOL_VERSION"

# For subsequent releases: chain to the prior signed version
PREV_HASH=$(jq -r '.skill_hash' tools/nmap_scan.clad.toml.sig.prior)
schemapin-sign tools/nmap_scan.clad.toml \
    --expires-in 6mo \
    --schema-version "$TOOL_VERSION" \
    --previous-hash "$PREV_HASH"
```

Verifiers (Symbiont, custom runtimes) SHOULD:

1. Treat `expired = true` as a policy signal — refuse high-risk tools, prompt on medium-risk, log on low-risk.
2. Maintain a per-tool `latest_known_hash` next to the TOFU pin. On encountering a signature whose `previous_hash` doesn't match that pin, prompt the operator (similar to the TOFU key-rotation prompt) before rolling forward.
3. When the vendor publishes a `_schemapin.{vendor-domain}` TXT record, fetch it and require the fingerprint to match the discovery-document key. Mismatch is a hard fail (`DOMAIN_MISMATCH`).

See the canonical SchemaPin guides for protocol detail:

- [Signature expiration](https://docs.schemapin.org/signature-expiration/)
- [Schema version binding](https://docs.schemapin.org/schema-version-binding/)
- [DNS TXT cross-verification](https://docs.schemapin.org/dns-txt/)

Backward compatibility: all three are additive optional. SchemaPin v1.3 verifiers ignore the new fields entirely; ToolClad publishers can adopt them at their own pace without breaking older runtimes.

## No-Eval Guarantee

Conditional evaluators in `[command.conditionals]` use closed-vocabulary parsers:

```toml
[command.conditionals]
service_port = { when = "port != 0", template = "-s {port}" }
```

The `when` expression supports only:

- Variable references (declared parameter names)
- Comparison operators (`==`, `!=`)
- Logical operators (`and`, `or`)
- String literals and numeric literals

**SECURITY REQUIREMENT:** Implementations MUST NOT use `eval()`, `Function()`, `exec()`, or any dynamic code execution mechanism to resolve conditions. Doing so creates a Remote Code Execution (RCE) vulnerability if an attacker can influence manifest content or argument values. All four reference implementations enforce this with a regex-based comparison parser.

## Cross-Language Scope Validation

Scope validation involves non-trivial logic: CIDR containment math, IPv4/IPv6 normalization, DNS wildcard suffix matching. Re-implementing this in four languages creates a risk of security drift.

To mitigate this, ToolClad provides:

1. **Normative test vectors** (`tests/scope_vectors.json` for scope matching, `tests/injection_vectors.json` for argument and manifest rejection) — shared test cases that all implementations must pass
2. **Fuzz targets** in each runtime that assert the validator never panics and never returns a value containing whitespace, a quote, or a leading dash for a string-derived type without the corresponding opt-in
3. **Centralization path** — production deployments can use a single scope validation endpoint (gRPC/HTTP) or compile a Rust-based validator to WebAssembly for cross-language use

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
    -> The policy gate (and, in a hosting runtime, Cedar) authorizes this invocation
      -> The executor validates arguments against manifest types
        -> The executor constructs and runs the command
          -> Each layer trusts the one before it
```

Each layer in the chain has a single responsibility:

1. **SchemaPin**: Integrity -- the manifest is authentic and unmodified
2. **Manifest**: Interface -- only declared operations with typed parameters
3. **Policy gate / Cedar**: Authorization -- this agent, in this context, is allowed to invoke this tool
4. **Executor**: Validation -- all parameter values satisfy their type constraints
5. **Runtime**: Execution -- array-based dispatch with a hardened environment, timeout, and process isolation
