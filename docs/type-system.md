# Type System

ToolClad provides 14 built-in types (10 core + 4 extended) that cover the validation patterns repeated across tool wrappers. Every type includes injection sanitization by default. Types are designed so that "valid according to the type" means "safe to interpolate into a command."

## Injection Sanitization

All string-based types reject shell metacharacters by default:

```
Blocked characters: ; | & $ ` ( ) { } [ ] < > ! \n \r
```

Newline injection (`\n`, `\r`) is blocked on all string-based types. This prevents argument splitting, header injection, and command chaining. The command is never constructed if validation fails.

Even if injection characters somehow passed type validation, array-based execution (`execve`, no `sh -c`) treats them as literal strings. Injection sanitization is the first defense layer; direct `execve` is the second.

---

## Core Types

### `string`

General-purpose text. Optionally constrained by regex `pattern`. When `sanitize = ["injection"]` is set, shell metacharacters are explicitly rejected. Without explicit sanitization, strings are still validated against any declared `pattern`.

**Validation rules:**

- Trim whitespace
- If `sanitize = ["injection"]`, reject shell metacharacters
- If `pattern` is declared, value must match the regex
- Empty strings are allowed unless `required = true` and no `default` is set

```toml
[args.name]
type = "string"
description = "General text argument"

[args.module_path]
type = "string"
pattern = "^(exploit|auxiliary|post)/[a-zA-Z0-9_/]+$"
sanitize = ["injection"]
description = "Metasploit module path"
```

**Valid:** `hello-world`, `exploit/windows/smb/ms17_010`

**Rejected:** `hello; rm -rf /` (injection), `$(whoami)` (injection), `Hello123` (pattern mismatch for `^[a-z]+$`)

### `integer`

Numeric value parsed from a string. Optional `min`/`max` bounds with optional `clamp` behavior.

**Validation rules:**

- Must parse as a signed 64-bit integer
- If `min` is set and value is below, reject (or clamp if `clamp = true`)
- If `max` is set and value is above, reject (or clamp if `clamp = true`)

```toml
[args.threads]
type = "integer"
min = 1
max = 64
clamp = true       # Out-of-range values are clamped, not rejected
default = 4
description = "Concurrent threads"
```

**Valid:** `42`, `-1` (if no min constraint), `0`

**Clamped:** `100` becomes `64` (when `max = 64, clamp = true`), `0` becomes `1` (when `min = 1, clamp = true`)

**Rejected:** `abc` (not a number), `100` (when `max = 64, clamp = false`)

### `port`

Integer in the range 1--65535. No additional constraints needed.

**Validation rules:**

- Must parse as an unsigned 16-bit integer
- Must be between 1 and 65535 inclusive (port 0 is rejected)

```toml
[args.target_port]
type = "port"
default = 443
description = "Target port"
```

**Valid:** `80`, `443`, `8080`, `65535`

**Rejected:** `0`, `70000`, `abc`, `-1`

### `boolean`

Exactly `"true"` or `"false"` (strings). No truthy/falsy interpretation. No `"yes"`, `"no"`, `"1"`, `"0"`.

**Validation rules:**

- Value must be exactly the string `"true"` or `"false"`

```toml
[args.verbose]
type = "boolean"
default = "false"
description = "Enable verbose output"
```

**Valid:** `true`, `false`

**Rejected:** `yes`, `no`, `1`, `0`, `True`, `FALSE`

### `enum`

Value must be in the declared `allowed` list. Exact string match, case-sensitive.

**Validation rules:**

- The `allowed` field must be present in the arg definition
- Value must exactly match one entry in the `allowed` list

```toml
[args.scan_type]
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect", "aggressive"]
description = "Type of scan to perform"
```

**Valid:** `ping`, `service`, `syn`

**Rejected:** `Ping` (case mismatch), `full` (not in allowed list), `aggressive_scan` (not in list)

### `scope_target`

Injection-safe string validated for use as a network target. Blocks wildcards (`*`). Valid values: IPv4 addresses, IPv6 addresses, CIDR ranges, and hostnames. Automatically checked against the project scope (`scope/scope.toml`) when running in Symbiont.

**Validation rules:**

- Reject all shell metacharacters
- Reject wildcard characters (`*`)
- Must match one of: valid IPv4, valid IPv6, valid CIDR (IPv4), or valid hostname

```toml
[args.target]
type = "scope_target"
required = true
description = "Target CIDR, IP, or hostname"
```

**Valid:** `10.0.1.1`, `10.0.1.0/24`, `example.com`, `::1`, `2001:db8::1`

**Rejected:** `*.example.com` (wildcard), `10.0.0.0/8; rm -rf /` (injection), `not a valid host` (invalid format)

### `url`

Valid URL structure. Must start with `http://` or `https://`. Optional `schemes` restriction and `scope_check` flag.

**Validation rules:**

- Reject shell metacharacters
- Must match URL pattern: `^https?://[a-zA-Z0-9\-\.]+(/[^\s]*)?$`
- If `schemes` is set, the URL scheme must be in the list
- If `scope_check = true`, the host is extracted and validated against the project scope

```toml
[args.target_url]
type = "url"
schemes = ["http", "https"]    # Only these URL schemes allowed
scope_check = true              # Extract host for scope validation
description = "Target web application URL"
```

**Valid:** `http://example.com/path`, `https://test.org`

**Rejected:** `ftp://evil.com` (invalid scheme), `not a url` (invalid format), `javascript:alert(1)` (invalid scheme)

### `path`

File path with safety constraints. Blocks directory traversal and absolute paths.

**Validation rules:**

- Reject shell metacharacters
- Reject traversal sequences: `../` and `..\`
- Reject absolute paths: paths starting with `/` or containing `X:` (Windows drive letter)

```toml
[args.wordlist]
type = "path"
required = false
description = "Path to wordlist file"
```

**Valid:** `config/settings.toml`, `data/wordlist.txt`, `output.json`

**Rejected:** `../../../etc/passwd` (traversal), `/etc/shadow` (absolute), `C:\Windows\System32` (absolute)

### `ip_address`

Valid IPv4 or IPv6 address. Parsed and validated by standard library address parsers.

**Validation rules:**

- Must parse as a valid `Ipv4Addr` or `Ipv6Addr`

```toml
[args.lhost]
type = "ip_address"
description = "Listener IP address (LHOST)"
```

**Valid:** `192.168.1.1`, `10.0.0.1`, `::1`, `2001:db8::1`, `fe80::1`

**Rejected:** `not-an-ip`, `999.999.999.999`, `example.com`

### `cidr`

Valid CIDR notation. IPv4 address followed by `/` and a prefix length (0--32).

**Validation rules:**

- Must match CIDR pattern: `^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$`
- The IP portion must parse as a valid IPv4 address
- The prefix length must be 0--32

```toml
[args.network]
type = "cidr"
description = "Network range to scan"
```

**Valid:** `10.0.1.0/24`, `192.168.0.0/16`, `10.0.0.0/8`

**Rejected:** `10.0.0.0/33` (prefix too large), `10.0.0.0` (missing prefix), `not-cidr/24` (invalid IP)

---

## Extended Types

### `msf_options`

Semicolon-delimited `set KEY VALUE` pairs for Metasploit. Shell metacharacters are rejected in both keys and values.

**Validation rules:**

- Split on `;` delimiter
- Each segment must match `set KEY VALUE` format
- No shell metacharacters in keys or values

```toml
[args.options]
type = "msf_options"
required = false
description = "Additional set KEY VALUE options, semicolon-delimited"
```

**Valid:** `set THREADS 10; set SSL true`

**Rejected:** `set RHOSTS $(whoami)` (injection)

### `credential_file`

Path type with additional constraint: the file must exist and be readable. Used for username/password lists in brute-force tools.

**Validation rules:**

- All `path` type rules apply (no traversal, no absolute paths)
- File must exist on disk
- File must be readable by the current process

```toml
[args.password_file]
type = "credential_file"
required = false
description = "Path to password list"
```

### `duration`

Integer with optional time suffix. Bare numbers are treated as seconds. Normalized to seconds for command interpolation.

**Validation rules:**

- Must be a positive integer, optionally followed by a suffix
- Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours)
- Bare integers are treated as seconds

```toml
[args.timeout]
type = "duration"
default = "5m"
description = "Script timeout override"
```

**Valid:** `30` (30 seconds), `30s` (30 seconds), `5m` (300 seconds), `2h` (7200 seconds)

### `regex_match`

String that must match a declared `pattern` (required for this type). Functionally similar to `string` with a `pattern`, but semantically indicates the value must conform to a specific format. Injection sanitization is applied by default.

**Validation rules:**

- The `pattern` field is mandatory for this type
- Value must match the declared regex
- Shell metacharacters are rejected

```toml
[args.module]
type = "regex_match"
pattern = "^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$"
description = "Module identifier"
```

---

## Custom Types

Define reusable types in `toolclad.toml` at the project root:

```toml
# toolclad.toml
[types.service_protocol]
base = "enum"
allowed = ["ssh", "ftp", "http", "https", "smb", "rdp", "mysql", "postgres", "mssql", "vnc"]

[types.severity_level]
base = "enum"
allowed = ["info", "low", "medium", "high", "critical"]

[types.nuclei_template_id]
base = "string"
pattern = "^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$"
```

Reference in manifests:

```toml
[args.service]
type = "service_protocol"
description = "Target service"

[args.severity]
type = "severity_level"
description = "Minimum severity to report"
```

Custom types inherit all validation behavior from their `base` type, plus any additional constraints declared in the type definition. This eliminates duplication across manifests when multiple tools share the same domain-specific types.

---

## Type Composition Summary

| Constraint | Applies To | Behavior |
|------------|-----------|----------|
| `min` / `max` | `integer` | Bounds checking |
| `clamp` | `integer` | Clamp to range instead of rejecting |
| `pattern` | `string`, `regex_match` | Regex validation |
| `allowed` | `enum` | Exhaustive value list |
| `schemes` | `url` | Restrict URL schemes |
| `scope_check` | `url` | Extract host for scope validation |
| `sanitize` | all string-based | Explicit injection sanitization |
| `default` | any | Value when parameter not provided |

## Validation Error Examples

```
target: injection characters detected (;) in scope_target value
scan_type: value "full" not in allowed list [ping, service, version, syn]
threads: value 100 exceeds max 64
target_url: scheme "ftp" not in allowed schemes [http, https]
wordlist: path traversal detected (../)
lhost: invalid IP address "not-an-ip"
network: invalid CIDR notation "10.0.1.0/33"
port: port must be 1-65535
```

Every validation error identifies the parameter name, the type constraint that failed, and the rejected value. The command is never constructed if any argument fails validation.
