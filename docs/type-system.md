# Type System

ToolClad provides 15 built-in types (11 core + 4 extended) that cover the validation patterns repeated across tool wrappers. Every type includes injection sanitization by default. Types are designed so that "valid according to the type" means "safe to interpolate into a command."

## Injection Sanitization and Value Hygiene

All string-based types reject shell metacharacters by default:

```
Blocked characters: ; | & $ ` ( ) { } [ ] < > !
```

In addition, every **string-derived** type (`string`, `path`, `credential_file`, `regex_match`, `url`, `scope_target`, `duration`, `msf_options`) is checked, in this order, before any type-specific parsing:

| # | Rule | Error | Opt-out |
|---|------|-------|---------|
| 1 | No NUL byte (`\0`) -- applies to **every** type, including `enum` | `must not contain NUL bytes` | none |
| 2 | No control characters (U+0000-U+001F, U+007F); this covers `\n`, `\r`, `\t` | `must not contain control characters` | none |
| 3 | No `'`, `"`, or `\` | `must not contain quote or backslash characters` | none |
| 4 | No Unicode whitespace | `must not contain whitespace` | `allow_whitespace = true`, honored only when the manifest declares `command.exec` directly; `msf_options` is exempt (the space is its separator); `url` is never exempt |
| 5 | No leading `-` or `+` | `must not start with '-' or '+' (set allow_leading_dash = true to permit)` | `allow_leading_dash = true` |

Numeric types (`integer`, `number`, `port`) apply rule 5 to the **output** value after range-checking or clamping: `-1` with no bounds is rejected, `-5` with `clamp = true` and `min = 1` becomes `1` and passes, and `allow_leading_dash = true` permits a negative result. `enum` values are exempt from rules 2-5 because they come from the manifest's `allowed` list.

`allow_whitespace` is only honored in `exec` mode: a `template` that was compiled to `exec` at load is still validated in template mode, where whitespace is always rejected. In `exec` mode a value stays exactly one argv element no matter what it contains, which is why whitespace can be permitted there.

**Pattern anchoring.** Every `pattern` -- on `[args.*]` and on custom types -- is anchored before use: one leading `^` and one trailing `$` are stripped if present, then the pattern is compiled as `^(?:pat)$`. Python uses `^(?:pat)\Z` with `re.match` so a trailing newline cannot match. A pattern always describes the whole value, never a substring.

These rules prevent argument splitting, option injection, header injection, and command chaining. The command is never constructed if validation fails.

Even if injection characters somehow passed type validation, array-based execution (`execve`, no `sh -c`) treats them as literal strings. Injection sanitization is the first defense layer; direct `execve` is the second.

---

## Core Types

### `string`

General-purpose text. Optionally constrained by an anchored regex `pattern`. Shell metacharacters and the value-hygiene rules above are applied by default; `sanitize = ["injection"]` makes that explicit.

**Validation rules:**

- Value hygiene (NUL, control characters, quotes/backslash, whitespace, leading dash)
- Reject shell metacharacters
- If `pattern` is declared, the whole value must match `^(?:pattern)$`
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

[args.headers]
type = "string"
allow_whitespace = true        # honored only when [command] uses exec = [...]
default = ""
description = "One extra header as 'Key: Value'"
```

**Valid:** `hello-world`, `exploit/windows/smb/ms17_010`, `X-Trace: on` (only with `allow_whitespace = true` in `exec` mode)

**Rejected:** `hello; rm -rf /` (injection), `$(whoami)` (injection), `Hello123` (pattern mismatch for `^[a-z]+$`), `a b` (whitespace), `-v` (leading dash), `it's` (quote)

### `integer`

Numeric value parsed from a string. Optional `min`/`max` bounds with optional `clamp` behavior.

**Validation rules:**

- The string form must match `^[+-]?\d+$` -- no surrounding whitespace, no `0x10`, no `1_000`, no empty string
- Must parse as a signed 64-bit integer
- If `min` is set and value is below, reject (or clamp if `clamp = true`)
- If `max` is set and value is above, reject (or clamp if `clamp = true`)
- The resulting value must not start with `-` or `+` unless `allow_leading_dash = true`

```toml
[args.threads]
type = "integer"
min = 1
max = 64
clamp = true       # Out-of-range values are clamped, not rejected
default = 4
description = "Concurrent threads"
```

**Valid:** `42`, `0`, `-1` (only with `allow_leading_dash = true`)

**Clamped:** `100` becomes `64` (when `max = 64, clamp = true`), `-5` becomes `1` (when `min = 1, clamp = true`; the clamped output has no leading dash, so it passes)

**Rejected:** `abc` (not a number), `100` (when `max = 64, clamp = false`), `-1` (leading dash without `allow_leading_dash`), ` 7 ` (whitespace), `0x10`

### `number`

Floating-point value parsed from a string. Optional `min_float`/`max_float` bounds with optional `clamp` behavior.

**Validation rules:**

- Must parse as a finite float; `NaN`, `inf`, and `-inf` are rejected
- If `min_float` is set and value is below, reject (or clamp if `clamp = true`)
- If `max_float` is set and value is above, reject (or clamp if `clamp = true`)
- The output is re-rendered from the parsed float with the shortest round-trip representation, so all four runtimes produce the same string
- The resulting value must not start with `-` or `+` unless `allow_leading_dash = true`

```toml
[args.confidence]
type = "number"
min_float = 0.0
max_float = 1.0
clamp = true
default = 0.5
description = "Confidence threshold"
```

**Valid:** `0.75`, `1`, `2.5e-3`

**Rejected:** `NaN`, `inf`, `abc`, `-0.5` (leading dash without `allow_leading_dash`)

### `port`

Integer in the range 1--65535. No additional constraints needed.

**Validation rules:**

- The string form must match `^\d+$`
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

The strings `true` or `false`, compared case-insensitively and normalized to lowercase. No truthy/falsy interpretation. No `"yes"`, `"no"`, `"1"`, `"0"`.

**Validation rules:**

- Value must equal `true` or `false` ignoring case
- The normalized lowercase form is what reaches the command

```toml
[args.verbose]
type = "boolean"
default = "false"
description = "Enable verbose output"
```

**Valid:** `true`, `false`, `True`, `FALSE` (normalized to `true` / `false`)

**Rejected:** `yes`, `no`, `1`, `0`, ` true` (whitespace)

### `enum`

Value must be in the declared `allowed` list. Exact string match, case-sensitive.

**Validation rules:**

- The `allowed` field must be present in the arg definition
- Value must exactly match one entry in the `allowed` list
- NUL bytes are rejected; the other hygiene rules do not apply because the value is drawn from the manifest's list

```toml
[args.scan_type]
type = "enum"
allowed = ["ping", "service", "version", "syn", "os_detect", "aggressive"]
description = "Type of scan to perform"
```

**Valid:** `ping`, `service`, `syn`

**Rejected:** `Ping` (case mismatch), `full` (not in allowed list), `aggressive_scan` (not in list)

### `scope_target`

Injection-safe string validated for use as a network target. Blocks wildcards (`*`). Valid values: IPv4 addresses, IPv6 addresses, CIDR ranges (IPv4 and IPv6), and hostnames. On its own this is a **shape check**: it guarantees the value is a well-formed target. Allowlisting against the project scope requires `scope_check = true`, and blocking internal ranges requires `block_internal = true`.

**Validation rules:**

- Value hygiene (NUL, control characters, quotes/backslash, whitespace, leading dash)
- Reject all shell metacharacters and wildcard characters (`*`)
- ASCII only; punycode (`xn--`) labels are rejected
- Must match one of: canonical IPv4, canonical IPv6, IPv4 or IPv6 CIDR, or a valid hostname. Non-canonical IP literal encodings (`0x7f000001`, `2130706433`, `0177.0.0.1`, `127.1`) are rejected; a numeric top-level label and a trailing dot are rejected
- The [host and IP policy](#host-and-ip-policy-block_internal) applies: link-local ranges and the internal-name denylist are always blocked; `block_internal = true` blocks the private ranges too and resolves hostnames
- If `scope_check = true`, the value is checked against `scope/scope.toml` (fail-closed)

```toml
[args.target]
type = "scope_target"
required = true
block_internal = true       # required when the tool reaches the network
scope_check = true          # optional: allowlist against scope/scope.toml
description = "Target CIDR, IP, or hostname"
```

**Valid:** `10.0.1.1`, `10.0.1.0/24`, `example.com`, `2001:db8::/32` (shape only -- with `block_internal = true` the private and documentation ranges here are rejected)

**Rejected:** `*.example.com` (wildcard), `10.0.0.0/8; rm -rf /` (injection), `not a valid host` (whitespace / invalid format), `-example.com` (leading dash), `localhost` (always blocked), `169.254.169.254` (always blocked), `127.0.0.1.nip.io` (embedded IP literal), `example.com.` (trailing dot)

### `url`

A `scheme://host[:port][/path][?query][#fragment]` URL with an allowlisted scheme, no userinfo, and a host that passes the host/IP policy. Optional `schemes`, `block_internal`, and `scope_check`.

**Validation rules, in order:**

1. Value hygiene (NUL, control characters, quotes/backslash, leading dash) and the shell-metacharacter blocklist. Whitespace is **never** allowed in a `url`, even with `allow_whitespace = true`. The metacharacter blocklist rejects `{` and `}`, so a value can never carry a `{_secret:...}` reference.
2. The value must contain `://`; it is split into `scheme` and the remainder.
3. The scheme (compared lowercase) must be in `schemes` when that list is non-empty, otherwise in the default `["http", "https"]`.
4. `javascript`, `data`, `file`, `blob`, `about`, `gopher`, `dict`, `ftp`, `ldap`, `jar`, `netdoc`, `mailto`, `ws`, and `wss` are rejected with a dedicated message **even if listed in `schemes`**.
5. Userinfo is rejected: an `@` before the first `/` of the authority fails.
6. The host is everything between `://` and the first `/`, `?`, or `#`. An empty host is rejected. A bracketed IPv6 literal `[...]` is unwrapped. A trailing `:port` is split off and must be 1-65535.
7. The [host and IP policy](#host-and-ip-policy-block_internal) is applied to the host: punycode and non-canonical IP literals are rejected, embedded IP literals are unwrapped, the internal-name denylist and always-blocked ranges apply, and `block_internal = true` adds the private ranges and DNS resolution.
8. If `scope_check = true`, the host is checked against `scope/scope.toml` (fail-closed).

```toml
[args.target_url]
type = "url"
schemes = ["http", "https"]    # Only these URL schemes allowed (this is also the default)
block_internal = true          # Required when the tool fetches the URL
scope_check = true              # Extract host for scope validation
description = "Target web application URL"
```

**Valid:** `http://example.com/path`, `https://test.org:8443/`, `https://[2001:db8::1]/` (shape only; rejected under `block_internal`)

**Rejected:** `ftp://evil.com` (scheme always denied), `not a url` (no `://`), `javascript:alert(1)` (scheme always denied), `https://user:pw@example.com/` (userinfo), `https://example.com:99999/` (port out of range), `https://localhost/` (internal name, always blocked), `http://169.254.169.254/latest/meta-data/` (link-local, always blocked), `http://10.0.0.1/` (rejected under `block_internal`), `http://127.0.0.1.nip.io/` (embedded IP literal), `https://example.com/{_secret:token}` (braces)

### `path`

File path with safety constraints. Blocks directory traversal and absolute paths.

**Validation rules:**

- Value hygiene (NUL, control characters, quotes/backslash, whitespace, leading dash)
- Reject shell metacharacters
- Reject any `..` path component -- `../x`, `foo/..`, and a bare `..` are all rejected, not just the `../` substring
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

Valid IPv4 or IPv6 address literal in canonical form. Optional `block_internal` and `scope_check`.

**Validation rules:**

- Must parse as a valid IPv4 or IPv6 address
- Non-canonical encodings (`0x7f000001`, `2130706433`, `0177.0.0.1`, `127.1`) are rejected
- The [host and IP policy](#host-and-ip-policy-block_internal) applies: link-local `169.254.0.0/16` and `fe80::/10` are always blocked; `block_internal = true` blocks loopback, private, CGNAT, documentation, and reserved ranges
- If `scope_check = true`, the address must be contained in an allowed CIDR of `scope/scope.toml`

```toml
[args.lhost]
type = "ip_address"
description = "Listener IP address (LHOST)"
```

**Valid:** `192.168.1.1`, `10.0.0.1`, `::1`, `2001:db8::1` (shape only -- all four are rejected under `block_internal = true`), `93.184.216.34`

**Rejected:** `not-an-ip`, `999.999.999.999`, `example.com`, `fe80::1` (link-local, always blocked), `169.254.169.254` (always blocked), `0x7f000001` (non-canonical)

### `cidr`

Valid CIDR notation: an IPv4 or IPv6 address followed by `/` and a prefix length. Optional `block_internal` and `scope_check`.

**Validation rules:**

- The address portion must parse as a canonical IPv4 or IPv6 address
- The prefix length must be 0-32 for IPv4 and 0-128 for IPv6
- The [host and IP policy](#host-and-ip-policy-block_internal) is tested for **overlap**: the range is rejected if it overlaps any blocked range, not only if its base address is blocked. `8.0.0.0/5` fails under `block_internal` because it overlaps `10.0.0.0/8`
- If `scope_check = true`, the range must be **fully contained** in an allowed CIDR of `scope/scope.toml`

```toml
[args.network]
type = "cidr"
block_internal = true
description = "Network range to scan"
```

**Valid:** `10.0.1.0/24`, `192.168.0.0/16`, `2001:db8::/32` (shape only -- all rejected under `block_internal`), `203.0.113.0/24` (shape only; documentation range)

**Rejected:** `10.0.0.0/33` (prefix too large), `10.0.0.0` (missing prefix), `not-cidr/24` (invalid IP), `0.0.0.0/0` (overlaps always-blocked link-local), `8.0.0.0/5` (overlaps `10.0.0.0/8` under `block_internal`)

---

## Extended Types

### `msf_options`

Semicolon-delimited `set KEY VALUE` pairs for Metasploit. Shell metacharacters are rejected in both keys and values. This is the only string-derived type exempt from the whitespace rule, because the space is its `KEY VALUE` separator; NUL, control characters, quotes/backslash, and a leading dash are still rejected.

**Validation rules:**

- Value hygiene except the whitespace rule
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

Integer with optional time-unit components. Bare numbers are treated as seconds.

**Validation rules:**

- Value hygiene (NUL, control characters, quotes/backslash, whitespace, leading dash)
- Must match `^\d+$` or `^(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?$` with a non-empty match -- no surrounding whitespace, no trailing newline
- Bare integers are treated as seconds

```toml
[args.timeout]
type = "duration"
default = "5m"
description = "Script timeout override"
```

**Valid:** `30`, `30s`, `5m`, `2h`, `1h30m`, `500ms`

**Rejected:** `` (empty), `5 m` (whitespace), `-5m` (leading dash), `5d` (unknown unit), `30s\n` (trailing newline)

### `regex_match`

String that must match a declared `pattern` (required for this type). Functionally similar to `string` with a `pattern`, but semantically indicates the value must conform to a specific format. Injection sanitization is applied by default.

**Validation rules:**

- The `pattern` field is mandatory for this type
- The whole value must match the declared regex (anchored as `^(?:pattern)$`)
- Shell metacharacters and the value-hygiene rules are applied

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

Rules that apply to custom types:

- A custom `pattern` is anchored exactly like an arg `pattern`: `[a-z]+` means `^(?:[a-z]+)$`, not a substring search.
- A custom type **cannot** carry `block_internal` or `scope_check`. An argument that names a network target must therefore use the built-in `scope_target`, `url`, `ip_address`, or `cidr` type directly. A custom type whose `base` is one of those still counts as a network target for the egress lint, so a manifest that dispatches a network-egress binary with such an argument is refused at load unless the argument sets `block_internal = true` -- which it cannot through the custom type.
- The CLIs discover `toolclad.toml` by walking up from the manifest's directory, so custom types resolve both from the library and from `toolclad validate` / `toolclad test`.

---

## Host and IP Policy (`block_internal`)

The network-target types (`scope_target`, `url` hosts, `ip_address`, `cidr`) share one range table, implemented identically in all four runtimes.

### Always blocked

These are rejected regardless of `block_internal`:

| Range | Reason |
|-------|--------|
| `169.254.0.0/16` | IPv4 link-local, includes the cloud metadata address `169.254.169.254` |
| `fe80::/10` | IPv6 link-local |
| IPv4-mapped IPv6 forms of the above (`::ffff:169.254.0.0/112`) | same |
| `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, `*.lan`, `*.intranet`, `*.corp`, `*.private`, `metadata.google.internal` | internal-name denylist, rejected with `resolves to an internal name — always blocked` |

### Blocked when `block_internal = true`

| Family | Ranges |
|--------|--------|
| IPv4 | loopback `127.0.0.0/8`, private `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, CGNAT `100.64.0.0/10`, unspecified `0.0.0.0/8`, broadcast `255.255.255.255`, documentation `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, benchmarking `198.18.0.0/15`, reserved `240.0.0.0/4` |
| IPv6 | loopback `::1`, unspecified `::`, unique-local `fc00::/7`, link-local `fe80::/10`, documentation `2001:db8::/32` |
| Mapped | IPv4-mapped IPv6 forms of all of the above |

### Hostname rules

Applied to `scope_target` values and `url` hosts before any lookup:

1. Punycode (`xn--`) labels are rejected.
2. Non-canonical IP literal encodings are rejected: `0x...`, all-numeric-label forms, octal and shorthand forms.
3. **Embedded IP literals**: if the first four dot-separated labels parse as a canonical dotted-quad IPv4 (`127.0.0.1.nip.io`, `169.254.169.254.xip.io`), or the first label is a dashed quad (`10-0-0-1.nip.io`), the host is treated as that IP and the range policy applies.
4. The internal-suffix denylist above is always applied.
5. **DNS resolution under `block_internal`**: when `block_internal = true` and the host is a name, it is resolved and the range policy is applied to **every** A and AAAA answer. Resolution failure is a rejection (fail closed): `could not resolve host '<h>' to verify it is public (block_internal)`. Rust uses `(host, 0).to_socket_addrs()`, Go `net.DefaultResolver.LookupIPAddr` with a 2 s context, Python `socket.getaddrinfo(host, None)`.
   - **JavaScript**: synchronous DNS is not available. The synchronous `validateArg` rejects a *hostname* under `block_internal` with `hostname cannot be verified without DNS resolution; pass an IP literal or use validateArgAsync`. The exported `validateArgAsync` performs the lookup with `dns.promises.lookup({ all: true })` and applies the same policy. This is strictly more restrictive than the other runtimes, never less.

### CIDR overlap

A CIDR value is tested for **overlap** with each blocked range, not just its base address. `8.0.0.0/5` therefore fails under `block_internal` because it overlaps `10.0.0.0/8`, and `0.0.0.0/0` always fails because it overlaps link-local.

### Egress lint

At load, if `[tool] network_egress = true`, or the manifest uses `[http]` or `[browser]` (which are treated as egress), or the dispatched binary (`tool.binary`, `exec[0]`, or the template's first token) has a basename in the known egress list (`curl`, `wget`, `nmap`, `nc`, `ncat`, `netcat`, `masscan`, `telnet`, `ssh`, `ping`, `fping`, `httpie`, `http`, `wfuzz`, `ffuf`, `hydra`, `nikto`), then **every** argument whose type is `scope_target`, `url`, `ip_address`, `cidr`, or a custom type based on one of those must set `block_internal = true`, or the manifest is rejected.

---

## Scope Enforcement (`scope_check`)

`scope_check = true` on an argument of type `scope_target`, `url`, `ip_address`, or `cidr` checks the value (the host, for `url`) against the project's `scope/scope.toml`. The file is found via `TOOLCLAD_SCOPE_FILE` or by walking up from the manifest's directory; if none is reachable the value is **rejected** (fail closed). Blocked rules win over allowed rules; `*.example.com` matches strict subdomains at any depth but neither `example.com` nor `evil-example.com`; an IP must be contained in an allowed CIDR and a CIDR value must be fully contained. Without `scope_check = true`, no scope allowlisting happens -- `scope_target` by itself is only a shape check. See [Security Model: Scope Enforcement](security-model.md#scope-enforcement) for the full rules.

---

## Type Composition Summary

| Constraint | Applies To | Behavior |
|------------|-----------|----------|
| `min` / `max` | `integer` | Bounds checking |
| `min_float` / `max_float` | `number` | Bounds checking |
| `clamp` | `integer`, `number` | Clamp to range instead of rejecting |
| `pattern` | `string`, `regex_match`, custom types | Anchored regex validation (`^(?:pat)$`) |
| `allowed` | `enum` | Exhaustive value list |
| `schemes` | `url` | Restrict URL schemes (default `["http", "https"]`; dangerous schemes always refused) |
| `block_internal` | `scope_target`, `url`, `ip_address`, `cidr` | Block loopback/private/reserved ranges, resolve hostnames fail-closed, CIDR overlap check |
| `scope_check` | `scope_target`, `url`, `ip_address`, `cidr` | Check value (host for `url`) against `scope/scope.toml`, fail-closed |
| `allow_whitespace` | string-derived types except `url` | Permit whitespace; honored only in `exec` mode |
| `allow_leading_dash` | string-derived and numeric types | Permit a leading `-` / `+` |
| `sanitize` | all string-based | Explicit injection sanitization |
| `default` | any | Value when parameter not provided |

## Validation Error Examples

```
target: injection characters detected (;) in scope_target value
target: must not contain whitespace
target: must not start with '-' or '+' (set allow_leading_dash = true to permit)
target: must not contain NUL bytes
target: resolves to an internal name — always blocked
target: could not resolve host 'intranet-only.example' to verify it is public (block_internal)
target: target '203.0.113.9' is not in scope
target: scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)
scan_type: value "full" not in allowed list [ping, service, version, syn]
threads: value 100 exceeds max 64
target_url: scheme "ftp" not in allowed schemes [http, https]
wordlist: path traversal detected (..)
lhost: invalid IP address "not-an-ip"
network: invalid CIDR notation "10.0.1.0/33"
port: port must be 1-65535
```

Every validation error identifies the parameter name, the type constraint that failed, and the rejected value. The command is never constructed if any argument fails validation.
