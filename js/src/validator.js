import { existsSync, statSync } from "node:fs";

/**
 * Shell metacharacters that indicate injection attempts.
 */
const SHELL_METACHARACTERS = /[;&|`$(){}[\]!#<>\n\r\\'"]/;

/**
 * Check a string value for shell injection metacharacters.
 * @param {string} value
 * @throws {Error} if metacharacters are found
 */
export function checkInjection(value) {
  if (SHELL_METACHARACTERS.test(value)) {
    throw new Error(
      `Injection detected: value contains shell metacharacters: ${value}`
    );
  }
}

/**
 * Validate an argument value against its declared type definition.
 * Returns the cleaned/coerced value on success, throws on failure.
 *
 * @param {object} argDef - Argument definition from the manifest
 * @param {*} value - The raw value to validate
 * @returns {*} The validated and possibly coerced value
 */
export function validateArg(argDef, value) {
  const type = argDef.type;

  const handler = TYPE_HANDLERS[type];
  if (!handler) {
    throw new Error(`Unknown argument type: ${type}`);
  }
  return handler(argDef, value);
}

const TYPE_HANDLERS = {
  string: validateString,
  integer: validateInteger,
  number: validateNumber,
  port: validatePort,
  boolean: validateBoolean,
  enum: validateEnum,
  scope_target: validateScopeTarget,
  url: validateUrl,
  path: validatePath,
  ip_address: validateIpAddress,
  cidr: validateCidr,
  msf_options: validateMsfOptions,
  credential_file: validateCredentialFile,
  duration: validateDuration,
  regex_match: validateRegexMatch,
};

function validateString(argDef, value) {
  const str = String(value);
  if (str.length === 0 && argDef.required) {
    throw new Error(`String argument is required but empty`);
  }
  checkInjection(str);
  if (argDef.pattern) {
    const re = new RegExp(argDef.pattern);
    if (!re.test(str)) {
      throw new Error(
        `Value "${str}" does not match pattern: ${argDef.pattern}`
      );
    }
  }
  return str;
}

function validateInteger(argDef, value) {
  const num = Number(value);
  if (!Number.isInteger(num)) {
    throw new Error(`Expected integer, got: ${value}`);
  }
  if (argDef.min !== undefined || argDef.max !== undefined) {
    if (argDef.clamp) {
      const lo = argDef.min ?? -Infinity;
      const hi = argDef.max ?? Infinity;
      return Math.max(lo, Math.min(hi, num));
    }
    if (argDef.min !== undefined && num < argDef.min) {
      throw new Error(`Integer ${num} is below minimum ${argDef.min}`);
    }
    if (argDef.max !== undefined && num > argDef.max) {
      throw new Error(`Integer ${num} exceeds maximum ${argDef.max}`);
    }
  }
  return num;
}

function validateNumber(argDef, value) {
  const num = Number(value);
  if (!Number.isFinite(num)) {
    throw new Error(`Expected finite number, got: ${value}`);
  }
  const min = argDef.min_float ?? (argDef.min !== undefined ? Number(argDef.min) : undefined);
  const max = argDef.max_float ?? (argDef.max !== undefined ? Number(argDef.max) : undefined);
  if (argDef.clamp) {
    const lo = min ?? -Infinity;
    const hi = max ?? Infinity;
    return Math.max(lo, Math.min(hi, num));
  }
  if (min !== undefined && num < min) {
    throw new Error(`Number ${num} is below minimum ${min}`);
  }
  if (max !== undefined && num > max) {
    throw new Error(`Number ${num} exceeds maximum ${max}`);
  }
  return num;
}

function validatePort(argDef, value) {
  const num = Number(value);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    throw new Error(`Invalid port number: ${value} (must be 1-65535)`);
  }
  return num;
}

function validateBoolean(argDef, value) {
  const str = String(value).toLowerCase();
  if (str !== "true" && str !== "false") {
    throw new Error(`Boolean must be exactly "true" or "false", got: ${value}`);
  }
  return str === "true";
}

function validateEnum(argDef, value) {
  const str = String(value);
  if (!argDef.allowed || !argDef.allowed.includes(str)) {
    throw new Error(
      `Value "${str}" not in allowed values: [${(argDef.allowed || []).join(", ")}]`
    );
  }
  return str;
}

function hasPunycodeLabel(host) {
  return host.split(".").some(
    (label) => label.length >= 4 && label.slice(0, 4).toLowerCase() === "xn--"
  );
}

// RFC 1035 §2.3.4 caps a fully-qualified domain name at 253 octets.
// IPv6 textual form maxes out at 45 chars. We use 253 as the upper bound
// for any scope_target shape — hostnames, IPv4, IPv6, and CIDRs all fit
// well below it, and rejecting anything longer is defense-in-depth
// against buffer-pathological payloads.
const SCOPE_TARGET_MAX_LEN = 253;

function validateScopeTarget(argDef, value) {
  // Scope validation rules (aligned across Rust, Python, JS, Go):
  // 1. Reject shell metacharacters  2. Block * and ? wildcards
  // 3. Surface specific failure modes (traversal, IDN, non-ASCII, slashes)
  //    BEFORE the generic regex catch-all so forensic triage and per-fence
  //    bite-rate analysis can distinguish attack shapes.
  // 4. Accept valid IPv4, IPv6, CIDR, or hostname.
  const str = String(value);
  if (str.length === 0) {
    throw new Error("scope_target must not be empty");
  }
  if (str !== str.trim()) {
    // RFC 1035 / RFC 5891 don't permit terminal whitespace in hostname
    // labels. Reject explicitly so any upstream CLI trimming can't mask
    // malformed input.
    throw new Error(
      `scope_target must not contain leading or trailing whitespace: ${str}`
    );
  }
  if (str.length > SCOPE_TARGET_MAX_LEN) {
    throw new Error(
      `scope_target exceeds ${SCOPE_TARGET_MAX_LEN}-character limit (RFC 1035 §2.3.4): length=${str.length}`
    );
  }
  checkInjection(str);
  if (str.includes("*") || str.includes("?")) {
    throw new Error(`Wildcard not allowed in scope_target: ${str}`);
  }

  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Re = /^[0-9a-fA-F:]+$/;
  const cidrRe = /^[0-9a-fA-F.:]+\/\d{1,3}$/;
  const hostnameRe =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

  if (str.includes("../") || str.includes("..\\") || str.includes("/..")) {
    throw new Error(
      `scope_target must not contain path traversal sequences: ${str}`
    );
  }
  if (str.includes("/") && !cidrRe.test(str) && !ipv4Re.test(str) && !ipv6Re.test(str)) {
    throw new Error(
      `scope_target must not contain '/' (use CIDR notation for ranges): ${str}`
    );
  }
  // checkInjection already rejects backslashes, but keep an explicit message
  // for forensic clarity if the upstream check ever loosens.
  if (/[^\x00-\x7f]/.test(str)) {
    throw new Error(
      `scope_target must be ASCII (non-ASCII hostnames including IDN homoglyphs are rejected; gate IDN registration upstream if needed): ${str}`
    );
  }
  // Defense-in-depth against IDN homoglyph bypass via punycode: an attacker
  // who registers a Cyrillic-homoglyph domain (exаmple.com) and supplies its
  // ASCII punycode form (xn--example-9c.com) would otherwise satisfy the
  // ASCII-strict hostname regex below. Reject xn-- labels.
  if (hasPunycodeLabel(str)) {
    throw new Error(
      `scope_target must not contain punycode (xn--) labels — IDN/IDNA hostnames are rejected to prevent homoglyph bypass; gate IDN registration upstream if needed: ${str}`
    );
  }

  if (
    !ipv4Re.test(str) &&
    !ipv6Re.test(str) &&
    !cidrRe.test(str) &&
    !hostnameRe.test(str)
  ) {
    throw new Error(`Invalid scope_target: ${str} (must be IP, CIDR, or hostname)`);
  }
  return str;
}

function validateUrl(argDef, value) {
  const str = String(value);
  let parsed;
  try {
    parsed = new URL(str);
  } catch {
    throw new Error(`Invalid URL: ${str}`);
  }
  if (argDef.schemes && argDef.schemes.length > 0) {
    const scheme = parsed.protocol.replace(":", "");
    if (!argDef.schemes.includes(scheme)) {
      throw new Error(
        `URL scheme "${scheme}" not in allowed schemes: [${argDef.schemes.join(", ")}]`
      );
    }
  }
  return str;
}

function validatePath(argDef, value) {
  const str = String(value);
  checkInjection(str);
  if (str.startsWith("/") || (str.length >= 2 && str[1] === ":")) {
    throw new Error(`Path must be relative, not absolute: ${str}`);
  }
  if (str.includes("../") || str.includes("..\\")) {
    throw new Error(`Path traversal not allowed: ${str}`);
  }
  return str;
}

function validateIpAddress(argDef, value) {
  const str = String(value);
  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Re = /^[0-9a-fA-F:]+$/;
  if (!ipv4Re.test(str) && !ipv6Re.test(str)) {
    throw new Error(`Invalid IP address: ${str}`);
  }
  if (ipv4Re.test(str)) {
    const octets = str.split(".").map(Number);
    if (octets.some((o) => o < 0 || o > 255)) {
      throw new Error(`Invalid IPv4 address: ${str}`);
    }
  }
  return str;
}

function validateCidr(argDef, value) {
  const str = String(value);
  const cidrRe = /^[0-9a-fA-F.:]+\/\d{1,3}$/;
  if (!cidrRe.test(str)) {
    throw new Error(`Invalid CIDR notation: ${str}`);
  }
  const [addr, prefix] = str.split("/");
  const prefixNum = Number(prefix);
  // IPv4 check
  if (addr.includes(".")) {
    validateIpAddress(argDef, addr);
    if (prefixNum < 0 || prefixNum > 32) {
      throw new Error(`Invalid CIDR prefix for IPv4: /${prefix}`);
    }
  } else {
    // IPv6
    if (prefixNum < 0 || prefixNum > 128) {
      throw new Error(`Invalid CIDR prefix for IPv6: /${prefix}`);
    }
  }
  return str;
}

function validateMsfOptions(argDef, value) {
  const str = String(value);
  const keyRe = /^[A-Z][A-Z0-9_]*$/;
  const metacharNoSemi = /[|&$`(){}[\]!#<>\n\r]/;
  for (const pair of str.split(";")) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const spaceIdx = trimmed.indexOf(" ");
    if (spaceIdx === -1) {
      throw new Error(
        `msf_options: invalid pair '${trimmed}' (expected 'KEY VALUE')`
      );
    }
    const key = trimmed.substring(0, spaceIdx);
    const val = trimmed.substring(spaceIdx + 1);
    if (!keyRe.test(key)) {
      throw new Error(
        `msf_options: invalid key '${key}' (must be uppercase alphanumeric)`
      );
    }
    if (metacharNoSemi.test(val)) {
      throw new Error(`msf_options: value contains disallowed characters`);
    }
  }
  return str;
}

function validateCredentialFile(argDef, value) {
  const str = String(value);
  checkInjection(str);
  if (str.startsWith("/") || (str.length >= 2 && str[1] === ":")) {
    throw new Error(`Credential file must be a relative path: ${str}`);
  }
  if (str.includes("../") || str.includes("..\\")) {
    throw new Error(`Path traversal not allowed: ${str}`);
  }
  if (!existsSync(str)) {
    throw new Error(`Credential file not found: ${str}`);
  }
  if (!statSync(str).isFile()) {
    throw new Error(`Not a file: ${str}`);
  }
  return str;
}

function validateDuration(argDef, value) {
  const str = String(value);
  // Plain integer seconds
  if (/^\d+$/.test(str)) return str;
  // Duration with suffix
  if (/^(?:\d+h)?(?:\d+m)?(?:\d+s)?(?:\d+ms)?$/.test(str) && str.length > 0)
    return str;
  throw new Error(
    `Invalid duration: '${str}' (e.g. '30', '5m', '2h', '1h30m', '500ms')`
  );
}

function validateRegexMatch(argDef, value) {
  const str = String(value);
  checkInjection(str);
  if (!argDef.pattern) {
    throw new Error("regex_match type requires a 'pattern' field");
  }
  const re = new RegExp(argDef.pattern);
  if (!re.test(str)) {
    throw new Error(
      `Value '${str}' does not match required pattern: ${argDef.pattern}`
    );
  }
  return str;
}

/**
 * Validate an argument using custom type definitions.
 * @param {object} argDef - Argument definition
 * @param {*} value - Value to validate
 * @param {object} customTypes - Map of custom type name to definition
 * @returns {*} Validated value
 */
export function validateArgWithCustomTypes(argDef, value, customTypes) {
  if (customTypes && customTypes[argDef.type]) {
    const custom = customTypes[argDef.type];
    const handler = TYPE_HANDLERS[custom.base];
    if (!handler) {
      throw new Error(
        `Custom type '${argDef.type}' has invalid base type '${custom.base}'`
      );
    }
    // Merge custom type constraints into a synthetic argDef
    const synthetic = {
      ...argDef,
      type: custom.base,
      allowed: custom.allowed || argDef.allowed,
      pattern: custom.pattern || argDef.pattern,
      min: custom.min ?? argDef.min,
      max: custom.max ?? argDef.max,
      min_float: custom.min_float ?? argDef.min_float,
      max_float: custom.max_float ?? argDef.max_float,
    };
    return handler(synthetic, value);
  }
  return validateArg(argDef, value);
}
