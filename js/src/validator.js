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

function validateScopeTarget(argDef, value) {
  // NOTE: Scope validation (CIDR, DNS wildcard) should ideally be centralized
  // to avoid implementation drift across languages. For production use,
  // defer scope checking to the Symbiont runtime's scope enforcement module.
  const str = String(value);
  checkInjection(str);
  // Block wildcards
  if (str.includes("*")) {
    throw new Error(`Wildcard not allowed in scope_target: ${str}`);
  }
  // Must look like an IP, CIDR, or hostname
  const hostnameRe = /^[a-zA-Z0-9._:-]+$/;
  const cidrRe = /^[0-9a-fA-F.:]+\/[0-9]+$/;
  if (!hostnameRe.test(str) && !cidrRe.test(str)) {
    throw new Error(`Invalid scope_target: ${str}`);
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
    };
    return handler(synthetic, value);
  }
  return validateArg(argDef, value);
}
