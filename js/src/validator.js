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
