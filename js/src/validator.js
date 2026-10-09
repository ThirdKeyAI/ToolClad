import { existsSync, statSync } from "node:fs";
import { promises as dns } from "node:dns";
import {
  parseCanonicalIp,
  parseCidr,
  parseIpv6,
  enforceIpPolicy,
  enforceCidrPolicy,
  embeddedIpv4Literal,
  internalNameReason,
  looksLikeIpLiteral,
  hasPunycodeLabel,
} from "./hostpolicy.js";

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
 * Types whose validated value is passed to the tool as free-form text.
 * They receive the full value-hygiene pass (NUL, control characters,
 * quotes/backslash, whitespace, leading dash) before type-specific parsing.
 */
const STRING_DERIVED_TYPES = new Set([
  "string",
  "path",
  "credential_file",
  "regex_match",
  "url",
  "scope_target",
  "duration",
  "msf_options",
]);

/** Numeric types: the leading-dash rule is applied to the parsed output. */
const NUMERIC_TYPES = new Set(["integer", "number", "port"]);

const LEADING_DASH_MESSAGE =
  "must not start with '-' or '+' (set allow_leading_dash = true to permit)";

/**
 * Anchor a manifest `pattern` so it must match the whole value: strip one
 * leading `^` and one trailing unescaped `$`, then wrap in `^(?:...)$`.
 * @param {string} pattern
 * @returns {string} Anchored pattern source
 */
export function anchorPattern(pattern) {
  let p = String(pattern);
  if (p.startsWith("^")) p = p.slice(1);
  if (endsWithUnescapedDollar(p)) p = p.slice(0, -1);
  return `^(?:${p})$`;
}

function endsWithUnescapedDollar(p) {
  if (!p.endsWith("$")) return false;
  let backslashes = 0;
  for (let i = p.length - 2; i >= 0 && p[i] === "\\"; i--) backslashes++;
  return backslashes % 2 === 0;
}

function compilePattern(pattern) {
  return new RegExp(anchorPattern(pattern));
}

function startsWithDash(str) {
  return str.startsWith("-") || str.startsWith("+");
}

/**
 * Value hygiene for string-derived types. Rules run in a fixed order; the NUL
 * rule is applied to every type by the caller before this runs.
 */
function checkValueHygiene(str, argDef, type, execMode) {
  // Rule 2: every C0 control (tab, newline, CR included), DEL, and the C1
  // range. Unconditional: allow_whitespace never relaxes it.
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) {
      throw new Error("must not contain control characters");
    }
  }
  // Rule 3: quotes and backslash. scope_target keeps its specific message.
  if (type === "scope_target" && str.includes("\\")) {
    throw new Error(
      `scope_target must not contain backslash escape sequences: ${str}`
    );
  }
  if (/['"\\]/.test(str)) {
    throw new Error("must not contain quote or backslash characters");
  }
  // Rule 4: whitespace. Only the ASCII space U+0020 can ever be permitted:
  // msf_options needs it as its KEY VALUE separator, and other types may opt
  // in with allow_whitespace, honored only when the manifest declared exec
  // directly (never for url). Every other whitespace character (U+00A0,
  // U+2000-200A, U+2028, U+2029, U+3000, ...) is a homoglyph, not a separator.
  if (/\s/.test(str)) {
    const spaceOk =
      type === "msf_options" ||
      (type !== "url" && argDef.allow_whitespace === true && execMode === true);
    if (!spaceOk || /[^\S ]/.test(str)) {
      throw new Error("must not contain whitespace");
    }
  }
  // Rule 5: leading dash.
  if (startsWithDash(str) && argDef.allow_leading_dash !== true) {
    throw new Error(LEADING_DASH_MESSAGE);
  }
}

function runValidation(handler, type, argDef, value, execMode) {
  const str = String(value);
  // Rule 1: NUL is rejected for every type, enum and numerics included.
  if (str.includes("\0")) {
    throw new Error("must not contain NUL bytes");
  }
  if (STRING_DERIVED_TYPES.has(type)) {
    checkValueHygiene(str, argDef, type, execMode);
  }
  const out = handler(argDef, value);
  if (NUMERIC_TYPES.has(type)) {
    // The leading-dash rule applies to the output after clamping/range checks,
    // so a clamped negative that lands on a non-negative bound passes.
    if (startsWithDash(String(out)) && argDef.allow_leading_dash !== true) {
      throw new Error(LEADING_DASH_MESSAGE);
    }
  }
  return out;
}

/**
 * The one step the synchronous validator cannot perform. A hostname under
 * `block_internal` can only be shown to be public by resolving it and testing
 * every answer, and Node has no synchronous resolver. Rather than fork the
 * validator into a sync and an async copy, a type handler returns one of
 * these in place of the value; the sync entry points refuse it and the async
 * entry points satisfy it with a bounded `dns.promises.lookup`. Everything
 * before this point (hygiene, structure, the literal and CIDR policy, the
 * internal-name denylist, embedded literals) is one implementation that runs
 * identically on both paths.
 */
class HostResolution {
  /**
   * @param {string} host - The name to resolve
   * @param {(addresses: object[]) => *} complete - Applies the policy to the
   *   parsed answers and returns the validated value
   */
  constructor(host, complete) {
    this.host = host;
    this.complete = complete;
  }
}

const UNRESOLVED_HOST_MESSAGE =
  "hostname cannot be verified without DNS resolution; pass an IP literal or use validateArgAsync";

/** Sync entry points: a pending resolution is a refusal, never a pass. */
function settleSync(out) {
  if (out instanceof HostResolution) {
    throw new Error(UNRESOLVED_HOST_MESSAGE);
  }
  return out;
}

/** Async entry points: a pending resolution is satisfied by a lookup. */
async function settleAsync(out) {
  if (out instanceof HostResolution) {
    return out.complete(await resolveHostAddresses(out.host));
  }
  return out;
}

/** Upper bound on one lookup. A resolver that does not answer cannot show a name is public. */
const RESOLVE_TIMEOUT_MS = 2000;

function couldNotResolve(host) {
  return new Error(`could not resolve host '${host}' to verify it is public (block_internal)`);
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`lookup timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Resolve `host` to every A/AAAA answer, each parsed as a canonical literal.
 * Any failure — a lookup error, the timeout, an empty answer set, an answer
 * the strict parser does not accept — is a refusal: a name that cannot be
 * resolved cannot be shown to be public.
 *
 * Seam for a follow-up outside this wave: the addresses returned here are
 * what the policy approved, but the tool will resolve the name again on its
 * own and may be answered differently (the resolve-then-reconnect window).
 * A runtime should pin the approved address into the invocation, e.g.
 * `curl --resolve host:443:ip`, rather than hand the tool the bare name.
 * @param {string} host
 * @returns {Promise<object[]>} Parsed addresses from parseCanonicalIp
 */
async function resolveHostAddresses(host) {
  let answers;
  try {
    answers = await withTimeout(dns.lookup(host, { all: true }), RESOLVE_TIMEOUT_MS);
  } catch {
    throw couldNotResolve(host);
  }
  if (!Array.isArray(answers) || answers.length === 0) {
    throw couldNotResolve(host);
  }
  const addresses = [];
  for (const answer of answers) {
    const ip = parseCanonicalIp(String(answer && answer.address));
    if (ip === null) {
      throw couldNotResolve(host);
    }
    addresses.push(ip);
  }
  return addresses;
}

/**
 * The shared validation pipeline. May return a HostResolution, which the
 * entry point settles.
 */
function validateArgCore(argDef, value, execMode) {
  const type = argDef.type;

  const handler = TYPE_HANDLERS[type];
  if (!handler) {
    throw new Error(`Unknown argument type: ${type}`);
  }
  return runValidation(handler, type, argDef, value, execMode);
}

/**
 * Validate an argument value against its declared type definition.
 * Returns the cleaned/coerced value on success, throws on failure.
 *
 * Synchronous: a `scope_target` or `url` hostname under `block_internal`
 * cannot be verified without DNS resolution and is refused here; pass an IP
 * literal or use validateArgAsync.
 *
 * @param {object} argDef - Argument definition from the manifest
 * @param {*} value - The raw value to validate
 * @param {boolean} [execMode=false] - true only when the manifest declared
 *   command.exec directly; enables allow_whitespace. A template compiled to
 *   exec is still template mode (strict).
 * @returns {*} The validated and possibly coerced value
 */
export function validateArgMode(argDef, value, execMode = false) {
  return settleSync(validateArgCore(argDef, value, execMode));
}

/**
 * Strict (template-mode) validation: whitespace is always rejected.
 * @param {object} argDef - Argument definition from the manifest
 * @param {*} value - The raw value to validate
 * @returns {*} The validated and possibly coerced value
 */
export function validateArg(argDef, value) {
  return validateArgMode(argDef, value, false);
}

/**
 * validateArgMode with DNS resolution: the same pipeline, but a hostname
 * under `block_internal` is resolved (bounded to 2 s) and every A/AAAA
 * answer is held to the range policy. Resolution failure is a refusal.
 * @param {object} argDef - Argument definition from the manifest
 * @param {*} value - The raw value to validate
 * @param {boolean} [execMode=false] - See validateArgMode
 * @returns {Promise<*>} The validated and possibly coerced value
 */
export async function validateArgAsync(argDef, value, execMode = false) {
  return settleAsync(validateArgCore(argDef, value, execMode));
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
    const re = compilePattern(argDef.pattern);
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

// RFC 1035 §2.3.4 caps a fully-qualified domain name at 253 octets.
// IPv6 textual form maxes out at 45 chars. We use 253 as the upper bound
// for any scope_target shape — hostnames, IPv4, IPv6, and CIDRs all fit
// well below it, and rejecting anything longer is defense-in-depth
// against buffer-pathological payloads.
const SCOPE_TARGET_MAX_LEN = 253;

/** RFC 1035 §2.3.4 caps each DNS label at 63 octets. */
const DNS_LABEL_MAX_LEN = 63;

/** Structural hostname: LDH labels joined by dots (same regex as Rust). */
const HOSTNAME_RE =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

/**
 * Something shaped like CIDR notation. Used only to choose the error message
 * for a value containing `/`; the strict parse is `parseCidr`.
 */
const CIDR_SHAPE_RE = /^[0-9a-fA-F.:]+\/[0-9]{1,3}$/;

/** Schemes a `url` argument accepts when the manifest sets no `schemes`. */
const DEFAULT_URL_SCHEMES = Object.freeze(["http", "https"]);

/**
 * Schemes a `url` argument never accepts, even when a manifest lists one in
 * `schemes`: each is either a non-network scheme a fetcher would turn into
 * local file or code access, or a protocol-smuggling vector (gopher and dict
 * speak raw bytes to an arbitrary port).
 */
const DENIED_URL_SCHEMES = new Set([
  "javascript",
  "data",
  "file",
  "blob",
  "about",
  "gopher",
  "dict",
  "ftp",
  "ldap",
  "jar",
  "netdoc",
  "mailto",
  "ws",
  "wss",
]);

/**
 * True if the rightmost DNS label is not entirely numeric: a real TLD is
 * never all digits (RFC 3696 §2), which also rejects dotted-decimal IPs
 * that the strict parser already refused.
 */
function tldNotAllNumeric(host) {
  const tld = host.slice(host.lastIndexOf(".") + 1);
  return tld.length > 0 && !/^[0-9]+$/.test(tld);
}

function hasOverlongLabel(host) {
  return host.split(".").some((label) => label.length > DNS_LABEL_MAX_LEN);
}

function validateScopeTarget(argDef, value) {
  // Scope validation rules (aligned across Rust, Python, JS, Go):
  // 1. Reject shell metacharacters  2. Block * and ? wildcards
  // 3. Surface specific failure modes (traversal, IDN, non-ASCII, slashes)
  //    BEFORE the generic regex catch-all so forensic triage and per-fence
  //    bite-rate analysis can distinguish attack shapes.
  // 4. Accept a canonical IP literal, a CIDR with a canonical base, or a
  //    hostname — under the host policy of hostpolicy.js.
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

  if (str.includes("../") || str.includes("..\\") || str.includes("/..")) {
    throw new Error(
      `scope_target must not contain path traversal sequences: ${str}`
    );
  }
  if (str.includes("/") && !CIDR_SHAPE_RE.test(str)) {
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
  // Per-label DNS length: the total-length check above does not bound an
  // individual label.
  if (hasOverlongLabel(str)) {
    throw new Error(
      `scope_target has a DNS label exceeding ${DNS_LABEL_MAX_LEN} octets (RFC 1035 §2.3.4): ${str}`
    );
  }

  const blockInternal = argDef.block_internal === true;

  // Canonical IP literals only. The strict parsers accept dotted-quad IPv4
  // and standard IPv6 and nothing else, so integer/hex/octal/shorthand
  // encodings (2130706433, 0x7f000001, 0177.0.0.1, 127.1 — all of which a
  // libc resolver would expand to 127.0.0.1) fail here and are rejected as
  // non-canonical literals below.
  const ip = parseCanonicalIp(str);
  if (ip !== null) {
    enforceIpPolicy(ip, blockInternal);
    return str;
  }

  // CIDR ranges: a canonical base address with an in-bounds prefix. The
  // whole range is tested for overlap with each blocked prefix, so a
  // supernet with a public base address (`8.0.0.0/5`) is still refused.
  if (str.includes("/")) {
    const cidr = parseCidr(str);
    if (cidr === null) {
      throw new Error(`Invalid scope_target: ${str} (must be IP, CIDR, or hostname)`);
    }
    enforceCidrPolicy(cidr, blockInternal);
    return str;
  }

  // A non-canonical IP-literal encoding must not slip through as a
  // "hostname": a downstream resolver would expand it to an address. No
  // legitimate hostname is all-numeric labels or a 0x-prefixed hex literal.
  if (looksLikeIpLiteral(str)) {
    throw new Error(
      `scope_target looks like a non-canonical IP literal; use dotted-quad IPv4 or standard IPv6: ${str}`
    );
  }

  // Hostname: structural regex plus a non-numeric rightmost label, then the
  // hostname policy shared with the url host.
  if (HOSTNAME_RE.test(str) && tldNotAllNumeric(str)) {
    return applyHostnamePolicy(str, blockInternal, str);
  }
  throw new Error(`Invalid scope_target: ${str} (must be IP, CIDR, or hostname)`);
}

/**
 * Hostname policy shared by `scope_target` and the host of a `url`, applied
 * after the structural checks (punycode, non-canonical literals, the LDH
 * regex) have passed:
 *
 * 1. Embedded IPv4 literal (`127.0.0.1.nip.io`, `10-0-0-1.nip.io`): the
 *    address written in the name is held to the literal policy, since a
 *    wildcard-DNS zone answers with exactly that address. An address the
 *    policy allows continues as an ordinary hostname.
 * 2. Internal-name denylist, with or without `block_internal`.
 * 3. Under `block_internal`, a name can only be shown to be public by
 *    resolving it. That step is returned as a HostResolution for the entry
 *    point to satisfy (async) or refuse (sync); the completion applies the
 *    range policy to every answer, so a name that resolves to one public and
 *    one internal address (rebinding, split horizon) is refused.
 *
 * @param {string} host - The hostname
 * @param {boolean} blockInternal
 * @param {string} value - The validated value to return on success
 * @returns {string|HostResolution}
 */
function applyHostnamePolicy(host, blockInternal, value) {
  const embedded = embeddedIpv4Literal(host);
  if (embedded !== null) {
    enforceIpPolicy(embedded, blockInternal);
  }
  const internal = internalNameReason(host);
  if (internal !== null) {
    throw new Error(`target ${internal}`);
  }
  if (!blockInternal) {
    return value;
  }
  return new HostResolution(host, (addresses) => {
    for (const ip of addresses) {
      enforceIpPolicy(ip, true);
    }
    return value;
  });
}

/**
 * Split a URL into its lowercased scheme and everything after `://`.
 * A value without `://` is not a URL for our purposes; a bare `scheme:` form
 * (`mailto:`, `javascript:`) is refused here rather than parsed.
 * @param {string} str
 * @returns {{scheme: string, rest: string}}
 * @throws {Error} when the value has no `scheme://` prefix
 */
export function splitUrlScheme(str) {
  const idx = str.indexOf("://");
  const scheme = idx === -1 ? "" : str.slice(0, idx).toLowerCase();
  // RFC 3986 §3.1: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  if (idx === -1 || !/^[a-z][a-z0-9+.-]*$/.test(scheme)) {
    throw new Error(`Invalid URL: ${str} (expected scheme://host)`);
  }
  return { scheme, rest: str.slice(idx + 3) };
}

const URL_PORT_MESSAGE = "URL port must be 1-65535";

/**
 * Extract the host from the part of a URL after `://`. The authority is
 * everything up to the first `/`, `?` or `#`; an `@` inside it is userinfo
 * and is refused outright. A bracketed IPv6 literal is unwrapped and must be
 * canonical; otherwise the host ends at the first `:` and whatever follows
 * must be a plain decimal port in 1-65535.
 *
 * This is deliberately not a WHATWG parser: nothing is normalized, so what
 * a reviewer reads in the manifest is what the host policy sees.
 *
 * @param {string} rest - The URL text after `://`
 * @returns {{host: string, port: number|null, bracketed: boolean}}
 * @throws {Error} on userinfo, an empty or malformed host, or a bad port
 */
export function parseUrlAuthority(rest) {
  const end = rest.search(/[/?#]/);
  const authority = end === -1 ? rest : rest.slice(0, end);
  if (authority.includes("@")) {
    throw new Error("URL must not contain userinfo (user:pass@host)");
  }

  let host;
  let portText = null;
  let bracketed = false;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close === -1) {
      throw new Error(`Invalid URL authority: unterminated IPv6 bracket: ${authority}`);
    }
    host = authority.slice(1, close);
    if (parseIpv6(host) === null) {
      throw new Error(
        `Invalid URL authority: bracketed host '${host}' is not a canonical IPv6 literal`
      );
    }
    bracketed = true;
    const after = authority.slice(close + 1);
    if (after !== "") {
      if (!after.startsWith(":")) {
        throw new Error(
          `Invalid URL authority: unexpected text after IPv6 bracket: ${authority}`
        );
      }
      portText = after.slice(1);
    }
  } else {
    const colon = authority.indexOf(":");
    if (colon === -1) {
      host = authority;
    } else {
      host = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
    }
  }

  if (host === "") {
    throw new Error("URL host must not be empty");
  }

  let port = null;
  if (portText !== null) {
    // Plain decimal only: Number() would accept "+1", "0x50", " 80".
    if (!/^[0-9]{1,5}$/.test(portText)) {
      throw new Error(`${URL_PORT_MESSAGE} (got '${portText}')`);
    }
    port = Number(portText);
    if (port < 1 || port > 65535) {
      throw new Error(`${URL_PORT_MESSAGE} (got '${portText}')`);
    }
  }

  return { host, port, bracketed };
}

/**
 * The `url` validator, in order: the string-derived hygiene has already run
 * (whitespace is never admitted for a `url`, opt-in or not); then the shell
 * metacharacter blocklist, which rejects `{` and `}` and therefore any
 * `{_secret:…}` reference; then a structural parse — `scheme://`, the scheme
 * allowlist, the scheme denylist, no userinfo, host extraction with an
 * optional port — and finally the host policy of hostpolicy.js.
 *
 * The value is returned untouched. This is not a WHATWG / RFC 3986
 * normalizer: the fetcher downstream will parse the value again with its own
 * rules, so anything a human reviewer of the manifest could misread is
 * refused here rather than normalized away.
 */
function validateUrl(argDef, value) {
  const str = String(value);
  // Step 1 (continued): the metacharacter blocklist.
  checkInjection(str);

  // Step 2: `scheme://rest`.
  const { scheme, rest } = splitUrlScheme(str);

  // Step 3: allowlist — the manifest's `schemes` when set, else http/https.
  const allowed =
    Array.isArray(argDef.schemes) && argDef.schemes.length > 0
      ? argDef.schemes.map((s) => String(s).toLowerCase())
      : DEFAULT_URL_SCHEMES;
  if (!allowed.includes(scheme)) {
    throw new Error(
      `URL scheme "${scheme}" not in allowed schemes: [${allowed.join(", ")}]`
    );
  }

  // Step 4: explicit denial, even when a manifest lists the scheme.
  if (DENIED_URL_SCHEMES.has(scheme)) {
    throw new Error(`URL scheme "${scheme}" is never allowed for a url argument`);
  }

  // Steps 5-6: no userinfo; host and optional port.
  const { host } = parseUrlAuthority(rest);

  // Step 7: host policy — the same checks as scope_target, since curl and
  // wget-style fetchers are the prime SSRF vector.
  if (hasPunycodeLabel(host)) {
    throw new Error(`URL host must not contain punycode (xn--) labels: ${host}`);
  }
  const blockInternal = argDef.block_internal === true;
  const ip = parseCanonicalIp(host);
  let out;
  if (ip !== null) {
    enforceIpPolicy(ip, blockInternal);
    out = str;
  } else {
    if (looksLikeIpLiteral(host)) {
      throw new Error(
        `URL host looks like a non-canonical IP literal; use dotted-quad IPv4 or a hostname: ${host}`
      );
    }
    if (host.length > SCOPE_TARGET_MAX_LEN || hasOverlongLabel(host)) {
      throw new Error("URL host exceeds DNS length limits (RFC 1035 §2.3.4)");
    }
    if (!HOSTNAME_RE.test(host)) {
      throw new Error(`URL host is not a valid hostname or IP literal: ${host}`);
    }
    out = applyHostnamePolicy(host, blockInternal, str);
  }

  // Step 8 — SCOPE HOOK: when `argDef.scope_check` is set, the scope checker
  // (a later wave) is consulted here with `host`. Not implemented yet; the
  // flag is parsed and carried so manifests can already declare it.

  return out;
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

/**
 * A canonical IPv4 or IPv6 literal, under the same egress policy as every
 * other address-carrying type: link-local is always refused, the rest of
 * the non-public table under `block_internal`.
 */
function validateIpAddress(argDef, value) {
  const str = String(value);
  const ip = parseCanonicalIp(str);
  if (ip === null) {
    if (/^[0-9.]+$/.test(str)) {
      throw new Error(`Invalid IPv4 address: ${str}`);
    }
    throw new Error(`Invalid IP address: ${str}`);
  }
  enforceIpPolicy(ip, argDef.block_internal === true);
  return str;
}

/**
 * `address/prefix` with a canonical base address and an in-bounds prefix.
 * The whole range is tested for overlap with each blocked prefix, so a
 * supernet with a public base address is refused along with its contents.
 */
function validateCidr(argDef, value) {
  const str = String(value);
  const slash = str.indexOf("/");
  if (slash === -1) {
    throw new Error(`Invalid CIDR notation: ${str}`);
  }
  const ip = parseCanonicalIp(str.slice(0, slash));
  const prefixText = str.slice(slash + 1);
  if (ip === null || !/^[0-9]{1,3}$/.test(prefixText)) {
    throw new Error(`Invalid CIDR notation: ${str}`);
  }
  const prefix = Number(prefixText);
  if (ip.family === 4 && prefix > 32) {
    throw new Error(`Invalid CIDR prefix for IPv4: /${prefixText}`);
  }
  if (ip.family === 6 && prefix > 128) {
    throw new Error(`Invalid CIDR prefix for IPv6: /${prefixText}`);
  }
  enforceCidrPolicy({ ip, prefix }, argDef.block_internal === true);
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
  const re = compilePattern(argDef.pattern);
  if (!re.test(str)) {
    throw new Error(
      `Value '${str}' does not match required pattern: ${argDef.pattern}`
    );
  }
  return str;
}

/**
 * The shared custom-type pipeline. May return a HostResolution, which the
 * entry point settles.
 */
function validateArgWithCustomTypesCore(argDef, value, customTypes, execMode) {
  if (customTypes && Object.hasOwn(customTypes, argDef.type)) {
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
    return runValidation(handler, custom.base, synthetic, value, execMode);
  }
  return validateArgCore(argDef, value, execMode);
}

/**
 * Validate an argument using custom type definitions. Synchronous: see
 * validateArgMode for the hostname rule under `block_internal`.
 * @param {object} argDef - Argument definition
 * @param {*} value - Value to validate
 * @param {object} customTypes - Map of custom type name to definition
 * @param {boolean} [execMode=false] - See validateArgMode
 * @returns {*} Validated value
 */
export function validateArgWithCustomTypesMode(
  argDef,
  value,
  customTypes,
  execMode = false
) {
  return settleSync(validateArgWithCustomTypesCore(argDef, value, customTypes, execMode));
}

/**
 * Strict (template-mode) custom-type validation.
 * @param {object} argDef - Argument definition
 * @param {*} value - Value to validate
 * @param {object} customTypes - Map of custom type name to definition
 * @returns {*} Validated value
 */
export function validateArgWithCustomTypes(argDef, value, customTypes) {
  return validateArgWithCustomTypesMode(argDef, value, customTypes, false);
}

/**
 * validateArgWithCustomTypesMode with DNS resolution: see validateArgAsync.
 * @param {object} argDef - Argument definition
 * @param {*} value - Value to validate
 * @param {object} customTypes - Map of custom type name to definition
 * @param {boolean} [execMode=false] - See validateArgMode
 * @returns {Promise<*>} Validated value
 */
export async function validateArgWithCustomTypesAsync(
  argDef,
  value,
  customTypes,
  execMode = false
) {
  return settleAsync(validateArgWithCustomTypesCore(argDef, value, customTypes, execMode));
}
