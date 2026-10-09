/**
 * Scope enforcement.
 *
 * An argument with `scope_check = true` (types `scope_target`, `url`,
 * `ip_address`, `cidr`) is held to the project scope file,
 * `scope/scope.toml`:
 *
 *   [scope]
 *   allowed_domains = ["example.com", "*.example.com"]
 *   allowed_cidrs   = ["10.0.1.0/24"]
 *   blocked_domains = []
 *   blocked_cidrs   = []
 *
 * Discovery: the path in `TOOLCLAD_SCOPE_FILE` (an unreadable path is an
 * error, never a fallback), else `scope/scope.toml` searched upward from the
 * manifest's directory (the process cwd for an in-memory manifest).
 *
 * Matching: blocked rules first and they always win; `example.com` matches
 * that host exactly (case-insensitive); `*.example.com` matches a strict
 * subdomain at any depth, never the apex and never a plain string suffix
 * (`evil-example.com`); an IP matches a CIDR that contains it; a CIDR
 * matches only an allowed CIDR that fully contains it (and is blocked by any
 * blocked CIDR it overlaps). No match is a refusal, and so is a missing
 * scope file (fail closed).
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import TOML from "@iarna/toml";
import {
  parseCanonicalIp,
  parseCidr,
  ipInRange,
  prefixesOverlap,
  toIpv4Mapped,
  toIpv4MappedPrefix,
} from "./hostpolicy.js";

/** Argument types that honor `scope_check = true`. */
export const SCOPE_CHECK_TYPES = Object.freeze(["scope_target", "url", "ip_address", "cidr"]);

/** The scope file key allowlist: exactly `[scope]` and its four lists. */
const SCOPE_LIST_KEYS = Object.freeze([
  "allowed_domains",
  "allowed_cidrs",
  "blocked_domains",
  "blocked_cidrs",
]);

export const NO_SCOPE_FILE_MESSAGE =
  "scope_check is enabled but no scope/scope.toml was found (set TOOLCLAD_SCOPE_FILE)";

const NORMALIZED = Symbol("toolclad.scope");

const DOMAIN_LABEL_RE = /^[a-z0-9-]+$/;

function validDomainRule(rule) {
  const body = rule.startsWith("*.") ? rule.slice(2) : rule;
  if (body.length === 0) return false;
  return body.split(".").every((label) => DOMAIN_LABEL_RE.test(label));
}

/**
 * Build a scope definition from a `[scope]` table. Rules are checked here so
 * a malformed scope file fails at load rather than silently matching nothing.
 * @param {object} table - The `[scope]` table (snake_case lists)
 * @param {string} [source="scope"] - Where the table came from, for messages
 * @returns {object} Normalized scope definition
 */
export function makeScope(table, source = "scope") {
  if (table === null || typeof table !== "object" || Array.isArray(table)) {
    throw new Error(`${source}: [scope] must be a table`);
  }
  for (const key of Object.keys(table)) {
    if (!SCOPE_LIST_KEYS.includes(key)) {
      throw new Error(`${source}: unknown key 'scope.${key}' in scope file`);
    }
  }
  const lists = {};
  for (const key of SCOPE_LIST_KEYS) {
    const value = table[key] ?? [];
    if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
      throw new Error(`${source}: scope.${key} must be an array of strings`);
    }
    lists[key] = value;
  }
  const domains = (key) =>
    lists[key].map((rule) => {
      if (!validDomainRule(rule)) {
        throw new Error(
          `${source}: invalid domain rule '${rule}' in scope.${key} (lowercase letters, digits, '.', '-', optional leading '*.')`
        );
      }
      return rule;
    });
  const cidrs = (key) =>
    lists[key].map((text) => {
      const range = parseCidr(text);
      if (range === null) {
        throw new Error(`${source}: invalid CIDR '${text}' in scope.${key}`);
      }
      return { text, range };
    });
  return Object.freeze({
    [NORMALIZED]: true,
    source,
    allowed_domains: Object.freeze(domains("allowed_domains")),
    blocked_domains: Object.freeze(domains("blocked_domains")),
    allowed_cidrs: Object.freeze(cidrs("allowed_cidrs")),
    blocked_cidrs: Object.freeze(cidrs("blocked_cidrs")),
  });
}

function normalize(scope) {
  return scope && scope[NORMALIZED] === true ? scope : makeScope(scope);
}

/**
 * Load and validate a scope file. Unknown keys, a malformed CIDR and a bad
 * domain rule are load errors.
 * @param {string} path
 * @returns {object} Normalized scope definition
 */
export function loadScopeFile(path) {
  let content;
  try {
    content = readFileSync(path, "utf-8");
  } catch (err) {
    throw new Error(`cannot read scope file '${path}': ${err.message}`);
  }
  const doc = TOML.parse(content);
  for (const key of Object.keys(doc)) {
    if (key !== "scope") {
      throw new Error(`${path}: unknown key '${key}' in scope file`);
    }
  }
  return makeScope(doc.scope ?? {}, path);
}

/**
 * Find and load the scope file: `TOOLCLAD_SCOPE_FILE` first (an unreadable
 * path is an error), else `scope/scope.toml` searched upward from `startDir`.
 * @param {string} [startDir=process.cwd()] - The manifest's directory
 * @returns {object|null} Normalized scope definition, or null if none exists
 */
export function discoverScope(startDir) {
  const env = process.env.TOOLCLAD_SCOPE_FILE;
  if (env !== undefined && env !== "") {
    return loadScopeFile(resolve(env));
  }
  let dir = resolve(startDir ?? process.cwd());
  for (;;) {
    const candidate = join(dir, "scope", "scope.toml");
    if (existsSync(candidate)) {
      return loadScopeFile(candidate);
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Hidden property loadManifest sets to the manifest file's directory. */
export const MANIFEST_DIR = Symbol.for("toolclad.manifestDir");

const manifestScopes = new WeakMap();

/**
 * The scope for a manifest, discovered from its source directory (the cwd
 * for an in-memory manifest) and cached per manifest object so the file is
 * read at most once per load. Null when no scope file exists.
 * @param {object} manifest
 * @returns {object|null}
 */
export function scopeForManifest(manifest) {
  if (manifestScopes.has(manifest)) return manifestScopes.get(manifest);
  const scope = discoverScope(manifest[MANIFEST_DIR]);
  manifestScopes.set(manifest, scope);
  return scope;
}

/**
 * True if the IP literal `ip` lies in the range `cidr`. False when either
 * fails to parse or the families differ (an IPv4-mapped IPv6 address is
 * compared against an IPv4 range as its IPv4 address).
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
export function ipInCidr(ip, cidr) {
  const addr = parseCanonicalIp(String(ip));
  const range = parseCidr(String(cidr));
  if (addr === null || range === null) return false;
  return addrInRange(addr, range);
}

function addrInRange(addr, range) {
  if (ipInRange(addr, range)) return true;
  if (range.ip.family === 4 && addr.family === 6) {
    const v4 = toIpv4Mapped(addr);
    return v4 !== null && ipInRange(v4, range);
  }
  return false;
}

/** True if `inner` lies entirely inside `outer`. */
function cidrContains(outer, inner) {
  let candidate = inner;
  if (outer.ip.family === 4 && inner.ip.family === 6) {
    candidate = toIpv4MappedPrefix(inner);
    if (candidate === null) return false;
  }
  return candidate.prefix >= outer.prefix && prefixesOverlap(outer, candidate);
}

function cidrOverlaps(rule, subject) {
  let candidate = subject;
  if (rule.ip.family === 4 && subject.ip.family === 6) {
    candidate = toIpv4MappedPrefix(subject);
    if (candidate === null) return false;
  }
  return prefixesOverlap(rule, candidate);
}

/**
 * True if `host` matches the domain rule `pattern`: an exact rule matches
 * the host case-insensitively; `*.suffix` matches a strict subdomain of
 * `suffix` at any depth (a label boundary, never the apex).
 * @param {string} host
 * @param {string} pattern
 * @returns {boolean}
 */
export function hostMatchesRule(host, pattern) {
  const h = String(host).toLowerCase();
  const p = String(pattern).toLowerCase();
  if (p.startsWith("*.")) {
    const suffix = p.slice(1);
    return h.length > suffix.length && h.endsWith(suffix);
  }
  return h === p;
}

/**
 * Enforce the scope on a subject: a hostname, an IP literal or a CIDR.
 * @param {string} subject - The host (for a url) or the value itself
 * @param {object|null|undefined} scope - A scope definition; null/undefined
 *   is the fail-closed refusal
 * @throws {Error} when the subject is out of scope or no scope exists
 */
export function checkScope(subject, scope) {
  if (scope === null || scope === undefined) {
    throw new Error(NO_SCOPE_FILE_MESSAGE);
  }
  const s = normalize(scope);
  const value = String(subject);
  const outOfScope = () => new Error(`target '${value}' is not in scope`);

  const ip = parseCanonicalIp(value);
  if (ip !== null) {
    if (s.blocked_cidrs.some((r) => addrInRange(ip, r.range))) throw outOfScope();
    if (s.allowed_cidrs.some((r) => addrInRange(ip, r.range))) return;
    throw outOfScope();
  }
  const cidr = value.includes("/") ? parseCidr(value) : null;
  if (cidr !== null) {
    if (s.blocked_cidrs.some((r) => cidrOverlaps(r.range, cidr))) throw outOfScope();
    if (s.allowed_cidrs.some((r) => cidrContains(r.range, cidr))) return;
    throw outOfScope();
  }
  if (s.blocked_domains.some((rule) => hostMatchesRule(value, rule))) throw outOfScope();
  if (s.allowed_domains.some((rule) => hostMatchesRule(value, rule))) return;
  throw outOfScope();
}

/**
 * True if the host of `url` is in a scope whose allowed domains are
 * `allowedHosts`. The url is not otherwise validated here.
 * @param {string} url
 * @param {string[]} allowedHosts
 * @returns {boolean}
 */
export function urlHostInScope(url, allowedHosts) {
  const str = String(url);
  const idx = str.indexOf("://");
  if (idx === -1) return false;
  const rest = str.slice(idx + 3);
  const end = rest.search(/[/?#]/);
  let authority = end === -1 ? rest : rest.slice(0, end);
  if (authority.includes("@")) return false;
  let host;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close === -1) return false;
    host = authority.slice(1, close);
  } else {
    const colon = authority.indexOf(":");
    host = colon === -1 ? authority : authority.slice(0, colon);
  }
  try {
    checkScope(host, { allowed_domains: allowedHosts });
    return true;
  } catch {
    return false;
  }
}
