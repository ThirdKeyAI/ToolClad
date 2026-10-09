/**
 * A small JSON-Schema subset validator used to check parsed tool output
 * against `[output.schema]`. No dependency; the supported keywords are:
 *
 *   type (one name or an array of names), properties, required,
 *   additionalProperties (boolean only), items (a single sub-schema), enum,
 *   minimum, maximum, minLength, maxLength, pattern.
 *
 * Unknown keywords are ignored. `integer` accepts any number with no
 * fractional part (so `30.0` is an integer). `pattern` is anchored like every
 * other pattern in ToolClad (`^(?:pat)$`). The whole document is walked in
 * document order and the first failure is reported as
 * `"<json pointer>: <message>"`, with the root rendered as `/`.
 */

import { anchorPattern } from "./validator.js";

const TYPE_NAMES = new Set([
  "object", "array", "string", "number", "integer", "boolean", "null",
]);

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The JSON type name of a value (`integer` is reported as `number`). */
function jsonTypeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "object") return "object";
  return typeof value;
}

function matchesType(value, name) {
  switch (name) {
    case "object":
      return isObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      return false;
  }
}

/** Describe a value's type for an error message, preferring `integer`. */
function describeType(value) {
  if (typeof value === "number" && Number.isInteger(value)) return "integer";
  return jsonTypeOf(value);
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
  }
  return false;
}

/** Escape one JSON-pointer reference token (RFC 6901). */
function pointerToken(token) {
  return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

function fail(pointer, message) {
  return `${pointer === "" ? "/" : pointer}: ${message}`;
}

function walk(schema, value, pointer) {
  if (!isObject(schema)) return null;

  if (schema.type !== undefined) {
    const names = Array.isArray(schema.type) ? schema.type : [schema.type];
    const known = names.filter((n) => TYPE_NAMES.has(n));
    if (known.length > 0 && !known.some((n) => matchesType(value, n))) {
      return fail(pointer, `expected ${known.join(" or ")}, got ${describeType(value)}`);
    }
  }

  if (Array.isArray(schema.enum)) {
    if (!schema.enum.some((member) => deepEqual(member, value))) {
      return fail(pointer, `value ${JSON.stringify(value)} is not one of the allowed values`);
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      return fail(pointer, `${value} is less than the minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      return fail(pointer, `${value} is greater than the maximum ${schema.maximum}`);
    }
  }

  if (typeof value === "string") {
    const length = [...value].length;
    if (typeof schema.minLength === "number" && length < schema.minLength) {
      return fail(pointer, `string is shorter than ${schema.minLength} characters`);
    }
    if (typeof schema.maxLength === "number" && length > schema.maxLength) {
      return fail(pointer, `string is longer than ${schema.maxLength} characters`);
    }
    if (typeof schema.pattern === "string") {
      let re;
      try {
        re = new RegExp(anchorPattern(schema.pattern), "u");
      } catch {
        return fail(pointer, `schema pattern is not a valid regular expression: ${schema.pattern}`);
      }
      if (!re.test(value)) {
        return fail(pointer, `string does not match pattern ${schema.pattern}`);
      }
    }
  }

  if (isObject(value)) {
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) {
        if (!Object.hasOwn(value, name)) {
          return fail(pointer, `missing required property '${name}'`);
        }
      }
    }
    const props = isObject(schema.properties) ? schema.properties : {};
    for (const [key, child] of Object.entries(value)) {
      const childPointer = `${pointer}/${pointerToken(key)}`;
      if (Object.hasOwn(props, key)) {
        const err = walk(props[key], child, childPointer);
        if (err) return err;
      } else if (schema.additionalProperties === false) {
        return fail(childPointer, "additional property is not allowed");
      }
    }
  }

  if (Array.isArray(value) && isObject(schema.items)) {
    for (let i = 0; i < value.length; i++) {
      const err = walk(schema.items, value[i], `${pointer}/${i}`);
      if (err) return err;
    }
  }

  return null;
}

/**
 * Validate `value` against `schema`.
 *
 * @param {object} schema - A JSON-Schema subset document
 * @param {*} value - The parsed value to check
 * @returns {string|null} `"<pointer>: <message>"` for the first failure, or null
 */
export function validateJsonSchema(schema, value) {
  return walk(schema, value, "");
}
