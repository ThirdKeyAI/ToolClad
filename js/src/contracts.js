/** Common reference-execution checks; these do not provide a sandbox. */
import { validateArg } from './validator.js';
import http from 'node:http';
import https from 'node:https';

export const MAX_REQUEST_BYTES = 1024 * 1024;
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const token = /\{(_secret:[A-Za-z0-9_]+|\w+)\}/g;

export function validateArguments(manifest, args) {
  const definitions = manifest.args || {};
  for (const name of Object.keys(args)) {
    if (!Object.hasOwn(definitions, name)) throw new Error(`Unknown argument: ${name}`);
  }
  const resolved = {};
  for (const [name, def] of Object.entries(definitions)) {
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name) || ['constructor', 'prototype', '__proto__'].includes(name)) {
      throw new Error(`Invalid argument name: ${name}`);
    }
    const value = Object.hasOwn(args, name) ? args[name] : (def.default ?? manifest.command?.defaults?.[name]);
    if (def.type === "literal_text" && Object.hasOwn(args, name) && typeof value !== "string") throw new Error(`literal_text requires a string: ${name}`);
    if (value === undefined || value === null) {
      if (def.required) throw new Error(`Missing required argument: ${name}`);
      continue;
    }
    if (String(value).includes('\0') || (def.required && def.type !== "literal_text" && !String(value).trim())) throw new Error(`Invalid empty or NUL argument: ${name}`);
    resolved[name] = validateArg(def, value);
  }
  if (Object.values(resolved).reduce((n, v) => n + Buffer.byteLength(String(v)), 0) > MAX_REQUEST_BYTES) throw new Error('Arguments exceed 1 MiB');
  return resolved;
}

export function checkExecution(manifest, dryRun = false) {
  const timeout = manifest.tool.timeout_seconds ?? 60;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) throw new Error('timeout_seconds must be between 1 and 3600');
  const command = manifest.command || {};
  if ([command.exec?.length || command.template, command.executor, manifest.http, manifest.mcp, manifest.session, manifest.browser].filter(Boolean).length > 1) throw new Error('Ambiguous execution backends');
  if (dryRun) return;
  if (Object.hasOwn(manifest, 'filesystem')) throw new Error('Filesystem grants require an embedding runtime');
  if ((manifest.tool.dispatch ?? 'exec') !== 'exec' || manifest.tool.human_approval || manifest.tool.cedar || Object.values(manifest.args || {}).some(a => a.scope_check)) {
    throw new Error('Execution requires an embedding runtime for dispatch, approval, Cedar or scope enforcement');
  }
  const parser = manifest.output?.parser;
  if (parser && !['builtin:json', 'builtin:xml', 'builtin:csv', 'builtin:jsonl', 'builtin:text'].includes(parser)) throw new Error('Custom output parsers require an embedding runtime');
}

export function childEnvironment() {
  return Object.fromEntries(['PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
}

export function splitTemplate(text) {
  const parts = [];
  let current = '', quote = '', started = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\' && quote !== "'") {
      const next = text[++i];
      if (next === undefined) throw new Error('Unfinished command escape');
      if (quote === '"' && !['"', '\\', '$', '`', '\n'].includes(next)) current += '\\';
      if (next !== '\n') current += next;
      started = true;
    } else if (quote) {
      if (c === quote) quote = ''; else current += c;
    } else if (c === "'" || c === '"') {
      quote = c; started = true;
    } else if (/\s/.test(c)) {
      if (started) { parts.push(current); current = ''; started = false; }
    } else { current += c; started = true; }
  }
  if (quote) throw new Error('Unclosed command quote');
  if (started) parts.push(current);
  return parts;
}

export function quoteArg(value) {
  const text = String(value);
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(text) ? text : "'" + text.replaceAll("'", "'\"'\"'") + "'";
}

export function templateArgv(template, values, fragments, present = {}) {
  const substitute = t => t.replace(token, (m, k) => String(values[k] ?? m));
  const argv = [];
  for (const part of splitTemplate(template)) {
    const match = /^\{(\w+)\}$/.exec(part);
    if (match && Object.hasOwn(fragments, match[1])) argv.push(...splitTemplate(fragments[match[1]]).map(substitute));
    else { const value = substitute(part); if (value || !part || [...part.matchAll(token)].some(m => Object.hasOwn(present, m[1]))) argv.push(value); }
  }
  if (!argv.length || !argv[0]) throw new Error('Command produced empty argv');
  return argv;
}

export function prepareHttp(manifest, args, dryRun = false) {
  args = validateArguments(manifest, args);
  checkExecution(manifest, dryRun);
  const def = manifest.http;
  const authority = /^(https?):\/\/([^/?#]+)/.exec(def.url);
  if (!authority || /[{}@\\]/.test(authority[2]) || def.url.includes('{_secret:')) throw new Error('HTTP URL requires a fixed http(s) authority without credentials or secrets');
  const url = def.url.replace(token, (m, k) => String(args[k] ?? m));
  const parsed = new URL(url);
  if (/[\x00-\x20\\]/.test(url) || parsed.hash || /^(https?):\/\/([^/?#]+)/.exec(url)?.[0] !== authority[0]) throw new Error('Invalid HTTP URL or changed authority');
  function render(template, json = false) {
    return template.replace(token, (m, key) => {
      let value;
      if (key.startsWith('_secret:')) {
        const name = 'TOOLCLAD_SECRET_' + key.slice(8).toUpperCase();
        value = dryRun ? '[REDACTED]' : process.env[name];
        if (value === undefined) throw new Error(`Missing secret environment variable: ${name}`);
      } else value = args[key] ?? m;
      return json ? JSON.stringify(String(value)).slice(1, -1) : String(value);
    });
  }
  const headers = Object.fromEntries(Object.entries(def.headers || {}).map(([k, v]) => [k, render(v)]));
  for (const [k, v] of Object.entries(headers)) if (/[\r\n\0]/.test(k + v)) throw new Error('Invalid HTTP header');
  const body = def.body_template === undefined ? undefined : render(def.body_template, true);
  if (Buffer.byteLength(url + (body || '') + Object.entries(headers).flat().join('')) > MAX_REQUEST_BYTES) throw new Error('HTTP request exceeds 1 MiB');
  return { url, headers, body, resolvedArgs: args };
}

export function requestHttp(url, options, timeoutSeconds) {
  // Core HTTP clients neither redirect nor consult proxy environment variables.
  return new Promise((resolve, reject) => {
    const client = new URL(url).protocol === 'https:' ? https : http;
    let timer;
    const req = client.request(url, { ...options, agent: false }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) req.destroy(new Error('HTTP response exceeds 4 MiB'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); });
    });
    req.on('error', e => { clearTimeout(timer); reject(e); });
    timer = setTimeout(() => req.destroy(new Error('HTTP request timed out')), timeoutSeconds * 1000);
    req.end(options.body);
  });
}
