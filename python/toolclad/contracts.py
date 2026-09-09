"""Common checks for reference execution. These checks do not provide a sandbox."""
import json
import os
import re
import shlex
from urllib.parse import urlsplit

from .validator import ValidationError, validate_arg

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TOKEN = re.compile(r"\{(_secret:[A-Za-z0-9_]+|\w+)\}")


def validate_arguments(manifest, args):
    unknown = set(args) - set(manifest.args)
    if unknown:
        raise ValidationError(f"Unknown arguments: {', '.join(sorted(unknown))}")
    resolved = {}
    for name, definition in manifest.args.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise ValidationError(f"Invalid argument name: {name}")
        if definition.type == "literal_text" and name in args and not isinstance(args[name], str):
            raise ValidationError(f"literal_text requires a string: {name}")
        value = args.get(name, definition.default)
        if value is None:
            value = manifest.command.defaults.get(name)
        if value is None:
            if definition.required:
                raise ValidationError(f"Missing required argument: '{name}'")
            continue
        if definition.type == "literal_text" and not isinstance(value, str):
            raise ValidationError(f"literal_text requires a string: {name}")
        value = str(value).lower() if isinstance(value, bool) else str(value)
        if "\0" in value or (definition.required and definition.type != "literal_text" and not value.strip()):
            raise ValidationError(f"Invalid empty or NUL argument: {name}")
        resolved[name] = validate_arg(definition, value)
    if sum(len(v.encode()) for v in resolved.values()) > MAX_REQUEST_BYTES:
        raise ValidationError("Arguments exceed 1 MiB")
    return resolved


def check_execution(manifest, dry_run=False):
    if type(manifest.tool.timeout_seconds) is not int or not 1 <= manifest.tool.timeout_seconds <= 3600:
        raise ValueError("timeout_seconds must be between 1 and 3600")
    command = manifest.command
    backends = sum(bool(v) for v in (
        command.exec or command.template, command.executor,
        manifest.http, manifest.mcp, manifest.session, manifest.browser,
    ))
    if backends > 1:
        raise ValueError("Ambiguous execution backends")
    if dry_run:
        return
    if (manifest.tool.dispatch != "exec" or manifest.tool.human_approval
            or manifest.tool.cedar._configured or manifest.tool.cedar.resource or manifest.tool.cedar.action
            or any(a.scope_check for a in manifest.args.values())):
        raise ValueError("Execution requires an embedding runtime for dispatch, approval, Cedar or scope enforcement")
    parser = manifest.output.parser if manifest.output else ""
    if parser and parser not in ("builtin:json", "builtin:xml", "builtin:csv", "builtin:jsonl", "builtin:text"):
        raise ValueError("Custom output parsers require an embedding runtime")


def child_environment():
    return {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}


def template_argv(template, values, fragments, present=()):
    """Only manifest-owned fragments may introduce argument boundaries."""
    def substitute(text):
        return TOKEN.sub(lambda m: str(values.get(m[1], m[0])), text)
    argv = []
    for token in shlex.split(template):
        match = TOKEN.fullmatch(token)
        if match and match[1] in fragments:
            argv.extend(substitute(part) for part in shlex.split(fragments[match[1]]))
        else:
            value = substitute(token)
            if value or not token or any(m[1] in present for m in TOKEN.finditer(token)):
                argv.append(value)
    if not argv or not argv[0]:
        raise ValueError("Command produced empty argv")
    return argv


def http_url(template, args):
    # Dynamic authorities need an egress broker; reference runners accept fixed origins.
    match = re.match(r"^(https?)://([^/?#]+)", template)
    if not match or any(c in match[2] for c in "{}@\\") or "{_secret:" in template:
        raise ValueError("HTTP URL requires a fixed http(s) authority without credentials or secrets")
    url = TOKEN.sub(lambda m: args.get(m[1], m[0]), template)
    parsed = urlsplit(url)
    if (parsed.scheme + "://" + parsed.netloc != match[0]
            or parsed.fragment or any(ord(c) <= 32 or c == "\\" for c in url)):
        raise ValueError("Invalid HTTP URL or changed authority")
    _ = parsed.port  # Reject malformed ports before requesting anything.
    return url


def http_template(template, args, *, dry_run=False, json_string=False):
    """Expand tokens in the trusted template exactly once; values remain literal."""
    def replace(match):
        key = match[1]
        if key.startswith("_secret:"):
            if dry_run:
                value = "[REDACTED]"
            else:
                name = "TOOLCLAD_SECRET_" + key[8:].upper()
                if name not in os.environ:
                    raise ValueError(f"Missing secret environment variable: {name}")
                value = os.environ[name]
        else:
            value = args.get(key, match[0])
        return json.dumps(value)[1:-1] if json_string else value
    return TOKEN.sub(replace, template)
