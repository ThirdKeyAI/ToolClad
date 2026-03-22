---
title: Browser Mode
description: CDP browser mode for governed browser automation
---

# Browser Mode

Browser mode manages browser sessions through direct CDP (Chrome DevTools Protocol) WebSocket connections. The governance model is identical to CLI session mode: typed commands, per-interaction Cedar gating, scope enforcement, state-aware policies, output schema validation, evidence capture. The transport is a browser engine instead of a PTY.

---

## `[tool.browser]` Configuration

The `[browser]` section controls browser lifecycle and connection behavior.

### Connection Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `engine` | string | `"cdp"` | `"cdp-direct"` (recommended) or `"playwright"` (optional convenience layer) |
| `connect` | string | `"launch"` | `"launch"` spawns a new headless browser. `"live"` attaches to a running Chrome session. |
| `headless` | boolean | `true` | Run headless. Ignored when `connect = "live"`. |

### Timeouts and Limits

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `startup_timeout_seconds` | integer | `60` | Max time to wait for browser ready |
| `session_timeout_seconds` | integer | `1800` | Max total session lifetime |
| `idle_timeout_seconds` | integer | `300` | Max time between interactions |
| `max_interactions` | integer | `100` | Maximum command/response rounds |

### Content Extraction

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `extract_mode` | string | `"accessibility_tree"` | Default content extraction: `"accessibility_tree"`, `"html"`, or `"text"` |

The accessibility tree is the recommended default. It returns a compact semantic representation of the page (buttons, links, headings, form fields) instead of raw HTML. This is dramatically more token-efficient for LLM consumption.

When raw HTML is needed (for scraping or debugging), use the `extract_html` command with a CSS selector to scope the output.

### Example

```toml
[browser]
engine = "cdp-direct"
connect = "launch"
headless = true
extract_mode = "accessibility_tree"
startup_timeout_seconds = 10
session_timeout_seconds = 600
idle_timeout_seconds = 120
max_interactions = 200
```

---

## `[browser.scope]` -- URL Scope Enforcement

The `[browser.scope]` section defines which domains the browser can visit. This is the browser equivalent of target scope checking on CLI tools like nmap.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_domains` | array | `[]` | Glob patterns for permitted navigation domains |
| `blocked_domains` | array | `[]` | Glob patterns for explicitly blocked domains |
| `allow_external` | boolean | `false` | If `false`, browser cannot leave `allowed_domains`. If `true`, allows unlisted domains but still blocks `blocked_domains`. |

```toml
[browser.scope]
allowed_domains = ["*.example.com", "docs.example.com"]
blocked_domains = ["*.evil.com", "admin.*"]
allow_external = false
```

### Enforcement Levels

Scope checking operates at three levels:

1. **Navigation commands.** The `navigate` command's URL is validated against `[browser.scope]` before the CDP command fires.
2. **Redirect interception.** The BrowserExecutor intercepts HTTP redirects and validates each hop. A page at `allowed.example.com` that redirects to `evil.com` is blocked mid-redirect.
3. **Link click validation.** When the agent uses `click` on a link, the executor resolves the `href` and validates before allowing the navigation.

The `allow_external = false` setting is the strictest mode: the browser cannot leave the declared domain set under any circumstances.

---

## `[browser.commands.*]` -- Browser Commands

Each entry in `[browser.commands]` declares a permitted browser operation. Each command becomes a separate MCP tool visible to the LLM during the session.

### Command Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `description` | string | -- | Human-readable description shown in MCP tool listing |
| `risk_tier` | string | `"low"` | `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `human_approval` | boolean | `false` | Whether this command requires human approval |
| `args.*` | table | -- | Typed arguments for the command |

### Action Types

#### `navigate` -- Navigate to a URL

```toml
[browser.commands.navigate]
description = "Navigate a tab to a URL"
risk_tier = "medium"
args.url = { type = "url", schemes = ["https"], scope_check = true }
```

URLs are scope-checked against `[browser.scope]` before the CDP command fires.

#### `click` -- Click an element

```toml
[browser.commands.click]
description = "Click an element by CSS selector"
risk_tier = "low"
args.selector = { type = "string", pattern = "^[a-zA-Z0-9_.#\\[\\]=\"' >:()-]+$" }
```

#### `type_text` -- Type into an element

```toml
[browser.commands.type_text]
description = "Type text into the focused element"
risk_tier = "low"
args.text = { type = "string", sanitize = ["injection"] }
```

#### `scroll` -- Scroll the page

```toml
[browser.commands.scroll]
description = "Scroll the page"
risk_tier = "low"
args.direction = { type = "enum", allowed = ["up", "down"] }
args.amount = { type = "integer", min = 1, max = 10, default = 3 }
```

#### `wait_for` -- Wait for an element

```toml
[browser.commands.wait_for]
description = "Wait for an element to appear"
risk_tier = "low"
args.selector = { type = "string" }
args.timeout_ms = { type = "integer", min = 100, max = 30000, default = 5000 }
```

#### `extract` / `snapshot` -- Extract page content

```toml
[browser.commands.snapshot]
description = "Get accessibility tree snapshot of the current page"
risk_tier = "low"
args.selector = { type = "string", required = false, description = "Optional CSS selector to scope the snapshot" }

[browser.commands.extract_html]
description = "Get raw HTML scoped to a CSS selector"
risk_tier = "low"
args.selector = { type = "string", required = true }
```

#### `screenshot` -- Capture evidence

```toml
[browser.commands.screenshot]
description = "Capture page screenshot for evidence"
risk_tier = "low"
```

#### `submit_form` -- Submit a form (high risk)

```toml
[browser.commands.submit_form]
description = "Submit a form"
risk_tier = "high"
human_approval = true
args.selector = { type = "string" }
```

#### `execute_js` -- Evaluate JavaScript (high risk)

```toml
[browser.commands.execute_js]
description = "Evaluate JavaScript in page context"
risk_tier = "high"
human_approval = true
args.expression = { type = "string" }
```

### Commands Reference Table

| Command | Description | Risk | Arguments |
|---------|-------------|------|-----------|
| `navigate` | Navigate a tab to a URL | medium | `url` (url, scope-checked) |
| `click` | Click an element by CSS selector | low | `selector` (string) |
| `type_text` | Type text into the focused element | low | `text` (string, injection-safe) |
| `submit_form` | Submit a form | high | `selector` (string) |
| `snapshot` | Get accessibility tree snapshot | low | `selector` (optional string) |
| `extract_html` | Get raw HTML scoped to a CSS selector | low | `selector` (string) |
| `screenshot` | Capture page screenshot for evidence | low | -- |
| `execute_js` | Evaluate JavaScript in page context | high | `expression` (string) |
| `wait_for` | Wait for an element to appear | low | `selector`, `timeout_ms` |
| `go_back` | Navigate back in browser history | low | -- |
| `list_tabs` | List open browser tabs | low | -- |
| `network_timing` | Get network resource timing data | low | -- |

---

## Interaction Tracking

The BrowserExecutor tracks session state after each interaction.

### `[browser.state]` Fields

```toml
[browser.state]
fields = ["url", "title", "domain", "has_forms", "is_authenticated", "page_loaded", "tab_count"]
```

| Field | Source | Use |
|-------|--------|-----|
| `url` | Current page URL | Domain-based policies |
| `title` | Page title | Context for agent reasoning |
| `domain` | Extracted from URL | Scope enforcement |
| `has_forms` | DOM inspection | Form submission gating |
| `is_authenticated` | Session cookies, user profile elements | Elevated caution on authenticated pages |
| `page_loaded` | Page load event + network idle | Ready detection |
| `tab_count` | Chrome tab enumeration | Tab management policies |

Cedar policies can reference these fields for authorization decisions.

---

## Evidence Collection

Every browser interaction produces a structured evidence envelope. When `[tool.evidence].screenshots = true`, the BrowserExecutor also captures a page screenshot at each interaction for the audit trail.

The evidence envelope includes:

- Current URL, title, and domain after the command
- Content (accessibility tree, HTML, or command result)
- Page state for Cedar policy context
- Screenshot file path (if configured)
- Interaction count
- SHA-256 hash of the output

---

## Per-Interaction ORGA Gating

Each browser command goes through the full Observe-Reason-Gate-Act cycle:

```
Iteration 1:
  Observe:  {url: "https://app.example.com/login", title: "Login", has_forms: true}
  Reason:   LLM proposes browser_session.type_text(selector="#email", text="user@co.com")
  Gate:     Cedar: is type_text allowed? ToolClad: text is injection-safe
  Act:      BrowserExecutor sends CDP command, waits for page stable

Iteration 2:
  Observe:  {url: "https://app.example.com/login", title: "Login"}
  Reason:   LLM proposes browser_session.submit_form(selector="#login-form")
  Gate:     Cedar: submit_form requires human_approval -> PENDING
  Act:      (blocked until human approves)

Iteration 3:
  Observe:  {url: "https://app.example.com/dashboard", is_authenticated: true}
  Reason:   LLM proposes browser_session.navigate(url="https://evil.com/exfil")
  Gate:     ToolClad: URL scope check -> DENY (domain not in allowed_domains)
  Act:      (blocked, denial fed back to agent)
```

---

## Live Browser Attachment

When `connect = "live"`, the BrowserExecutor attaches to the user's running Chrome session via its debug port (`http://localhost:9222/json`). This enables:

- Interaction with tabs the user already has open, including logged-in sessions
- Agent operates in the user's authenticated context
- The executor does not own the browser lifecycle

```toml
[tool]
name = "chrome_live"
mode = "browser"
description = "Governed access to live Chrome session"
risk_tier = "medium"

[tool.cedar]
resource = "Web::BrowserSession"
action = "browse"

[browser]
engine = "cdp-direct"
connect = "live"
headless = false
idle_timeout_seconds = 1200

[browser.scope]
allowed_domains = ["github.com", "*.internal.corp.com"]
blocked_domains = ["*.evil.com"]
allow_external = false
```

---

## Cedar Policy Examples

### Allow navigation only to allowed domains

```cedar
permit (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "navigate" &&
    resource.url_domain in Web::DomainSet::"allowed"
};
```

### Block form submission on authenticated pages without approval

```cedar
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "submit_form" &&
    resource.page_state.is_authenticated == true
}
unless {
    resource.human_approved == true
};
```

### Block all JavaScript execution unless approved

```cedar
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "execute_js"
}
unless {
    resource.human_approved == true
};
```

### Rate limit form submissions per session

```cedar
forbid (
    principal,
    action == Web::Action::"browse",
    resource
)
when {
    resource.command == "submit_form" &&
    resource.session_submit_count >= 5
};
```

---

## Use Cases

| Use Case | Connect Mode | Commands Used | Governance Value |
|----------|--------------|---------------|------------------|
| Web application testing | `launch` | navigate, click, type_text, submit_form, snapshot | Scope-locked to test environment. Form submission gated. |
| Competitive intelligence | `launch` | navigate, snapshot, screenshot | Read-only. No form submission, no JS execution. |
| Form filling / workflow automation | `launch` | navigate, type_text, submit_form, snapshot | Human approval on submission. Scope-locked to target app. |
| Web scraping | `launch` | navigate, snapshot, click | Read-only. Rate-limited. Domain-locked. |
| Developer assistant (live browser) | `live` | list_tabs, snapshot, extract_html, screenshot | Read-only access to user's logged-in sessions. |
| Internal tool automation | `live` | navigate, click, type_text, submit_form, snapshot | Agent in user's authenticated context. Scope-locked to internal domains. |
| Debugging / monitoring | `live` | snapshot, network_timing, screenshot | Read-only inspection of live page state and performance. |

---

## Out of Scope

The following are explicitly excluded from browser mode:

- **Coordinate-based clicking** (`clickxy`, pixel-coordinate targeting): ToolClad browser commands operate on CSS selectors, which are semantic and validatable. Coordinate-based clicking depends on viewport size and zoom level, making it non-deterministic and ungovernable.
- **Raw CDP passthrough**: Exposing raw Chrome DevTools Protocol methods to the agent bypasses all ToolClad validation. Browser commands are the governed surface; raw CDP is the implementation detail the BrowserExecutor uses internally.
- **Non-headless GUI automation**: Browser mode supports both headless and live browser attachment, but interaction is always through CSS selectors and typed commands via CDP. GUI-level automation (mouse movement, screen capture-based element detection) is out of scope.
