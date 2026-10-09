use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level manifest parsed from a `.clad.toml` file.
///
/// Every section carries `deny_unknown_fields`: a manifest is a security
/// contract, so a key the runtime does not implement is a load error rather
/// than a control that silently degrades to "off". The loader checks the
/// document against the key allowlist first (so it can name every unknown
/// key); serde is the second layer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub tool: ToolMeta,
    #[serde(default)]
    pub args: HashMap<String, ArgDef>,
    #[serde(default)]
    pub command: CommandDef,
    /// Output schema. Required for execution-mode manifests; optional when
    /// `tool.dispatch = "callback"` (validator-only embeddings).
    #[serde(default)]
    pub output: Option<OutputDef>,
    pub http: Option<HttpDef>,
    pub mcp: Option<McpProxyDef>,
    pub session: Option<SessionDef>,
    pub browser: Option<BrowserDef>,
    /// Directory the manifest was loaded from (`None` when parsed from a
    /// string). The scope file is discovered upward from here. Set by the
    /// loader; not part of the TOML surface.
    #[serde(skip)]
    pub source_dir: Option<std::path::PathBuf>,
    /// The project scope, loaded once at manifest load when any argument sets
    /// `scope_check = true` and a scope file was found. Not part of the TOML
    /// surface.
    #[serde(skip)]
    pub scope: Option<crate::scope::ScopeDef>,
}

/// Accepted values for `tool.mode`.
pub const MODES: &[&str] = &["oneshot", "session", "browser"];

impl Manifest {
    /// Effective execution mode. `tool.mode` is advisory: when declared it is
    /// returned as-is, otherwise the mode is derived from the backend section
    /// present (`[session]` → `"session"`, `[browser]` → `"browser"`, else
    /// `"oneshot"`).
    pub fn mode(&self) -> &str {
        match self.tool.mode.as_deref() {
            Some(mode) => mode,
            None if self.session.is_some() => "session",
            None if self.browser.is_some() => "browser",
            None => "oneshot",
        }
    }
}

/// Tool metadata section `[tool]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
    pub binary: String,
    pub description: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_risk_tier")]
    pub risk_tier: String,
    #[serde(default)]
    pub human_approval: bool,
    /// Dispatch mode. `"exec"` (default) runs an execution backend; `"callback"`
    /// declares the manifest as validator-only — no [output] or backend
    /// required. Useful for in-process embeddings where ToolClad is the typed
    /// argument fence and dispatch happens elsewhere.
    #[serde(default = "default_dispatch")]
    pub dispatch: String,
    /// Advisory execution mode: `"oneshot"`, `"session"`, or `"browser"`.
    /// Validated at load; see [`Manifest::mode`] for the derived value when
    /// absent.
    #[serde(default)]
    pub mode: Option<String>,
    /// Declares that the tool connects to a network destination derived from
    /// its arguments, so every network-target argument must default-deny
    /// internal addresses.
    #[serde(default)]
    pub network_egress: bool,
    /// Permit an interpreter (`sh`, `python`, `env`, ...) as the command's
    /// argv[0]. Off by default: an interpreter turns an argument into code.
    #[serde(default)]
    pub allow_interpreter: bool,
    pub cedar: Option<CedarMeta>,
    pub evidence: Option<EvidenceMeta>,
    pub limits: Option<ToolLimits>,
}

/// Resource limits for the child process `[tool.limits]`. Each limit is
/// applied only when declared.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLimits {
    pub nproc: Option<u64>,
    pub nofile: Option<u64>,
    pub fsize_bytes: Option<u64>,
    pub address_space_bytes: Option<u64>,
    pub cpu_seconds: Option<u64>,
}

fn default_dispatch() -> String {
    "exec".to_string()
}

fn default_timeout() -> u64 {
    60
}

fn default_risk_tier() -> String {
    "low".to_string()
}

/// Cedar policy integration metadata `[tool.cedar]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CedarMeta {
    pub resource: String,
    pub action: String,
}

/// Evidence capture configuration `[tool.evidence]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMeta {
    pub output_dir: String,
    #[serde(default)] // defaults to false, matching Python
    pub capture: bool,
    #[serde(default = "default_hash")]
    pub hash: String,
    /// Capture a screenshot per interaction (browser mode).
    #[serde(default)]
    pub screenshots: bool,
}

fn default_true() -> bool {
    true
}

fn default_hash() -> String {
    "sha256".to_string()
}

/// Argument definition `[args.<name>]`.
///
/// Each argument has a typed validator, optional constraints (min/max, pattern,
/// allowed list), and injection sanitization by default.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArgDef {
    #[serde(default)]
    pub position: u32,
    #[serde(default)]
    pub required: bool,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    #[serde(default)]
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub sanitize: Option<Vec<String>>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    /// Float bound for `number` type. Falls back to `min` cast to f64 when unset.
    #[serde(default)]
    pub min_float: Option<f64>,
    /// Float bound for `number` type. Falls back to `max` cast to f64 when unset.
    #[serde(default)]
    pub max_float: Option<f64>,
    #[serde(default)]
    pub clamp: bool,
    /// `url` only: scheme allowlist, compared case-insensitively. Empty means
    /// the default `["http", "https"]`. A scheme on the fixed denylist
    /// (javascript, data, file, blob, about, gopher, dict, ftp, ldap, jar,
    /// netdoc, mailto, ws, wss) is refused even when listed here.
    #[serde(default)]
    pub schemes: Vec<String>,
    /// `scope_target`, `url`, `ip_address` and `cidr` only (any other type
    /// is a load error): check the value (the host, for a `url`) against the
    /// project scope file, failing closed when none is found. See
    /// `crate::scope`.
    #[serde(default)]
    pub scope_check: bool,
    /// `scope_target`, `url`, `ip_address` and `cidr`: when true, reject a
    /// target in a non-public range — loopback, private, shared/CGNAT,
    /// unspecified, broadcast, documentation, benchmarking, reserved, and the
    /// IPv6 equivalents (incl. v4-mapped); the table lives in
    /// `crate::hostpolicy`. A literal is tested directly, a CIDR by overlap
    /// with every blocked range, and a hostname is resolved and every A/AAAA
    /// answer tested (a name that cannot be resolved is refused). Regardless
    /// of this flag, link-local (incl. cloud-metadata 169.254.0.0/16) and the
    /// internal-name denylist (`localhost`, `*.local`, `*.internal`, ...) are
    /// refused, and an IP literal embedded in a hostname (`127.0.0.1.nip.io`)
    /// is treated as that address. SSRF defense-in-depth, opt-in per arg so
    /// tools that legitimately target internal hosts are unaffected; an
    /// egress manifest must set it on every network-target argument.
    #[serde(default)]
    pub block_internal: bool,
    /// Permit a value that starts with `-` or `+`. Off by default so a user
    /// value can never be parsed by the target binary as an option
    /// (`-iL /etc/passwd`, `--output=/etc/cron.d/x`, `-rf`).
    #[serde(default)]
    pub allow_leading_dash: bool,
    /// Permit whitespace inside a string-derived value. Honored only when the
    /// manifest declares `command.exec` directly, because an `exec` element is
    /// a single argv entry that is never re-split. A `template`, even one
    /// compiled to exec at load, stays strict.
    #[serde(default)]
    pub allow_whitespace: bool,
}

/// Command construction definition `[command]`.
///
/// Supports two invocation forms:
/// - `exec = ["cmd", "arg1", "{placeholder}"]` — canonical, shell-free array execution
/// - `template = "cmd arg1 {placeholder}"` — deprecated string form, tokenized
///   at load into the same array (placeholders must be whole, unquoted tokens)
///
/// When both are present, `exec` takes precedence and `template` is kept for
/// display only.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDef {
    pub template: Option<String>,
    /// Canonical array-based command construction that maps directly to execve.
    /// Each element is a separate argv entry; `{placeholder}` tokens are interpolated
    /// but the result is never re-split, so values containing spaces are safe.
    /// When only `template` is given, the loader fills this in from the
    /// tokenized template.
    pub exec: Option<Vec<String>>,
    pub executor: Option<String>,
    #[serde(default)]
    pub defaults: Option<HashMap<String, toml::Value>>,
    #[serde(default)]
    pub mappings: Option<HashMap<String, HashMap<String, String>>>,
    #[serde(default)]
    pub conditionals: Option<HashMap<String, ConditionalDef>>,
    /// When set to `"--"` (the only accepted value), argv construction inserts
    /// a literal `--` immediately before the first argv entry that came from a
    /// token consisting solely of a user-argument placeholder, so the target
    /// binary stops option parsing before any user-controlled value.
    #[serde(default)]
    pub end_of_options: Option<String>,
    /// True when the manifest declared `exec` directly (as opposed to a
    /// `template` compiled to exec at load). Only a declared `exec` unlocks
    /// `allow_whitespace`. Set by the loader; not part of the TOML surface.
    #[serde(skip)]
    pub exec_was_declared: bool,
}

/// A conditional fragment `[command.conditionals.<name>]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalDef {
    pub when: String,
    pub template: String,
    /// The template tokenized at load (placeholders still unresolved). Each
    /// token is substituted individually at build time and the result is
    /// spliced into argv as `{_<name>}`. Not part of the TOML surface.
    #[serde(skip)]
    pub tokens: Vec<String>,
}

/// Output definition `[output]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDef {
    pub format: String,
    #[serde(default)]
    pub parser: Option<String>,
    #[serde(default = "default_true")]
    pub envelope: bool,
    #[serde(default = "default_schema")]
    pub schema: serde_json::Value,
    /// Upper bound on captured output, in bytes.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_schema() -> serde_json::Value {
    serde_json::json!({"type": "object"})
}

fn default_max_bytes() -> u64 {
    8_388_608
}

/// HTTP backend configuration `[http]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDef {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body_template: Option<String>,
    #[serde(default)]
    pub success_status: Vec<u16>,
    #[serde(default)]
    pub error_status: Vec<u16>,
}

/// MCP proxy backend configuration `[mcp]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpProxyDef {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub field_map: HashMap<String, String>,
}

/// Session mode configuration `[session]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionDef {
    pub startup_command: String,
    pub ready_pattern: String,
    #[serde(default = "default_timeout")]
    pub startup_timeout_seconds: u64,
    #[serde(default = "default_300")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_1800")]
    pub session_timeout_seconds: u64,
    #[serde(default = "default_100")]
    pub max_interactions: u32,
    pub interaction: Option<SessionInteractionDef>,
    #[serde(default)]
    pub commands: HashMap<String, SessionCommandDef>,
    pub child_detection: Option<SessionChildDetectionDef>,
}

/// Child-session detection `[session.child_detection]`.
///
/// Parsed so a manifest that declares it loads. A match on tool output alone
/// never registers a child session: output is attacker-influenced, so a child
/// context may only be registered when the runtime observes it through a
/// channel the far side does not control, with the contract taken from
/// `manifest`, resolved at load time.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionChildDetectionDef {
    pub pattern: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub manifest: String,
}

fn default_300() -> u64 {
    300
}

fn default_1800() -> u64 {
    1800
}

fn default_100() -> u32 {
    100
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInteractionDef {
    #[serde(default)]
    pub input_sanitize: Vec<String>,
    #[serde(default = "default_1mb")]
    pub output_max_bytes: u64,
    #[serde(default = "default_2000")]
    pub output_wait_ms: u64,
}

fn default_1mb() -> u64 {
    1_048_576
}

fn default_2000() -> u64 {
    2000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCommandDef {
    pub pattern: String,
    pub description: String,
    #[serde(default = "default_risk_tier")]
    pub risk_tier: String,
    #[serde(default)]
    pub human_approval: bool,
    #[serde(default)]
    pub extract_target: bool,
    #[serde(default)]
    pub args: HashMap<String, ArgDef>,
}

/// Browser mode configuration `[browser]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDef {
    #[serde(default = "default_cdp")]
    pub engine: String,
    #[serde(default = "default_true")]
    pub headless: bool,
    /// "launch" (spawn headless) or "live" (attach to running Chrome)
    #[serde(default = "default_launch")]
    pub connect: String,
    /// "accessibility_tree" | "html" | "text"
    #[serde(default = "default_a11y")]
    pub extract_mode: String,
    #[serde(default = "default_10")]
    pub startup_timeout_seconds: u64,
    #[serde(default = "default_600")]
    pub session_timeout_seconds: u64,
    #[serde(default = "default_120")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_200")]
    pub max_interactions: u32,
    pub scope: Option<BrowserScopeDef>,
    #[serde(default)]
    pub commands: HashMap<String, BrowserCommandDef>,
    pub state: Option<BrowserStateDef>,
    pub defaults: Option<BrowserDefaultsDef>,
}

/// Per-command defaults `[browser.defaults]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDefaultsDef {
    /// "accessibility_tree" | "html" | "text"
    pub extract_mode: Option<String>,
}

fn default_10() -> u64 {
    10
}

fn default_120() -> u64 {
    120
}

fn default_200() -> u32 {
    200
}

fn default_600() -> u64 {
    600
}

fn default_cdp() -> String {
    "cdp".to_string()
}

fn default_launch() -> String {
    "launch".to_string()
}

fn default_a11y() -> String {
    "accessibility_tree".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserScopeDef {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub allow_external: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCommandDef {
    pub description: String,
    #[serde(default = "default_risk_tier")]
    pub risk_tier: String,
    #[serde(default)]
    pub human_approval: bool,
    #[serde(default)]
    pub args: HashMap<String, ArgDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserStateDef {
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Evidence envelope wrapping tool execution results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub status: String,
    pub scan_id: String,
    pub tool: String,
    pub command: String,
    pub duration_ms: u64,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    pub exit_code: i32,
    pub stderr: String,
    pub results: serde_json::Value,
    /// True when stdout, stderr or an HTTP body was cut at `[output] max_bytes`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub output_truncated: bool,
}

/// Errors produced by ToolClad operations.
#[derive(Debug, Clone)]
pub enum ToolCladError {
    /// Manifest parsing or structural error.
    ManifestError(String),
    /// Argument validation failure.
    ValidationError(String),
    /// Command construction error.
    CommandError(String),
    /// Execution error (timeout, process failure, etc.).
    ExecutionError(String),
    /// The policy gate refused the call before anything ran. Displays as
    /// `policy gate denied: <reason>`.
    PolicyDenied(String),
}

impl std::fmt::Display for ToolCladError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestError(msg) => write!(f, "manifest error: {msg}"),
            Self::ValidationError(msg) => write!(f, "validation error: {msg}"),
            Self::CommandError(msg) => write!(f, "command error: {msg}"),
            Self::ExecutionError(msg) => write!(f, "execution error: {msg}"),
            Self::PolicyDenied(reason) => write!(f, "policy gate denied: {reason}"),
        }
    }
}

impl std::error::Error for ToolCladError {}

/// Custom type definition from toolclad.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomTypeDef {
    pub base: String,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    #[serde(default)]
    pub min_float: Option<f64>,
    #[serde(default)]
    pub max_float: Option<f64>,
}
