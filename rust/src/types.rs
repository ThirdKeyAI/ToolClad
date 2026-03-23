use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level manifest parsed from a `.clad.toml` file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub tool: ToolMeta,
    #[serde(default)]
    pub args: HashMap<String, ArgDef>,
    #[serde(default)]
    pub command: CommandDef,
    pub output: OutputDef,
    pub http: Option<HttpDef>,
    pub mcp: Option<McpProxyDef>,
    pub session: Option<SessionDef>,
    pub browser: Option<BrowserDef>,
}

/// Tool metadata section `[tool]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub cedar: Option<CedarMeta>,
    pub evidence: Option<EvidenceMeta>,
}

fn default_timeout() -> u64 {
    60
}

fn default_risk_tier() -> String {
    "low".to_string()
}

/// Cedar policy integration metadata `[tool.cedar]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CedarMeta {
    pub resource: String,
    pub action: String,
}

/// Evidence capture configuration `[tool.evidence]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvidenceMeta {
    pub output_dir: String,
    #[serde(default)] // defaults to false, matching Python
    pub capture: bool,
    #[serde(default = "default_hash")]
    pub hash: String,
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
    #[serde(default)]
    pub clamp: bool,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub scope_check: bool,
}

/// Command construction definition `[command]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CommandDef {
    pub template: Option<String>,
    pub executor: Option<String>,
    #[serde(default)]
    pub defaults: Option<HashMap<String, toml::Value>>,
    #[serde(default)]
    pub mappings: Option<HashMap<String, HashMap<String, String>>>,
    #[serde(default)]
    pub conditionals: Option<HashMap<String, ConditionalDef>>,
}

/// A conditional fragment `[command.conditionals.<name>]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalDef {
    pub when: String,
    pub template: String,
}

/// Output definition `[output]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputDef {
    pub format: String,
    #[serde(default)]
    pub parser: Option<String>,
    #[serde(default = "default_true")]
    pub envelope: bool,
    #[serde(default = "default_schema")]
    pub schema: serde_json::Value,
}

fn default_schema() -> serde_json::Value {
    serde_json::json!({"type": "object"})
}

/// HTTP backend configuration `[http]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub struct McpProxyDef {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub field_map: HashMap<String, String>,
}

/// Session mode configuration `[session]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub struct BrowserScopeDef {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub allow_external: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
}

impl std::fmt::Display for ToolCladError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestError(msg) => write!(f, "manifest error: {msg}"),
            Self::ValidationError(msg) => write!(f, "validation error: {msg}"),
            Self::CommandError(msg) => write!(f, "command error: {msg}"),
            Self::ExecutionError(msg) => write!(f, "execution error: {msg}"),
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
}
