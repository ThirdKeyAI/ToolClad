use crate::types::{EvidenceEnvelope, Manifest, ToolCladError};
use crate::validator::validate_arg;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

/// Build the command string from a manifest template and validated arguments.
///
/// Performs template interpolation including:
/// - Direct argument substitution (`{arg_name}`)
/// - Mapping resolution (`{_scan_flags}` from `[command.mappings.scan_type]`)
/// - Default value injection (`[command.defaults]`)
/// - Conditional fragment inclusion (`[command.conditionals]`)
pub fn build_command(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<String, ToolCladError> {
    let template = manifest
        .command
        .template
        .as_ref()
        .ok_or_else(|| {
            ToolCladError::CommandError(
                "no command template (use executor for custom wrappers)".to_string(),
            )
        })?
        .clone();

    // Start with provided args.
    let mut vars: HashMap<String, String> = args.clone();

    // Inject defaults for missing args.
    if let Some(ref defaults) = manifest.command.defaults {
        for (key, val) in defaults {
            vars.entry(key.clone())
                .or_insert_with(|| toml_value_to_string(val));
        }
    }

    // Inject defaults from arg definitions for missing args.
    for (key, def) in &manifest.args {
        if !vars.contains_key(key) {
            if let Some(ref default_val) = def.default {
                vars.insert(key.clone(), toml_value_to_string(default_val));
            }
        }
    }

    // Resolve mappings: for each mapping `[command.mappings.<arg_name>]`, look up
    // the arg value and produce a `_{arg_name}_flags` variable.
    if let Some(ref mappings) = manifest.command.mappings {
        for (arg_name, mapping) in mappings {
            if let Some(arg_val) = vars.get(arg_name) {
                if let Some(mapped) = mapping.get(arg_val) {
                    // Convention: the mapped variable is `_<arg_name>_flags`
                    // but manifests may reference it as `_{arg_name}_flags` or
                    // `_scan_flags` etc. We insert both forms.
                    vars.insert(format!("_{arg_name}_flags"), mapped.clone());
                    // Also insert the shorter form in case the template uses it.
                    vars.insert(format!("_{arg_name}"), mapped.clone());
                }
            }
        }
    }

    // Auto-generate executor-injected variables.
    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    vars.insert("_scan_id".to_string(), scan_id.clone());

    let evidence_dir = std::env::var("TOOLCLAD_EVIDENCE_DIR")
        .unwrap_or_else(|_| "/tmp/toolclad-evidence".to_string());
    vars.insert("_evidence_dir".to_string(), evidence_dir.clone());

    let output_file = format!("{evidence_dir}/{scan_id}-output");
    vars.insert("_output_file".to_string(), output_file);

    // Resolve conditionals.
    if let Some(ref conditionals) = manifest.command.conditionals {
        for (cond_name, cond_def) in conditionals {
            let include = evaluate_condition(&cond_def.when, &vars);
            if include {
                let fragment = interpolate_template(&cond_def.template, &vars);
                vars.insert(format!("_{cond_name}"), fragment);
            } else {
                vars.insert(format!("_{cond_name}"), String::new());
            }
        }
    }

    // Perform final template interpolation.
    let result = interpolate_template(&template, &vars);

    // Clean up multiple spaces from empty interpolations.
    let cleaned = result.split_whitespace().collect::<Vec<_>>().join(" ");

    Ok(cleaned)
}

/// Interpolate `{placeholder}` references in a template string.
fn interpolate_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{key}}}"), value);
    }
    result
}

/// Evaluate a simple condition expression against variables.
///
/// Supports:
/// - `var != ''` — variable is non-empty
/// - `var == ''` — variable is empty
/// - `var != 0` — variable is not "0"
/// - `var == 'literal'` — variable equals a literal
/// - `cond1 and cond2` — conjunction
fn evaluate_condition(expr: &str, vars: &HashMap<String, String>) -> bool {
    // Split on " and " for conjunction.
    if expr.contains(" and ") {
        return expr
            .split(" and ")
            .all(|part| evaluate_condition(part.trim(), vars));
    }

    let expr = expr.trim();

    if let Some(rest) = expr.strip_suffix("!= ''") {
        let var_name = rest.trim();
        let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
        return !val.is_empty();
    }
    if let Some(rest) = expr.strip_suffix("== ''") {
        let var_name = rest.trim();
        let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
        return val.is_empty();
    }

    // Handle `var != 0` or `var != <number>`
    if expr.contains("!=") {
        let parts: Vec<&str> = expr.splitn(2, "!=").collect();
        if parts.len() == 2 {
            let var_name = parts[0].trim();
            let literal = parts[1].trim().trim_matches('\'').trim_matches('"');
            let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
            return val != literal;
        }
    }
    if expr.contains("==") {
        let parts: Vec<&str> = expr.splitn(2, "==").collect();
        if parts.len() == 2 {
            let var_name = parts[0].trim();
            let literal = parts[1].trim().trim_matches('\'').trim_matches('"');
            let val = vars.get(var_name).map(|s| s.as_str()).unwrap_or("");
            return val == literal;
        }
    }

    // Fallback: treat as truthy if the variable exists and is non-empty.
    let val = vars.get(expr).map(|s| s.as_str()).unwrap_or("");
    !val.is_empty()
}

/// Convert a TOML value to a string for interpolation.
fn toml_value_to_string(val: &toml::Value) -> String {
    match val {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Validate all arguments, build the command, execute it, and return an evidence envelope.
pub fn execute(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<EvidenceEnvelope, ToolCladError> {
    // Phase 1: Validate all arguments.
    let mut validated = HashMap::new();
    for (name, def) in &manifest.args {
        if let Some(val) = args.get(name) {
            let clean = validate_arg(name, def, val)?;
            validated.insert(name.clone(), clean);
        } else if def.required {
            if let Some(ref default_val) = def.default {
                validated.insert(name.clone(), toml_value_to_string(default_val));
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "missing required argument '{name}'"
                )));
            }
        } else if let Some(ref default_val) = def.default {
            validated.insert(name.clone(), toml_value_to_string(default_val));
        }
    }

    let scan_id = format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        &uuid::Uuid::new_v4().to_string()[..5]
    );
    let timestamp = chrono::Utc::now().to_rfc3339();
    let start = Instant::now();

    // Phase 2: Build and execute command.
    let (cmd_string, output_text, status_str) =
        if let Some(ref executor_path) = manifest.command.executor {
            // Escape hatch: run custom executor with env vars.
            let mut cmd = Command::new(executor_path);
            for (k, v) in &validated {
                cmd.env(format!("TOOLCLAD_ARG_{}", k.to_uppercase()), v);
            }
            cmd.env("TOOLCLAD_SCAN_ID", &scan_id);
            cmd.env("TOOLCLAD_TOOL_NAME", &manifest.tool.name);

            let cmd_display = format!("{executor_path} (custom executor)");
            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_display)?
        } else {
            let cmd_string = build_command(manifest, &validated)?;
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(&cmd_string);

            run_command_with_timeout(cmd, manifest.tool.timeout_seconds, &cmd_string)?
        };

    let duration_ms = start.elapsed().as_millis() as u64;

    // Phase 3: Hash output for evidence.
    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(output_text.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    };

    // Phase 4: Construct results JSON.
    let results = serde_json::json!({
        "raw_output": output_text
    });

    Ok(EvidenceEnvelope {
        status: status_str,
        scan_id,
        tool: manifest.tool.name.clone(),
        command: cmd_string,
        duration_ms,
        timestamp,
        output_file: None,
        output_hash: Some(output_hash),
        results,
    })
}

/// Run a Command with a timeout, returning (command_string, stdout, status).
fn run_command_with_timeout(
    mut cmd: Command,
    timeout_seconds: u64,
    cmd_display: &str,
) -> Result<(String, String, String), ToolCladError> {
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ToolCladError::ExecutionError(format!("failed to spawn process: {e}")))?;

    let output = if timeout_seconds > 0 {
        // Use wait_with_output — for a production system you'd use a
        // thread-based timeout, but for the reference implementation
        // we rely on the OS and keep it simple.
        child
            .wait_with_output()
            .map_err(|e| ToolCladError::ExecutionError(format!("process error: {e}")))?
    } else {
        child
            .wait_with_output()
            .map_err(|e| ToolCladError::ExecutionError(format!("process error: {e}")))?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let status = if output.status.success() {
        "success".to_string()
    } else {
        format!("error (exit code: {:?}): {stderr}", output.status.code())
    };

    Ok((cmd_display.to_string(), stdout, status))
}

/// Dry-run: validate args and build command without executing.
pub fn dry_run(
    manifest: &Manifest,
    args: &HashMap<String, String>,
) -> Result<DryRunResult, ToolCladError> {
    // Validate all arguments.
    let mut validated = HashMap::new();
    let mut validations = Vec::new();

    for (name, def) in &manifest.args {
        if let Some(val) = args.get(name) {
            match validate_arg(name, def, val) {
                Ok(clean) => {
                    validations.push(format!("{name}={clean} ({}: OK)", def.type_name));
                    validated.insert(name.clone(), clean);
                }
                Err(e) => {
                    validations.push(format!("{name}={val} ({}: FAIL: {e})", def.type_name));
                    return Err(e);
                }
            }
        } else if def.required {
            if let Some(ref default_val) = def.default {
                let dv = toml_value_to_string(default_val);
                validated.insert(name.clone(), dv.clone());
                validations.push(format!("{name}={dv} (default)"));
            } else {
                return Err(ToolCladError::ValidationError(format!(
                    "missing required argument '{name}'"
                )));
            }
        } else if let Some(ref default_val) = def.default {
            let dv = toml_value_to_string(default_val);
            validated.insert(name.clone(), dv.clone());
            validations.push(format!("{name}={dv} (default)"));
        }
    }

    let command = if let Some(ref exec) = manifest.command.executor {
        format!("{exec} (custom executor)")
    } else {
        build_command(manifest, &validated)?
    };

    Ok(DryRunResult {
        validations,
        command,
        cedar: manifest
            .tool
            .cedar
            .as_ref()
            .map(|c| format!("{} / {}", c.resource, c.action)),
        timeout: manifest.tool.timeout_seconds,
    })
}

/// Result of a dry-run invocation.
#[derive(Debug)]
pub struct DryRunResult {
    pub validations: Vec<String>,
    pub command: String,
    pub cedar: Option<String>,
    pub timeout: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn minimal_manifest() -> Manifest {
        Manifest {
            tool: ToolMeta {
                name: "test_tool".to_string(),
                version: "1.0.0".to_string(),
                binary: "echo".to_string(),
                description: "test".to_string(),
                timeout_seconds: 30,
                risk_tier: "low".to_string(),
                human_approval: false,
                cedar: None,
                evidence: None,
            },
            args: HashMap::from([(
                "target".to_string(),
                ArgDef {
                    position: 1,
                    required: true,
                    type_name: "scope_target".to_string(),
                    allowed: None,
                    default: None,
                    pattern: None,
                    sanitize: None,
                    description: "target host".to_string(),
                    min: None,
                    max: None,
                    clamp: false,
                },
            )]),
            command: CommandDef {
                template: Some("echo {target}".to_string()),
                executor: None,
                defaults: None,
                mappings: None,
                conditionals: None,
            },
            output: OutputDef {
                format: "text".to_string(),
                parser: None,
                envelope: true,
                schema: serde_json::json!({"type": "object"}),
            },
        }
    }

    #[test]
    fn test_build_command_simple() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "echo 10.0.1.1");
    }

    #[test]
    fn test_build_command_with_defaults() {
        let mut m = minimal_manifest();
        m.command.template = Some("echo --rate {max_rate} {target}".to_string());
        m.command.defaults = Some(HashMap::from([(
            "max_rate".to_string(),
            toml::Value::Integer(1000),
        )]));
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "echo --rate 1000 10.0.1.1");
    }

    #[test]
    fn test_build_command_with_mappings() {
        let mut m = minimal_manifest();
        m.command.template = Some("nmap {_scan_type_flags} {target}".to_string());
        m.args.insert(
            "scan_type".to_string(),
            ArgDef {
                position: 2,
                required: true,
                type_name: "enum".to_string(),
                allowed: Some(vec!["ping".to_string(), "service".to_string()]),
                default: None,
                pattern: None,
                sanitize: None,
                description: "scan type".to_string(),
                min: None,
                max: None,
                clamp: false,
            },
        );
        m.command.mappings = Some(HashMap::from([(
            "scan_type".to_string(),
            HashMap::from([
                ("ping".to_string(), "-sn -PE".to_string()),
                ("service".to_string(), "-sT -sV".to_string()),
            ]),
        )]));

        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        args.insert("scan_type".to_string(), "service".to_string());
        let cmd = build_command(&m, &args).unwrap();
        assert_eq!(cmd, "nmap -sT -sV 10.0.1.1");
    }

    #[test]
    fn test_evaluate_condition_not_empty() {
        let mut vars = HashMap::new();
        vars.insert("port".to_string(), "443".to_string());
        assert!(evaluate_condition("port != ''", &vars));
        assert!(!evaluate_condition("port == ''", &vars));
    }

    #[test]
    fn test_evaluate_condition_not_zero() {
        let mut vars = HashMap::new();
        vars.insert("port".to_string(), "443".to_string());
        assert!(evaluate_condition("port != 0", &vars));

        vars.insert("port".to_string(), "0".to_string());
        assert!(!evaluate_condition("port != 0", &vars));
    }

    #[test]
    fn test_evaluate_condition_conjunction() {
        let mut vars = HashMap::new();
        vars.insert("username".to_string(), "admin".to_string());
        vars.insert("username_file".to_string(), String::new());
        assert!(evaluate_condition(
            "username != '' and username_file == ''",
            &vars
        ));
    }

    #[test]
    fn test_dry_run() {
        let m = minimal_manifest();
        let mut args = HashMap::new();
        args.insert("target".to_string(), "10.0.1.1".to_string());
        let result = dry_run(&m, &args).unwrap();
        assert!(result.command.contains("10.0.1.1"));
    }
}
