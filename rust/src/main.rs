use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::process;

#[derive(Parser)]
#[command(
    name = "toolclad",
    about = "ToolClad: Declarative CLI tool interface executor",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and validate a .clad.toml manifest
    Validate {
        /// Path to the manifest file
        manifest: String,
        /// Report unknown manifest keys as warnings instead of refusing the
        /// manifest (authoring aid; library loading is always strict)
        #[arg(long)]
        allow_unknown_keys: bool,
    },
    /// Execute a tool defined by a manifest
    Run {
        /// Path to the manifest file
        manifest: String,
        /// Arguments as key=value pairs
        #[arg(long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,
        /// Approve the call: skip the default policy gate, which denies
        /// manifests with human_approval = true or risk_tier high/critical
        #[arg(long)]
        approve: bool,
    },
    /// Output MCP JSON schema for a manifest
    Schema {
        /// Path to the manifest file
        manifest: String,
    },
    /// Dry run: validate args and show constructed command without executing
    Test {
        /// Path to the manifest file
        manifest: String,
        /// Arguments as key=value pairs
        #[arg(long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,
    },
}

fn parse_arg_pairs(pairs: &[String]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid argument format '{pair}', expected KEY=VALUE"))?;
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Validate {
            manifest,
            allow_unknown_keys,
        } => cmd_validate(&manifest, allow_unknown_keys),
        Commands::Run {
            manifest,
            args,
            approve,
        } => cmd_run(&manifest, &args, approve),
        Commands::Schema { manifest } => cmd_schema(&manifest),
        Commands::Test { manifest, args } => cmd_test(&manifest, &args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn cmd_validate(path: &str, allow_unknown_keys: bool) -> Result<(), Box<dyn std::error::Error>> {
    let manifest =
        toolclad::load_manifest_with(path, toolclad::LoadOptions { allow_unknown_keys })?;
    println!("Manifest:     {path}");
    println!("Tool:         {}", manifest.tool.name);
    println!("Version:      {}", manifest.tool.version);
    println!("Binary:       {}", manifest.tool.binary);
    println!("Mode:         {}", manifest.mode());
    println!("Risk tier:    {}", manifest.tool.risk_tier);
    println!("Timeout:      {}s", manifest.tool.timeout_seconds);
    println!("Arguments:    {}", manifest.args.len());
    for (name, def) in &manifest.args {
        let req = if def.required { "required" } else { "optional" };
        println!("  {name}: {} ({req})", def.type_name);
    }
    if let Some(ref cedar) = manifest.tool.cedar {
        println!("Cedar:        {} / {}", cedar.resource, cedar.action);
    }
    println!(
        "Output:       {}",
        manifest
            .output
            .as_ref()
            .map(|o| o.format.as_str())
            .unwrap_or("(none — callback dispatch)")
    );
    println!("Dispatch:     {}", manifest.tool.dispatch);
    println!("\nOK - manifest is valid");
    Ok(())
}

fn cmd_run(
    path: &str,
    arg_pairs: &[String],
    approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toolclad::load_manifest(path)?;
    let args = parse_arg_pairs(arg_pairs)?;
    let envelope = if approve {
        toolclad::executor::execute_approved(&manifest, &args)?
    } else {
        toolclad::executor::execute(&manifest, &args)?
    };
    let json = serde_json::to_string_pretty(&envelope)?;
    println!("{json}");
    Ok(())
}

fn cmd_schema(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toolclad::load_manifest(path)?;
    let schema = toolclad::generate_mcp_schema(&manifest);
    let json = serde_json::to_string_pretty(&schema)?;
    println!("{json}");
    Ok(())
}

fn cmd_test(path: &str, arg_pairs: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toolclad::load_manifest(path)?;
    let args = parse_arg_pairs(arg_pairs)?;
    let result = toolclad::executor::dry_run(&manifest, &args)?;

    println!("  Manifest:  {path}");
    println!("  Arguments:");
    for v in &result.validations {
        println!("    {v}");
    }
    println!("  Command:   {}", result.command);
    if let Some(ref cedar) = result.cedar {
        println!("  Cedar:     {cedar}");
    }
    println!("  Timeout:   {}s", result.timeout);
    println!("  Risk tier: {}", manifest.tool.risk_tier);
    let approval = match toolclad::default_gate(&manifest, &HashMap::new()) {
        toolclad::GateDecision::Allow => "not required".to_string(),
        toolclad::GateDecision::Deny(reason) => format!("required ({reason}; use run --approve)"),
    };
    println!("  Approval:  {approval}");
    println!();
    println!("  [dry run -- command not executed]");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(tool_extra: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("toolclad-cli-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("gate-{}.clad.toml", tool_extra.len()));
        std::fs::write(
            &path,
            format!(
                "[tool]\nname = \"t\"\nversion = \"1.0.0\"\nbinary = \"echo\"\ndescription = \"x\"\n\
                 {tool_extra}\n\n[command]\nexec = [\"echo\", \"hi\"]\n\n[output]\nformat = \"text\"\n"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn run_without_approve_is_denied_by_the_gate() {
        let path = write_manifest("human_approval = true");
        let err = cmd_run(path.to_str().unwrap(), &[], false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "policy gate denied: manifest requires human approval (human_approval = true)"
        );
        // An echo-based manifest runs once approved.
        cmd_run(path.to_str().unwrap(), &[], true).unwrap();
        // The dry run is not gated.
        cmd_test(path.to_str().unwrap(), &[]).unwrap();
        let _ = std::fs::remove_file(path);
    }
}
