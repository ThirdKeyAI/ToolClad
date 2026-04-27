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
    },
    /// Execute a tool defined by a manifest
    Run {
        /// Path to the manifest file
        manifest: String,
        /// Arguments as key=value pairs
        #[arg(long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,
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
        Commands::Validate { manifest } => cmd_validate(&manifest),
        Commands::Run { manifest, args } => cmd_run(&manifest, &args),
        Commands::Schema { manifest } => cmd_schema(&manifest),
        Commands::Test { manifest, args } => cmd_test(&manifest, &args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn cmd_validate(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toolclad::load_manifest(path)?;
    println!("Manifest:     {path}");
    println!("Tool:         {}", manifest.tool.name);
    println!("Version:      {}", manifest.tool.version);
    println!("Binary:       {}", manifest.tool.binary);
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

fn cmd_run(path: &str, arg_pairs: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toolclad::load_manifest(path)?;
    let args = parse_arg_pairs(arg_pairs)?;
    let envelope = toolclad::executor::execute(&manifest, &args)?;
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
    println!();
    println!("  [dry run -- command not executed]");
    Ok(())
}
