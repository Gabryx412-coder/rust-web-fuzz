use clap::{ Parser, Subcommand };
use log::{ info, error };
use std::path::PathBuf;

mod config;
mod core;
mod scanner;
mod modules;
mod plugin_host;
mod report;

#[derive(Parser)]
#[command(name = "rwf")]
#[command(about = "Rust Web Fuzz: Advanced Vulnerability Scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, value_name = "FILE", default_value = "config.yaml")]
    config: PathBuf,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or endpoint
    Scan {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        wordlist: Option<PathBuf>,
    },
    /// Fuzz parameters on a target
    Fuzz {
        #[arg(short, long)]
        target: String,
    },
    /// Generate report from JSON
    Report {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Run in daemon mode (placeholder)
    Daemon,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    std::env::set_var("RUST_LOG", log_level);
    env_logger::init();

    let config = config::load_config(&cli.config)?;

    match cli.command {
        Commands::Scan { target, wordlist } => {
            info!("Starting Scan on {}", target);
            core::run_scan(target, wordlist, config).await?;
        }
        Commands::Fuzz { target } => {
            info!("Starting Fuzzing on {}", target);
            core::run_fuzz(target, config).await?;
        }
        Commands::Report { input, output } => {
            report::generate_html_report(input, output)?;
        }
        Commands::Daemon => {
            info!("Daemon mode started (Listening for jobs...)");
            // Implementation placeholder for cluster management
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    }

    Ok(())
}
