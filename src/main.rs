mod exec;
mod ldd;
mod sandbox;
mod utils;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{debug, error, info};
use std::path::PathBuf;
use std::process;
use which::which;

/// A lightweight, secure sandbox for running Linux processes using Landlock
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Set logging level
    #[arg(long, value_enum, default_value_t = LogLevel::Error)]
    log_level: LogLevel,

    /// Allow read-only access to these paths
    #[arg(long = "ro", value_name = "PATH")]
    read_only_paths: Vec<PathBuf>,

    /// Allow read-only access with execution to these paths
    #[arg(long = "rox", value_name = "PATH")]
    read_only_executable_paths: Vec<PathBuf>,

    /// Allow read-write access to these paths
    #[arg(long = "rw", value_name = "PATH")]
    read_write_paths: Vec<PathBuf>,

    /// Allow read-write access with execution to these paths
    #[arg(long = "rwx", value_name = "PATH")]
    read_write_executable_paths: Vec<PathBuf>,

    /// Allow binding to these TCP ports
    #[arg(long = "bind-tcp", value_name = "PORT")]
    bind_tcp_ports: Vec<u16>,

    /// Allow connecting to these TCP ports
    #[arg(long = "connect-tcp", value_name = "PORT")]
    connect_tcp_ports: Vec<u16>,

    /// Use best effort mode (fall back to less restrictive sandbox if necessary)
    #[arg(long)]
    best_effort: bool,

    /// Environment variables to pass to the sandboxed command (KEY=VALUE or just KEY to pass current value)
    #[arg(long = "env", value_name = "VAR")]
    env_vars: Vec<String>,

    /// Allow unrestricted filesystem access
    #[arg(long)]
    unrestricted_filesystem: bool,

    /// Allow unrestricted network access
    #[arg(long)]
    unrestricted_network: bool,

    /// Automatically add the executable path to --rox
    #[arg(long)]
    add_exec: bool,

    /// Automatically add library dependencies to --rox
    #[arg(long)]
    ldd: bool,

    /// Command to run and its arguments
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn to_filter(self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logger
    env_logger::Builder::new()
        .filter_level(cli.log_level.to_filter())
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false)
        .init();

    debug!("CLI arguments: {:#?}", cli);

    // Ensure we have a command to run
    if cli.command.is_empty() {
        error!("Missing command to run");
        process::exit(1);
    }

    // Extract command and args
    let command = cli.command[0].clone();
    let args = if cli.command.len() > 1 {
        cli.command[1..].to_vec()
    } else {
        Vec::new()
    };

    info!("Command: {}, args: {:?}", command, args);

    // Find the full path to the binary
    let binary_path =
        which(&command).with_context(|| format!("Failed to find binary: {}", command))?;
    let binary_path_str = binary_path.to_string_lossy().to_string();

    // Initialize sandbox configuration
    let mut sandbox_config = sandbox::Config::new();

    // Copy CLI configuration to sandbox configuration
    sandbox_config.read_only_paths = cli.read_only_paths.clone();
    sandbox_config.read_write_paths = cli.read_write_paths.clone();
    sandbox_config.read_only_executable_paths = cli.read_only_executable_paths.clone();
    sandbox_config.read_write_executable_paths = cli.read_write_executable_paths.clone();
    sandbox_config.bind_tcp_ports = cli.bind_tcp_ports.clone();
    sandbox_config.connect_tcp_ports = cli.connect_tcp_ports.clone();
    sandbox_config.best_effort = cli.best_effort;
    sandbox_config.unrestricted_filesystem = cli.unrestricted_filesystem;
    sandbox_config.unrestricted_network = cli.unrestricted_network;

    // Add executable to read-only executable paths if requested
    if cli.add_exec {
        debug!("Adding executable path: {}", binary_path_str);
        sandbox_config
            .read_only_executable_paths
            .push(binary_path.clone());
    }

    // Add library dependencies if requested
    if cli.ldd {
        match ldd::list(&binary_path_str) {
            Ok(lib_paths) => {
                for lib_path in lib_paths {
                    debug!("Adding library path: {}", lib_path);
                    sandbox_config
                        .read_only_executable_paths
                        .push(PathBuf::from(lib_path));
                }
            }
            Err(err) => {
                error!("Failed to detect library dependencies: {}", err);
                process::exit(1);
            }
        }
    }

    // Process environment variables
    let env_vars = utils::process_environment_vars(&cli.env_vars);

    // Apply sandbox configuration
    if let Err(err) = sandbox::apply(&sandbox_config) {
        error!("Failed to apply sandbox: {}", err);
        process::exit(1);
    }

    // Execute the command (this should replace the current process)
    if let Err(err) = exec::run(&binary_path_str, &args, &env_vars) {
        error!("Failed to execute command: {}", err);
        process::exit(1);
    }

    // We should never reach this point unless exec::run fails
    Ok(())
}
