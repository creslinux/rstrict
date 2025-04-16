use anyhow::{Context, Result};
use log::{debug, error, info};
use nix::unistd::execvpe;
use std::ffi::CString;
use std::process::Command;

pub fn run(command: &str, args: &[String], env_vars: &[String]) -> Result<()> {
    info!("Executing: {} with args: {:?}", command, args);
    debug!("Environment variables: {:?}", env_vars);

    // Convert command and args to CString
    let command_cstr = CString::new(command).context("Failed to convert command to CString")?;

    // Combine command and args for execvp
    let mut all_args = Vec::with_capacity(args.len() + 1);
    all_args.push(command_cstr.clone());

    for arg in args {
        let arg_cstr =
            CString::new(arg.as_str()).context("Failed to convert argument to CString")?;
        all_args.push(arg_cstr);
    }

    // Process environment variables
    let mut env_cstrings = Vec::new();
    for env_var in env_vars {
        let env_cstr = CString::new(env_var.as_str())
            .context("Failed to convert environment variable to CString")?;
        env_cstrings.push(env_cstr);
    }

    // Execute the command, replacing the current process
    // Use execvpe to specify environment variables explicitly
    match execvpe(&command_cstr, &all_args, &env_cstrings) {
        Ok(_) => unreachable!(), // This will never happen as execvpe replaces the process
        Err(err) => {
            error!("Failed to execute command: {}", err);
            Err(anyhow::anyhow!("Failed to execute command: {}", err))
        }
    }
}

/// Get library dependencies of a binary using ldd, including necessary system paths
pub fn get_library_dependencies(binary: &str) -> Result<Vec<String>> {
    debug!("Detecting library dependencies for: {}", binary);

    let output = Command::new("ldd")
        .arg(binary)
        .output()
        .context("Failed to execute ldd command")?;

    if !output.status.success() {
        error!(
            "ldd command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(anyhow::anyhow!("ldd command failed"));
    }

    let output_str = String::from_utf8(output.stdout).context("Invalid UTF-8 output from ldd")?;
    let mut lib_paths = Vec::new();
    let mut parent_dirs = std::collections::HashSet::new();

    // First pass: Extract all library paths
    for line in output_str.lines() {
        // Skip empty lines and lines without => (usually the binary name or statically linked libs)
        if line.is_empty() || !line.contains("=>") {
            continue;
        }

        // Extract the library path
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let lib_path = parts[2].trim_matches(|c| c == '(' || c == ')');
            if !lib_path.is_empty() {
                lib_paths.push(lib_path.to_string());

                // Add parent directory
                if let Some(parent) = std::path::Path::new(lib_path).parent() {
                    if let Some(parent_str) = parent.to_str() {
                        parent_dirs.insert(parent_str.to_string());
                    }
                }
            }
        }
    }

    // Second pass: Look for direct loader references (usually at the first line)
    for line in output_str.lines() {
        if line.contains("=>") {
            // Skip
        } else if line.contains("/lib64/ld-linux") || line.contains("/lib/ld-linux") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let loader_path = parts[0].trim();
                if !loader_path.is_empty() && loader_path.starts_with('/') {
                    lib_paths.push(loader_path.to_string());

                    // Add parent directory
                    if let Some(parent) = std::path::Path::new(loader_path).parent() {
                        if let Some(parent_str) = parent.to_str() {
                            parent_dirs.insert(parent_str.to_string());
                        }
                    }
                }
            }
        }
    }

    // Add common system directories that might be needed
    let system_dirs = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ];

    for dir in system_dirs.iter() {
        if std::path::Path::new(dir).exists() {
            parent_dirs.insert(dir.to_string());
        }
    }

    // Add all parent directories to the library paths
    for dir in parent_dirs {
        lib_paths.push(dir);
    }

    debug!("Detected library paths: {:?}", lib_paths);
    Ok(lib_paths)
}

