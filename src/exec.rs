use anyhow::{Context, Result};
use log::{debug, error, info};
use nix::unistd::execvpe;
use std::ffi::CString;

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
