# <img src="https://rstrict.cloud/rstrict-logo.svg" width="68" height="68" alt="rstrict logo" style="vertical-align:bottom;position:relative;top:8px;"> rstrict

A lightweight, secure sandbox for running Linux processes using the Linux kernel's [Landlock LSM](https://docs.kernel.org/userspace-api/landlock.html), implemented in Rust with the excellent [`landlock-rs`](https://docs.rs/landlock/latest/landlock/) crate.

**rstrict** leverages the Linux **Landlock** security module to sandbox processes, allowing you to run commands with restricted access to the filesystem and network, reducing the potential impact of vulnerabilities or unintended actions.

[![CI](https://github.com/creslinux/rstrict/actions/workflows/ci.yml/badge.svg)](https://github.com/creslinux/rstrict/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rstrict.svg)](https://crates.io/crates/rstrict)
[![Binary Crate](https://img.shields.io/badge/crate-binary-yellow.svg)](https://crates.io/crates/rstrict)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://mit-license.org/)

[Website](https://rstrict.cloud/) | [Guides](https://rstrict.cloud/learn/) | [Docs](https://rstrict.cloud/documentation/) | [Crate](https://crates.io/crates/rstrict)


For detailed information about the underlying Landlock security module, see the [official Linux kernel documentation](https://docs.kernel.org/userspace-api/landlock.html).

Quote:
>The goal of Landlock is to enable restriction of ambient rights (e.g. global filesystem or network access) for a set of processes. Because Landlock is a stackable LSM, it makes it possible to create safe security sandboxes as new security layers in addition to the existing system-wide access-controls. This kind of sandbox is expected to help mitigate the security impact of bugs or unexpected/malicious behaviors in user space applications. Landlock empowers any process, including unprivileged ones, to securely restrict themselves.

> The two existing types of rules are:

> Filesystem rules
> For these rules, the object is a file hierarchy, and the related filesystem actions are defined with filesystem access rights.

>Network rules (since ABI v4)
> For these rules, the object is a TCP port, and the related actions are defined with network access rights.
-- Landlock

## Quick Start Examples

The basic command structure is:

```bash
rstrict [OPTIONS] -- <COMMAND> [COMMAND_ARGS...]
```

Example Sandboxing
```bash
# allow `ls` and its linked libraries to run, allow access to read /tmp
rstrict --log-level debug --ro /tmp --ldd --add-exec -- ls -l /tmp 


# Curl sandbox example
# --add-exec Allow executing curl binary (optional helper)
# --ldd Allow executing curl's libraries (optional helper)
# --ro Read DNS configuration
# --ro Read Name service configuration
# --ro Read Hosts file
# --ro Read SSL certificates
# --connect-tcp <port> Allow connections to HTTPS Port
rstrict --log-level info \
        --add-exec \
        --ldd \
        --ro /etc/resolv.conf \
        --ro /etc/nsswitch.conf \
        --ro /etc/hosts \
        --ro /etc/ssl/certs \
        --connect-tcp 443 \
        -- \
        curl https://example.com
```
** `--ldd` and `--add-exec` are optional convenience flags, including the executables path and any dependencies with `--rox` will have the same effect. 


## Security Model

rstrict follows the fundamental security principle of "deny by default, allow explicitly." When a process is sandboxed with rstrict:

1. **Default Denial**: All handled Landlock operations are denied unless explicitly allowed by rules
2. **Inheritance**: Restrictions automatically apply to child processes
3. **Accumulation**: New rules can only add restrictions, never remove them
4. **Least Privilege**: Target only required resources with minimal permissions

## Features and Landlock Mapping

rstrict provides user-friendly flags that directly map to Landlock's underlying access control mechanisms:

| **Feature Type** | **rstrict Flags** | **Landlock Access Rights** | **Available Since** |
|------------------|-------------------|-----------------------------|---------------------|
| **Filesystem Access** | | | |
| | `--ro <PATH>` | `LANDLOCK_ACCESS_FS_READ_FILE`, `LANDLOCK_ACCESS_FS_READ_DIR` (applied to PATH; recursively if PATH is a directory) | ABI v1 |
| | `--rw <PATH>` | `--ro` rights + `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_TRUNCATE`, etc. (applied to PATH; recursively if PATH is a directory) | ABI v1+ |
| | `--rox <PATH>` | `--ro` rights + `LANDLOCK_ACCESS_FS_EXECUTE` (applied to PATH; recursively if PATH is a directory) | ABI v1 |
| | `--rwx <PATH>` | `--rw` rights + `LANDLOCK_ACCESS_FS_EXECUTE` (applied to PATH; recursively if PATH is a directory) | ABI v1 |
| **Network Control** | | | |
| | `--bind-tcp <PORT>` | `LANDLOCK_ACCESS_NET_BIND_TCP` | ABI v4+ |
| | `--connect-tcp <PORT>` | `LANDLOCK_ACCESS_NET_CONNECT_TCP` | ABI v4+ |
| **Helper Functions** | | | |
| | `--add-exec` | Automatically adds command executable to `--rox` | N/A |
| | `--ldd` | Automatically adds libraries to `--rox` | N/A |
| | `--env` | Environment variable management | N/A |

### Filesystem Access Controls

rstrict's filesystem flags provide intuitive access control that maps to Landlock's more granular permissions:

- **`--ro <PATH>`**: Allow read-only access to the specified path
  - If PATH is a directory: Permissions apply recursively to all files/directories beneath it
  - If PATH is a file: Permissions apply only to that specific file
  - Maps to `LANDLOCK_ACCESS_FS_READ_FILE` and `LANDLOCK_ACCESS_FS_READ_DIR`
  - Example use: Configuration files, static assets

- **`--rw <PATH>`**: Allow read-write access to the specified path
  - If PATH is a directory: Read-write permissions apply recursively to all files/directories beneath it
  - If PATH is a file: Read-write permissions apply only to that specific file
  - Includes all `--ro` rights plus write operations like:
    - `LANDLOCK_ACCESS_FS_WRITE_FILE`
    - `LANDLOCK_ACCESS_FS_TRUNCATE` (ABI v3+)
    - `LANDLOCK_ACCESS_FS_REMOVE_FILE`/`LANDLOCK_ACCESS_FS_REMOVE_DIR`
    - `LANDLOCK_ACCESS_FS_MAKE_REG`/`LANDLOCK_ACCESS_FS_MAKE_DIR`, etc.
  - Example use: Log directories, temp folders

- **`--rox <PATH>`**: Allow read and execute access to the specified path
  - If PATH is a directory: Read-execute permissions apply recursively to all files/directories beneath it
  - If PATH is a file: Read-execute permissions apply only to that specific file
  - Includes `--ro` rights plus `LANDLOCK_ACCESS_FS_EXECUTE`
  - Example use: System libraries, binaries, scripts

- **`--rwx <PATH>`**: Allow read, write, and execute access to the specified path
  - If PATH is a directory: Read-write-execute permissions apply recursively to all files/directories beneath it
  - If PATH is a file: Read-write-execute permissions apply only to that specific file
  - Combines `--rw` and `--rox` permissions
  - Example use: Application working directories needing full access

### Network Access Controls

rstrict's network flags directly correspond to Landlock's TCP socket controls (available since ABI v4):

- **`--bind-tcp <PORT>`**: Allow binding to the specified TCP port
  - Maps to `LANDLOCK_ACCESS_NET_BIND_TCP`
  - Example use: Web servers, database services

- **`--connect-tcp <PORT>`**: Allow outgoing TCP connections to the specified port
  - Maps to `LANDLOCK_ACCESS_NET_CONNECT_TCP`
  - Example use: API clients, web scrapers

**Important Note:** Landlock network rules currently **only restrict TCP** bind/connect operations. **UDP, ICMP, and other protocols are NOT restricted** by these rules.

### Helper Flags

rstrict provides convenience flags to simplify common sandboxing tasks:

- **`--add-exec`**: Automatically find `<COMMAND>` in `$PATH` and add it to the `--rox` list
  - Saves you from having to manually locate and specify the executable path

- **`--ldd`**: Run `ldd` on `<COMMAND>` to find and add shared library dependencies
  - Automatically discovers and adds libraries with appropriate execute permissions
  - Adds common system library directories (like `/lib`, `/usr/lib`) to the `--rox` list

- **`--env <VAR>`**: Manage environment variables for the sandboxed process
  - `--env KEY=VALUE`: Sets an environment variable
  - `--env KEY`: Inherits a value from the current environment

## Requirements

*   **Linux Kernel:**
    *   **5.13+** for basic Landlock filesystem sandboxing (ABI v1).
    *   **5.15+** for `LANDLOCK_ACCESS_FS_REFER` support (ABI v2).
    *   **5.16+** for truncate operations via `LANDLOCK_ACCESS_FS_TRUNCATE` (ABI v3).
    *   **5.19+** for network sandboxing via `LANDLOCK_ACCESS_NET_*` (ABI v4).
    *   **6.2+** for device ioctl control via `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ABI v5).
    *   **6.5+** for IPC scoping controls (ABI v6).
*   **Rust Toolchain:** (Latest stable recommended for building from source).
*   **`ldd` command:** Required *only* if using the `--ldd` helper flag.

## Installation

### From Crates.io (Recommended)

```bash
cargo install rstrict
```

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/creslinux/rstrict.git
    cd rstrict
    ```
2.  Build the release binary:
    ```bash
    cargo build --release
    ```
3.  The binary will be located at `target/release/rstrict`. You can copy it to a location in your `$PATH`:
    ```bash
    sudo cp target/release/rstrict /usr/local/bin/
    ```

## Usage

The basic command structure is:

```bash
rstrict [OPTIONS] -- <COMMAND> [COMMAND_ARGS...]
```
The basic command structure is:

```bash
rstrict [OPTIONS] -- <COMMAND> [COMMAND_ARGS...]
```

*   `[OPTIONS]`: Flags to configure the sandbox rules (see table above).
*   `--`: **Required:** Separates `rstrict` options from the command you want to run.
*   `<COMMAND>`: The command to execute inside the sandbox.
*   `[COMMAND_ARGS...]`: Arguments for the command being executed.

### Options

**Filesystem Access:**

*   `--ro <PATH>`: Allow read-only access to the specified path. If PATH is a directory, permissions apply recursively to everything beneath it. If PATH is a file, permissions apply only to that specific file. Can be used multiple times.
*   `--rw <PATH>`: Allow read-write access to the specified path. If PATH is a directory, permissions apply recursively to everything beneath it. If PATH is a file, permissions apply only to that specific file. Can be used multiple times.
*   `--rox <PATH>`: Allow read + execute access to the specified path. If PATH is a directory, permissions apply recursively to everything beneath it. If PATH is a file, permissions apply only to that specific file. Can be used multiple times.
*   `--rwx <PATH>`: Allow read-write + execute access to the specified path. If PATH is a directory, permissions apply recursively to everything beneath it. If PATH is a file, permissions apply only to that specific file. Can be used multiple times.

**Network Access (TCP Only):**

*   `--bind-tcp <PORT>`: Allow binding to the specified TCP port. Can be used multiple times.
*   `--connect-tcp <PORT>`: Allow outgoing TCP connections to the specified port. Can be used multiple times.

**Helper Flags:**

*   `--add-exec`: Automatically find `<COMMAND>` in `$PATH` and add it to the `--rox` list.
*   `--ldd`: Run `ldd` on `<COMMAND>` to find shared library dependencies and add them to `--rox`.
*   `--env <VAR>`: Specify environment variables for the sandboxed process.
    *   `--env KEY=VALUE`: Sets the variable `KEY` to `VALUE`.
    *   `--env KEY`: Inherits the value of `KEY` from the current environment.

**Unrestricted Access:**

*   `--unrestricted-filesystem`: Disable Landlock filesystem rules.
*   `--unrestricted-network`: Disable Landlock network (TCP) rules.

**Logging & Meta:**

*   `--log-level <LEVEL>`: Set logging verbosity. Options: `error` (default), `warn`, `info`, `debug`, `trace`.
*   `--help`: Show help message and exit.
*   `--version`: Show version information and exit.

## How It Works

1. **Command Parsing**: rstrict processes command-line flags to build a sandboxing configuration
2. **Path Resolution**: Paths specified in flags are resolved to their absolute locations
3. **Library Discovery**: If `--ldd` is used, shared libraries are automatically discovered
4. **Ruleset Creation**: rstrict creates a Landlock ruleset with the specified access rights
5. **Rule Addition**: Each path/port rule is added to the ruleset with appropriate permissions
6. **Self-Restriction**: rstrict applies the ruleset to itself using Landlock's `restrict_self()`
7. **Command Execution**: rstrict uses `execvpe` to replace itself with the target command
8. **Inherited Restrictions**: The target command runs with the Landlock restrictions already in place

This approach ensures the security boundary is established before the target program begins execution.

## Examples

**1. Running `ls` with minimal read access:**

```bash
# Basic filesystem sandbox
rstrict --log-level info \
        --ro /home \
        --add-exec \
        --ldd \
        -- \
        ls -l /home
```
*Output should show details for `/bin/bash`. Trying `ls -l /tmp` would fail with a permission error.*

**2. Running `curl` to fetch a webpage (HTTPS):**

```bash
rstrict --log-level info \
        --add-exec \
        --ldd \
        --ro /etc/resolv.conf \
        --ro /etc/nsswitch.conf \
        --ro /etc/hosts \
        --ro /etc/ssl/certs \
        --connect-tcp 443 \
        -- \
        curl https://example.com
```

*   `--add-exec`, `--ldd`: Allow `curl` and its libraries to run
*   `--ro /etc/resolv.conf`, etc.: Allow DNS resolver configuration access
*   `--ro /etc/ssl/certs`: Allow TLS certificate verification
*   `--connect-tcp 443`: Allow HTTPS connections

**3. Allowing write access to a specific directory:**

```bash
# Create a temporary directory first
mkdir ./my_temp_data

# Run touch with write access to only that directory
rstrict --log-level info \
        --rw ./my_temp_data \
        --add-exec \
        --ldd \
        -- \
        touch ./my_temp_data/test_file.txt
```

**4. Running a web server on port 8080 can connect to MySQL on 3306:**

```bash
rstrict --log-level info \
        --ro /app/static \
        --rw /app/logs \
        --bind-tcp 8080 \
        --connect-tcp 3306 \
        --add-exec \
        --ldd \
        -- \
        /app/myserver --port 8080
```

## Landlock ABI Version Compatibility

rstrict adapts to the available Landlock features on your kernel at runtime. It will use the highest supported ABI version and adjust its behavior accordingly:

| ABI Version | Kernel | Features Added |
|-------------|--------|---------------|
| v1 | 5.13+ | Basic filesystem controls (read, write, execute) |
| v2 | 5.15+ | File linking/renaming between directories (`LANDLOCK_ACCESS_FS_REFER`) |
| v3 | 5.16+ | File truncation control (`LANDLOCK_ACCESS_FS_TRUNCATE`) |
| v4 | 5.19+ | TCP network controls (bind, connect) |
| v5 | 6.2+ | Device IOCTL control (`LANDLOCK_ACCESS_FS_IOCTL_DEV`) |
| v6 | 6.5+ | IPC scoping (signals, abstract UNIX sockets) |

## Limitations

*   **Linux Only**: Landlock is a Linux-specific kernel feature.
*   **Kernel Version**: Features depend on kernel support for specific Landlock ABIs.
*   **Network Restrictions (TCP Only)**: UDP, ICMP, etc. are not restricted.
*   **No UID/GID Changes**: rstrict does not change user or group IDs.
*   **Maximum Ruleset Layers**: Limited to 16 stacked rulesets per process.

## Contributing

Contributions (bug reports, feature requests, pull requests) are welcome! Please open an issue on the GitHub repository to discuss changes.

## License

This project is licensed under the [MIT License](https://mit-license.org/).
