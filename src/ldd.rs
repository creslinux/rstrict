use ::elf::endian::AnyEndian;
use elf::{file::Class, ElfStream};
use std::{collections::HashSet, path::PathBuf, process::Command};

use anyhow::{bail, Context, Result};
const ET_DYN: u16 = 3;

fn parse_interp(input: &str) -> Vec<String> {
    let mut paths = vec![];
    for line in input.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let &[name, arrow, path, _] = &fields[..] else {
            continue;
        };
        // the name should not equal the path
        // the path must not be empty
        // an arrow must exist
        // the path must not be a memory address in paretheses
        if name == path || path.is_empty() || arrow != "=>" || path.starts_with('(') {
            continue;
        }
        paths.push(path.to_owned());
    }
    paths
}

fn call_interp(interp: &str, binary_path: &str) -> Result<Vec<String>> {
    let command_run = Command::new(interp)
        .args(["--list", binary_path])
        .output()
        .context(format!(
            "failed to call interpreter {interp:?} on binary {binary_path:?}"
        ))?;
    if !command_run.status.success() {
        bail!("failed to call interpreter {interp:?} on binary {binary_path:?}: program exited with status {}", command_run.status)
    }
    Ok(parse_interp(std::str::from_utf8(&command_run.stdout)?))
}

fn inspect_elf_interp(binary_path: &str) -> Result<Option<String>> {
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .open(binary_path)
        .context(format!("failed to open binary {binary_path:?}"))?;
    let mut stream = ElfStream::<AnyEndian, std::fs::File>::open_stream(handle)
        .context(format!("failed to read binary {binary_path:?}"))?;

    // accessing these in the same order as they appear in the binary
    // refer to: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#ELF_header
    let class = stream.ehdr.class;
    let elf_type = stream.ehdr.e_type;

    let interp_header = match stream
        .section_header_by_name(".interp")
        .context("elf section table should be parseable")?
        .cloned()
    {
        Some(h) => h,
        None => return Ok(None), // the binary is statically linked and has no .interp section
    };

    let (section, _compression_header) = stream
        .section_data(&interp_header)
        .context("unable to access binary interp section despite the header's existence")?;

    // trim any null bytes from the CString
    // TODO: maybe actually use a CString here?
    let interp = std::str::from_utf8(section)?.trim_end_matches('\0');

    // ignore shebang interpreters
    if interp.starts_with("#!") {
        return Ok(None);
    }

    if !interp.is_empty() {
        return Ok(Some(interp.to_string()));
    }

    let unknown_class = class == Class::ELF64 || class == Class::ELF32;
    let dynamic_elf = elf_type != ET_DYN;

    if !dynamic_elf || unknown_class {
        return Ok(None);
    }

    // We have a shared library. These have no interp section,
    // so we try to guess with known interpreters.
    Ok(ld_so(class))
}

fn ld_so(class: Class) -> Option<String> {
    let arch_specific = match class {
        Class::ELF32 => "/lib32/ld-*.so.*",
        Class::ELF64 => "/lib64/ld-*.so.*",
    };

    let generic = "/lib/ld-*.so.*";

    let arch_specific_iter =
        glob::glob(arch_specific).expect("failed to parse ld.so globbing pattern");
    let generic_iter = glob::glob(generic).expect("failed to parse ld.so globbing pattern");

    arch_specific_iter
        .chain(generic_iter)
        .filter_map(Result::ok)
        .filter_map(|path| path.to_str().map(ToString::to_string))
        .next()
}

pub fn list(binary_path: &str) -> Result<Vec<String>> {
    let Some(interp) = inspect_elf_interp(binary_path)? else {
        return Ok(vec![]);
    };
    let mut dependencies = call_interp(&interp, binary_path)?;
    dependencies.push(interp);
    follow(dependencies)
}

fn follow(dependencies: Vec<String>) -> Result<Vec<String>> {
    let mut seen_deps = HashSet::new();
    for dep in dependencies {
        follow_internal(std::path::PathBuf::from(dep), &mut seen_deps)?;
    }
    Ok(seen_deps
        .iter()
        .filter_map(|path| path.to_str())
        .map(ToString::to_string)
        .collect())
}

fn follow_internal(mut dep: PathBuf, seen: &mut HashSet<PathBuf>) -> Result<()> {
    loop {
        if seen.contains(&dep) {
            return Ok(());
        }
        let lstat = dep.symlink_metadata()?;
        seen.insert(dep.clone());

        if !lstat.is_symlink() {
            return Ok(());
        }

        let mut next = dep.read_link()?;

        if next.is_relative() {
            if let Some(parent) = dep.parent() {
                next = parent.join(next);
            }
        }

        dep = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interp_path_is_memory_address() {
        let input = "linux-vdso.so.1 => (0x00007fdf495cd000)";
        assert!(parse_interp(input).is_empty());
    }

    #[test]
    fn test_parse_interp_path_is_unavailable() {
        let input = "libpcre2-8.so.0 =>  (0x00007fdf49524000)";
        assert!(parse_interp(input).is_empty());
    }

    #[test]
    fn test_parse_interp_path_is_available() {
        let input = "libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f70f6c10000)";
        assert_eq!(
            parse_interp(input),
            vec!["/lib64/libpthread.so.0".to_owned()]
        );
    }

    #[test]
    fn test_parse_interp_very_long_path() {
        let input = "libpcre2-8.so.0 => /nix/store/nalqwq0dpzqnp4nfv25370cb17q3wx4j-pcre2-10.44/lib/libpcre2-8.so.0 (0x00007fdf49524000)";
        assert_eq!(
            parse_interp(input),
            vec![
                "/nix/store/nalqwq0dpzqnp4nfv25370cb17q3wx4j-pcre2-10.44/lib/libpcre2-8.so.0"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn test_parse_interp_many_paths() {
        let input = "        linux-vdso.so.1 =>  (0x00007fffd33f2000)
        libdl.so.2 => /lib64/libdl.so.2 (0x00007f70f7855000)
        librt.so.1 => /lib64/librt.so.1 (0x00007f70f764d000)
        libstdc++.so.6 => /lib64/libstdc++.so.6 (0x00007f70f7345000)
        libm.so.6 => /lib64/libm.so.6 (0x00007f70f7043000)
        libgcc_s.so.1 => /lib64/libgcc_s.so.1 (0x00007f70f6e2d000)
        libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f70f6c10000)
        libc.so.6 => /lib64/libc.so.6 (0x00007f70f684f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f70f7a61000)
";
        assert_eq!(
            parse_interp(input),
            vec![
                "/lib64/libdl.so.2".to_owned(),
                "/lib64/librt.so.1".to_owned(),
                "/lib64/libstdc++.so.6".to_owned(),
                "/lib64/libm.so.6".to_owned(),
                "/lib64/libgcc_s.so.1".to_owned(),
                "/lib64/libpthread.so.0".to_owned(),
                "/lib64/libc.so.6".to_owned(),
            ]
        );
    }
}
