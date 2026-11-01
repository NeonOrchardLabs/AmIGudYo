use anyhow::{Result, bail};

/// Create app-owned directories beneath the executable's resolved folder.
/// Reject pre-existing junctions/symlinks instead of following them elsewhere.
pub fn portable_directory(parts: &[&str]) -> Result<std::path::PathBuf> {
    let executable = std::env::current_exe()?;
    let root = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Executable folder unavailable"))?
        .canonicalize()?;
    let mut path = root.clone();
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("Invalid portable directory component");
        }
        path.push(part);
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        reject_link(&path)?;
        if !path.is_dir() || !path.canonicalize()?.starts_with(&root) {
            bail!("Portable directory is outside the executable folder");
        }
    }
    Ok(path)
}

pub fn reject_link(path: &std::path::Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            bail!("Portable storage refuses a reparse point");
        }
    }
    if meta.file_type().is_symlink() {
        bail!("Portable storage refuses a symbolic link");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Portable,
    EmbeddedOnly,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    pub logging: bool,
}

impl Policy {
    pub fn network_allowed(&self) -> bool {
        self.mode == Mode::Portable
    }
    pub fn storage_allowed(&self) -> bool {
        self.mode == Mode::Portable
    }
    pub fn require_network(&self) -> Result<()> {
        if !self.network_allowed() {
            bail!("--noexternal uses embedded resources only; network access is disabled");
        }
        Ok(())
    }
    pub fn require_storage(&self) -> Result<()> {
        if !self.storage_allowed() {
            bail!("--noexternal keeps application data in memory; file access is disabled");
        }
        Ok(())
    }
}
