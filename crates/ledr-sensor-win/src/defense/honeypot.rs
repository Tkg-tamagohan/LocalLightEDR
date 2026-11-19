//! Honeypot decoy file deployment and removal lifecycle (`L-06`).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use ledr_proto::HONEYPOT_DEFAULT_FILENAME;

use crate::SensorError;

const HONEYPOT_DECOY_CONTENT: &[u8] = b"LocalEDR Canary Decoy File - Do Not Modify or Delete.\r\n";

/// Manages deployment and removal of lexicographically-first honeypot decoy files (`L-06`).
#[derive(Debug, Clone)]
pub struct HoneypotManager {
    roots: Vec<PathBuf>,
    create_missing_roots: bool,
    deployed_paths: Vec<PathBuf>,
}

impl Default for HoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotManager {
    /// Creates a [`HoneypotManager`] targeting the default user profile folders:
    /// `%USERPROFILE%\Documents`, `%USERPROFILE%\Desktop`, and `%USERPROFILE%\Pictures`.
    pub fn new() -> Self {
        let roots = default_honeypot_roots();
        Self {
            roots,
            create_missing_roots: false,
            deployed_paths: Vec::new(),
        }
    }

    /// Creates a [`HoneypotManager`] targeting an explicit list of root directories (for tests or
    /// custom policies).
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            create_missing_roots: true,
            deployed_paths: Vec::new(),
        }
    }

    /// Returns the configured directory roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Returns the paths currently tracked as deployed honeypots.
    pub fn deployed_paths(&self) -> &[PathBuf] {
        &self.deployed_paths
    }

    /// Deploys `!00_LocalEDR_Canary_DoNotEdit.docx` into configured roots and tracks created paths.
    pub fn deploy_honeypots(&mut self) -> Result<Vec<PathBuf>, SensorError> {
        let mut created = Vec::new();
        for root in &self.roots {
            if self.create_missing_roots {
                std::fs::create_dir_all(root)?;
            } else if !root.is_dir() {
                continue;
            }

            let target = root.join(HONEYPOT_DEFAULT_FILENAME);
            if !target.exists() {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                file.write_all(HONEYPOT_DECOY_CONTENT)?;
                file.flush()?;
            }

            if !self.deployed_paths.contains(&target) {
                self.deployed_paths.push(target.clone());
            }
            created.push(target);
        }
        Ok(created)
    }

    /// Deletes all tracked honeypot files cleanly, returning the number of files removed.
    pub fn remove_honeypots(&mut self) -> Result<usize, SensorError> {
        let tracked = std::mem::take(&mut self.deployed_paths);
        let mut removed = 0usize;
        let mut remaining = Vec::new();

        for (idx, path) in tracked.iter().enumerate() {
            match std::fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    remaining.extend_from_slice(&tracked[idx..]);
                    self.deployed_paths = remaining;
                    return Err(SensorError::Io(err));
                }
            }
        }

        Ok(removed)
    }
}

fn default_honeypot_roots() -> Vec<PathBuf> {
    let Some(profile) = std::env::var_os("USERPROFILE") else {
        return Vec::new();
    };
    let base = PathBuf::from(profile);
    vec![
        base.join("Documents"),
        base.join("Desktop"),
        base.join("Pictures"),
    ]
}
