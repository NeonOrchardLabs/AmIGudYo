//! Advisory metadata preparation. This does not claim to contain repair installers.
use crate::{audit::Audit, policy::Policy};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    time::Duration,
};

pub fn inspect(policy: &Policy) -> Result<Option<String>> {
    if !policy.storage_allowed() {
        return Ok(None);
    }
    let dir = std::env::current_exe()?
        .parent()
        .context("Executable folder unavailable")?
        .join("airgap");
    let file = match std::fs::File::open(dir.join("manifest.json")) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut manifest_bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut manifest_bytes)?;
    if manifest_bytes.len() > 64 * 1024 {
        bail!("Offline manifest is too large");
    }
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let mut bytes = Vec::new();
    std::fs::File::open(dir.join("kev.json"))?
        .take(20 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 20 * 1024 * 1024 {
        bail!("Offline catalog is too large");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if manifest["sha256"].as_str() != Some(digest.as_str()) {
        bail!("Offline catalog integrity check failed");
    }
    let data: serde_json::Value = serde_json::from_slice(&bytes)?;
    let entries = data["vulnerabilities"]
        .as_array()
        .context("Offline catalog has no entries")?;
    let date = data["dateReleased"]
        .as_str()
        .context("Offline catalog has no release date")?;
    Ok(Some(format!(
        "Local CISA KEV metadata: {} entries, released {date}. SHA-256 matches local manifest (corruption check, not a publisher signature). Freshness is not verified; no product-version matcher or repair packages are available.",
        entries.len()
    )))
}

pub fn prepare(policy: &Policy, audit: &mut Audit) -> Result<String> {
    policy.require_network()?;
    policy.require_storage()?;
    audit.log(
        "NETWORK",
        "Downloading CISA KEV advisory metadata over HTTPS",
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(45))
        .https_only(true)
        .build()?;
    let response = client
        .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response
        .take(20 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 20 * 1024 * 1024 {
        bail!("Advisory response exceeds 20 MiB limit");
    }
    let data: serde_json::Value =
        serde_json::from_slice(&bytes).context("Invalid advisory JSON")?;
    let entries = data["vulnerabilities"]
        .as_array()
        .context("Missing vulnerability catalog")?;
    let date = data["dateReleased"]
        .as_str()
        .context("Missing catalog release date")?;
    let version = data["catalogVersion"]
        .as_str()
        .context("Missing catalog version")?;
    let dir = crate::policy::portable_directory(&["airgap"])?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let manifest = serde_json::json!({"format":1,"catalog":"CISA KEV","catalog_version":version,"date_released":date,"sha256":digest,"entries":entries.len(),"repair_packages":0,"ready_for_all_repairs":false,"coverage":"Catalog metadata only; no affected-version matcher or installer payloads"});
    write_catalog_file(&dir, "kev.json", &bytes)?;
    write_catalog_file(
        &dir,
        "manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    let message = format!(
        "Saved {} advisory entries, catalog {version}, released {date}. Metadata only: no repair packages or CVE matcher; offline repair kit is incomplete.",
        entries.len()
    );
    audit.log("BUNDLE", &message);
    Ok(message)
}

fn write_catalog_file(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Result<()> {
    crate::policy::reject_link(dir)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let temp = dir.join(format!("{name}-{}-{stamp}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        crate::policy::reject_link(dir)?;
        std::fs::rename(&temp, dir.join(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_mode_rejects_preparation_before_io() {
        let policy = Policy {
            mode: crate::policy::Mode::EmbeddedOnly,
            logging: false,
        };
        let mut audit = Audit::new(false, None).unwrap();
        assert!(
            prepare(&policy, &mut audit)
                .unwrap_err()
                .to_string()
                .contains("--noexternal")
        );
        assert!(audit.events().is_empty());
    }
}
