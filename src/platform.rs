//! In-process Windows probes. These inspect local policy, not CVE applicability.
use crate::model::{Finding, InstalledApp, OsProfile, Repair, Status};
use anyhow::Result;

#[cfg(windows)]
mod native {
    use super::*;
    use anyhow::{Context, bail};
    use std::{collections::BTreeMap, io, marker::PhantomData, rc::Rc};
    use windows::Win32::{
        Foundation::{RPC_E_CHANGED_MODE, VARIANT_TRUE},
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
    };
    use winreg::{RegKey, enums::*};

    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// COM initialization is balanced on this thread only. An existing apartment
    /// may be borrowed, but this call must not uninitialize somebody else's COM.
    struct Apartment {
        initialized_here: bool,
        _thread_bound: PhantomData<Rc<()>>,
    }

    impl Apartment {
        fn enter() -> Result<Self> {
            // No COM object is used until initialization succeeds or an existing
            // apartment is confirmed by RPC_E_CHANGED_MODE.
            let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            let initialized_here = if hr == RPC_E_CHANGED_MODE {
                false
            } else {
                hr.ok().context("Initialize COM for Windows Firewall")?;
                true // Both S_OK and S_FALSE require a matching CoUninitialize.
            };
            Ok(Self {
                initialized_here,
                _thread_bound: PhantomData,
            })
        }
    }

    impl Drop for Apartment {
        fn drop(&mut self) {
            if self.initialized_here {
                unsafe { CoUninitialize() };
            }
        }
    }

    fn with_firewall<T>(f: impl FnOnce(&INetFwPolicy2) -> Result<T>) -> Result<T> {
        let _apartment = Apartment::enter()?;
        // The interface is released before the apartment guard on this thread.
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
                .context("Open native Windows Firewall policy")?;
        f(&policy)
    }

    fn installation() -> Result<(String, String, String)> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(CURRENT_VERSION, KEY_READ | KEY_WOW64_64KEY)
            .context("Read Windows installation identity")?;
        let kind: String = key
            .get_value("InstallationType")
            .context("Read Windows installation type")?;
        let edition: String = key
            .get_value("EditionID")
            .or_else(|_| key.get_value("ProductName"))
            .context("Read Windows edition")?;
        let build: String = key
            .get_value("CurrentBuildNumber")
            .context("Read Windows build")?;
        let revision: u32 = key.get_value("UBR").unwrap_or(0);
        Ok((kind, edition, format!("{build}.{revision}")))
    }

    pub fn detect_os() -> OsProfile {
        match installation() {
            Ok((kind, edition, build)) => {
                let is_server = kind.to_ascii_lowercase().contains("server");
                let has_desktop =
                    kind.eq_ignore_ascii_case("Client") || kind.eq_ignore_ascii_case("Server");
                let mut capabilities = vec!["windows-registry-inventory".into()];
                if with_firewall(|_| Ok(())).is_ok() {
                    capabilities.push("native-firewall-policy".into());
                }
                OsProfile {
                    edition,
                    build,
                    is_server,
                    has_desktop,
                    capabilities,
                }
            }
            Err(_) => OsProfile {
                edition: "Windows (edition not verified)".into(),
                build: "Unknown".into(),
                // Do not infer that an unclassified installation is a desktop.
                is_server: false,
                has_desktop: false,
                capabilities: vec![],
            },
        }
    }

    fn optional_string(key: &RegKey, name: &str) -> Result<String> {
        match key.get_value::<String, _>(name) {
            Ok(value) => Ok(value.trim().to_owned()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                // Unexpected registry value types are not trusted strings.
                Ok(String::new())
            }
            Err(error) => Err(error).context("Registry inventory value unreadable"),
        }
    }

    pub fn inventory() -> Result<Vec<InstalledApp>> {
        let mut apps = BTreeMap::new();
        let mut opened_sources = 0;
        for (hive, view) in [
            (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
            (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
            (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
        ] {
            let source = match RegKey::predef(hive)
                .open_subkey_with_flags(UNINSTALL, KEY_READ | view)
            {
                Ok(key) => key,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("Registry inventory source unreadable"),
            };
            opened_sources += 1;
            for name in source.enum_keys() {
                let name = name.context("Registry inventory enumeration incomplete")?;
                let key = match source.open_subkey_with_flags(name, KEY_READ | view) {
                    Ok(key) => key,
                    // Entries can disappear while software is uninstalled.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error).context("Registry inventory entry unreadable"),
                };
                let name = optional_string(&key, "DisplayName")?;
                if name.is_empty() {
                    continue;
                }
                let version = optional_string(&key, "DisplayVersion")?;
                let publisher = optional_string(&key, "Publisher")?;
                let identity = (
                    name.to_lowercase(),
                    version.clone(),
                    publisher.to_lowercase(),
                );
                apps.entry(identity).or_insert(InstalledApp {
                    name,
                    version,
                    publisher,
                });
            }
        }
        if opened_sources == 0 {
            bail!("No supported Windows uninstall inventory source was available");
        }
        // This is registered desktop-software inventory, not every installed
        // package, portable executable, runtime, driver, or user project.
        Ok(apps.into_values().collect())
    }

    fn profiles() -> [(NET_FW_PROFILE_TYPE2, &'static str, Repair); 3] {
        [
            (
                NET_FW_PROFILE2_DOMAIN,
                "Domain",
                Repair::EnableDomainFirewall,
            ),
            (
                NET_FW_PROFILE2_PRIVATE,
                "Private",
                Repair::EnablePrivateFirewall,
            ),
            (
                NET_FW_PROFILE2_PUBLIC,
                "Public",
                Repair::EnablePublicFirewall,
            ),
        ]
    }

    pub fn scan_checks() -> Vec<Finding> {
        let installation_type = installation().ok().map(|x| x.0);
        let confirmed_client = installation_type
            .as_deref()
            .is_some_and(|x| x.eq_ignore_ascii_case("Client"));
        let result = with_firewall(|policy| {
            let active = unsafe { policy.CurrentProfileTypes() }
                .context("Read active firewall profile types")?;
            let modify_state = unsafe { policy.LocalPolicyModifyState() }
                .context("Read firewall policy modification state")?;
            Ok(profiles().into_iter().map(|(profile, name, repair)| {
                let id = repair.id().to_owned();
                let base = format!(
                    "{} profile; active={}; local_policy_modify_state={}. ",
                    name, active & profile.0 != 0, modify_state.0,
                );
                match unsafe { policy.get_FirewallEnabled(profile) } {
                    Ok(value) => {
                        let enabled = value.0 != 0;
                        let modifiable = modify_state == NET_FW_MODIFY_STATE_OK;
                        let status = if !enabled {
                            Status::NeedsAttention
                        } else if !modifiable {
                            Status::Unknown
                        } else {
                            Status::Passed
                        };
                        Finding {
                            id,
                            name: format!("{name} firewall local policy"),
                            status,
                            evidence: format!(
                                "{base}enabled={enabled}. This reads local policy; it does not prove effective network protection or validate rule safety.{}{}",
                                if !modifiable { " Local policy is restricted or overridden; effective state is not verified." } else { "" },
                                if !confirmed_client { " Repair is unavailable on server or unclassified installations to avoid remote-service lockout." } else { "" },
                            ),
                            source: "Windows Firewall INetFwPolicy2 (local policy)".into(),
                            repair: (!enabled && modifiable && confirmed_client).then_some(repair),
                            change_risk: None,
                        }
                    }
                    Err(error) => Finding {
                        id,
                        name: format!("{name} firewall local policy"),
                        status: Status::Unknown,
                        evidence: format!("{base}Profile could not be read: {error}"),
                        source: "Windows Firewall INetFwPolicy2 (local policy)".into(),
                        repair: None,
                        change_risk: None,
                    },
                }
            }).collect())
        });
        match result {
            Ok(findings) => findings,
            Err(error) => profiles()
                .into_iter()
                .map(|(_, name, repair)| Finding {
                    id: repair.id().into(),
                    name: format!("{name} firewall local policy"),
                    status: Status::Unknown,
                    evidence: format!("Native firewall probe unavailable: {error:#}"),
                    source: "Windows Firewall INetFwPolicy2 (local policy)".into(),
                    repair: None,
                    change_risk: None,
                })
                .collect(),
        }
    }

    pub fn apply_repair(repair: Repair) -> Result<String> {
        // Classification must succeed. Unknown is not permission to make a
        // desktop-oriented change on what might be a remotely managed server.
        let (kind, _, _) = installation()?;
        if !kind.eq_ignore_ascii_case("Client") {
            bail!(
                "Firewall repair is status-only on server or unclassified installations: changing it could block remote management or services"
            );
        }
        let (profile, name, _) = profiles()
            .into_iter()
            .find(|(_, _, candidate)| *candidate == repair)
            .context("Unsupported firewall repair")?;
        with_firewall(|policy| {
            let before = unsafe { policy.get_FirewallEnabled(profile) }
                .context("Read original firewall policy before repair")?
                .0
                != 0;
            if before {
                return Ok(format!(
                    "{name} local firewall policy is already enabled; no change made. Effective network protection was not tested."
                ));
            }
            let state = unsafe { policy.LocalPolicyModifyState() }
                .context("Read firewall modification policy before repair")?;
            if state != NET_FW_MODIFY_STATE_OK {
                bail!(
                    "Local firewall policy cannot be safely modified: policy state {} (Group Policy override or restrictions); no change made",
                    state.0
                );
            }
            // Caller must obtain explicit approval for this exact Repair and
            // its disclosed impact. There is no shell, elevation, rule rewrite,
            // or automatic retry in this native operation.
            unsafe { policy.put_FirewallEnabled(profile, VARIANT_TRUE) }.context(
                "Enable selected firewall profile; administrator rights may be required",
            )?;
            let after = unsafe { policy.get_FirewallEnabled(profile) }
                .context("Setting accepted but local firewall readback failed; repair remains unverified")?.0 != 0;
            let state_after = unsafe { policy.LocalPolicyModifyState() }.context(
                "Setting accepted but policy-state recheck failed; repair remains unverified",
            )?;
            if !after || state_after != NET_FW_MODIFY_STATE_OK {
                bail!(
                    "Setting was attempted but local readback did not verify an unrestricted enabled policy (enabled={after}, policy_state={}); no automatic rollback attempted",
                    state_after.0
                );
            }
            Ok(format!(
                "{name} local firewall policy changed from enabled=false to enabled=true; separate local readback verified it. Existing rules retained. Effective network protection and remote-service reachability were not tested. No automatic rollback performed."
            ))
        })
    }
}

#[cfg(windows)]
pub use native::{apply_repair, detect_os, inventory, scan_checks};

#[cfg(not(windows))]
pub fn detect_os() -> OsProfile {
    OsProfile {
        edition: std::env::consts::OS.into(),
        build: "Unknown".into(),
        ..Default::default()
    }
}

#[cfg(not(windows))]
pub fn inventory() -> Result<Vec<InstalledApp>> {
    anyhow::bail!("Registered Windows software inventory is unavailable on this platform")
}

#[cfg(not(windows))]
pub fn scan_checks() -> Vec<Finding> {
    vec![Finding {
        id: "windows-firewall".into(),
        name: "Windows Firewall policy".into(),
        status: Status::Unsupported,
        evidence: "Native Windows checks are unavailable on this operating system".into(),
        source: "Platform capability".into(),
        repair: None,
        change_risk: None,
    }]
}

#[cfg(not(windows))]
pub fn apply_repair(_repair: Repair) -> Result<String> {
    anyhow::bail!("Native Windows repair is unsupported on this platform")
}
