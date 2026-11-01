//! Bounded native registry hardening. These are configured-state checks, not CVE
//! detections or proof that a policy is active in existing sessions. No helpers,
//! script execution, downloads, key creation, service restarts, or auto-elevation.
use crate::model::{Finding, Repair, Risk, Status};
use anyhow::{Result, bail};

const UAC_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const MSI_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\Installer";
const SMB_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
const RDP_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

#[derive(Clone, Copy)]
enum Hive {
    Machine,
    CurrentUser,
}

#[derive(Clone, Copy)]
struct Recipe {
    repair: Repair,
    hive: Hive,
    key: &'static str,
    value: &'static str,
    dangerous: u32,
    target: u32,
    acceptable: &'static [u32],
    missing_is_off: bool,
}

const RECIPES: &[Recipe] = &[
    Recipe {
        repair: Repair::EnableUac,
        hive: Hive::Machine,
        key: UAC_KEY,
        value: "EnableLUA",
        dangerous: 0,
        target: 1,
        acceptable: &[1],
        missing_is_off: false,
    },
    Recipe {
        repair: Repair::UacSecureDesktop,
        hive: Hive::Machine,
        key: UAC_KEY,
        value: "PromptOnSecureDesktop",
        dangerous: 0,
        target: 1,
        acceptable: &[1],
        missing_is_off: false,
    },
    Recipe {
        repair: Repair::UacAdminConsent,
        hive: Hive::Machine,
        key: UAC_KEY,
        value: "ConsentPromptBehaviorAdmin",
        dangerous: 0,
        target: 2,
        acceptable: &[1, 2, 3, 4, 5],
        missing_is_off: false,
    },
    Recipe {
        repair: Repair::DisableElevatedMsiMachine,
        hive: Hive::Machine,
        key: MSI_KEY,
        value: "AlwaysInstallElevated",
        dangerous: 1,
        target: 0,
        acceptable: &[0],
        missing_is_off: true,
    },
    Recipe {
        repair: Repair::DisableElevatedMsiUser,
        hive: Hive::CurrentUser,
        key: MSI_KEY,
        value: "AlwaysInstallElevated",
        dangerous: 1,
        target: 0,
        acceptable: &[0],
        missing_is_off: true,
    },
    Recipe {
        repair: Repair::DisableSmbGuest,
        hive: Hive::Machine,
        key: SMB_KEY,
        value: "AllowInsecureGuestAuth",
        dangerous: 1,
        target: 0,
        acceptable: &[0],
        missing_is_off: false,
    },
    Recipe {
        repair: Repair::RequireRdpNla,
        hive: Hive::Machine,
        key: RDP_KEY,
        value: "UserAuthentication",
        dangerous: 0,
        target: 1,
        acceptable: &[1],
        missing_is_off: false,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Dword(u32),
    Missing,
    Unreadable,
}

fn classify(recipe: Recipe, value: Value) -> Status {
    match value {
        Value::Dword(v) if v == recipe.dangerous => Status::NeedsAttention,
        Value::Dword(v) if recipe.acceptable.contains(&v) => Status::Passed,
        Value::Missing if recipe.missing_is_off => Status::Passed,
        _ => Status::Unknown,
    }
}

fn recipe(repair: Repair) -> Option<Recipe> {
    RECIPES.iter().copied().find(|r| r.repair == repair)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Context {
    local_policy: bool,
}

impl Context {
    fn change_risk(self) -> Option<Risk> {
        self.local_policy.then_some(Risk::Critical)
    }
    fn policy_notice(self) -> &'static str {
        if self.local_policy {
            "Local Group Policy may reapply this configured value; this is an approved local registry override, not a permanent policy-source repair."
        } else {
            "No applied registry/security GPO was observed in the verified local policy lists."
        }
    }
}

fn verified_local_gpo(machine_link: bool, link: Option<&str>) -> bool {
    machine_link && link.is_some_and(|name| name.eq_ignore_ascii_case("Local"))
}

#[cfg(windows)]
mod native {
    use super::*;
    use anyhow::Context as _;
    use std::io;
    use windows::{
        Win32::{
            Foundation::{FreeLibrary, HMODULE},
            NetworkManagement::NetManagement::{
                NETSETUP_JOIN_STATUS, NetApiBufferFree, NetFreeAadJoinInformation,
                NetGetAadJoinInformation, NetGetJoinInformation, NetSetupUnjoined,
                NetSetupWorkgroupName,
            },
            Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
            System::{
                GroupPolicy::{
                    FreeGPOListW, GPLinkMachine, GPO_LIST_FLAG_MACHINE, GROUP_POLICY_OBJECTW,
                    GetAppliedGPOListW,
                },
                LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        },
        core::{BOOL, GUID, HRESULT, PCSTR, PCWSTR, PWSTR, w},
    };
    use winreg::{RegKey, enums::*};

    struct Module(HMODULE);
    impl Drop for Module {
        fn drop(&mut self) {
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }

    fn root(hive: Hive) -> RegKey {
        RegKey::predef(match hive {
            Hive::Machine => HKEY_LOCAL_MACHINE,
            Hive::CurrentUser => HKEY_CURRENT_USER,
        })
    }

    fn open_target(hive: Hive, path: &str, access: u32) -> io::Result<RegKey> {
        let mut key = root(hive);
        let parts: Vec<_> = path.split('\\').collect();
        for (index, part) in parts.iter().enumerate() {
            // Walk through anchored handles, opening a link object itself rather
            // than following it. Never let an approved HKCU target redirect into
            // an unrelated HKLM key when the process is elevated.
            let rights = if index + 1 == parts.len() {
                access
            } else {
                KEY_READ
            };
            let child = key.open_subkey_with_options_flags(
                part,
                REG_OPTION_OPEN_LINK,
                rights | KEY_WOW64_64KEY,
            )?;
            match child.get_raw_value("SymbolicLinkValue") {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Registry link or reserved link marker is not an eligible repair target",
                    ));
                }
            }
            key = child;
        }
        Ok(key)
    }

    fn read(hive: Hive, key: &str, value: &str) -> Value {
        let key = match open_target(hive, key, KEY_READ) {
            Ok(key) => key,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Value::Missing,
            Err(_) => return Value::Unreadable,
        };
        match key.get_raw_value(value) {
            Ok(value) if value.vtype == REG_DWORD && value.bytes.len() == 4 => {
                Value::Dword(u32::from_le_bytes(
                    value
                        .bytes
                        .as_ref()
                        .try_into()
                        .expect("DWORD length checked"),
                ))
            }
            Ok(_) => Value::Unreadable,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Value::Missing,
            Err(_) => Value::Unreadable,
        }
    }

    /// Fail closed on servers, unknown membership, enterprise registration,
    /// unreadable policy state, or nonlocal/unknown registry/security GPO ownership.
    /// Identifiers/account information returned by Windows are never displayed.
    fn eligible_client_context() -> Result<Context> {
        let version = root(Hive::Machine)
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .context("Windows installation classification unavailable")?;
        let kind: String = version
            .get_value("InstallationType")
            .context("Windows installation type unavailable")?;
        let build: String = version
            .get_value("CurrentBuildNumber")
            .context("Windows build unavailable")?;
        if !kind.eq_ignore_ascii_case("Client") || build.parse::<u32>().unwrap_or(0) < 10240 {
            bail!(
                "Registry repairs require a verified Windows 10/11 client; server, older, or unclassified targets are status-only"
            );
        }

        let mut name = PWSTR::null();
        let mut join = NETSETUP_JOIN_STATUS::default();
        let code = unsafe { NetGetJoinInformation(PCWSTR::null(), &mut name, &mut join) };
        if !name.is_null() {
            unsafe {
                let _ = NetApiBufferFree(Some(name.0.cast()));
            }
        }
        if code != 0 || (join != NetSetupUnjoined && join != NetSetupWorkgroupName) {
            bail!(
                "Domain membership is managed or could not be verified; use the owning policy administrator"
            );
        }
        let aad = unsafe { NetGetAadJoinInformation(PCWSTR::null()) }
            .context("Workplace/Entra registration state could not be verified")?;
        if !aad.is_null() {
            unsafe {
                NetFreeAadJoinInformation(Some(aad));
            }
            bail!(
                "Workplace/Entra registration is present; registry repairs must be managed through its policy owner"
            );
        }

        // Dynamic System32-only lookup: unsupported MDM APIs must not become a
        // DLL load requirement for the whole executable on Server Core.
        let module = Module(
            unsafe {
                LoadLibraryExW(
                    w!("MDMRegistration.dll"),
                    None,
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            }
            .context("MDM registration API unavailable; management state is unknown")?,
        );
        let proc = unsafe {
            GetProcAddress(
                module.0,
                PCSTR(b"IsDeviceRegisteredWithManagement\0".as_ptr()),
            )
        }
        .context("MDM registration API unavailable; management state is unknown")?;
        type MdmQuery = unsafe extern "system" fn(*mut BOOL, u32, PWSTR) -> HRESULT;
        // This exact documented export and ABI are checked before invocation.
        let query: MdmQuery = unsafe { std::mem::transmute(proc) };
        let mut registered = BOOL(0);
        unsafe { query(&mut registered, 0, PWSTR::null()) }
            .ok()
            .context("MDM registration state could not be verified")?;
        if registered.as_bool() {
            bail!(
                "MDM registration is present; registry repairs are controlled by its policy owner"
            );
        }

        // Scope per-user GPO reads to the process token, matching HKCU even when
        // running under an account different from the interactive desktop user.
        let mut token = windows::Win32::Foundation::HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .context("Policy account scope could not be verified")?;
        struct Token(windows::Win32::Foundation::HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let token = Token(token);
        let mut bytes = 0;
        unsafe {
            let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 64 * 1024 {
            bail!("Policy account scope could not be verified");
        }
        let mut data = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(data.as_mut_ptr().cast()),
                bytes,
                &mut bytes,
            )
        }
        .context("Policy account scope could not be verified")?;
        let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
        let registry_cse = GUID::from_u128(0x35378eac_683f_11d2_a89a_00c04fbbcfa2);
        let security_cse = GUID::from_u128(0x827d319e_6eac_11d2_a4ea_00c04f79f83a);
        let mut context = Context::default();
        for (flags, extension) in [
            (GPO_LIST_FLAG_MACHINE, registry_cse),
            (GPO_LIST_FLAG_MACHINE, security_cse),
            (0, registry_cse),
        ] {
            let mut list: *mut GROUP_POLICY_OBJECTW = std::ptr::null_mut();
            let code = unsafe {
                GetAppliedGPOListW(
                    flags,
                    PCWSTR::null(),
                    Some(user.User.Sid),
                    &extension,
                    &mut list,
                )
            };
            struct GpoList(*mut GROUP_POLICY_OBJECTW);
            impl Drop for GpoList {
                fn drop(&mut self) {
                    if !self.0.is_null() {
                        unsafe {
                            let _ = FreeGPOListW(self.0);
                        }
                    }
                }
            }
            let list = GpoList(list);
            if code != 0 {
                bail!(
                    "Applied Group Policy state could not be verified (Windows status {code}); no registry repair is offered"
                );
            }
            let mut node = list.0;
            let mut seen = std::collections::HashSet::new();
            while !node.is_null() {
                if seen.len() >= 256 || !seen.insert(node as usize) {
                    bail!(
                        "Applied Group Policy list is incomplete or malformed; ownership is unknown"
                    );
                }
                // The API-owned list remains alive while inspected. Never
                // disclose its display names, paths, or domain identifiers.
                let policy = unsafe { &*node };
                let link = if policy.lpLink.is_null() {
                    None
                } else {
                    Some(
                        unsafe { policy.lpLink.to_string() }
                            .context("Applied Group Policy link could not be classified")?,
                    )
                };
                if !verified_local_gpo(policy.GPOLink == GPLinkMachine, link.as_deref()) {
                    bail!(
                        "Nonlocal or unknown Group Policy ownership is present; registry overrides are not permitted"
                    );
                }
                context.local_policy = true;
                node = policy.pNext;
            }
        }
        Ok(context)
    }

    fn prerequisites(recipe: Recipe) -> Result<()> {
        if recipe.repair == Repair::RequireRdpNla {
            let os = crate::platform::detect_os();
            let edition = os.edition.to_ascii_lowercase();
            if !(edition.starts_with("professional")
                || edition.starts_with("enterprise")
                || edition.starts_with("education"))
            {
                bail!("RDP host support is not verified for this Windows edition");
            }
            match read(
                Hive::Machine,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections",
            ) {
                Value::Dword(0) => {}
                Value::Dword(1) => {
                    bail!("RDP hosting is disabled; no active-host NLA repair is offered")
                }
                _ => bail!("RDP hosting configuration could not be verified"),
            }
            // The recipe edits local RDP-Tcp state only. An explicit policy
            // override is never rewritten, even on a workgroup computer.
            if read(
                Hive::Machine,
                r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                "UserAuthentication",
            ) != Value::Missing
            {
                bail!(
                    "An RDP authentication policy override is present or unreadable; no local override will be made"
                );
            }
        }
        Ok(())
    }

    fn finding(recipe: Recipe, management: &Result<Context>) -> Finding {
        let value = read(recipe.hive, recipe.key, recipe.value);
        let (status, detail) = match management {
            Err(error) => (
                Status::Unknown,
                format!("Management/applicability gate: {error:#}"),
            ),
            Ok(_) => match prerequisites(recipe) {
                Err(error) => (Status::Unknown, format!("Applicability: {error:#}")),
                Ok(()) => {
                    let status = classify(recipe, value);
                    let observed = match value {
                        Value::Dword(value) => format!("REG_DWORD={value}"),
                        Value::Missing if recipe.missing_is_off => {
                            "not configured (documented MSI opt-in is off in this scope)".into()
                        }
                        Value::Missing => "missing; no default assumed".into(),
                        Value::Unreadable => "unreadable or not REG_DWORD".into(),
                    };
                    (
                        status,
                        format!(
                            "Observed {observed}; target DWORD={}. {}",
                            recipe.target,
                            if recipe.repair == Repair::UacAdminConsent {
                                "Existing values 1..5 are preserved; this check does not rank their relative strength."
                            } else {
                                ""
                            }
                        ),
                    )
                }
            },
        };
        let hive = match recipe.hive {
            Hive::Machine => "HKLM",
            Hive::CurrentUser => "HKCU (process account)",
        };
        Finding {
            id: recipe.repair.id().into(),
            name: recipe.repair.title().into(),
            status,
            evidence: format!(
                "{hive}\\{}\\{}; {detail} {} Scope: configured 64-bit registry policy only; runtime protection, current sessions, and network reachability are not verified. Restart/activation boundary={}.{}",
                recipe.key,
                recipe.value,
                management
                    .as_ref()
                    .map(|context| context.policy_notice())
                    .unwrap_or("Policy ownership is not verified; no override is authorized."),
                recipe.repair.restart_required(),
                if matches!(
                    recipe.repair,
                    Repair::DisableElevatedMsiMachine | Repair::DisableElevatedMsiUser
                ) {
                    " MSI elevation requires both machine and user opt-ins; a single observed value does not prove an active elevation path."
                } else {
                    ""
                }
            ),
            source: recipe.repair.source().into(),
            repair: (status == Status::NeedsAttention).then_some(recipe.repair),
            change_risk: management
                .as_ref()
                .ok()
                .and_then(|context| context.change_risk()),
        }
    }

    pub fn scan_checks() -> Vec<Finding> {
        let management = eligible_client_context();
        RECIPES
            .iter()
            .copied()
            .map(|r| finding(r, &management))
            .collect()
    }

    pub fn apply_repair(repair: Repair) -> Result<String> {
        let recipe = recipe(repair).context("Not a built-in registry recipe")?;
        let context_before = eligible_client_context()
            .context("Registry repair eligibility could not be established")?;
        prerequisites(recipe)?;
        let key = open_target(recipe.hive, recipe.key, KEY_READ | KEY_SET_VALUE)
            .context("Open existing registry repair target; elevation may be required")?;
        let before = read(recipe.hive, recipe.key, recipe.value);
        if before != Value::Dword(recipe.dangerous) {
            bail!(
                "Configured value is no longer the exact eligible DWORD {}; no change made",
                recipe.dangerous
            );
        }
        // Never create absent keys or replace an unfamiliar value. The plan
        // approval gate must already have bound this exact action and evidence.
        key.set_value(recipe.value, &recipe.target)
            .context("Write approved DWORD; administrator permission may be required")?;
        let after = read(recipe.hive, recipe.key, recipe.value);
        if after != Value::Dword(recipe.target) {
            bail!(
                "Write attempted, but fresh configured-state readback did not match target {}; no automatic rollback performed",
                recipe.target
            );
        }
        // A policy registration appearing during the operation invalidates any
        // verification claim. Do not fight it or automatically undo its state.
        let context_after = eligible_client_context().context("Write attempted; management state changed or is unverifiable, so the repair is not verified")?;
        if context_before != context_after {
            bail!(
                "Write attempted; local policy context changed during the repair and configured-state verification is incomplete. No automatic rollback performed"
            );
        }
        Ok(format!(
            "{} configured DWORD {} -> {}; fresh registry readback verified. {} Runtime activation/protection is not verified. Restart/activation boundary={}. Original recovery: {}",
            repair.id(),
            recipe.dangerous,
            recipe.target,
            context_before.policy_notice(),
            repair.restart_required(),
            repair.rollback()
        ))
    }
}

#[cfg(windows)]
pub use native::{apply_repair, scan_checks};

#[cfg(not(windows))]
pub fn scan_checks() -> Vec<Finding> {
    RECIPES
        .iter()
        .map(|r| Finding {
            id: r.repair.id().into(),
            name: r.repair.title().into(),
            status: Status::Unsupported,
            evidence: "Windows native registry recipe unavailable on this platform".into(),
            source: r.repair.source().into(),
            repair: None,
            change_risk: None,
        })
        .collect()
}

#[cfg(not(windows))]
pub fn apply_repair(_repair: Repair) -> Result<String> {
    bail!("Native Windows registry repair is unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_local_policy_override_is_critical_and_not_a_permanent_policy_fix() {
        assert!(verified_local_gpo(true, Some("Local")));
        let context = Context { local_policy: true };
        let recipe = recipe(Repair::EnableUac).unwrap();
        assert_eq!(classify(recipe, Value::Dword(0)), Status::NeedsAttention);
        assert_eq!(context.change_risk(), Some(Risk::Critical));
        assert!(context.policy_notice().contains("may reapply"));
        assert!(
            context
                .policy_notice()
                .contains("not a permanent policy-source repair")
        );
        assert_eq!(classify(recipe, Value::Missing), Status::Unknown);
        assert_eq!(classify(recipe, Value::Unreadable), Status::Unknown);
        assert_eq!(Context::default().change_risk(), None);
    }

    #[test]
    fn nonlocal_or_unknown_gpo_links_cannot_be_treated_as_local_overrides() {
        for (machine_link, link) in [
            (false, Some("Local")), // Site/domain/OU/unknown enum is never local.
            (true, Some("LDAP://sample.invalid")),
            (true, Some("remote-computer")),
            (true, Some("")),
            (true, None),
        ] {
            assert!(!verified_local_gpo(machine_link, link));
        }
        assert!(verified_local_gpo(true, Some("LOCAL")));
        let mixed = [(true, Some("Local")), (false, Some("Local"))];
        assert!(
            !mixed
                .into_iter()
                .all(|(kind, name)| verified_local_gpo(kind, name))
        );
    }

    #[test]
    fn missing_values_are_unknown_except_documented_msi_opt_in() {
        for r in RECIPES {
            assert_eq!(
                classify(*r, Value::Missing),
                if r.missing_is_off {
                    Status::Passed
                } else {
                    Status::Unknown
                }
            );
            assert_eq!(classify(*r, Value::Unreadable), Status::Unknown);
        }
    }
    #[test]
    fn only_exact_dangerous_values_are_candidates() {
        for r in RECIPES {
            assert_eq!(
                classify(*r, Value::Dword(r.dangerous)),
                Status::NeedsAttention
            );
            assert_eq!(classify(*r, Value::Dword(r.target)), Status::Passed);
            assert_eq!(classify(*r, Value::Dword(u32::MAX)), Status::Unknown);
        }
    }
    #[test]
    fn administrator_consent_preserves_all_existing_nonzero_choices() {
        let r = recipe(Repair::UacAdminConsent).unwrap();
        for existing in 1..=5 {
            assert_eq!(classify(r, Value::Dword(existing)), Status::Passed);
        }
        assert_eq!(classify(r, Value::Dword(6)), Status::Unknown);
    }
    #[test]
    fn recipe_ids_and_public_metadata_are_complete() {
        let mut ids = std::collections::HashSet::new();
        for repair in Repair::all() {
            assert!(ids.insert(repair.id()));
            assert_eq!(Repair::from_id(repair.id()), Some(*repair));
            assert!(!repair.title().is_empty());
            assert!(!repair.impact().is_empty());
            assert!(!repair.rollback().is_empty());
            assert!(repair.source().starts_with("https://learn.microsoft.com/"));
        }
        assert_eq!(Repair::RequireRdpNla.risk(), crate::model::Risk::Critical);
    }
}
