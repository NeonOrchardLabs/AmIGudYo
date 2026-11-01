use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    NeedsAttention,
    Unknown,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub evidence: String,
    pub source: String,
    pub repair: Option<Repair>,
    /// Context-specific action impact, e.g. an explicitly approved local-GPO override.
    #[serde(default)]
    pub change_risk: Option<Risk>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repair {
    EnableDomainFirewall,
    EnablePrivateFirewall,
    EnablePublicFirewall,
    EnableUac,
    UacSecureDesktop,
    UacAdminConsent,
    DisableElevatedMsiMachine,
    DisableElevatedMsiUser,
    DisableSmbGuest,
    RequireRdpNla,
}

/// Risk describes the impact of applying a repair, not a CVE severity score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Moderate,
    High,
    Critical,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Moderate => "Moderate",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl Repair {
    pub fn all() -> &'static [Self] {
        &[
            Self::EnableDomainFirewall,
            Self::EnablePrivateFirewall,
            Self::EnablePublicFirewall,
            Self::EnableUac,
            Self::UacSecureDesktop,
            Self::UacAdminConsent,
            Self::DisableElevatedMsiMachine,
            Self::DisableElevatedMsiUser,
            Self::DisableSmbGuest,
            Self::RequireRdpNla,
        ]
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall => "firewall-domain",
            Self::EnablePrivateFirewall => "firewall-private",
            Self::EnablePublicFirewall => "firewall-public",
            Self::EnableUac => "uac-enable",
            Self::UacSecureDesktop => "uac-secure-desktop",
            Self::UacAdminConsent => "uac-admin-consent",
            Self::DisableElevatedMsiMachine => "msi-no-elevated-machine",
            Self::DisableElevatedMsiUser => "msi-no-elevated-user",
            Self::DisableSmbGuest => "smb-no-insecure-guest",
            Self::RequireRdpNla => "rdp-require-nla",
        }
    }
    pub fn from_id(id: &str) -> Option<Self> {
        Self::all().iter().copied().find(|repair| repair.id() == id)
    }
    pub fn title(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall => "Enable Domain firewall local policy",
            Self::EnablePrivateFirewall => "Enable Private firewall local policy",
            Self::EnablePublicFirewall => "Enable Public firewall local policy",
            Self::EnableUac => "Enable User Account Control",
            Self::UacSecureDesktop => "Put UAC prompts on the secure desktop",
            Self::UacAdminConsent => "Require administrator elevation consent",
            Self::DisableElevatedMsiMachine => "Disable machine-wide elevated MSI opt-in",
            Self::DisableElevatedMsiUser => "Disable this account's elevated MSI opt-in",
            Self::DisableSmbGuest => "Reject insecure SMB guest logons",
            Self::RequireRdpNla => "Require Network Level Authentication for RDP",
        }
    }
    pub fn risk(self) -> Risk {
        match self {
            Self::RequireRdpNla => Risk::Critical,
            Self::EnableDomainFirewall
            | Self::EnablePrivateFirewall
            | Self::EnablePublicFirewall
            | Self::EnableUac
            | Self::DisableSmbGuest => Risk::High,
            Self::UacSecureDesktop
            | Self::UacAdminConsent
            | Self::DisableElevatedMsiMachine
            | Self::DisableElevatedMsiUser => Risk::Moderate,
        }
    }
    pub fn impact(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall
            | Self::EnablePrivateFirewall
            | Self::EnablePublicFirewall => {
                "Enables only the selected Windows Firewall profile, retaining existing rules. This can interrupt remote access or services. Administrator permission may be required. Effective network protection is not proven by a local readback."
            }
            Self::EnableUac => {
                "Enables configured UAC. Elevation and application compatibility behavior can change after restart. Existing elevated processes remain elevated; this does not prove active UAC protection before restart."
            }
            Self::UacSecureDesktop => {
                "Moves configured elevation prompts to the secure desktop. Accessibility or remote-support workflows may change. UAC must be enabled; current elevation dialogs are not changed."
            }
            Self::UacAdminConsent => {
                "Changes only a no-prompt administrator setting to consent on the secure desktop. Unattended elevation may stop. Existing nonzero consent settings are preserved; UAC must be enabled."
            }
            Self::DisableElevatedMsiMachine => {
                "Removes the machine-wide AlwaysInstallElevated opt-in. Unmanaged installers or MSI repairs that depended on it may fail without normal elevation. Managed administrator-deployed packages are a separate mechanism."
            }
            Self::DisableElevatedMsiUser => {
                "Removes AlwaysInstallElevated only for the account running this process, not other accounts. Unmanaged MSI installs/repairs depending on this opt-in may need normal elevation. This account may differ from the desktop's signed-in user."
            }
            Self::DisableSmbGuest => {
                "Rejects unauthenticated SMB guest connections. Legacy NAS or shared folders using guest access may become inaccessible. Existing sessions are not terminated or verified; reconnect/restart before relying on new behavior."
            }
            Self::RequireRdpNla => {
                "Requires pre-session authentication for RDP. Older clients, credential problems, or authentication dependencies can lock out remote access. Have local console or another tested recovery route. No service restart or reachability test is performed automatically."
            }
        }
    }
    pub fn rollback(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall
            | Self::EnablePrivateFirewall
            | Self::EnablePublicFirewall => {
                "Disable only the changed firewall profile to restore its original disabled local state; this reduces protection. No automatic rollback."
            }
            Self::EnableUac => {
                "Restore EnableLUA=0 and restart to recover the original configuration; this disables UAC. No automatic rollback."
            }
            Self::UacSecureDesktop => {
                "Restore PromptOnSecureDesktop=0 to recover the original prompt configuration. No automatic rollback."
            }
            Self::UacAdminConsent => {
                "Restore ConsentPromptBehaviorAdmin=0 to recover the original no-prompt configuration. No automatic rollback."
            }
            Self::DisableElevatedMsiMachine | Self::DisableElevatedMsiUser => {
                "Restore AlwaysInstallElevated=1 in only the changed scope to recover the original opt-in; this may enable dangerous system-level MSI elevation. No automatic rollback."
            }
            Self::DisableSmbGuest => {
                "Restore the changed AllowInsecureGuestAuth policy value to 1, then reconnect/restart as needed; this re-enables insecure guest access. No automatic rollback."
            }
            Self::RequireRdpNla => {
                "From the local console or another tested administration route, restore the changed RDP-Tcp UserAuthentication value to 0 and restart as needed. No automatic rollback."
            }
        }
    }
    /// Conservative activation boundary; readback alone is configured-state proof.
    pub fn restart_required(self) -> bool {
        matches!(
            self,
            Self::EnableUac | Self::DisableSmbGuest | Self::RequireRdpNla
        )
    }
    pub fn action_description(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall => {
                "Native INetFwPolicy2::put_FirewallEnabled(Domain, true), then fresh local-policy readback"
            }
            Self::EnablePrivateFirewall => {
                "Native INetFwPolicy2::put_FirewallEnabled(Private, true), then fresh local-policy readback"
            }
            Self::EnablePublicFirewall => {
                "Native INetFwPolicy2::put_FirewallEnabled(Public, true), then fresh local-policy readback"
            }
            Self::EnableUac => {
                "Native 64-bit HKLM registry: HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System EnableLUA DWORD 0 -> 1; preserve other values"
            }
            Self::UacSecureDesktop => {
                "Native 64-bit HKLM registry: HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System PromptOnSecureDesktop DWORD 0 -> 1; preserve other values"
            }
            Self::UacAdminConsent => {
                "Native 64-bit HKLM registry: HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System ConsentPromptBehaviorAdmin DWORD 0 -> 2; preserve values 1..5"
            }
            Self::DisableElevatedMsiMachine => {
                "Native 64-bit HKLM registry: HKLM/SOFTWARE/Policies/Microsoft/Windows/Installer AlwaysInstallElevated DWORD 1 -> 0"
            }
            Self::DisableElevatedMsiUser => {
                "Native 64-bit current-process-account HKCU registry: HKCU/SOFTWARE/Policies/Microsoft/Windows/Installer AlwaysInstallElevated DWORD 1 -> 0"
            }
            Self::DisableSmbGuest => {
                "Native 64-bit HKLM registry: HKLM/SOFTWARE/Policies/Microsoft/Windows/LanmanWorkstation AllowInsecureGuestAuth DWORD 1 -> 0"
            }
            Self::RequireRdpNla => {
                "Native 64-bit HKLM registry: SYSTEM/CurrentControlSet/Control/Terminal Server/WinStations/RDP-Tcp UserAuthentication DWORD 0 -> 1"
            }
        }
    }
    pub fn source(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall
            | Self::EnablePrivateFirewall
            | Self::EnablePublicFirewall => {
                "https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-put_firewallenabled"
            }
            Self::EnableUac | Self::UacSecureDesktop | Self::UacAdminConsent => {
                "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration/"
            }
            Self::DisableElevatedMsiMachine | Self::DisableElevatedMsiUser => {
                "https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated"
            }
            Self::DisableSmbGuest => {
                "https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/cannot-access-shared-folder-file-explorer"
            }
            Self::RequireRdpNla => {
                "https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/cannot-connect-rdp-azure-vm"
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OsProfile {
    pub edition: String,
    pub build: String,
    pub is_server: bool,
    pub has_desktop: bool,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
}
