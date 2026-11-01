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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repair {
    EnableDomainFirewall,
    EnablePrivateFirewall,
    EnablePublicFirewall,
}

impl Repair {
    pub fn id(self) -> &'static str {
        match self {
            Self::EnableDomainFirewall => "firewall-domain",
            Self::EnablePrivateFirewall => "firewall-private",
            Self::EnablePublicFirewall => "firewall-public",
        }
    }
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "firewall-domain" => Some(Self::EnableDomainFirewall),
            "firewall-private" => Some(Self::EnablePrivateFirewall),
            "firewall-public" => Some(Self::EnablePublicFirewall),
            _ => None,
        }
    }
    pub fn impact(self) -> &'static str {
        "Enables only the selected Windows Firewall profile, retaining existing rules. This can interrupt remote access or services. Administrator permission may be required. Reverting requires disabling that profile; no automatic rollback is performed."
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
