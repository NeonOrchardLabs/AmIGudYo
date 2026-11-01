//! Explicit Windows Update Agent inspection and separately approved cached installation.
use crate::model::{Finding, Status};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CRITERIA: &str = "IsInstalled=0 and IsHidden=0 and Type='Software'";
pub const SOURCE: &str =
    "https://learn.microsoft.com/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search";
pub const MAX_UPDATES: usize = 10_000;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
pub const SCOPE: &str = "Cached WUA applicability for visible, uninstalled software updates in the configured service scope; cache freshness and complete effective coverage are unknown. Drivers, hidden updates and superseded updates are not comprehensively checked.";
pub const ONLINE_SCOPE: &str = "Online WUA applicability for visible, uninstalled software updates from the configured default service. Advisory dates, advisory age and complete effective coverage are unknown. This query does not establish a CVE date range. Drivers, hidden updates and superseded updates are not comprehensively checked.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionIssue {
    pub operation: String,
    pub hresult: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCategory {
    pub id: String,
    pub name: String,
    pub kind: String,
}

/// Numeric values are the WUA InstallationImpact and InstallationRebootBehavior enums.
/// Keeping the original value also preserves unknown future values without guessing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationBehavior {
    pub can_request_user_input: bool,
    pub impact: i32,
    pub reboot_behavior: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub update_id: String,
    pub revision: i32,
    pub title: Option<String>,
    pub kb_article_ids: Option<Vec<String>>,
    pub msrc_severity: Option<String>,
    pub categories: Option<Vec<UpdateCategory>>,
    pub downloaded: Option<bool>,
    pub eula_accepted: Option<bool>,
    pub reboot_pending: Option<bool>,
    pub installation_behavior: Option<InstallationBehavior>,
    pub issues: Vec<InspectionIssue>,
}

impl UpdateInfo {
    pub fn exact_key(&self) -> String {
        format!("{}@{}", self.update_id.to_ascii_lowercase(), self.revision)
    }

    fn metadata_bytes(&self) -> usize {
        self.update_id.len()
            + self.title.as_ref().map_or(0, String::len)
            + self.msrc_severity.as_ref().map_or(0, String::len)
            + self
                .kb_article_ids
                .as_ref()
                .map_or(0, |values| values.iter().map(String::len).sum())
            + self.categories.as_ref().map_or(0, |values| {
                values
                    .iter()
                    .map(|v| v.id.len() + v.name.len() + v.kind.len())
                    .sum()
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateReport {
    /// True only when enumeration and every requested metadata read succeeded.
    /// This never asserts cache freshness or comprehensive vulnerability coverage.
    pub complete: bool,
    pub criteria: String,
    pub scope: String,
    pub requested_online: bool,
    pub server_selection: Option<i32>,
    pub result_code: i32,
    pub reported_count: usize,
    pub updates: Vec<UpdateInfo>,
    pub issues: Vec<InspectionIssue>,
}

impl UpdateReport {
    pub fn summary(&self) -> String {
        format!(
            "{} update(s) from {} search; {}. Advisory age and complete coverage unknown. No update payload downloads or installations.",
            self.updates.len(),
            if self.requested_online {
                "online"
            } else {
                "cached"
            },
            if self.complete {
                "inspection completed"
            } else {
                "inspection incomplete"
            }
        )
    }

    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = vec![Finding {
            id: "windows-update-cache-scope".into(),
            name: if self.requested_online {
                "Windows Update Online"
            } else {
                "Windows Update Cache"
            }
            .into(),
            status: Status::Unknown,
            evidence: format!(
                "{} {} Search result={}; reported={}; issues={}. Search can take time and is run only on request.",
                self.summary(),
                self.scope,
                self.result_code,
                self.reported_count,
                self.issues.len()
            ),
            source: SOURCE.into(),
            repair: None,
            change_risk: None,
        }];
        findings.extend(self.updates.iter().map(|update| Finding {
            id: format!("windows-update-{}", update.exact_key()),
            name: update.title.clone().unwrap_or_else(|| "Windows Update (metadata unavailable)".into()),
            status: if self.complete && update.issues.is_empty() { Status::NeedsAttention } else { Status::Unknown },
            evidence: format!("Applicable identity={}; KB={:?}; MSRC={:?}; downloaded={:?}; EULA accepted={:?}; reboot pending={:?}; installation behavior={:?}; metadata issues={}. {} Installation is not offered by this check.", update.exact_key(), update.kb_article_ids, update.msrc_severity, update.downloaded, update.eula_accepted, update.reboot_pending, update.installation_behavior, update.issues.len(), self.scope),
            source: SOURCE.into(), repair: None, change_risk: None,
        }));
        findings
    }
}

fn bounded_count(count: i32, limit: usize) -> Result<usize> {
    let count = usize::try_from(count)
        .map_err(|_| anyhow::anyhow!("Invalid WUA collection count; applicability unknown"))?;
    if count > limit {
        bail!(
            "WUA collection exceeds supported bound; applicability unknown (no results truncated)"
        );
    }
    Ok(count)
}

fn deduplicate(updates: Vec<UpdateInfo>, issues: &mut Vec<InspectionIssue>) -> Vec<UpdateInfo> {
    let mut unique = BTreeMap::new();
    for update in updates {
        let key = update.exact_key();
        if let Some(previous) = unique.get(&key) {
            if previous != &update {
                issues.push(InspectionIssue {
                    operation: "Conflicting duplicate update identity".into(),
                    hresult: None,
                });
            }
        } else {
            unique.insert(key, update);
        }
    }
    unique.into_values().collect()
}

#[cfg(windows)]
mod native {
    use super::*;
    use windows::{
        Win32::{
            Foundation::{RPC_E_CHANGED_MODE, VARIANT_FALSE, VARIANT_TRUE},
            System::{
                Com::{
                    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                    CoUninitialize,
                },
                UpdateAgent::*,
            },
        },
        core::{BSTR, Interface},
    };

    struct Apartment(bool);
    impl Drop for Apartment {
        fn drop(&mut self) {
            if self.0 {
                unsafe { CoUninitialize() };
            }
        }
    }
    fn checked<T>(value: windows::core::Result<T>, operation: &str) -> Result<T> {
        value.map_err(|error| {
            anyhow::anyhow!(
                "{operation} failed (HRESULT 0x{:08X}); applicability unknown",
                error.code().0 as u32
            )
        })
    }
    fn metadata<T>(
        value: windows::core::Result<T>,
        operation: &str,
        issues: &mut Vec<InspectionIssue>,
    ) -> Option<T> {
        match value {
            Ok(value) => Some(value),
            Err(error) => {
                issues.push(InspectionIssue {
                    operation: operation.into(),
                    hresult: Some(error.code().0),
                });
                None
            }
        }
    }
    fn text(value: BSTR) -> windows::core::Result<String> {
        if value.len() > 16_384 {
            return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                0x80070057u32 as i32,
            )));
        }
        Ok(value.to_string())
    }

    unsafe fn inspect_update(update: &IUpdate) -> Result<UpdateInfo> {
        unsafe {
            let identity = checked(update.Identity(), "Read update identity")?;
            let id = checked(identity.UpdateID().and_then(text), "Read update ID")?;
            let revision = checked(identity.RevisionNumber(), "Read revision")?;
            if windows::core::GUID::try_from(id.as_str()).is_err() || revision < 0 {
                bail!("Invalid WUA identity; applicability unknown");
            }
            let mut issues = Vec::new();
            let title = metadata(update.Title().and_then(text), "Read title", &mut issues);
            let msrc_severity = metadata(
                update.MsrcSeverity().and_then(text),
                "Read MSRC severity",
                &mut issues,
            );
            let downloaded = metadata(update.IsDownloaded(), "Read download state", &mut issues)
                .map(|v| v.0 != 0);
            let eula_accepted =
                metadata(update.EulaAccepted(), "Read EULA acceptance", &mut issues)
                    .map(|v| v.0 != 0);
            let reboot_pending = metadata(
                update.cast::<IUpdate2>().and_then(|v| v.RebootRequired()),
                "Read pending reboot",
                &mut issues,
            )
            .map(|v| v.0 != 0);
            let installation_behavior = metadata(
                update.InstallationBehavior().and_then(|v| {
                    Ok(InstallationBehavior {
                        can_request_user_input: v.CanRequestUserInput()?.0 != 0,
                        impact: v.Impact()?.0,
                        reboot_behavior: v.RebootBehavior()?.0,
                    })
                }),
                "Read installation behavior",
                &mut issues,
            );
            let kb_article_ids =
                match metadata(update.KBArticleIDs(), "Read KB collection", &mut issues) {
                    Some(values) => {
                        let count = bounded_count(checked(values.Count(), "Read KB count")?, 512)?;
                        let mut result = Vec::new();
                        for index in 0..count {
                            if let Some(value) = metadata(
                                values.get_Item(index as i32).and_then(text),
                                "Read KB ID",
                                &mut issues,
                            ) {
                                result.push(value);
                            }
                        }
                        Some(result)
                    }
                    None => None,
                };
            let categories = match metadata(update.Categories(), "Read categories", &mut issues) {
                Some(values) => {
                    let count =
                        bounded_count(checked(values.Count(), "Read category count")?, 256)?;
                    let mut result = Vec::new();
                    for index in 0..count {
                        let value = values.get_Item(index as i32).and_then(|v| {
                            Ok(UpdateCategory {
                                id: text(v.CategoryID()?)?,
                                name: text(v.Name()?)?,
                                kind: text(v.Type()?)?,
                            })
                        });
                        if let Some(value) = metadata(value, "Read category", &mut issues) {
                            result.push(value);
                        }
                    }
                    Some(result)
                }
                None => None,
            };
            Ok(UpdateInfo {
                update_id: id.to_ascii_lowercase(),
                revision,
                title,
                kb_article_ids,
                msrc_severity,
                categories,
                downloaded,
                eula_accepted,
                reboot_pending,
                installation_behavior,
                issues,
            })
        }
    }

    pub fn inspect_cached() -> Result<UpdateReport> {
        inspect(false)
    }

    pub(crate) fn inspect_online() -> Result<UpdateReport> {
        inspect(true)
    }

    fn inspect(online: bool) -> Result<UpdateReport> {
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
            let _apartment = if initialized.is_ok() {
                Apartment(true)
            } else if initialized == RPC_E_CHANGED_MODE {
                Apartment(false)
            } else {
                checked(initialized.ok(), "Initialize COM")?;
                unreachable!()
            };
            let session: IUpdateSession = checked(
                CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER),
                "Create native Windows Update session",
            )?;
            let searcher = checked(session.CreateUpdateSearcher(), "Create update searcher")?;
            checked(
                searcher.SetServerSelection(ssDefault),
                "Select configured default update service",
            )?;
            checked(
                searcher.SetOnline(if online { VARIANT_TRUE } else { VARIANT_FALSE }),
                "Set requested search connectivity",
            )?;
            if checked(searcher.Online(), "Verify requested connectivity")?.as_bool() != online {
                bail!("WUA did not retain requested connectivity; search refused");
            }
            let mut issues = Vec::new();
            let server_selection = metadata(
                searcher.ServerSelection(),
                "Read configured service selection",
                &mut issues,
            )
            .map(|v| v.0);
            let result = checked(
                searcher.Search(&BSTR::from(CRITERIA)),
                "Search update applicability",
            )?;
            let result_code = checked(result.ResultCode(), "Read search result")?.0;
            if result_code != orcSucceeded.0 {
                issues.push(InspectionIssue {
                    operation: "Update search did not fully succeed".into(),
                    hresult: None,
                });
            }
            if let Some(warnings) = metadata(result.Warnings(), "Read search warnings", &mut issues)
            {
                let count = bounded_count(
                    checked(warnings.Count(), "Read warning count")?,
                    MAX_UPDATES,
                )?;
                for index in 0..count {
                    if let Some(warning) =
                        metadata(warnings.get_Item(index as i32), "Read warning", &mut issues)
                    {
                        let hresult =
                            metadata(warning.HResult(), "Read warning HRESULT", &mut issues);
                        issues.push(InspectionIssue {
                            operation: "WUA search warning".into(),
                            hresult,
                        });
                    }
                }
            }
            let values = checked(result.Updates(), "Read search updates")?;
            let reported_count =
                bounded_count(checked(values.Count(), "Read update count")?, MAX_UPDATES)?;
            let mut updates = Vec::new();
            let mut metadata_bytes = 0usize;
            for index in 0..reported_count {
                let update = checked(values.get_Item(index as i32), "Read update entry")?;
                let update = inspect_update(&update)?;
                metadata_bytes = metadata_bytes.saturating_add(update.metadata_bytes());
                if metadata_bytes > MAX_METADATA_BYTES {
                    bail!(
                        "WUA metadata exceeds supported memory bound; applicability unknown (no results truncated)"
                    );
                }
                updates.push(update);
            }
            let updates = deduplicate(updates, &mut issues);
            let complete = issues.is_empty() && updates.iter().all(|v| v.issues.is_empty());
            Ok(UpdateReport {
                complete,
                criteria: CRITERIA.into(),
                scope: if online { ONLINE_SCOPE } else { SCOPE }.into(),
                requested_online: online,
                server_selection,
                result_code,
                reported_count,
                updates,
                issues,
            })
        }
    }

    unsafe fn ready_bundle(update: &IUpdate, depth: usize, remaining: &mut usize) -> Result<()> {
        unsafe {
            if depth > 8 || *remaining == 0 {
                bail!("Update bundle exceeds supported inspection bounds; installation refused");
            }
            *remaining -= 1;
            if !checked(update.IsDownloaded(), "Read bundle download state")?.as_bool()
                || !checked(update.EulaAccepted(), "Read bundle EULA state")?.as_bool()
                || checked(update.CanRequireSource(), "Read bundle source requirement")?.as_bool()
            {
                bail!(
                    "Every bundle must already be downloaded, have its EULA accepted, and require no external source; installation refused"
                );
            }
            let behavior = checked(update.InstallationBehavior(), "Read bundle behavior")?;
            if checked(
                behavior.CanRequestUserInput(),
                "Read bundle interaction requirement",
            )?
            .as_bool()
                || !matches!(checked(behavior.Impact(), "Read bundle impact")?.0, 0..=2)
                || !matches!(
                    checked(behavior.RebootBehavior(), "Read bundle reboot behavior")?.0,
                    0..=2
                )
            {
                bail!(
                    "Bundle interaction or installation behavior is unsupported; installation refused"
                );
            }
            let update2: IUpdate2 = checked(update.cast(), "Read bundle reboot capability")?;
            if checked(update2.RebootRequired(), "Read bundle pending reboot")?.as_bool() {
                bail!("Bundle already requires restart; installation refused");
            }
            let children = checked(update.BundledUpdates(), "Read bundled updates")?;
            let count = bounded_count(checked(children.Count(), "Read bundle count")?, 256)?;
            for index in 0..count {
                ready_bundle(
                    &checked(children.get_Item(index as i32), "Read bundled update")?,
                    depth + 1,
                    remaining,
                )?;
            }
            Ok(())
        }
    }

    /// Internal executor: caller must bind explicit Critical approval to this exact
    /// metadata snapshot. It never accepts EULAs, downloads, elevates, or reboots.
    pub(crate) fn apply_cached(expected: &UpdateInfo) -> Result<String> {
        unsafe {
            let context = crate::recipes::local_client_repair_context()?;
            if !expected.issues.is_empty()
                || expected.downloaded != Some(true)
                || expected.eula_accepted != Some(true)
                || expected.reboot_pending != Some(false)
            {
                bail!(
                    "Approved update metadata is incomplete or not ready for cached installation"
                );
            }
            // Independent full cached refresh first: partial results cannot authorize an install.
            let fresh = inspect_cached()?;
            if !fresh.complete
                || fresh
                    .updates
                    .iter()
                    .find(|v| v.exact_key() == expected.exact_key())
                    != Some(expected)
            {
                bail!(
                    "Cached update metadata changed or applicability is unknown; review a new plan"
                );
            }
            let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
            let _apartment = if initialized.is_ok() {
                Apartment(true)
            } else if initialized == RPC_E_CHANGED_MODE {
                Apartment(false)
            } else {
                checked(initialized.ok(), "Initialize COM")?;
                unreachable!()
            };
            let session: IUpdateSession = checked(
                CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER),
                "Create native update session",
            )?;
            let searcher = checked(session.CreateUpdateSearcher(), "Create update searcher")?;
            checked(
                searcher.SetServerSelection(ssDefault),
                "Select configured default update service",
            )?;
            checked(
                searcher.SetOnline(VARIANT_FALSE),
                "Request cached-only search",
            )?;
            if checked(searcher.Online(), "Verify cached mode")?.as_bool() {
                bail!("Cached mode was not retained; installation refused");
            }
            let result = checked(
                searcher.Search(&BSTR::from(CRITERIA)),
                "Revalidate cached updates",
            )?;
            if checked(result.ResultCode(), "Read revalidation result")? != orcSucceeded
                || checked(
                    checked(result.Warnings(), "Read revalidation warnings")?.Count(),
                    "Read warning count",
                )? != 0
            {
                bail!("Cached revalidation is incomplete; installation refused");
            }
            let updates = checked(result.Updates(), "Read revalidated updates")?;
            let count = bounded_count(
                checked(updates.Count(), "Read revalidated count")?,
                MAX_UPDATES,
            )?;
            let mut selected = None;
            for index in 0..count {
                let update = checked(updates.get_Item(index as i32), "Read revalidated update")?;
                let identity = checked(update.Identity(), "Read revalidated identity")?;
                if checked(identity.UpdateID(), "Read revalidated ID")?
                    .to_string()
                    .eq_ignore_ascii_case(&expected.update_id)
                    && checked(identity.RevisionNumber(), "Read revalidated revision")?
                        == expected.revision
                {
                    if selected.is_some() || inspect_update(&update)? != *expected {
                        bail!(
                            "Selected metadata changed or identity is duplicated; installation refused"
                        );
                    }
                    selected = Some(update);
                }
            }
            let selected = selected.ok_or_else(|| {
                anyhow::anyhow!("Selected update is no longer applicable; review a new plan")
            })?;
            ready_bundle(&selected, 0, &mut 256)?;
            let system: ISystemInformation = checked(
                CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER),
                "Read native servicing state",
            )?;
            if checked(system.RebootRequired(), "Read pending system restart")?.as_bool() {
                bail!("Windows already requires restart; installation refused");
            }
            let installer = checked(session.CreateUpdateInstaller(), "Create update installer")?;
            let quiet: IUpdateInstaller2 =
                checked(installer.cast(), "Require quiet installer support")?;
            checked(
                installer.SetIsForced(VARIANT_FALSE),
                "Disable forced installation",
            )?;
            checked(
                installer.SetAllowSourcePrompts(VARIANT_FALSE),
                "Disable source prompts",
            )?;
            checked(
                quiet.SetForceQuiet(VARIANT_TRUE),
                "Require noninteractive installation",
            )?;
            if checked(installer.IsForced(), "Verify force setting")?.as_bool()
                || checked(installer.AllowSourcePrompts(), "Verify source prompts")?.as_bool()
                || !checked(quiet.ForceQuiet(), "Verify quiet setting")?.as_bool()
            {
                bail!("Installer safety settings were not retained; installation refused");
            }
            let collection: IUpdateCollection = checked(
                CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER),
                "Create selected update collection",
            )?;
            checked(
                collection.Add(&selected),
                "Select exactly one reviewed update",
            )?;
            checked(installer.SetUpdates(&collection), "Set selected update")?;
            if checked(installer.IsBusy(), "Read installer busy state")?.as_bool()
                || checked(
                    installer.RebootRequiredBeforeInstallation(),
                    "Read installer restart prerequisite",
                )?
                .as_bool()
            {
                bail!("Windows servicing is busy or requires restart; installation refused");
            }
            if crate::recipes::local_client_repair_context()? != context {
                bail!("Management context changed; installation refused");
            }
            // From this point errors explicitly disclose that installation may have occurred.
            let outcome = checked(
                installer.Install(),
                "Installation attempted; native completion unverified",
            )?;
            let verification = (|| -> Result<String> {
                let code = checked(outcome.ResultCode(), "Read installation result")?;
                let hresult = checked(outcome.HResult(), "Read installation HRESULT")?;
                let action = checked(outcome.GetUpdateResult(0), "Read selected update result")?;
                let action_code = checked(action.ResultCode(), "Read selected result code")?;
                let action_hresult = checked(action.HResult(), "Read selected HRESULT")?;
                let reboot = checked(outcome.RebootRequired(), "Read installation restart state")?
                    .as_bool()
                    || checked(action.RebootRequired(), "Read selected restart state")?.as_bool()
                    || checked(system.RebootRequired(), "Recheck system restart state")?.as_bool();
                let detail = format!(
                    "{}: result={}, HRESULT=0x{:08X}; selected result={}, HRESULT=0x{:08X}; restart required={reboot}",
                    expected.exact_key(),
                    code.0,
                    hresult as u32,
                    action_code.0,
                    action_hresult as u32
                );
                if code != orcSucceeded
                    || action_code != orcSucceeded
                    || hresult < 0
                    || action_hresult < 0
                {
                    bail!("{detail}; installation did not fully succeed");
                }
                if crate::recipes::local_client_repair_context()? != context {
                    bail!("{detail}; management context changed");
                }
                let post = checked(
                    session.CreateUpdateSearcher(),
                    "Create independent verification searcher",
                )?;
                checked(
                    post.SetServerSelection(ssDefault),
                    "Select verification service",
                )?;
                checked(post.SetOnline(VARIANT_FALSE), "Keep verification offline")?;
                if checked(post.Online(), "Verify offline verification")?.as_bool() {
                    bail!("{detail}; cached verification mode unavailable");
                }
                let criteria = format!(
                    "UpdateID='{}' and RevisionNumber={} and IsInstalled=1",
                    expected.update_id, expected.revision
                );
                let verified = checked(
                    post.Search(&BSTR::from(criteria)),
                    "Refresh selected installed state",
                )?;
                if checked(verified.ResultCode(), "Read verification search result")?
                    != orcSucceeded
                    || checked(
                        checked(verified.Warnings(), "Read verification warnings")?.Count(),
                        "Read verification warning count",
                    )? != 0
                {
                    bail!("{detail}; independent verification incomplete");
                }
                let values = checked(verified.Updates(), "Read verification updates")?;
                if checked(values.Count(), "Read verification count")? != 1 {
                    bail!("{detail}; exact installed-state verification unavailable");
                }
                let installed = checked(values.get_Item(0), "Read verified update")?;
                let identity = checked(installed.Identity(), "Read verified identity")?;
                if !checked(identity.UpdateID(), "Read verified ID")?
                    .to_string()
                    .eq_ignore_ascii_case(&expected.update_id)
                    || checked(identity.RevisionNumber(), "Read verified revision")?
                        != expected.revision
                    || !checked(installed.IsInstalled(), "Read installed state")?.as_bool()
                {
                    bail!("{detail}; exact update is not independently confirmed installed");
                }
                if reboot {
                    bail!(
                        "{detail}; installed state verified, but restart is pending. Stop this batch; no restart was initiated"
                    );
                }
                Ok(format!(
                    "{detail}; exact installed state verified by a separate cached search. No automatic restart. Runtime protection is not proven."
                ))
            })();
            verification.map_err(|error| anyhow::anyhow!("Installation attempted; batch must stop on failure or pending restart. {error}. No automatic rollback."))
        }
    }
}

#[cfg(windows)]
pub(crate) use native::apply_cached;
#[cfg(windows)]
pub use native::inspect_cached;
#[cfg(windows)]
pub(crate) use native::inspect_online;
#[cfg(not(windows))]
pub(crate) fn inspect_online() -> Result<UpdateReport> {
    bail!("Native online Windows Update inspection is unavailable on this platform")
}
#[cfg(not(windows))]
pub(crate) fn apply_cached(_expected: &UpdateInfo) -> Result<String> {
    bail!("Native cached installation is unavailable on this platform")
}
#[cfg(not(windows))]
pub fn inspect_cached() -> Result<UpdateReport> {
    bail!("Native cached Windows Update inspection is unavailable on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item() -> UpdateInfo {
        UpdateInfo {
            update_id: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".into(),
            revision: 1,
            title: Some("Example".into()),
            kb_article_ids: Some(vec![]),
            msrc_severity: Some(String::new()),
            categories: Some(vec![]),
            downloaded: Some(true),
            eula_accepted: Some(true),
            reboot_pending: Some(false),
            installation_behavior: Some(InstallationBehavior {
                can_request_user_input: false,
                impact: 0,
                reboot_behavior: 2,
            }),
            issues: vec![],
        }
    }
    #[test]
    fn bounds_never_truncate() {
        assert!(bounded_count(-1, MAX_UPDATES).is_err());
        assert!(bounded_count(10001, MAX_UPDATES).is_err());
        assert_eq!(bounded_count(10000, MAX_UPDATES).unwrap(), 10000);
    }
    #[test]
    fn identities_include_revision_and_duplicates_conflict() {
        let first = item();
        let mut next = first.clone();
        next.revision = 2;
        assert_ne!(first.exact_key(), next.exact_key());
        let mut issues = vec![];
        assert_eq!(
            deduplicate(vec![first.clone(), first.clone()], &mut issues).len(),
            1
        );
        assert!(issues.is_empty());
        next.revision = 1;
        next.downloaded = Some(false);
        deduplicate(vec![first, next], &mut issues);
        assert_eq!(issues.len(), 1);
    }
    #[test]
    fn cached_success_never_claims_full_coverage_or_offers_repairs() {
        let mut report = UpdateReport {
            complete: true,
            criteria: CRITERIA.into(),
            scope: SCOPE.into(),
            requested_online: false,
            server_selection: Some(0),
            result_code: 2,
            reported_count: 1,
            updates: vec![item()],
            issues: vec![],
        };
        let findings = report.findings();
        assert_eq!(findings[0].status, Status::Unknown);
        assert_eq!(findings[1].status, Status::NeedsAttention);
        assert!(findings.iter().all(|v| v.repair.is_none()));
        report.requested_online = true;
        report.scope = ONLINE_SCOPE.into();
        assert!(report.summary().contains("online search"));
        assert_eq!(report.findings()[0].name, "Windows Update Online");
        assert!(report.findings()[0].evidence.contains("CVE date range"));
        report.complete = false;
        assert!(
            report
                .findings()
                .iter()
                .all(|v| v.status == Status::Unknown)
        );
    }
}
