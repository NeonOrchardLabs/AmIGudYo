//! Approval-bound execution of exact cached Windows Update identities.
use crate::{
    audit::Audit,
    model::OsProfile,
    platform,
    updates::{self, UpdateInfo, UpdateReport},
};
use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const IMPACT: &str = "Critical change: installs only the selected Windows Update identities/revisions from content already downloaded by Windows. Publisher-defined bundled components may be included. Applications, services and remote access can be interrupted. A restart may be required. Metadata freshness and full vulnerability coverage remain unknown. No download, automatic license acceptance or automatic restart is authorized.";
pub const RECOVERY: &str = "No automatic rollback. Some updates cannot be uninstalled. Recovery may require Windows recovery tools or a previously prepared system image; the app does not create one. Review the publisher's update notes before approving.";

#[derive(Clone, Debug, Serialize)]
pub struct UpdatePlan {
    id: String,
    os: OsProfile,
    updates: Vec<UpdateInfo>,
    impact: String,
    recovery: String,
}
impl UpdatePlan {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn updates(&self) -> &[UpdateInfo] {
        &self.updates
    }
    pub fn impact(&self) -> &str {
        &self.impact
    }
    pub fn recovery(&self) -> &str {
        &self.recovery
    }
    fn digest(&self) -> String {
        let bytes = serde_json::to_vec(&(
            1u32,
            env!("CARGO_PKG_VERSION"),
            &self.os,
            &self.updates,
            &self.impact,
            &self.recovery,
        ))
        .expect("Typed update plan serializes");
        format!("{:x}", Sha256::digest(bytes))
    }
    fn validate(&self) -> Result<()> {
        if self.updates.is_empty() || self.id != self.digest() {
            bail!("Update plan changed or is empty; review again");
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct UpdateApproval {
    id: String,
}

/// Conservative metadata eligibility; the native executor separately checks every bundle.
pub fn eligible(update: &UpdateInfo) -> bool {
    valid_key(&update.exact_key())
        && update.issues.is_empty()
        && update
            .title
            .as_ref()
            .is_some_and(|title| !title.trim().is_empty())
        && update.downloaded == Some(true)
        && update.eula_accepted == Some(true)
        && update.reboot_pending == Some(false)
        && update
            .installation_behavior
            .as_ref()
            .is_some_and(|behavior| {
                !behavior.can_request_user_input
                    && (0..=2).contains(&behavior.impact)
                    && (0..=2).contains(&behavior.reboot_behavior)
            })
}

pub fn valid_key(key: &str) -> bool {
    let Some((id, revision)) = key.split_once('@') else {
        return false;
    };
    if id.len() != 36
        || revision.is_empty()
        || !revision.bytes().all(|b| b.is_ascii_digit())
        || revision.parse::<i32>().is_err()
    {
        return false;
    }
    id.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

pub fn build_plan(report: &UpdateReport, keys: &[String], os: &OsProfile) -> Result<UpdatePlan> {
    if !report.complete
        || report.requested_online
        || report.criteria != updates::CRITERIA
        || report.server_selection != Some(0)
        || report.result_code != 2
        || !report.issues.is_empty()
    {
        bail!("A complete cached applicability query in the configured source scope is required");
    }
    if os.is_server || os.build.is_empty() || os.edition == "Unknown" {
        bail!("Update installation requires a verified Windows client; this target is status-only");
    }
    if keys.is_empty() {
        bail!("Select at least one exact update identity@revision");
    }
    let mut selected = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in keys {
        if !valid_key(key) || !seen.insert(key.to_ascii_lowercase()) {
            bail!("Invalid or duplicate exact update identity@revision");
        }
        let matches: Vec<_> = report
            .updates
            .iter()
            .filter(|update| update.exact_key().eq_ignore_ascii_case(key))
            .collect();
        if matches.len() != 1 || !eligible(matches[0]) {
            bail!(
                "Selected update is not eligible: exact identity, complete metadata, cached content, prior license acceptance and noninteractive behavior are required"
            );
        }
        selected.push(matches[0].clone());
    }
    let mut plan = UpdatePlan {
        id: String::new(),
        os: os.clone(),
        updates: selected,
        impact: IMPACT.into(),
        recovery: RECOVERY.into(),
    };
    plan.id = plan.digest();
    Ok(plan)
}

pub fn approve_plan(plan: &UpdatePlan, approve_critical: bool) -> Result<UpdateApproval> {
    plan.validate()?;
    if !approve_critical {
        bail!("Explicit critical approval is required for this exact update plan");
    }
    Ok(UpdateApproval {
        id: plan.id.clone(),
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateOutcome {
    pub key: String,
    pub verified: bool,
    pub message: String,
}

pub fn execute_plan(
    plan: &UpdatePlan,
    approval: &UpdateApproval,
    policy: &crate::policy::Policy,
    audit: &mut Audit,
) -> Vec<UpdateOutcome> {
    if !policy.storage_allowed() {
        audit.log(
            "WARN",
            "--noexternal refuses nonembedded update payload installation; no install attempted",
        );
        return rejected(
            plan,
            "--noexternal cannot install nonembedded Windows Update payloads; embedded configuration repairs remain available",
        );
    }
    let current = platform::detect_os();
    if current.edition != plan.os.edition
        || current.build != plan.os.build
        || current.is_server != plan.os.is_server
    {
        return rejected(plan, "OS identity changed; review again");
    }
    execute_impl(plan, approval, audit, |expected| {
        updates::apply_cached(expected).map_err(|error| format!("{error:#}"))
    })
}
fn rejected(plan: &UpdatePlan, message: &str) -> Vec<UpdateOutcome> {
    plan.updates
        .iter()
        .map(|update| UpdateOutcome {
            key: update.exact_key(),
            verified: false,
            message: message.into(),
        })
        .collect()
}
fn execute_impl(
    plan: &UpdatePlan,
    approval: &UpdateApproval,
    audit: &mut Audit,
    mut apply: impl FnMut(&UpdateInfo) -> std::result::Result<String, String>,
) -> Vec<UpdateOutcome> {
    if plan.validate().is_err() || approval.id != plan.id {
        audit.log(
            "ERROR",
            "Update approval does not match the reviewed snapshot; no install attempted",
        );
        return rejected(plan, "Update approval does not match this reviewed plan");
    }
    audit.log(
        "CONSENT",
        format!(
            "Windows update plan={} critical_approved=true actions={}",
            plan.id,
            plan.updates.len()
        ),
    );
    audit.log("PLAN", &plan.impact);
    audit.log("RECOVERY", &plan.recovery);
    let mut stopped = false;
    plan.updates.iter().map(|update| {
        let key = update.exact_key();
        if stopped { return UpdateOutcome {key, verified:false, message:"Skipped after earlier failure; review a fresh plan".into()}; }
        audit.log("BEFORE", serde_json::to_string(update).expect("Typed update metadata serializes"));
        audit.log("ACTION", format!("Install exact cached Windows Update {key}; no download, license acceptance or restart authorized"));
        match apply(update) {
            Ok(message) => { audit.log("VERIFY", &message); UpdateOutcome {key,verified:true,message} }
            Err(message) => { stopped=true; audit.log("ERROR", &message); UpdateOutcome {key,verified:false,message} }
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updates::InstallationBehavior;
    fn update() -> UpdateInfo {
        UpdateInfo {
            update_id: "00000000-0000-0000-0000-000000000001".into(),
            revision: 1,
            title: Some("Fixture security update".into()),
            kb_article_ids: Some(vec!["000001".into()]),
            msrc_severity: Some("Important".into()),
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
    fn report() -> UpdateReport {
        UpdateReport {
            complete: true,
            criteria: updates::CRITERIA.into(),
            scope: updates::SCOPE.into(),
            requested_online: false,
            server_selection: Some(0),
            result_code: 2,
            reported_count: 1,
            updates: vec![update()],
            issues: vec![],
        }
    }
    fn os() -> OsProfile {
        OsProfile {
            edition: "Professional".into(),
            build: "test-build".into(),
            ..Default::default()
        }
    }
    fn plan() -> UpdatePlan {
        build_plan(&report(), &[update().exact_key()], &os()).unwrap()
    }
    #[test]
    fn unknown_incomplete_and_uncached_updates_cannot_be_planned() {
        let mut candidate = report();
        candidate.complete = false;
        assert!(build_plan(&candidate, &[update().exact_key()], &os()).is_err());
        let mut candidate = report();
        candidate.updates[0].downloaded = Some(false);
        assert!(build_plan(&candidate, &[update().exact_key()], &os()).is_err());
        let mut value = update();
        value.eula_accepted = None;
        assert!(!eligible(&value));
        value = update();
        value.installation_behavior.as_mut().unwrap().impact = 2;
        assert!(
            eligible(&value),
            "Exclusive updates are installed one at a time"
        );
        value = update();
        value
            .installation_behavior
            .as_mut()
            .unwrap()
            .can_request_user_input = true;
        assert!(!eligible(&value));
        assert!(!valid_key(
            "00000000-0000-0000-0000-000000000001@1 or IsInstalled=1"
        ));
        assert!(
            build_plan(
                &report(),
                &[update().exact_key(), update().exact_key()],
                &os()
            )
            .is_err()
        );
    }
    #[test]
    fn exact_critical_approval_and_snapshot_are_required_before_native_install() {
        let mut plan = plan();
        assert!(approve_plan(&plan, false).is_err());
        let approval = approve_plan(&plan, true).unwrap();
        plan.updates[0].revision += 1;
        let results = execute_impl(
            &plan,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            |_| panic!("must not install"),
        );
        assert!(!results[0].verified);
    }
    #[test]
    fn failure_stops_the_remaining_update_batch() {
        let mut report = report();
        let mut other = update();
        other.update_id = "00000000-0000-0000-0000-000000000002".into();
        report.updates.push(other);
        let keys = report
            .updates
            .iter()
            .map(UpdateInfo::exact_key)
            .collect::<Vec<_>>();
        let plan = build_plan(&report, &keys, &os()).unwrap();
        let approval = approve_plan(&plan, true).unwrap();
        let mut calls = 0;
        let results = execute_impl(
            &plan,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            |_| {
                calls += 1;
                Err("fixture failure".into())
            },
        );
        assert_eq!(calls, 1);
        assert!(results.iter().all(|result| !result.verified));
    }
    #[test]
    fn embedded_mode_refuses_payload_execution_before_os_or_installer_access() {
        let plan = plan();
        let approval = approve_plan(&plan, true).unwrap();
        let policy = crate::policy::Policy {
            mode: crate::policy::Mode::EmbeddedOnly,
            logging: false,
        };
        let result = execute_plan(
            &plan,
            &approval,
            &policy,
            &mut Audit::new(false, None).unwrap(),
        );
        assert!(!result[0].verified);
        assert!(result[0].message.contains("--noexternal"));
    }
}
