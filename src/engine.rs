use crate::{
    audit::Audit,
    model::{Finding, InstalledApp, OsProfile, Repair, Risk, Status},
    platform, recipes,
};
use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub os: OsProfile,
    pub apps: Vec<InstalledApp>,
    pub findings: Vec<Finding>,
}

fn probe() -> Vec<Finding> {
    let mut findings = platform::scan_checks();
    findings.extend(recipes::scan_checks());
    findings
}

pub fn scan(audit: &mut Audit) -> Report {
    audit.log("SCAN", "Starting native read-only inspection");
    let os = platform::detect_os();
    audit.log(
        "CHECK",
        format!("Windows edition={} build={}", os.edition, os.build),
    );
    let mut findings = probe();
    let apps = match platform::inventory() {
        Ok(apps) => {
            audit.log(
                "INVENTORY",
                format!("Registered applications: {}", apps.len()),
            );
            apps
        }
        Err(error) => {
            audit.log("WARN", format!("Software inventory unavailable: {error:#}"));
            findings.push(Finding {
                id: "inventory".into(),
                name: "Registered software inventory".into(),
                status: Status::Unknown,
                evidence: format!("{error:#}"),
                source: "Windows registry".into(),
                repair: None,
                change_risk: None,
            });
            vec![]
        }
    };
    findings.push(Finding { id: "advisory-coverage".into(), name: "Known vulnerability coverage".into(), status: Status::Unknown, evidence: "No verified product/version advisory matcher is bundled in this development build. Coverage dates are not established. Registered software inventory does not determine CVE exposure. No model is trained or connected.".into(), source: "Coverage manifest".into(), repair: None, change_risk: None });
    for f in &findings {
        audit.log(
            "RESULT",
            format!("{} status={:?} | {}", f.id, f.status, f.evidence),
        );
    }
    audit.log(
        "DONE",
        format!(
            "checks={} attention={} unknown={} changed=0",
            findings.len(),
            findings
                .iter()
                .filter(|f| f.status == Status::NeedsAttention)
                .count(),
            findings
                .iter()
                .filter(|f| f.status == Status::Unknown)
                .count()
        ),
    );
    Report { os, apps, findings }
}

pub fn scan_with_policy(policy: &crate::policy::Policy, audit: &mut Audit) -> Report {
    let mut report = scan(audit);
    let metadata = match crate::bundle::inspect(policy) {
        Ok(Some(info)) => info,
        Ok(None) if !policy.storage_allowed() => "Embedded-only mode: external catalogs are disabled. Local checks still run.".into(),
        Ok(None) => "No offline advisory data found. Prepare offline data on a connected computer; local checks still run.".into(),
        Err(e) => format!("Offline advisory data is unusable: {e:#}. Local checks still run."),
    };
    audit.log("COVERAGE", &metadata);
    if let Some(f) = report
        .findings
        .iter_mut()
        .find(|f| f.id == "advisory-coverage")
    {
        f.evidence.push(' ');
        f.evidence.push_str(&metadata);
    }
    report
}

/// Explicit native cached-data inspection. It never requests an online search.
pub fn scan_cached_updates(audit: &mut Audit) -> (Vec<Finding>, String) {
    let (_, findings, message) = scan_cached_update_report(audit);
    (findings, message)
}

pub fn scan_cached_update_report(
    audit: &mut Audit,
) -> (Option<crate::updates::UpdateReport>, Vec<Finding>, String) {
    audit.log("CHECK", "Checking applicability against Windows Update Agent's cached metadata; no online search or installation requested");
    match crate::updates::inspect_cached() {
        Ok(report) => {
            let message = report.summary();
            let findings = report.findings();
            for finding in &findings {
                audit.log(
                    "RESULT",
                    format!(
                        "{} status={:?} | {}",
                        finding.id, finding.status, finding.evidence
                    ),
                );
            }
            audit.log("COVERAGE", &message);
            (Some(report), findings, message)
        }
        Err(error) => {
            let message = format!(
                "Cached update applicability unavailable: {error:#}. No online search, download or installation was requested; freshness and missing-update coverage remain unknown."
            );
            audit.log("WARN", &message);
            (
                None,
                vec![Finding {
                    id: "windows-update-coverage".into(),
                    name: "Windows update applicability".into(),
                    status: Status::Unknown,
                    evidence: message.clone(),
                    source: "Windows Update Agent (cached metadata)".into(),
                    repair: None,
                    change_risk: None,
                }],
                message,
            )
        }
    }
}

/// Explicit connected refresh; a second cached query supplies the review snapshot.
pub fn refresh_update_report(
    policy: &crate::policy::Policy,
    audit: &mut Audit,
) -> (Option<crate::updates::UpdateReport>, Vec<Finding>, String) {
    let result = (|| -> Result<()> {
        policy.require_network()?;
        audit.log("NETWORK", "Refreshing applicability from the configured Windows update service. Windows sends applicability information and maintains its own cache; this app requests no update payload download or installation");
        let report = crate::updates::inspect_online()?;
        if !report.complete {
            bail!(
                "Configured update service returned an incomplete applicability result; issues={}",
                report.issues.len()
            );
        }
        audit.log("RESULT", format!("Connected applicability query completed; returned_updates={}. This is not a CVE coverage count", report.updates.len()));
        Ok(())
    })();
    match result {
        Ok(()) => {
            let (report, findings, message) = scan_cached_update_report(audit);
            let message = format!("Configured-service refresh completed. {message}");
            (report, findings, message)
        }
        Err(error) => {
            let message = format!(
                "Update data refresh unavailable: {error:#}. No update installation was requested; use cached checks separately if needed."
            );
            audit.log("WARN", &message);
            (
                None,
                vec![Finding {
                    id: "windows-update-coverage".into(),
                    name: "Windows update data".into(),
                    status: Status::Unknown,
                    evidence: message.clone(),
                    source: crate::updates::SOURCE.into(),
                    repair: None,
                    change_risk: None,
                }],
                message,
            )
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PlannedRepair {
    pub repair: Repair,
    pub name: String,
    pub risk: Risk,
    pub impact: String,
    pub rollback: String,
    pub restart_required: bool,
    pub action: String,
    pub source: String,
    pub before: Finding,
}

/// In-process review snapshot. The digest identifies content; it is not a
/// publisher signature or cryptographic proof that a human approved it.
#[derive(Clone, Debug, Serialize)]
pub struct RepairPlan {
    id: String,
    os: OsProfile,
    entries: Vec<PlannedRepair>,
}
impl RepairPlan {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn entries(&self) -> &[PlannedRepair] {
        &self.entries
    }
    pub fn has_critical(&self) -> bool {
        self.entries.iter().any(|e| e.risk == Risk::Critical)
    }
    fn digest(&self) -> String {
        let bytes = serde_json::to_vec(&(1u32, env!("CARGO_PKG_VERSION"), &self.os, &self.entries))
            .expect("Typed repair plan must serialize");
        format!("{:x}", Sha256::digest(bytes))
    }
    fn validate(&self) -> Result<()> {
        if self.entries.is_empty() || self.id != self.digest() {
            bail!("Repair plan changed or is empty; review a fresh plan");
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct PlanApproval {
    plan_id: String,
    include_critical: bool,
}

pub fn build_plan(repairs: &[Repair], report: &Report) -> Result<RepairPlan> {
    if repairs.is_empty() {
        bail!("Select at least one eligible repair");
    }
    let mut entries = Vec::new();
    for &repair in repairs {
        if entries
            .iter()
            .any(|entry: &PlannedRepair| entry.repair == repair)
        {
            bail!("Duplicate repair in plan: {}", repair.id());
        }
        let Some(before) = report.findings.iter().find(|f| {
            f.id == repair.id() && f.status == Status::NeedsAttention && f.repair == Some(repair)
        }) else {
            bail!(
                "{} is not eligible in this scan; unavailable and unknown checks cannot be forced",
                repair.id()
            );
        };
        entries.push(PlannedRepair {
            repair,
            name: repair.title().into(),
            risk: before
                .change_risk
                .unwrap_or(repair.risk())
                .max(repair.risk()),
            impact: repair.impact().into(),
            rollback: repair.rollback().into(),
            restart_required: repair.restart_required(),
            action: repair.action_description().into(),
            source: repair.source().into(),
            before: before.clone(),
        });
    }
    let mut plan = RepairPlan {
        id: String::new(),
        os: report.os.clone(),
        entries,
    };
    plan.id = plan.digest();
    Ok(plan)
}

/// Called from the UI consent action or explicit CLI approval for this plan.
pub fn approve_plan(plan: &RepairPlan, include_critical: bool) -> Result<PlanApproval> {
    plan.validate()?;
    if plan.has_critical() && !include_critical {
        bail!("This plan contains critical changes; explicitly approve the critical impact first");
    }
    Ok(PlanApproval {
        plan_id: plan.id.clone(),
        include_critical,
    })
}
pub fn execute_plan(
    plan: &RepairPlan,
    approval: &PlanApproval,
    audit: &mut Audit,
) -> Vec<(Repair, std::result::Result<String, String>)> {
    let os = platform::detect_os();
    if os.edition != plan.os.edition
        || os.build != plan.os.build
        || os.is_server != plan.os.is_server
    {
        return rejected(plan, "OS identity changed; review a fresh plan");
    }
    execute_plan_impl(plan, approval, audit, probe, |repair| {
        match repair {
            Repair::EnableDomainFirewall
            | Repair::EnablePrivateFirewall
            | Repair::EnablePublicFirewall => platform::apply_repair(repair),
            _ => recipes::apply_repair(repair),
        }
        .map_err(|e| format!("{e:#}"))
    })
}
fn rejected(plan: &RepairPlan, reason: &str) -> Vec<(Repair, std::result::Result<String, String>)> {
    plan.entries
        .iter()
        .map(|e| (e.repair, Err(reason.to_owned())))
        .collect()
}
fn execute_plan_impl(
    plan: &RepairPlan,
    approval: &PlanApproval,
    audit: &mut Audit,
    mut probe: impl FnMut() -> Vec<Finding>,
    mut apply: impl FnMut(Repair) -> std::result::Result<String, String>,
) -> Vec<(Repair, std::result::Result<String, String>)> {
    if plan.validate().is_err()
        || approval.plan_id != plan.id
        || (plan.has_critical() && !approval.include_critical)
    {
        audit.log(
            "ERROR",
            "Approval does not match the reviewed plan; no changes attempted",
        );
        return rejected(
            plan,
            "Approval does not match this plan; no changes attempted",
        );
    }
    audit.log(
        "CONSENT",
        format!(
            "plan={} actions={} critical_approved={}",
            plan.id,
            plan.entries.len(),
            approval.include_critical
        ),
    );
    let mut results = Vec::new();
    let mut stopped = false;
    for entry in &plan.entries {
        if stopped {
            results.push((
                entry.repair,
                Err("Skipped after earlier failure; review a fresh plan before retrying".into()),
            ));
            continue;
        }
        let current = probe();
        let unchanged = current.iter().any(|f| {
            f.id == entry.before.id
                && f.status == Status::NeedsAttention
                && f.repair == Some(entry.repair)
                && f.evidence == entry.before.evidence
                && f.source == entry.before.source
                && f.name == entry.before.name
                && f.change_risk == entry.before.change_risk
        });
        if !unchanged {
            audit.log(
                "WARN",
                format!(
                    "{} changed since review; no write attempted",
                    entry.repair.id()
                ),
            );
            results.push((
                entry.repair,
                Err(
                    "Current evidence differs from the approved plan; scan and review again".into(),
                ),
            ));
            stopped = true;
            continue;
        }
        audit.log(
            "PLAN",
            format!(
                "{} change_risk={} restart_required={}",
                entry.repair.id(),
                entry.risk.label(),
                entry.restart_required
            ),
        );
        audit.log("RECOVERY", &entry.rollback);
        audit.log(
            "BEFORE",
            format!("{} | {}", entry.repair.id(), entry.before.evidence),
        );
        audit.log(
            "ACTION",
            format!("{} | {}", entry.repair.id(), entry.action),
        );
        let result=apply(entry.repair).and_then(|message| {
            let after=probe();
            if after.iter().any(|f|f.id==entry.repair.id() && f.status==Status::Passed) {
                audit.log("VERIFY",format!("{} configured state read back independently",entry.repair.id()));
                if entry.restart_required {
                    audit.log("RESTART",format!("{} requires restart; effective protection is not yet verified",entry.repair.id()));
                    Ok(format!("{message} Configuration verified; restart required before relying on the changed behavior."))
                } else { Ok(format!("{message} Configuration readback verified; runtime protection was not separately tested.")) }
            } else { Err("Write attempted; fresh configuration probe did not verify success. Check evidence before retrying.".into()) }
        });
        match &result {
            Ok(message) => audit.log("SUCCESS", message),
            Err(error) => {
                audit.log("ERROR", error);
                stopped = true;
            }
        }
        results.push((entry.repair, result));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_mode_blocks_update_refresh_before_native_network_query() {
        let policy = crate::policy::Policy {
            mode: crate::policy::Mode::EmbeddedOnly,
            logging: false,
        };
        let (report, findings, message) =
            refresh_update_report(&policy, &mut Audit::new(false, None).unwrap());
        assert!(report.is_none());
        assert_eq!(findings[0].status, Status::Unknown);
        assert!(message.contains("--noexternal"));
    }
    fn finding(r: Repair, status: Status) -> Finding {
        Finding {
            id: r.id().into(),
            name: r.title().into(),
            status,
            evidence: "value=0".into(),
            source: "native test probe".into(),
            repair: Some(r),
            change_risk: None,
        }
    }
    fn report(findings: Vec<Finding>) -> Report {
        Report {
            os: OsProfile::default(),
            apps: vec![],
            findings,
        }
    }
    fn plan(repairs: &[Repair]) -> RepairPlan {
        build_plan(
            repairs,
            &report(
                repairs
                    .iter()
                    .map(|&r| finding(r, Status::NeedsAttention))
                    .collect(),
            ),
        )
        .unwrap()
    }
    #[test]
    fn unknown_and_duplicate_actions_cannot_form_a_plan() {
        let a = Repair::EnablePrivateFirewall;
        assert!(build_plan(&[a], &report(vec![finding(a, Status::Unknown)])).is_err());
        assert!(build_plan(&[a, a], &report(vec![finding(a, Status::NeedsAttention)])).is_err());
    }
    #[test]
    fn approval_for_a_different_plan_cannot_write() {
        let a = plan(&[Repair::EnablePrivateFirewall]);
        let b = plan(&[Repair::EnablePublicFirewall]);
        let approval = approve_plan(&a, true).unwrap();
        let results = execute_plan_impl(
            &b,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || panic!("must not probe"),
            |_| panic!("must not write"),
        );
        assert!(results[0].1.is_err());
    }
    #[test]
    fn changed_evidence_after_review_cannot_write() {
        let a = Repair::EnablePrivateFirewall;
        let p = plan(&[a]);
        let approval = approve_plan(&p, true).unwrap();
        let results = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || {
                let mut f = finding(a, Status::NeedsAttention);
                f.evidence = "different state".into();
                vec![f]
            },
            |_| panic!("must not write"),
        );
        assert!(results[0].1.is_err());
    }
    #[test]
    fn failed_action_stops_later_writes() {
        let a = Repair::EnablePrivateFirewall;
        let b = Repair::EnablePublicFirewall;
        let p = plan(&[a, b]);
        let approval = approve_plan(&p, true).unwrap();
        let mut writes = 0;
        let result = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || {
                vec![
                    finding(a, Status::NeedsAttention),
                    finding(b, Status::NeedsAttention),
                ]
            },
            |_| {
                writes += 1;
                Err("denied".into())
            },
        );
        assert_eq!(writes, 1);
        assert!(result.iter().all(|(_, r)| r.is_err()));
    }
    #[test]
    fn successful_write_requires_fresh_verification() {
        let a = Repair::EnablePrivateFirewall;
        let p = plan(&[a]);
        let approval = approve_plan(&p, true).unwrap();
        let result = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || vec![finding(a, Status::NeedsAttention)],
            |_| Ok("accepted".into()),
        );
        assert!(result[0].1.is_err());
    }
    #[test]
    fn critical_plan_has_a_real_explicit_approval_path() {
        let a = Repair::RequireRdpNla;
        let p = plan(&[a]);
        assert!(approve_plan(&p, false).is_err());
        let approval = approve_plan(&p, true).unwrap();
        let mut reads = 0;
        let result = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || {
                reads += 1;
                vec![finding(
                    a,
                    if reads == 1 {
                        Status::NeedsAttention
                    } else {
                        Status::Passed
                    },
                )]
            },
            |_| Ok("configured".into()),
        );
        assert!(result[0].1.is_ok());
        assert_eq!(reads, 2);
    }
    #[test]
    fn editing_a_review_snapshot_invalidates_its_approval() {
        let mut p = plan(&[Repair::EnablePrivateFirewall]);
        let approval = approve_plan(&p, true).unwrap();
        p.entries[0].impact = "different effect".into();
        let result = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || panic!("no probe"),
            |_| panic!("no write"),
        );
        assert!(result[0].1.is_err());
    }
    #[test]
    fn local_policy_override_requires_critical_acknowledgment() {
        let action = Repair::UacSecureDesktop;
        let mut current = finding(action, Status::NeedsAttention);
        current.change_risk = Some(Risk::Critical);
        let p = build_plan(&[action], &report(vec![current])).unwrap();
        assert!(p.has_critical());
        assert_eq!(p.entries()[0].risk, Risk::Critical);
        assert!(approve_plan(&p, false).is_err());
        assert!(approve_plan(&p, true).is_ok());
    }
    #[test]
    fn new_contextual_risk_cannot_reuse_old_approval() {
        let action = Repair::UacSecureDesktop;
        let p = plan(&[action]);
        let approval = approve_plan(&p, false).unwrap();
        let results = execute_plan_impl(
            &p,
            &approval,
            &mut Audit::new(false, None).unwrap(),
            || {
                let mut f = finding(action, Status::NeedsAttention);
                f.change_risk = Some(Risk::Critical);
                vec![f]
            },
            |_| panic!("must not write under a changed policy context"),
        );
        assert!(results[0].1.is_err());
    }
}
