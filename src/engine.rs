use crate::{
    audit::Audit,
    model::{Finding, InstalledApp, OsProfile, Repair, Status},
    platform,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub os: OsProfile,
    pub apps: Vec<InstalledApp>,
    pub findings: Vec<Finding>,
}

pub fn scan_with_policy(policy: &crate::policy::Policy, audit: &mut Audit) -> Report {
    let mut report = scan(audit);
    let metadata = match crate::bundle::inspect(policy) {
        Ok(Some(info)) => info,
        Ok(None) if !policy.storage_allowed() => "Embedded-only mode: external catalogs are disabled. Local policy checks still run.".into(),
        Ok(None) => "No offline advisory data found. Prepare offline data on a connected computer; local policy checks still run.".into(),
        Err(e) => format!("Offline advisory data is unusable: {e:#}. Local policy checks still run."),
    };
    audit.log("COVERAGE", &metadata);
    if let Some(finding) = report
        .findings
        .iter_mut()
        .find(|f| f.id == "advisory-coverage")
    {
        finding.evidence.push(' ');
        finding.evidence.push_str(&metadata);
    }
    report
}

pub fn scan(audit: &mut Audit) -> Report {
    audit.log("SCAN", "Starting native read-only inspection");
    let os = platform::detect_os();
    audit.log(
        "CHECK",
        format!("Windows edition={} build={}", os.edition, os.build),
    );
    let mut findings = platform::scan_checks();
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
            });
            vec![]
        }
    };
    findings.push(Finding { id: "advisory-coverage".into(), name: "Known vulnerability coverage".into(), status: Status::Unknown, evidence: "No verified product/version advisory matcher is bundled in this development build. Coverage dates are not established. Registered software inventory does not determine CVE exposure. No model is trained or connected.".into(), source: "Coverage manifest".into(), repair: None });
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

fn eligible(repair: Repair, findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.status == Status::NeedsAttention && f.repair == Some(repair))
}

/// The caller must first present and obtain approval for all exact selected repairs.
/// Actions run sequentially; failures stop later actions and preserve separate results.
pub fn repair_batch(
    repairs: &[Repair],
    audit: &mut Audit,
) -> Vec<(Repair, Result<String, String>)> {
    repair_batch_impl(repairs, audit, platform::scan_checks, |repair| {
        platform::apply_repair(repair).map_err(|e| format!("{e:#}"))
    })
}

fn repair_batch_impl(
    repairs: &[Repair],
    audit: &mut Audit,
    mut probe: impl FnMut() -> Vec<Finding>,
    mut apply: impl FnMut(Repair) -> Result<String, String>,
) -> Vec<(Repair, Result<String, String>)> {
    let mut results = Vec::new();
    let mut seen = Vec::new();
    let mut stopped = false;
    audit.log(
        "PLAN",
        format!("Approved batch: {} selected actions", repairs.len()),
    );
    for &repair in repairs {
        if seen.contains(&repair) {
            continue;
        }
        seen.push(repair);
        if stopped {
            results.push((
                repair,
                Err("Skipped after earlier repair failure; scan again before retrying".into()),
            ));
            continue;
        }
        // Recheck eligibility immediately before each write, never trust stale UI data.
        if !eligible(repair, &probe()) {
            audit.log(
                "WARN",
                format!("{} no longer eligible; no change made", repair.id()),
            );
            results.push((
                repair,
                Err("Repair is no longer eligible; scan again".into()),
            ));
            stopped = true;
            continue;
        }
        audit.log(
            "ACTION",
            format!(
                "INetFwPolicy2::put_FirewallEnabled profile={} enabled=true",
                repair.id()
            ),
        );
        let result = apply(repair);
        let result = result.and_then(|message| {
            let recheck = probe();
            if recheck
                .iter()
                .any(|f| f.id == repair.id() && f.status == Status::Passed)
            {
                audit.log(
                    "VERIFY",
                    format!("{} fresh probe status=Passed", repair.id()),
                );
                Ok(message)
            } else {
                Err("Write attempted; independent local policy probe did not verify success".into())
            }
        });
        match &result {
            Ok(message) => audit.log("SUCCESS", message),
            Err(error) => {
                audit.log("ERROR", error);
                stopped = true;
            }
        }
        results.push((repair, result));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding(repair: Repair, status: Status) -> Finding {
        Finding {
            id: repair.id().into(),
            name: "test".into(),
            status,
            evidence: String::new(),
            source: String::new(),
            repair: Some(repair),
        }
    }
    #[test]
    fn failed_action_stops_remaining_writes() {
        let a = Repair::EnablePrivateFirewall;
        let b = Repair::EnablePublicFirewall;
        let mut calls = 0;
        let results = repair_batch_impl(
            &[a, b],
            &mut Audit::new(false, None).unwrap(),
            || {
                vec![
                    finding(a, Status::NeedsAttention),
                    finding(b, Status::NeedsAttention),
                ]
            },
            |_| {
                calls += 1;
                Err("denied".into())
            },
        );
        assert_eq!(calls, 1);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, r)| r.is_err()));
    }
    #[test]
    fn successful_write_without_fresh_verification_is_not_success() {
        let action = Repair::EnablePrivateFirewall;
        let results = repair_batch_impl(
            &[action],
            &mut Audit::new(false, None).unwrap(),
            || vec![finding(action, Status::NeedsAttention)],
            |_| Ok("write accepted".into()),
        );
        assert!(
            results[0]
                .1
                .as_ref()
                .unwrap_err()
                .contains("did not verify")
        );
    }
    #[test]
    fn duplicate_actions_are_applied_once_and_verified_separately() {
        let action = Repair::EnablePrivateFirewall;
        let mut reads = 0;
        let mut writes = 0;
        let results = repair_batch_impl(
            &[action, action],
            &mut Audit::new(false, None).unwrap(),
            || {
                reads += 1;
                vec![finding(
                    action,
                    if reads == 1 {
                        Status::NeedsAttention
                    } else {
                        Status::Passed
                    },
                )]
            },
            |_| {
                writes += 1;
                Ok("changed".into())
            },
        );
        assert_eq!((reads, writes, results.len()), (2, 1, 1));
        assert!(results[0].1.is_ok());
    }
    #[test]
    fn stale_or_unknown_findings_cannot_authorize_repairs() {
        let mut finding = Finding {
            id: "firewall-private".into(),
            name: "test".into(),
            status: Status::Unknown,
            evidence: String::new(),
            source: String::new(),
            repair: Some(Repair::EnablePrivateFirewall),
        };
        assert!(!eligible(Repair::EnablePrivateFirewall, &[finding.clone()]));
        finding.status = Status::NeedsAttention;
        assert!(eligible(Repair::EnablePrivateFirewall, &[finding.clone()]));
        assert!(!eligible(Repair::EnablePublicFirewall, &[finding]));
    }
}
