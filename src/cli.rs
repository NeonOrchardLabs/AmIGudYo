use anyhow::{Result, bail};

use crate::model::Repair;

pub const HELP: &str = "AmIGudYo security scanner (design name provisional)\n\
Usage: amigood [OPTIONS]\n\
\n\
  --help              Show this help.\n\
  --scan              Run supported local checks without opening the GUI.\n\
  --noexternal        Use embedded resources only; no network, helper processes,\n\
                      sidecars, or app-owned persistent files. Logs stay in memory.\n\
  --airgapready       Prepare offline-use data while connected. Cannot be combined\n\
                      with --noexternal. Preparation does not guarantee every repair\n\
                      is available offline.\n\
  --no-log            Disable all audit logging for this run.\n\
  --lowgraphics       Use the low-graphics interface.\n\
  --fix ID[,ID...]    Select built-in repairs, for example firewall-private.\n\
  --approve           Explicitly approve exactly the --fix set; required with --fix.\n\
  --approve-critical  Also approve critical changes in that exact batch.\n\
  --plan ID[,ID...]    Preview an eligible repair plan without changing settings.\n\
  --plan-id SHA256     Require --fix to match a previously reviewed plan ID.\n\
  --catalog           List all implemented repair actions and risk levels.\n\
\n\
Checks include local firewall, UAC, installer, SMB guest and RDP policy,\n\
registered desktop-software inventory, and advisory-data availability. There is\n\
no CVE affected-version matcher; this is not an all-CVE scanner or a complete\n\
security guarantee. Firewall changes can interrupt remote management or services;\n\
administrator permission may be required.\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub help: bool,
    pub scan: bool,
    pub noexternal: bool,
    pub no_log: bool,
    pub lowgraphics: bool,
    pub airgapready: bool,
    pub fix: Option<Vec<Repair>>,
    pub approve: bool,
    pub approve_critical: bool,
    pub plan: Option<Vec<Repair>>,
    pub plan_id: Option<String>,
    pub catalog: bool,
}

impl Options {
    /// Parse command-line arguments, excluding argv[0]. This function performs no I/O.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut options = Self {
            help: false,
            scan: false,
            noexternal: false,
            no_log: false,
            lowgraphics: false,
            airgapready: false,
            fix: None,
            approve: false,
            approve_critical: false,
            plan: None,
            plan_id: None,
            catalog: false,
        };

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => options.help = true,
                "--scan" => options.scan = true,
                "--noexternal" => options.noexternal = true,
                "--no-log" => options.no_log = true,
                "--lowgraphics" => options.lowgraphics = true,
                "--airgapready" => options.airgapready = true,
                "--approve" => options.approve = true,
                "--approve-critical" => options.approve_critical = true,
                "--catalog" => options.catalog = true,
                "--plan" => {
                    if options.plan.is_some() {
                        bail!("--plan may be specified only once");
                    }
                    let ids = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--plan requires repair IDs"))?;
                    options.plan = Some(parse_repairs(&ids)?);
                }
                "--plan-id" => {
                    if options.plan_id.is_some() {
                        bail!("--plan-id may be specified only once");
                    }
                    let id = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--plan-id requires a SHA-256 ID"))?;
                    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                        bail!("--plan-id requires a 64-character hexadecimal ID");
                    }
                    options.plan_id = Some(id.to_ascii_lowercase());
                }
                "--fix" => {
                    if options.fix.is_some() {
                        bail!(
                            "--fix may be specified only once; list repairs as comma-separated IDs"
                        );
                    }
                    let ids = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--fix requires one or more repair IDs"))?;
                    options.fix = Some(parse_repairs(&ids)?);
                }
                _ if arg.starts_with('-') => bail!("Unknown option: {arg}"),
                _ => bail!("Unexpected positional argument: {arg}"),
            }
        }

        if options.noexternal && options.airgapready {
            bail!(
                "--noexternal and --airgapready are incompatible: offline preparation requires network and storage"
            );
        }
        if options.airgapready
            && (options.scan || options.fix.is_some() || options.plan.is_some() || options.catalog)
        {
            bail!(
                "--airgapready is a preparation-only operation and cannot be combined with --scan or --fix"
            );
        }
        if options.plan.is_some() && options.fix.is_some() {
            bail!("Choose --plan preview or --fix, not both");
        }
        if options.catalog && (options.scan || options.plan.is_some() || options.fix.is_some()) {
            bail!("--catalog is a listing-only operation");
        }
        if options.approve_critical && (!options.approve || options.fix.is_none()) {
            bail!("--approve-critical requires --fix and --approve");
        }
        if options.plan_id.is_some() && options.fix.is_none() {
            bail!("--plan-id requires --fix");
        }
        match (&options.fix, options.approve) {
            (Some(_), false) => bail!("--fix requires explicit --approve; no repair was run"),
            (None, true) => bail!("--approve requires --fix; no repair was run"),
            _ => {}
        }
        if options.fix.is_some() || options.plan.is_some() {
            // A repair is always gated by a fresh scan in main, regardless of --scan.
            options.scan = true;
        }

        Ok(options)
    }
}

fn parse_repairs(ids: &str) -> Result<Vec<Repair>> {
    if ids.trim().is_empty() {
        bail!("--fix requires one or more repair IDs");
    }

    let mut repairs = Vec::new();
    for raw_id in ids.split(',') {
        let id = raw_id.trim();
        if id.is_empty() {
            bail!("--fix contains an empty repair ID");
        }
        let repair =
            Repair::from_id(id).ok_or_else(|| anyhow::anyhow!("Unknown repair ID: {id}"))?;
        if repairs.contains(&repair) {
            bail!("--fix lists repair ID more than once: {id}");
        }
        repairs.push(repair);
    }
    Ok(repairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options> {
        Options::parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn parses_safe_modes_and_approved_repair_batch() {
        let options = parse(&[
            "--noexternal",
            "--no-log",
            "--lowgraphics",
            "--fix",
            "firewall-private,firewall-public",
            "--approve",
        ])
        .unwrap();

        assert!(options.noexternal);
        assert!(options.no_log);
        assert!(options.lowgraphics);
        assert!(options.scan);
        assert_eq!(
            options.fix,
            Some(vec![
                Repair::EnablePrivateFirewall,
                Repair::EnablePublicFirewall
            ])
        );
        assert!(options.approve);
    }

    #[test]
    fn rejects_conflicts_and_missing_explicit_approval() {
        assert!(parse(&["--noexternal", "--airgapready"]).is_err());
        assert!(parse(&["--airgapready", "--scan"]).is_err());
        assert!(parse(&["--airgapready", "--fix", "firewall-private", "--approve"]).is_err());
        assert!(parse(&["--fix", "firewall-private"]).is_err());
        assert!(parse(&["--approve"]).is_err());
    }

    #[test]
    fn rejects_unknown_or_duplicate_repairs_and_flags() {
        assert!(parse(&["--fix", "firewall-private,firewall-private", "--approve"]).is_err());
        assert!(parse(&["--fix", "not-a-repair", "--approve"]).is_err());
        assert!(parse(&["--fix", "firewall-private", "--approve", "--unknown"]).is_err());
        assert!(parse(&["input.txt"]).is_err());
    }

    #[test]
    fn help_and_scan_parse_without_side_effect_options() {
        let options = parse(&["--help", "--scan"]).unwrap();
        assert!(options.help);
        assert!(options.scan);
        assert!(!options.noexternal);
        assert!(HELP.contains("no CVE affected-version matcher"));
    }
    #[test]
    fn preview_and_catalog_do_not_authorize_execution() {
        let preview = parse(&["--plan", "rdp-require-nla"]).unwrap();
        assert!(
            preview.scan && preview.plan.is_some() && preview.fix.is_none() && !preview.approve
        );
        let catalog = parse(&["--catalog"]).unwrap();
        assert!(catalog.catalog && !catalog.scan && !catalog.approve);
        assert!(parse(&["--plan", "rdp-require-nla", "--approve"]).is_err());
        assert!(parse(&["--catalog", "--scan"]).is_err());
        assert!(parse(&["--plan-id", "bad"]).is_err());
    }
    #[test]
    fn critical_approval_requires_a_named_approved_fix_set() {
        assert!(parse(&["--approve-critical"]).is_err());
        assert!(parse(&["--fix", "rdp-require-nla", "--approve-critical"]).is_err());
        let options = parse(&[
            "--fix",
            "rdp-require-nla",
            "--approve",
            "--approve-critical",
        ])
        .unwrap();
        assert!(options.approve_critical && options.approve && options.fix.is_some());
        assert!(
            parse(&[
                "--plan",
                "rdp-require-nla",
                "--fix",
                "rdp-require-nla",
                "--approve"
            ])
            .is_err()
        );
    }
}
