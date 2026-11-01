#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use amigood::{
    audit::Audit,
    bundle,
    cli::{HELP, Options},
    engine,
    model::{Repair, Status},
    platform,
    policy::{Mode, Policy},
};
use anyhow::{Context, Result, bail};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<()> {
    // The GUI does not open an extra console. CLI invocations can reuse their
    // existing terminal; redirected output handles remain inherited.
    #[cfg(all(windows, feature = "gui"))]
    if std::env::args_os().len() > 1 {
        use windows::Win32::System::Console::{
            ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let output_missing = GetStdHandle(STD_OUTPUT_HANDLE)
                .map(|h| h.is_invalid())
                .unwrap_or(true);
            if output_missing {
                let _ = AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }
    }
    // Parse all user input before resolving paths or creating an audit log.
    let options = Options::parse(std::env::args().skip(1))?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }

    let policy = Policy {
        mode: if options.noexternal {
            Mode::EmbeddedOnly
        } else {
            Mode::Portable
        },
        logging: !options.no_log,
    };
    let audit_path = if options.no_log || options.noexternal {
        None
    } else {
        Some(default_log_path()?)
    };
    let mut audit = Audit::new(policy.logging, audit_path)
        .context("Initialize audit logging; retry with --no-log to disable logging")?;

    if options.airgapready {
        let message = bundle::prepare(&policy, &mut audit)?;
        println!("{message}");
        return Ok(());
    }

    let os = platform::detect_os();
    let server_core_fallback = os.is_server && !os.has_desktop;
    let headless = options.scan || options.fix.is_some() || server_core_fallback;

    if !headless {
        #[cfg(feature = "gui")]
        {
            return amigood::gui::run(policy, audit, options.lowgraphics);
        }
        #[cfg(not(feature = "gui"))]
        {
            bail!("This build has no graphical interface; run with --scan for a headless check");
        }
    }

    if options.noexternal {
        println!(
            "Noexternal mode: network, helper processes, sidecars, and app-owned persistent files are disabled. Audit events remain in memory unless --no-log is also set."
        );
    }
    println!(
        "Scope: Windows Firewall local policy, registered desktop-software inventory, and advisory-data availability. No CVE affected-version matcher is present; results do not establish complete vulnerability coverage."
    );

    let report = engine::scan_with_policy(&policy, &mut audit);
    println!("{}", serde_json::to_string_pretty(&report)?);

    if let Some(repairs) = options.fix.as_deref() {
        ensure_fresh_candidates(repairs, &report.findings)?;
        println!("\nCombined repair review — explicit --approve was supplied for this exact set:");
        for repair in repairs {
            println!("- {}: {}", repair.id(), repair.impact());
        }
        println!(
            "Actions will run in order; a failed action stops later actions. Each selected action requires a fresh eligibility check and post-change local verification. Remote access and service availability are not tested."
        );

        audit.log(
            "CONSENT",
            format!(
                "User supplied explicit --approve for {}",
                repairs
                    .iter()
                    .map(|repair| repair.id())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
        let results = engine::repair_batch(repairs, &mut audit);
        let mut failed = false;
        for (repair, result) in results {
            match result {
                Ok(message) => println!("{}: {message}", repair.id()),
                Err(error) => {
                    eprintln!("{}: not verified: {error}", repair.id());
                    failed = true;
                }
            }
        }
        if failed {
            bail!(
                "One or more selected actions failed or were not verified; scan again before retrying"
            );
        }
    }

    Ok(())
}

fn ensure_fresh_candidates(repairs: &[Repair], findings: &[amigood::model::Finding]) -> Result<()> {
    for repair in repairs {
        let eligible = findings.iter().any(|finding| {
            finding.status == Status::NeedsAttention && finding.repair == Some(*repair)
        });
        if !eligible {
            bail!(
                "Repair {} is not an eligible NeedsAttention result in the fresh scan; no repairs were run",
                repair.id()
            );
        }
    }
    Ok(())
}

fn default_log_path() -> Result<PathBuf> {
    let parent = amigood::policy::portable_directory(&["Data", "logs"])?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_millis();
    Ok(parent.join(format!("{timestamp}-{}.jsonl", std::process::id())))
}
