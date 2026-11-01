#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use amigood::{
    audit::Audit,
    bundle,
    cli::{HELP, Options},
    engine,
    model::Repair,
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
    if options.catalog {
        let catalog: Vec<_> = Repair::all().iter().map(|r|serde_json::json!({"id":r.id(),"name":r.title(),"risk":r.risk(),"action":r.action_description(),"impact":r.impact(),"recovery":r.rollback(),"restart_required":r.restart_required(),"source":r.source()})).collect();
        println!("{}", serde_json::to_string_pretty(&catalog)?);
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
    let os = platform::detect_os();
    let server_core_fallback = os.is_server && !os.has_desktop;
    let headless = options.scan || options.fix.is_some() || server_core_fallback;
    let audit_path = if options.no_log || options.noexternal {
        None
    } else {
        Some(default_log_path()?)
    };
    let mut audit = Audit::new(policy.logging, audit_path)
        .context("Initialize audit logging; retry with --no-log to disable logging")?;
    // Verify the new copy can initialize its audit first. A failed portable
    // storage setup must not ask a healthy existing window to close.
    #[cfg(feature = "gui")]
    let instance = if !headless && !options.airgapready {
        audit.log("LAUNCH", "Requesting cooperative GUI handoff");
        let launch = amigood::instance::coordinate().inspect_err(|error| {
            audit.log("ERROR", format!("GUI handoff failed: {error:#}"));
        })?;
        match launch {
            amigood::instance::Launch::Owner(instance) => Some(instance),
            amigood::instance::Launch::Forwarded => return Ok(()),
        }
    } else {
        None
    };

    if options.airgapready {
        let message = bundle::prepare(&policy, &mut audit)?;
        println!("{message}");
        return Ok(());
    }

    if !headless {
        #[cfg(feature = "gui")]
        {
            return amigood::gui::run(
                policy,
                audit,
                options.lowgraphics,
                instance.context("GUI instance coordination unavailable")?,
            );
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
        "Scope: supported local Windows configuration checks, registered software inventory, and advisory-data availability. No CVE affected-version matcher is present; results do not establish complete vulnerability coverage."
    );

    let report = engine::scan_with_policy(&policy, &mut audit);
    println!("{}", serde_json::to_string_pretty(&report)?);

    if let Some(repairs) = options.plan.as_deref().or(options.fix.as_deref()) {
        let plan = engine::build_plan(repairs, &report)?;
        println!("\nReviewed plan:\n{}", serde_json::to_string_pretty(&plan)?);
        if options.plan.is_some() {
            return Ok(());
        }
        if options.plan_id.as_deref().is_some_and(|id| id != plan.id()) {
            bail!("Plan ID differs from the requested review; no changes were attempted");
        }
        let approval = engine::approve_plan(&plan, options.approve_critical)?;
        let results = engine::execute_plan(&plan, &approval, &mut audit);
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

fn default_log_path() -> Result<PathBuf> {
    let parent = amigood::policy::portable_directory(&["Data", "logs"])?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_millis();
    Ok(parent.join(format!("{timestamp}-{}.jsonl", std::process::id())))
}
