# Am I Good? (Working Name)

Portable Rust application for visible Windows security checks and approved repairs.
Development build: `0.1.0-dev.5`.

## Run

Open `amigood.exe` for the native interface, or use:

```powershell
.\amigood.exe --scan
.\amigood.exe --noexternal
.\amigood.exe --scan --noexternal --no-log
.\amigood.exe --lowgraphics
.\amigood.exe --airgapready
```

The interface provides Overview/Advanced views, light/dark themes, a live work
log, software inventory, and one combined review for selected repairs.
Server installations default to low graphics. Server Core uses the CLI.

## Opening A New Copy

GUI launches coordinate within the same Windows user, session and integrity
level. An idle participating copy exits cooperatively, then the executable you
just launched opens. Active scans, approved repairs and metadata preparation
finish before takeover; the old window shows a waiting notice. Window-close
requests during work are deferred until that work finishes too.

The new process waits up to two minutes before a busy owner acknowledges the
handoff. A request can be cancelled before acknowledgment without closing the
owner. After acknowledgment, the launcher waits for the owner to exit; it does
not kill a stuck process. Startup logging is initialized before requesting a
handoff, so a storage failure leaves the existing copy available.

Coordination uses private Windows kernel objects, without TCP, files, helper
processes or executable paths sent over IPC. Headless CLI commands run
independently. Separate elevated/non-elevated sessions are kept separate.
Builds older than `0.1.0-dev.4` do not support this protocol and must be closed
manually once. The app cannot safely infer whether those older builds are busy.

## Current Scope

The Repairs view lists all ten implemented actions, including current
applicability, change risk, impact and recovery instructions. Select eligible
repairs together and approve one reviewed plan. Critical changes have an
explicit plan-wide acknowledgment; they are available when applicability is
verified. Known local Group Policy registry overrides are marked Critical and
disclose that policy refresh may reapply the old value; these actions do not
rewrite the policy source. Domain/MDM-managed or unverifiable targets cannot be
forced into a plan.

Each plan has a content ID covering the observed evidence and proposed actions.
Approval is tied to that snapshot. Changed evidence requires a new review.
Actions run sequentially and stop after a failure; each configured result is
read back independently. Restart-required settings stay described as configured
changes, with runtime activation still unverified. Recovery instructions are
manual; the application does not provide automatic rollback.

```powershell
.\amigood.exe --catalog
.\amigood.exe --plan firewall-private,rdp-require-nla --noexternal --no-log
# After reviewing an applicable plan, --fix requires --approve.
# Critical plans also require --approve-critical. --plan-id can bind a CLI run
# to a previously copied plan ID. No approval authorizes future unseen actions.
```

- Reads Domain, Private and Public Windows Firewall local policy through COM.
- Inventories registered desktop applications through the Windows registry.
- Can enable selected eligible firewall profiles on confirmed desktop Windows,
  with explicit approval, fresh eligibility checks and separate verification.
- Refuses firewall changes on Server or unclassified installations.
- Adds native UAC, MSI elevated-install policy, SMB guest and RDP NLA checks and
  typed repairs on verified unmanaged Windows clients. Unknown values, missing
  undocumented defaults, registry links and domain/MDM policy targets are withheld.
- Reports uncertain or unsupported checks explicitly.

No CVE affected-version matcher or AI model is included yet. Coverage dates are
not established. An enabled local firewall setting is not proof of effective
network protection or safe rules. Repairs may interrupt remote connections and
may require administrator rights; the program does not elevate automatically.

## Portable And Offline

Initial resources are compiled into the executable. No installer, sidecar asset,
web runtime or helper process is required. Normal logs stay in `Data/logs` beside
the executable. If this location is unwritable, startup reports the failure;
`--no-log` disables logging. Settings currently apply to the session only.

`--noexternal` disables network, app-owned persistence and external catalogs.
Working data and logs stay in memory. Approved repair-target changes are allowed.

`--airgapready` downloads CISA KEV advisory metadata to the adjacent `airgap`
folder. This is an **incomplete kit**, with no installer payloads or applicability
matcher. Cached metadata can be read offline; its date and limits are displayed.
Local SHA-256 checks detect corruption, not malicious replacement or publisher
authenticity. No downloaded content is executed.

## Build

Rust 1.95.0 is pinned in `rust-toolchain.toml`. On Windows with MSVC build tools:

```powershell
cargo test
cargo build --release
```

The MSVC target uses the static C runtime. The application still requires the
normal Windows system libraries and a supported graphics adapter/driver.
Run `--scan` for a graphical-session-independent check.

Source is MIT licensed. No public release has been published.
