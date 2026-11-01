# Am I Good? (Working Name)

Portable Rust application for visible Windows security checks and approved repairs.
Development build: `0.1.0-dev.4`.

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

- Reads Domain, Private and Public Windows Firewall local policy through COM.
- Inventories registered desktop applications through the Windows registry.
- Can enable selected eligible firewall profiles on confirmed desktop Windows,
  with explicit approval, fresh eligibility checks and separate verification.
- Refuses firewall changes on Server or unclassified installations.
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
