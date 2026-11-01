//! Native presentation. All system work runs outside the rendering thread.
use crate::{
    audit::Audit,
    engine::{self, Report},
    model::{Finding, Repair, Status},
    policy::Policy,
};
use anyhow::Result;
use eframe::egui::{self, Color32, FontId, RichText, Stroke, TextFormat, Vec2};
use std::{sync::mpsc, time::Duration};

pub fn run(policy: Policy, audit: Audit, low: bool) -> Result<()> {
    let server = crate::platform::detect_os().is_server;
    let size = initial_window_size();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(size)
            .with_min_inner_size([480.0_f32.min(size[0]), 320.0_f32.min(size[1])])
            .with_clamp_size_to_monitor_size(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Am I Good?",
        options,
        Box::new(move |cc| {
            Ok(Box::new(Workbench::new(
                policy,
                audit,
                low || server,
                &cc.egui_ctx,
            )))
        }),
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Unable to start the graphical interface: {e}. Use --scan on systems without a desktop."
        )
    })
}

fn initial_window_size() -> [f32; 2] {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::{Foundation::POINT, Graphics::Gdi::*};
        let monitor = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if GetMonitorInfoW(monitor, &mut info).as_bool() {
            let dc = GetDC(None);
            let dpi_x = GetDeviceCaps(Some(dc), LOGPIXELSX).max(96) as f32;
            let dpi_y = GetDeviceCaps(Some(dc), LOGPIXELSY).max(96) as f32;
            ReleaseDC(None, dc);
            let width = (info.rcWork.right - info.rcWork.left) as f32 * 96.0 / dpi_x;
            let height = (info.rcWork.bottom - info.rcWork.top) as f32 * 96.0 / dpi_y;
            return [
                (width - 32.0).clamp(240.0, 960.0),
                (height - 64.0).clamp(240.0, 640.0),
            ];
        }
    }
    [960.0, 640.0]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    All,
    Windows,
    Apps,
    Network,
    Other,
}
impl Section {
    fn label(self) -> &'static str {
        match self {
            Self::All => "All checks",
            Self::Windows => "Windows",
            Self::Apps => "Apps",
            Self::Network => "Network",
            Self::Other => "Other",
        }
    }
    fn accepts(self, f: &Finding) -> bool {
        self == Self::All || self == category(f)
    }
}
enum Message {
    Scanned(Report),
    Repaired(Report, Vec<(Repair, std::result::Result<String, String>)>),
    Prepared(Report, std::result::Result<String, String>),
    Failed(String),
}
struct Workbench {
    policy: Policy,
    audit: Audit,
    report: Option<Report>,
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
    busy: bool,
    dark: bool,
    low: bool,
    advanced: bool,
    section: Section,
    selected: Vec<Repair>,
    expanded: Option<String>,
    review: bool,
    consent: bool,
    reviewed: Vec<Repair>,
    settings: bool,
    log_open: bool,
    log_follow: bool,
    message: String,
    message_error: bool,
}
impl Workbench {
    fn new(policy: Policy, audit: Audit, low: bool, ctx: &egui::Context) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut this = Self {
            policy,
            audit,
            report: None,
            tx,
            rx,
            busy: false,
            dark: ctx.theme() == egui::Theme::Dark,
            low,
            advanced: false,
            section: Section::All,
            selected: Vec::new(),
            expanded: None,
            review: false,
            consent: false,
            reviewed: Vec::new(),
            settings: false,
            log_open: true,
            log_follow: true,
            message: String::new(),
            message_error: false,
        };
        this.scan(ctx);
        this
    }
    fn scan(&mut self, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.message = "Checking this computer…".into();
        self.message_error = false;
        let mut audit = self.audit.clone();
        let policy = self.policy.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine::scan_with_policy(&policy, &mut audit)
            }));
            let message = match result {
                Ok(report) => Message::Scanned(report),
                Err(_) => {
                    audit.log(
                        "ERROR",
                        "Scan worker stopped unexpectedly; results are unavailable",
                    );
                    Message::Failed(
                        "Scan stopped unexpectedly. Run a new scan before making changes.".into(),
                    )
                }
            };
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }
    fn apply(&mut self, ctx: &egui::Context) {
        if self.busy || !self.consent || self.reviewed.is_empty() {
            return;
        }
        self.busy = true;
        self.review = false;
        self.consent = false;
        self.message = "Applying selected repairs and checking again…".into();
        self.message_error = false;
        let repairs = self.reviewed.clone();
        let mut audit = self.audit.clone();
        let policy = self.policy.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let results = engine::repair_batch(&repairs, &mut audit);
                let report = engine::scan_with_policy(&policy, &mut audit);
                Message::Repaired(report, results)
            }));
            let message = result.unwrap_or_else(|_| {
                audit.log("ERROR", "Repair worker stopped unexpectedly; system changes may have occurred and are not verified");
                Message::Failed("Repair stopped unexpectedly. Changes may have occurred. Scan again before another repair.".into())
            });
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }
    fn prepare(&mut self, ctx: &egui::Context) {
        if self.busy || !self.policy.network_allowed() {
            return;
        }
        self.busy = true;
        self.message = "Downloading advisory metadata…".into();
        self.message_error = false;
        let mut audit = self.audit.clone();
        let policy = self.policy.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let result =
                    crate::bundle::prepare(&policy, &mut audit).map_err(|e| format!("{e:#}"));
                let report = engine::scan_with_policy(&policy, &mut audit);
                Message::Prepared(report, result)
            }));
            let message = result.unwrap_or_else(|_| {
                audit.log("ERROR", "Offline preparation worker stopped unexpectedly; kit readiness is not verified");
                Message::Failed("Offline preparation stopped unexpectedly. Recheck the kit before using it.".into())
            });
            let _ = tx.send(message);
            ctx.request_repaint();
        });
    }
    fn receive(&mut self) {
        while let Ok(message) = self.rx.try_recv() {
            self.busy = false;
            match message {
                Message::Failed(error) => {
                    self.report = None;
                    self.selected.clear();
                    self.message = error;
                    self.message_error = true;
                }
                Message::Scanned(report) => {
                    self.report = Some(report);
                    self.message = "Checks complete".into();
                    self.message_error = false;
                }
                Message::Prepared(report, result) => {
                    self.report = Some(report);
                    self.message_error = result.is_err();
                    self.message = match result {
                        Ok(message) => message,
                        Err(error) => format!("Offline preparation failed: {error}"),
                    };
                }
                Message::Repaired(report, results) => {
                    let failures = results.iter().filter(|(_, r)| r.is_err()).count();
                    self.report = Some(report);
                    self.message_error = failures != 0;
                    self.message = if failures == 0 {
                        "Repair steps complete. Fresh check results are shown below.".into()
                    } else {
                        format!(
                            "{failures} repair step(s) failed. Fresh check results are shown below."
                        )
                    };
                    self.selected.clear();
                }
            }
            if let Some(report) = &self.report {
                self.selected.retain(|action| {
                    report
                        .findings
                        .iter()
                        .any(|f| f.repair == Some(*action) && f.status == Status::NeedsAttention)
                });
            }
        }
    }
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            jewel(ui, Color32::from_rgb(75, 139, 229), 17.0, self.low);
            ui.label(RichText::new("Am I Good?").strong().size(18.0));
            ui.weak(RichText::new("NEON ORCHARD").size(10.0));
            ui.separator();
            ui.selectable_value(&mut self.advanced, false, "Overview");
            ui.selectable_value(&mut self.advanced, true, "Advanced");
            ui.separator();
            ui.checkbox(&mut self.dark, "Dark");
            if ui.button("Settings").clicked() {
                self.settings = !self.settings;
            }
        });
    }
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("categories")
            .default_size(137.0)
            .min_size(110.0)
            .max_size(170.0)
            .resizable(false)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("sidebar-scroll")
                    .show(ui, |ui| {
                        ui.add_space(16.0);
                        for section in [
                            Section::All,
                            Section::Windows,
                            Section::Apps,
                            Section::Network,
                            Section::Other,
                        ] {
                            let count = self
                                .report
                                .as_ref()
                                .map(|r| r.findings.iter().filter(|f| section.accepts(f)).count());
                            let tint = self
                                .report
                                .as_ref()
                                .map(|report| {
                                    let entries = report
                                        .findings
                                        .iter()
                                        .filter(|f| section.accepts(f))
                                        .collect::<Vec<_>>();
                                    if entries.iter().any(|f| f.status == Status::NeedsAttention) {
                                        warning(self.dark)
                                    } else if entries.iter().any(|f| f.status != Status::Passed) {
                                        status_color(Status::Unknown, self.dark)
                                    } else if !entries.is_empty() {
                                        good(self.dark)
                                    } else {
                                        muted(self.dark)
                                    }
                                })
                                .unwrap_or_else(|| muted(self.dark));
                            let selected = self.section == section;
                            let fill = if selected {
                                if self.dark {
                                    blend(Color32::from_rgb(28, 32, 39), tint, 0.14)
                                } else {
                                    blend(Color32::from_rgb(247, 248, 250), tint, 0.12)
                                }
                            } else {
                                Color32::TRANSPARENT
                            };
                            let row = egui::Frame::new()
                                .fill(fill)
                                .corner_radius(if self.low { 2 } else { 7 })
                                .inner_margin(7)
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        jewel(ui, tint, 13.0, self.low);
                                        ui.label(
                                            RichText::new(section.label()).size(12.0).strong(),
                                        );
                                        if let Some(count) = count {
                                            ui.weak(RichText::new(count.to_string()).size(11.0));
                                        }
                                    });
                                });
                            if selected {
                                let rect = row.response.rect;
                                ui.painter().line_segment(
                                    [
                                        rect.left_top() + egui::vec2(5.0, 6.0),
                                        rect.left_bottom() + egui::vec2(5.0, -6.0),
                                    ],
                                    Stroke::new(2.0, tint),
                                );
                            }
                            if row.response.interact(egui::Sense::click()).clicked() {
                                self.section = section;
                            }
                            ui.add_space(3.0);
                        }
                        ui.add_space(16.0);
                        ui.separator();
                        ui.add_space(7.0);
                        if let Some(report) = &self.report {
                            ui.label(RichText::new(&report.os.edition).small());
                            ui.weak(format!("Build {}", report.os.build));
                        }
                        if !self.policy.network_allowed() {
                            ui.add_space(8.0);
                            ui.colored_label(warning(self.dark), "Embedded only");
                        }
                        if self.low {
                            ui.weak("Low graphics");
                        }
                    });
            });
    }
    fn work_log(&mut self, ui: &mut egui::Ui) {
        let height = ui.available_height();
        let panel = egui::Panel::bottom("work_log")
            .resizable(self.log_open)
            .default_size(if self.log_open { 166.0 } else { 31.0 })
            .min_size(31.0)
            .max_size((height * 0.45).max(70.0));
        let panel = if self.log_open {
            panel
        } else {
            panel.exact_size(31.0)
        };
        panel.show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .selectable_label(
                        self.log_open,
                        if self.log_open {
                            "▾ Work log"
                        } else {
                            "▸ Work log"
                        },
                    )
                    .clicked()
                {
                    self.log_open = !self.log_open;
                }
                if self.log_open {
                    ui.checkbox(&mut self.log_follow, "Follow");
                }
                if ui.small_button("Copy").clicked() {
                    let text = self
                        .audit
                        .events()
                        .iter()
                        .map(|e| format!("{:>7}ms {:7} {}", e.elapsed_ms, e.level, e.message))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ui.ctx().copy_text(text);
                }
                if !self.audit.enabled() {
                    ui.colored_label(warning(self.dark), "Logging off");
                }
            });
            if self.log_open {
                egui::ScrollArea::both()
                    .id_salt("work_output")
                    .auto_shrink([false, false])
                    .stick_to_bottom(self.log_follow)
                    .show(ui, |ui| {
                        for event in self.audit.events() {
                            let mut job = egui::text::LayoutJob::default();
                            let level_color = match event.level.as_str() {
                                "ERROR" | "FAIL" => danger(self.dark),
                                "WARN" => warning(self.dark),
                                "VERIFY" | "PASS" => good(self.dark),
                                _ => muted(self.dark),
                            };
                            append(
                                &mut job,
                                &format!("{:>7}ms ", event.elapsed_ms),
                                muted(self.dark),
                            );
                            append(&mut job, &format!("{:7} ", event.level), level_color);
                            highlight(&mut job, &event.message, self.dark);
                            ui.add(egui::Label::new(job).selectable(true));
                        }
                    });
            }
        });
    }
    fn content(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.heading(self.section.label());
            if ui
                .add_enabled(!self.busy, egui::Button::new("Scan again"))
                .clicked()
            {
                self.scan(ui.ctx());
            }
            if ui
                .add_enabled(
                    !self.busy && !self.selected.is_empty(),
                    egui::Button::new(format!("Fix selected ({})", self.selected.len())),
                )
                .clicked()
            {
                self.reviewed = self.selected.clone();
                self.review = true;
                self.consent = false;
            }
            if ui
                .add_enabled(
                    !self.busy && self.policy.network_allowed(),
                    egui::Button::new("Prepare offline data"),
                )
                .clicked()
            {
                self.prepare(ui.ctx());
            }
        });
        ui.colored_label(
            if self.message_error {
                danger(self.dark)
            } else {
                muted(self.dark)
            },
            &self.message,
        );
        let Some(report) = &self.report else {
            ui.add_space(20.0);
            ui.label(if self.busy {
                "Reading local Windows settings and installed applications."
            } else {
                "No current results. Run a new scan."
            });
            return;
        };
        let attention = report
            .findings
            .iter()
            .filter(|f| f.status == Status::NeedsAttention)
            .count();
        let unresolved = report
            .findings
            .iter()
            .filter(|f| matches!(f.status, Status::Unknown | Status::Unsupported))
            .count();
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("{attention} need attention")).color(warning(self.dark)),
            );
            ui.weak(format!("·  {unresolved} unverified or unsupported"));
        });
        ui.add_space(9.0);
        for finding in report.findings.iter().filter(|f| self.section.accepts(f)) {
            let color = status_color(finding.status, self.dark);
            let surface = if self.dark {
                Color32::from_rgb(36, 42, 50)
            } else {
                Color32::from_rgb(247, 248, 250)
            };
            let row = egui::Frame::new()
                .fill(surface)
                .corner_radius(if self.low { 2 } else { 7 })
                .inner_margin(10)
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        jewel(ui, color, 16.0, self.low);
                        if let Some(repair) = finding
                            .repair
                            .filter(|_| finding.status == Status::NeedsAttention)
                        {
                            let mut selected = self.selected.contains(&repair);
                            if ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Checkbox::without_text(&mut selected),
                                )
                                .changed()
                            {
                                if selected {
                                    self.selected.push(repair);
                                } else {
                                    self.selected.retain(|r| *r != repair);
                                }
                            }
                        }
                        ui.label(RichText::new(&finding.name).strong());
                        ui.label(
                            RichText::new(status_label(finding.status))
                                .color(color)
                                .small(),
                        );
                        if ui
                            .small_button(
                                if self.expanded.as_deref() == Some(finding.id.as_str()) {
                                    "Less"
                                } else {
                                    "Details"
                                },
                            )
                            .clicked()
                        {
                            self.expanded = if self.expanded.as_deref() == Some(finding.id.as_str())
                            {
                                None
                            } else {
                                Some(finding.id.clone())
                            };
                        }
                    });
                    if self.advanced || self.expanded.as_deref() == Some(finding.id.as_str()) {
                        ui.add_space(6.0);
                        ui.label(&finding.evidence);
                        ui.weak(format!("Source: {}", finding.source));
                        if self.advanced {
                            ui.monospace(&finding.id);
                        }
                    }
                });
            let rect = row.response.rect;
            ui.painter().line_segment(
                [
                    rect.left_top() + egui::vec2(5.0, 8.0),
                    rect.left_bottom() + egui::vec2(5.0, -8.0),
                ],
                Stroke::new(2.0, color.gamma_multiply(0.7)),
            );
            ui.add_space(6.0);
        }
        if self.section == Section::Apps {
            ui.add_space(8.0);
            ui.weak("Inventory is not a vulnerability verdict. Version-to-advisory matching is not available yet.");
            ui.collapsing(
                format!("Installed applications ({})", report.apps.len()),
                |ui| {
                    for app in &report.apps {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(&app.name);
                            ui.weak(&app.version);
                            if self.advanced {
                                ui.weak(&app.publisher);
                            }
                        });
                    }
                },
            );
        }
        if self.advanced {
            ui.collapsing("Detected OS capabilities", |ui| {
                for capability in &report.os.capabilities {
                    ui.label(capability);
                }
            });
        }
        ui.add_space(12.0);
        ui.separator();
        ui.weak("Coverage: local configuration checks. Advisory metadata does not establish CVE exposure.");
    }
    fn review_window(&mut self, ctx: &egui::Context) {
        if !self.review {
            return;
        }
        let mut apply = false;
        let mut cancel = false;
        egui::Window::new("Review selected repairs")
            .collapsible(false)
            .resizable(true)
            .default_width(440.0_f32.min((ctx.content_rect().width() - 36.0).max(200.0)))
            .max_width((ctx.content_rect().width() - 36.0).max(200.0))
            .max_height((ctx.content_rect().height() - 36.0).max(150.0))
            .constrain_to(ctx.content_rect().shrink(12.0))
            .vscroll(true)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for repair in &self.reviewed {
                            ui.strong(repair.id());
                            ui.label(repair.impact());
                            ui.add_space(10.0);
                        }
                    });
                ui.separator();
                ui.checkbox(&mut self.consent, "I approve these specific changes.");
                ui.horizontal(|ui| {
                    apply = ui
                        .add_enabled(
                            self.consent && !self.busy,
                            egui::Button::new("Apply and check again"),
                        )
                        .clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if cancel {
            self.review = false;
            self.consent = false;
        }
        if apply {
            self.apply(ctx);
        }
    }
    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.settings {
            return;
        }
        egui::Window::new("Settings").open(&mut self.settings).resizable(false).auto_sized()
            .default_width(350.0_f32.min((ctx.content_rect().width() - 36.0).max(200.0)))
            .max_width((ctx.content_rect().width() - 36.0).max(200.0))
            .max_height((ctx.content_rect().height() - 36.0).max(150.0))
            .constrain_to(ctx.content_rect().shrink(12.0)).vscroll(true).show(ctx, |ui| {
            ui.checkbox(&mut self.low, "Low graphics");
            ui.weak("Fewer effects and no interface animation. Checks stay the same.");
            ui.checkbox(&mut self.dark, "Dark theme");
            let mut enabled = self.audit.enabled();
            if ui.checkbox(&mut enabled, "Logging").changed() { self.audit.set_enabled(enabled); }
            ui.weak("Turning logging off clears the visible session log. Existing files are retained.");
            ui.checkbox(&mut self.log_open, "Show work log");
            ui.separator();
            ui.weak("Settings apply to this session. No GUI settings file is written.");
        });
    }
}
impl eframe::App for Workbench {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.receive();
        let ctx = ui.ctx().clone();
        ctx.set_visuals(if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
        ctx.style_mut_of(
            if self.dark {
                egui::Theme::Dark
            } else {
                egui::Theme::Light
            },
            |style| {
                style.animation_time = if self.low { 0.0 } else { 0.12 };
                style.spacing.item_spacing = egui::vec2(8.0, 6.0);
                style.spacing.scroll.floating = false;
                style.spacing.scroll.bar_width = 7.0;
                style.spacing.scroll.handle_min_length = 24.0;
                style.visuals.widgets.inactive.bg_stroke = Stroke::new(
                    1.0,
                    if self.dark {
                        Color32::from_rgb(65, 76, 91)
                    } else {
                        Color32::from_rgb(207, 215, 225)
                    },
                );
                if self.low {
                    style.visuals.window_shadow = egui::epaint::Shadow::NONE;
                    style.visuals.popup_shadow = egui::epaint::Shadow::NONE;
                }
            },
        );
        egui::Panel::top("header").show(ui, |ui| self.header(ui));
        egui::Panel::bottom("footer").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.weak("0.1.0-dev.1");
                ui.weak("Local checks · No CVE coverage yet");
            });
        });
        self.work_log(ui);
        self.sidebar(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| self.content(ui));
        });
        self.review_window(&ctx);
        self.settings_window(&ctx);
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

fn category(f: &Finding) -> Section {
    let text = format!("{} {}", f.id, f.name).to_ascii_lowercase();
    if text.contains("firewall") || text.contains("network") || text.contains("smb") {
        Section::Network
    } else if text.contains("inventory")
        || text.contains("application")
        || text.contains("advisory")
    {
        Section::Apps
    } else if text.contains("windows")
        || text.contains("restart")
        || text.contains("update")
        || text.contains("defender")
        || text.contains("os-")
    {
        Section::Windows
    } else {
        Section::Other
    }
}
fn status_label(status: Status) -> &'static str {
    match status {
        Status::Passed => "Passed",
        Status::NeedsAttention => "Needs attention",
        Status::Unknown => "Not verified",
        Status::Unsupported => "Not supported",
    }
}
fn muted(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(160, 173, 189)
    } else {
        Color32::from_rgb(90, 103, 119)
    }
}
fn good(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(102, 199, 164)
    } else {
        Color32::from_rgb(28, 132, 104)
    }
}
fn warning(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(237, 187, 104)
    } else {
        Color32::from_rgb(160, 104, 26)
    }
}
fn danger(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(243, 143, 149)
    } else {
        Color32::from_rgb(179, 52, 63)
    }
}
fn status_color(status: Status, dark: bool) -> Color32 {
    match status {
        Status::Passed => good(dark),
        Status::NeedsAttention => warning(dark),
        Status::Unknown => {
            if dark {
                Color32::from_rgb(180, 157, 230)
            } else {
                Color32::from_rgb(122, 89, 171)
            }
        }
        Status::Unsupported => muted(dark),
    }
}
fn blend(a: Color32, b: Color32, amount: f32) -> Color32 {
    let mix = |x: u8, y: u8| (f32::from(x) * (1.0 - amount) + f32::from(y) * amount).round() as u8;
    Color32::from_rgba_unmultiplied(
        mix(a.r(), b.r()),
        mix(a.g(), b.g()),
        mix(a.b(), b.b()),
        mix(a.a(), b.a()),
    )
}
/// A tiny rounded candy jewel: layered radial shading and curved reflections, no raster asset.
fn jewel(ui: &mut egui::Ui, tint: Color32, diameter: f32, low: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(diameter + 4.0), egui::Sense::hover());
    let center = rect.center();
    let radius = diameter * 0.5;
    let painter = ui.painter();
    if low {
        painter.circle_filled(center, radius, tint);
        return;
    }
    painter.circle_filled(
        center + egui::vec2(0.0, 1.3),
        radius + 0.8,
        Color32::from_black_alpha(36),
    );
    let base = blend(tint, Color32::BLACK, 0.38);
    painter.circle_filled(center, radius, base);
    for step in 0..18 {
        let f = step as f32 / 18.0;
        let color = blend(base, blend(tint, Color32::WHITE, 0.2), f);
        painter.circle_filled(
            center + egui::vec2(-f * radius * 0.13, -f * radius * 0.22),
            radius * (1.0 - f * 0.55),
            color,
        );
    }
    painter.add(egui::Shape::ellipse_filled(
        center + egui::vec2(-radius * 0.13, -radius * 0.43),
        egui::vec2(radius * 0.5, radius * 0.23),
        Color32::from_white_alpha(160),
    ));
    painter.add(egui::Shape::ellipse_filled(
        center + egui::vec2(radius * 0.18, radius * 0.56),
        egui::vec2(radius * 0.4, radius * 0.1),
        Color32::from_white_alpha(54),
    ));
    painter.circle_stroke(
        center,
        radius,
        Stroke::new(0.7, blend(tint, Color32::WHITE, 0.3)),
    );
}
fn append(job: &mut egui::text::LayoutJob, text: &str, color: Color32) {
    job.append(
        text,
        0.0,
        TextFormat {
            font_id: FontId::monospace(11.0),
            color,
            ..Default::default()
        },
    );
}
fn highlight(job: &mut egui::text::LayoutJob, text: &str, dark: bool) {
    let plain = if dark {
        Color32::from_rgb(215, 222, 232)
    } else {
        Color32::from_rgb(47, 57, 70)
    };
    let purple = if dark {
        Color32::from_rgb(195, 161, 235)
    } else {
        Color32::from_rgb(117, 68, 161)
    };
    let blue = if dark {
        Color32::from_rgb(134, 183, 250)
    } else {
        Color32::from_rgb(35, 92, 175)
    };
    for piece in text.split_inclusive(char::is_whitespace) {
        let token = piece.trim_end();
        if let Some((key, value)) = token.split_once('=') {
            append(job, key, muted(dark));
            append(job, "=", plain);
            let color = if key == "exit_code" {
                if value == "0" {
                    good(dark)
                } else {
                    danger(dark)
                }
            } else if matches!(value, "true" | "false") {
                purple
            } else if value.chars().any(|c| c.is_ascii_digit()) {
                warning(dark)
            } else {
                plain
            };
            append(job, value, color);
            append(job, &piece[token.len()..], plain);
            continue;
        }
        let color = if token.starts_with('-') {
            purple
        } else if token.starts_with("CVE-") {
            if dark {
                Color32::from_rgb(231, 159, 192)
            } else {
                Color32::from_rgb(157, 55, 108)
            }
        } else if token.contains('\\') || token.starts_with("https://") {
            if dark {
                Color32::from_rgb(130, 210, 217)
            } else {
                Color32::from_rgb(8, 114, 125)
            }
        } else if token.starts_with('"') || token.starts_with('\'') {
            good(dark)
        } else if token.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            warning(dark)
        } else if matches!(
            token
                .trim_matches(|c: char| !c.is_alphabetic())
                .to_ascii_lowercase()
                .as_str(),
            "failed" | "error" | "denied"
        ) {
            danger(dark)
        } else if token.contains("::")
            || token.contains("INetFwPolicy2")
            || token.starts_with("Get")
        {
            blue
        } else {
            plain
        };
        append(job, piece, color);
    }
}
