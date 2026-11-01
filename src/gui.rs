//! Native presentation. All system work runs outside the rendering thread.
use crate::{
    audit::Audit,
    engine::{self, Report},
    instance::{Control, Instance, WorkGuard},
    jewel::jewel,
    model::{Finding, Repair, Status},
    policy::Policy,
};
use anyhow::Result;
use eframe::egui::{self, Color32, FontId, RichText, Stroke, TextFormat};
use std::{sync::mpsc, time::Duration};

pub fn run(policy: Policy, audit: Audit, low: bool, instance: Instance) -> Result<()> {
    let server = crate::platform::detect_os().is_server;
    let size = initial_window_size();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(false)
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
                instance,
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
    instance: Instance,
    restart_waiting: bool,
    close_after_work: bool,
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
    expanded: std::collections::HashMap<String, bool>,
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
    fn new(
        policy: Policy,
        audit: Audit,
        low: bool,
        ctx: &egui::Context,
        instance: Instance,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut this = Self {
            instance,
            restart_waiting: false,
            close_after_work: false,
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
            expanded: Default::default(),
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
    fn begin_work(&mut self) -> Option<WorkGuard> {
        if self.close_after_work {
            return None;
        }
        match self.instance.begin_work() {
            Ok(guard) => Some(guard),
            Err(error) => {
                self.message = format!("A new copy is taking over: {error}");
                self.message_error = false;
                None
            }
        }
    }
    fn scan(&mut self, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        let Some(work) = self.begin_work() else {
            return;
        };
        self.busy = true;
        self.message = "Checking this computer…".into();
        self.message_error = false;
        let mut audit = self.audit.clone();
        let policy = self.policy.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _work = work;
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
        let Some(work) = self.begin_work() else {
            return;
        };
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
            let _work = work;
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
        let Some(work) = self.begin_work() else {
            return;
        };
        self.busy = true;
        self.message = "Downloading advisory metadata…".into();
        self.message_error = false;
        let mut audit = self.audit.clone();
        let policy = self.policy.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _work = work;
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
    fn titlebar(&mut self, ui: &mut egui::Ui) {
        let (bar, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 34.0), egui::Sense::hover());
        let controls = 120.0;
        let title =
            egui::Rect::from_min_max(bar.min, egui::pos2(bar.right() - controls, bar.bottom()));
        let drag = ui.interact(
            title,
            ui.id().with("window_drag"),
            egui::Sense::click_and_drag(),
        );
        let maximized = ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false));
        if drag.double_clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        } else if drag.drag_started_by(egui::PointerButton::Primary) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(title.shrink2(egui::vec2(9.0, 2.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
            |ui| {
                jewel(ui, Color32::from_rgb(75, 139, 229), 15.0, self.low);
                ui.label(RichText::new("Am I Good?").strong().size(14.0));
            },
        );
        for (index, label) in [
            "Minimize",
            if maximized { "Restore" } else { "Maximize" },
            "Close",
        ]
        .into_iter()
        .enumerate()
        {
            let rect = egui::Rect::from_min_size(
                egui::pos2(bar.right() - controls + index as f32 * 40.0, bar.top()),
                egui::vec2(40.0, 34.0),
            );
            let response = ui
                .interact(rect, ui.id().with(("caption", index)), egui::Sense::click())
                .on_hover_text(label);
            let mut ink = ui.visuals().text_color();
            if response.hovered() {
                let fill = if index == 2 {
                    ink = Color32::WHITE;
                    danger(self.dark)
                } else {
                    ui.visuals().widgets.hovered.bg_fill
                };
                ui.painter()
                    .rect_filled(rect.shrink2(egui::vec2(2.0, 3.0)), 3.0, fill);
            }
            let c = rect.center();
            let stroke = Stroke::new(1.2, ink);
            match index {
                0 => {
                    ui.painter().line_segment(
                        [c + egui::vec2(-5.0, 1.0), c + egui::vec2(5.0, 1.0)],
                        stroke,
                    );
                }
                1 => {
                    let icon = egui::Rect::from_center_size(c, egui::vec2(10.0, 9.0));
                    if maximized {
                        ui.painter().rect_stroke(
                            icon.translate(egui::vec2(2.0, -2.0)),
                            0.0,
                            stroke,
                            egui::StrokeKind::Inside,
                        );
                    }
                    ui.painter().rect_filled(icon, 0.0, ui.visuals().panel_fill);
                    ui.painter()
                        .rect_stroke(icon, 0.0, stroke, egui::StrokeKind::Inside);
                }
                _ => {
                    ui.painter().line_segment(
                        [c + egui::vec2(-5.0, -5.0), c + egui::vec2(5.0, 5.0)],
                        stroke,
                    );
                    ui.painter().line_segment(
                        [c + egui::vec2(-5.0, 5.0), c + egui::vec2(5.0, -5.0)],
                        stroke,
                    );
                }
            }
            if response.clicked() {
                match index {
                    0 => ui
                        .ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
                    1 => ui
                        .ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized)),
                    _ => {
                        self.close_after_work = true;
                        if !self.busy {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                }
            }
        }
    }
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
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
                                    Color32::from_rgb(43, 48, 56)
                                } else {
                                    Color32::from_rgb(231, 234, 238)
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
            finding_row(
                ui,
                finding,
                &mut self.expanded,
                &mut self.selected,
                self.advanced,
                self.busy,
                self.low,
                self.dark,
            );
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
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.busy {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            self.close_after_work = true;
        }
        if self.close_after_work && !self.busy {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        match self.instance.poll() {
            Control::Close => {
                self.audit.log(
                    "RESTART",
                    "Idle copy handing over to the newly launched executable",
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            Control::Waiting => {
                if !self.restart_waiting {
                    self.audit.log(
                        "RESTART",
                        "Handoff waiting for the current operation to finish",
                    );
                }
                self.restart_waiting = true;
            }
            Control::None => {
                if self.restart_waiting {
                    self.audit.log(
                        "RESTART",
                        "Pending handoff cleared; this copy continues running",
                    );
                    self.message = "Pending restart cancelled. Current work continues.".into();
                }
                self.restart_waiting = false;
            }
        }
        // Poll local kernel objects even when the UI is idle; no network or
        // app-owned storage is needed to discover another launch.
        ctx.request_repaint_after(Duration::from_secs(1));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        resize_edges(ui);
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
        egui::Panel::top("custom_titlebar").show(ui, |ui| self.titlebar(ui));
        egui::Panel::top("header").show(ui, |ui| self.header(ui));
        if self.restart_waiting || self.close_after_work {
            egui::Panel::top("restart_waiting").show(ui, |ui| {
                ui.label(if self.restart_waiting {
                    "New copy waiting. Finishing the current operation first."
                } else {
                    "This copy will close when the current operation finishes."
                });
            });
        }
        egui::Panel::bottom("footer").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.weak(env!("CARGO_PKG_VERSION"));
                ui.weak("Local checks · No CVE coverage yet");
            });
        });
        self.work_log(ui);
        self.sidebar(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
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

fn resize_edges(ui: &mut egui::Ui) {
    if ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }
    let r = ui.ctx().content_rect();
    let point = ui.ctx().input(|i| i.pointer.hover_pos());
    let Some(p) = point else {
        return;
    };
    let left = p.x < r.left() + 5.0;
    let right = p.x > r.right() - 5.0;
    let top = p.y < r.top() + 5.0;
    let bottom = p.y > r.bottom() - 5.0;
    use egui::{CursorIcon as C, ResizeDirection as D};
    let (direction, cursor) = match (left, right, top, bottom) {
        (true, _, true, _) => (D::NorthWest, C::ResizeNwSe),
        (_, true, true, _) => (D::NorthEast, C::ResizeNeSw),
        (true, _, _, true) => (D::SouthWest, C::ResizeNeSw),
        (_, true, _, true) => (D::SouthEast, C::ResizeNwSe),
        (true, _, _, _) => (D::West, C::ResizeHorizontal),
        (_, true, _, _) => (D::East, C::ResizeHorizontal),
        (_, _, true, _) => (D::North, C::ResizeVertical),
        (_, _, _, true) => (D::South, C::ResizeVertical),
        _ => return,
    };
    ui.ctx().set_cursor_icon(cursor);
    if ui
        .ctx()
        .input(|i| i.pointer.button_pressed(egui::PointerButton::Primary))
    {
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
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

#[derive(Clone, Copy)]
struct FindingRowLayout {
    header: egui::Rect,
    checkbox: Option<egui::Rect>,
    name: egui::Rect,
    status: egui::Rect,
}

fn short_name(finding: &Finding) -> &str {
    match finding.id.as_str() {
        "firewall-domain" => "Domain firewall",
        "firewall-private" => "Private firewall",
        "firewall-public" => "Public firewall",
        "windows-firewall" => "Windows Firewall",
        "advisory-coverage" => "Vulnerability coverage",
        "inventory" => "Registered apps",
        _ => &finding.name,
    }
}

#[allow(clippy::too_many_arguments)]
fn finding_row(
    ui: &mut egui::Ui,
    finding: &Finding,
    expanded: &mut std::collections::HashMap<String, bool>,
    selected: &mut Vec<Repair>,
    advanced: bool,
    busy: bool,
    low: bool,
    dark: bool,
) -> FindingRowLayout {
    let width = ui.available_width();
    let repair = finding
        .repair
        .filter(|_| finding.status == Status::NeedsAttention);
    let font = FontId::proportional(13.0);
    let ink = if dark {
        Color32::from_rgb(226, 231, 237)
    } else {
        Color32::from_rgb(35, 44, 56)
    };
    let status_galley = ui.painter().layout_no_wrap(
        status_label(finding.status).into(),
        FontId::proportional(11.0),
        ink,
    );
    let status_width = status_galley.size().x;
    let leading = 12.0 + 24.0 + if repair.is_some() { 28.0 } else { 0.0 };
    let trailing = 12.0 + 16.0 + 12.0 + status_width;
    let compact = width - leading - trailing - 14.0 < 80.0;
    let name_width = (width - leading - if compact { 40.0 } else { trailing + 14.0 }).max(20.0);
    let name_galley = ui
        .painter()
        .layout(short_name(finding).into(), font, ink, name_width);
    let content_height = name_galley.size().y
        + if compact {
            status_galley.size().y + 5.0
        } else {
            0.0
        };
    let height = (content_height.max(24.0) + 24.0).max(48.0);
    let (header_rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let header = ui.interact(
        header_rect,
        ui.id().with(("finding_header", &finding.id)),
        egui::Sense::click(),
    );
    header.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, true, &finding.name)
    });
    if header.hovered() || header.has_focus() {
        let fill = if dark {
            Color32::from_rgb(37, 42, 49)
        } else {
            Color32::from_rgb(244, 246, 248)
        };
        ui.painter().rect_filled(header_rect, 0.0, fill);
    }
    if header.has_focus() {
        ui.painter().rect_stroke(
            header_rect.shrink(1.0),
            0.0,
            Stroke::new(1.0, ui.visuals().widgets.active.fg_stroke.color),
            egui::StrokeKind::Inside,
        );
    }
    let center = header_rect.center().y;
    let jewel_rect = egui::Rect::from_center_size(
        egui::pos2(header_rect.left() + 22.0, center),
        egui::vec2(24.0, 24.0),
    );
    ui.scope_builder(egui::UiBuilder::new().max_rect(jewel_rect), |ui| {
        jewel(ui, status_color(finding.status, dark), 16.0, low);
    });
    let checkbox = repair.map(|_| {
        egui::Rect::from_center_size(
            egui::pos2(header_rect.left() + 48.0, center),
            egui::vec2(22.0, 24.0),
        )
    });
    let mut checkbox_activated = false;
    if let (Some(action), Some(rect)) = (repair, checkbox) {
        let mut checked = selected.contains(&action);
        let response = ui
            .scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                ui.add_enabled(!busy, egui::Checkbox::without_text(&mut checked))
            })
            .inner;
        checkbox_activated = response.clicked();
        if response.changed() {
            if checked {
                selected.push(action);
            } else {
                selected.retain(|r| *r != action);
            }
        }
    }
    let status_right = header_rect.right() - 12.0 - 16.0 - 12.0;
    let layout = FindingRowLayout {
        header: header_rect,
        checkbox,
        name: egui::Rect::from_min_size(
            egui::pos2(
                header_rect.left() + leading,
                if compact {
                    header_rect.top() + 12.0
                } else {
                    center - name_galley.size().y * 0.5
                },
            ),
            name_galley.size(),
        ),
        status: egui::Rect::from_min_size(
            egui::pos2(
                if compact {
                    header_rect.left() + leading
                } else {
                    status_right - status_width
                },
                if compact {
                    header_rect.top() + 12.0 + name_galley.size().y + 5.0
                } else {
                    center - status_galley.size().y * 0.5
                },
            ),
            status_galley.size(),
        ),
    };
    ui.painter().galley(layout.name.min, name_galley, ink);
    ui.painter().galley(layout.status.min, status_galley, ink);
    let open = expanded.get(&finding.id).copied().unwrap_or(advanced);
    let c = egui::pos2(header_rect.right() - 19.0, center);
    let points = if open {
        [
            c + egui::vec2(-3.0, -1.5),
            c + egui::vec2(0.0, 1.5),
            c + egui::vec2(3.0, -1.5),
        ]
    } else {
        [
            c + egui::vec2(-1.5, -3.0),
            c + egui::vec2(1.5, 0.0),
            c + egui::vec2(-1.5, 3.0),
        ]
    };
    ui.painter().add(egui::Shape::line(
        points.to_vec(),
        Stroke::new(1.2, muted(dark)),
    ));
    let over_checkbox = layout.checkbox.is_some_and(|r| {
        ui.input(|i| i.pointer.interact_pos())
            .is_some_and(|p| r.contains(p))
    });
    let keyboard = header.has_focus()
        && ui.input(|i| i.key_pressed(egui::Key::Enter) || i.key_pressed(egui::Key::Space));
    if keyboard || (header.clicked() && !checkbox_activated && !over_checkbox) {
        expanded.insert(finding.id.clone(), !open);
    }
    if expanded.get(&finding.id).copied().unwrap_or(advanced) {
        egui::Frame::new()
            .inner_margin(egui::Margin {
                left: 36,
                right: 12,
                top: 3,
                bottom: 12,
            })
            .show(ui, |ui| {
                ui.label(RichText::new(&finding.name).strong());
                ui.label(&finding.evidence);
                ui.weak(format!("Source: {}", finding.source));
                if advanced {
                    ui.monospace(&finding.id);
                }
            });
    }
    ui.separator();
    // This also documents the reserved gap between wrapped names and status text.
    debug_assert!(compact || layout.name.right() + 4.0 <= layout.status.left());
    debug_assert!(layout.header.contains_rect(layout.name));
    debug_assert!(layout.header.contains_rect(layout.status));
    layout
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

#[cfg(test)]
mod finding_row_tests {
    use super::*;
    use std::collections::HashMap;

    fn finding() -> Finding {
        Finding {
            id: "firewall-private".into(),
            name: "Private firewall local policy".into(),
            status: Status::NeedsAttention,
            evidence: "Local profile disabled; no external reachability verdict.".into(),
            source: "Windows Firewall policy".into(),
            repair: Some(Repair::EnablePrivateFirewall),
        }
    }
    fn frame(
        ctx: &egui::Context,
        width: f32,
        events: Vec<egui::Event>,
        expanded: &mut HashMap<String, bool>,
        selected: &mut Vec<Repair>,
        advanced: bool,
        busy: bool,
    ) -> FindingRowLayout {
        let mut layout = None;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, 700.0),
            )),
            events,
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                layout = Some(finding_row(
                    ui,
                    &finding(),
                    expanded,
                    selected,
                    advanced,
                    busy,
                    true,
                    false,
                ));
            });
        });
        // This headless harness does not upload the font atlas to a renderer.
        output.textures_delta.clear();
        layout.unwrap()
    }
    fn click(
        ctx: &egui::Context,
        pos: egui::Pos2,
        expanded: &mut HashMap<String, bool>,
        selected: &mut Vec<Repair>,
        advanced: bool,
        busy: bool,
    ) {
        for pressed in [true, false] {
            frame(
                ctx,
                320.0,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
                expanded,
                selected,
                advanced,
                busy,
            );
        }
    }
    #[test]
    fn checkbox_selection_and_disclosure_are_independent() {
        let ctx = egui::Context::default();
        let mut expanded = HashMap::new();
        let mut selected = Vec::new();
        let layout = frame(
            &ctx,
            320.0,
            vec![],
            &mut expanded,
            &mut selected,
            false,
            false,
        );
        click(
            &ctx,
            layout.checkbox.unwrap().center(),
            &mut expanded,
            &mut selected,
            false,
            false,
        );
        assert_eq!(selected, vec![Repair::EnablePrivateFirewall]);
        assert!(!expanded.get("firewall-private").copied().unwrap_or(false));
        click(
            &ctx,
            layout.name.center(),
            &mut expanded,
            &mut selected,
            false,
            false,
        );
        assert_eq!(expanded.get("firewall-private"), Some(&true));
        assert_eq!(selected, vec![Repair::EnablePrivateFirewall]);
    }
    #[test]
    fn busy_checkbox_does_not_select_or_disclose() {
        let ctx = egui::Context::default();
        let mut expanded = HashMap::new();
        let mut selected = Vec::new();
        let layout = frame(
            &ctx,
            320.0,
            vec![],
            &mut expanded,
            &mut selected,
            false,
            true,
        );
        click(
            &ctx,
            layout.checkbox.unwrap().center(),
            &mut expanded,
            &mut selected,
            false,
            true,
        );
        assert!(selected.is_empty());
        assert!(expanded.is_empty());
    }
    #[test]
    fn advanced_disclosure_can_close_and_reopen() {
        let ctx = egui::Context::default();
        let mut expanded = HashMap::new();
        let mut selected = Vec::new();
        let layout = frame(
            &ctx,
            320.0,
            vec![],
            &mut expanded,
            &mut selected,
            true,
            false,
        );
        click(
            &ctx,
            layout.name.center(),
            &mut expanded,
            &mut selected,
            true,
            false,
        );
        assert_eq!(expanded.get("firewall-private"), Some(&false));
        click(
            &ctx,
            layout.name.center(),
            &mut expanded,
            &mut selected,
            true,
            false,
        );
        assert_eq!(expanded.get("firewall-private"), Some(&true));
    }
    #[test]
    fn wrapped_names_and_status_keep_their_own_space() {
        for width in [240.0, 300.0, 700.0] {
            let ctx = egui::Context::default();
            let mut expanded = HashMap::new();
            let mut selected = Vec::new();
            let layout = frame(
                &ctx,
                width,
                vec![],
                &mut expanded,
                &mut selected,
                false,
                false,
            );
            assert!(layout.header.contains_rect(layout.name));
            assert!(layout.header.contains_rect(layout.status));
            assert!(!layout.name.intersects(layout.status));
            assert!(!layout.checkbox.unwrap().intersects(layout.name));
        }
    }
}
