//! Native rendering of the supplied .jewel CSS: rounded square rotated 45°,
//! a smooth five-stop gradient, a dark keyline and a restrained glow.
use eframe::egui::{self, Color32, Pos2, Stroke, Vec2};

pub fn jewel(ui: &mut egui::Ui, tint: Color32, diameter: f32, low: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(diameter + 8.0), egui::Sense::hover());
    let off = matches!(
        (tint.r(), tint.g(), tint.b()),
        (160, 173, 189) | (90, 103, 119)
    );
    paint(ui.painter(), rect.center(), diameter, tint, off, low);
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(
        (a.r() as f32 + (b.r() as f32 - a.r() as f32) * t) as u8,
        (a.g() as f32 + (b.g() as f32 - a.g() as f32) * t) as u8,
        (a.b() as f32 + (b.b() as f32 - a.b() as f32) * t) as u8,
        (a.a() as f32 + (b.a() as f32 - a.a() as f32) * t) as u8,
    )
}

fn outline(center: Pos2, diameter: f32) -> Vec<Pos2> {
    let half = diameter * std::f32::consts::FRAC_1_SQRT_2 * 0.5;
    let radius = 1.5_f32.min(half * 0.4);
    let k = half - radius;
    let mut points = Vec::with_capacity(24);
    for (cx, cy, start) in [
        (k, -k, -90.0_f32),
        (k, k, 0.0),
        (-k, k, 90.0),
        (-k, -k, 180.0),
    ] {
        for step in 0..=5 {
            let angle = (start + step as f32 * 18.0).to_radians();
            let x = cx + radius * angle.cos();
            let y = cy + radius * angle.sin();
            points.push(
                center
                    + egui::vec2(
                        (x - y) * std::f32::consts::FRAC_1_SQRT_2,
                        (x + y) * std::f32::consts::FRAC_1_SQRT_2,
                    ),
            );
        }
    }
    points
}

fn clip_y(points: &[Pos2], y: f32, keep_below: bool) -> Vec<Pos2> {
    let mut result = Vec::new();
    if points.is_empty() {
        return result;
    }
    let inside = |p: Pos2| if keep_below { p.y >= y } else { p.y <= y };
    let mut a = *points.last().unwrap();
    for &b in points {
        if inside(a) != inside(b) {
            let t = (y - a.y) / (b.y - a.y);
            result.push(egui::pos2(a.x + (b.x - a.x) * t, y));
        }
        if inside(b) {
            result.push(b);
        }
        a = b;
    }
    result
}

pub fn paint(
    painter: &egui::Painter,
    center: Pos2,
    diameter: f32,
    tint: Color32,
    off: bool,
    low: bool,
) {
    let points = outline(center, diameter);
    let border = Color32::from_rgba_unmultiplied(6, 4, 18, 217);
    let brand = tint.b() > tint.g() && tint.b() > tint.r();
    let colors = if brand {
        [
            Color32::WHITE,
            Color32::from_rgb(201, 191, 255),
            Color32::from_rgb(139, 123, 255),
            Color32::from_rgb(70, 168, 255),
            Color32::from_rgb(46, 211, 169),
        ]
    } else {
        [
            Color32::WHITE,
            mix(tint, Color32::WHITE, 0.65),
            mix(tint, Color32::WHITE, 0.12),
            tint,
            mix(tint, Color32::BLACK, 0.25),
        ]
    };
    if off {
        painter.add(egui::Shape::convex_polygon(
            points.clone(),
            Color32::TRANSPARENT,
            Stroke::new(2.5, border),
        ));
        painter.add(egui::Shape::convex_polygon(
            points,
            Color32::TRANSPARENT,
            Stroke::new(1.5, Color32::from_rgba_unmultiplied(201, 191, 255, 153)),
        ));
        return;
    }
    if !low {
        for (width, alpha) in [(6.0, 8), (4.0, 12), (2.0, 22)] {
            let glow = if brand {
                Color32::from_rgba_unmultiplied(124, 120, 255, alpha)
            } else {
                Color32::from_rgba_unmultiplied(tint.r(), tint.g(), tint.b(), alpha)
            };
            painter.add(egui::Shape::convex_polygon(
                points.clone(),
                Color32::TRANSPARENT,
                Stroke::new(width, glow),
            ));
        }
    }
    let min = points.iter().map(|p| p.y).fold(f32::INFINITY, f32::min);
    let max = points.iter().map(|p| p.y).fold(f32::NEG_INFINITY, f32::max);
    let stops = [0.0, 0.26, 0.54, 0.8, 1.0];
    let mut mesh = egui::Mesh::default();
    for band in 0..4 {
        let y0 = min + (max - min) * stops[band];
        let y1 = min + (max - min) * stops[band + 1];
        let polygon = clip_y(&clip_y(&points, y0, true), y1, false);
        if polygon.len() < 3 {
            continue;
        }
        let base = mesh.vertices.len() as u32;
        for p in &polygon {
            let t = ((p.y - y0) / (y1 - y0)).clamp(0.0, 1.0);
            mesh.colored_vertex(*p, mix(colors[band], colors[band + 1], t));
        }
        for n in 1..polygon.len() - 1 {
            mesh.add_triangle(base, base + n as u32, base + n as u32 + 1);
        }
    }
    painter.add(egui::Shape::mesh(mesh));
    painter.add(egui::Shape::convex_polygon(
        points,
        Color32::TRANSPARENT,
        Stroke::new(1.0, border),
    ));
}
