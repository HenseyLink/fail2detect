//! Дашборд: та же раскладка, что у bash-версии — шапка с фазами, скорость
//! (график по окнам 250 мс), три полосы задержки на общей шкале, потери, итог.

use std::path::Path;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::Frame;

use crate::engine::{Data, Phase, Plan};
use crate::result;
use crate::stats::{self, fmt};

const GREEN: Color = Color::LightGreen;
const MAGENTA: Color = Color::LightMagenta;
const CYAN: Color = Color::LightCyan;
const BLUE: Color = Color::LightBlue;
const GRAY: Color = Color::DarkGray;
const YELLOW: Color = Color::LightYellow;
const RED: Color = Color::LightRed;

pub struct View<'a> {
    pub data: &'a Data,
    pub plan: &'a Plan,
    pub version: &'a str,
    pub autosave: bool,
    /// итог показан: None — замер идёт; Some(сохранён?)
    pub saved: Option<bool>,
}

fn gray(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(GRAY))
}

fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

fn col(s: impl Into<String>, c: Color) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(c))
}

fn boxed(title: Line<'static>, c: Color) -> Block<'static> {
    let mut t = vec![col("─ ", c)];
    t.extend(title.spans);
    t.push(Span::raw(" "));
    Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().fg(c)).title(Line::from(t))
}

fn grade_color(g: &str) -> Color {
    match g {
        "A+" | "A" => GREEN,
        "B" => CYAN,
        "C" => YELLOW,
        "-" => GRAY,
        _ => RED,
    }
}

/// Столбики из 1/8 блоков: последние w окон (если окон меньше — растягиваем).
pub fn chart(values: &[f64], w: usize, h: usize, max: f64) -> Vec<String> {
    const G: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let n = values.len();
    let y: Vec<f64> = (0..w)
        .map(|c| {
            if n == 0 {
                return -1.0;
            }
            let idx = if n >= w { n - w + c } else { c * n / w };
            if max > 0.0 { values[idx] / max * h as f64 } else { 0.0 }
        })
        .collect();
    (0..h)
        .rev()
        .map(|r| {
            y.iter()
                .map(|&v| {
                    if v < 0.0 {
                        return if r == 0 { '·' } else { ' ' };
                    }
                    let f = v - r as f64;
                    if f >= 1.0 {
                        '█'
                    } else if f <= 0.0 {
                        if r == 0 { '▁' } else { ' ' }
                    } else {
                        let k = (f * 8.0 + 0.5) as usize;
                        if k < 1 { if r == 0 { '▁' } else { ' ' } } else { G[k.min(8)] }
                    }
                })
                .collect()
        })
        .collect()
}

/// Полоса задержки ├──▓▓┃▓▓──┤ в масштабе [lo, hi].
pub fn strip(w: usize, s: &stats::Stats, lo: f64, hi: f64, c: Color) -> Line<'static> {
    if w < 2 {
        return Line::default();   // окно слишком узкое
    }
    let hi = if hi <= lo { lo + 1.0 } else { hi };
    let x = |v: f64| (((v - lo) / (hi - lo) * (w - 1) as f64 + 0.5) as i64).clamp(0, w as i64 - 1) as usize;
    let (i0, i1, i2, i3, i4) = (x(s.min), x(s.p25), x(s.med), x(s.p75), x(s.max));
    let spans: Vec<Span> = (0..w)
        .map(|i| {
            if i == i2 {
                Span::styled("┃", Style::new().add_modifier(Modifier::BOLD))
            } else if i >= i1 && i <= i3 {
                col("▓", c)
            } else if i == i0 {
                col("├", c)
            } else if i == i4 {
                col("┤", c)
            } else if i > i0 && i < i4 {
                col("─", c)
            } else {
                gray("·")
            }
        })
        .collect();
    Line::from(spans)
}

fn nice_max(m: f64) -> f64 {
    if m <= 0.0 {
        return 1.0;
    }
    let e = 10f64.powf(m.log10().floor());
    let s = m / e;
    (if s <= 1.0 { 1.0 } else if s <= 2.0 { 2.0 } else if s <= 5.0 { 5.0 } else { 10.0 }) * e
}

fn tp_box(f: &mut Frame, area: Rect, v: &View, down: bool) {
    let (vals, dur, title, c) = if down {
        (&v.data.down, v.plan.download, "↓ Скачивание", GREEN)
    } else {
        (&v.data.up, v.plan.upload, "↑ Отдача", MAGENTA)
    };
    let live = v.saved.is_none();
    let st = result::tp_stats(vals, dur);
    let max = nice_max(st.map(|s| s.max).unwrap_or(0.0));
    let head = if live {
        Line::from(vec![bold(title), Span::raw("  "), col(fmt(vals.last().copied()), c).add_modifier(Modifier::BOLD), gray(" Мбит/с сейчас")])
    } else {
        Line::from(vec![bold(title), Span::raw("  "), col(fmt(st.map(|s| s.med)), c).add_modifier(Modifier::BOLD), gray(" Мбит/с (медиана)")])
    };
    let block = boxed(head, c);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width.saturating_sub(2) as usize;
    let h = inner.height.saturating_sub(1).max(1) as usize;
    let mut lines: Vec<Line> = chart(vals, w, h, max).into_iter().map(|s| Line::from(col(format!(" {s}"), c))).collect();
    let o = |x: Option<f64>| fmt(x);
    let mut foot = vec![
        gray(" ср "), Span::raw(o(st.map(|s| s.mean))),
        gray(" мед "), col(o(st.map(|s| s.med)), c),
        gray(" p25 "), Span::raw(o(st.map(|s| s.p25))),
        gray(" p75 "), Span::raw(o(st.map(|s| s.p75))),
    ];
    let scale = format!(" │ шкала {}", fmt(Some(max)));
    if Line::from(foot.clone()).width() + scale.chars().count() <= w {
        foot.push(gray(scale));
    }
    lines.push(Line::from(foot));
    f.render_widget(Paragraph::new(lines), inner);
}

fn lat_box(f: &mut Frame, area: Rect, vals: &[f64], title: &str, c: Color, lo: f64, hi: f64) {
    let st = stats::stats(vals);
    let block = boxed(Line::from(vec![bold(title), Span::raw(" "), col(fmt(st.map(|s| s.med)), c), gray(" мс")]), c);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width.saturating_sub(2) as usize;
    let lines = match st {
        Some(s) => vec![
            Line::from(vec![Span::raw(" ")].into_iter().chain(strip(w, &s, lo, hi, c).spans).collect::<Vec<_>>()),
            Line::from(vec![gray(" p25 "), Span::raw(fmt(Some(s.p25))), gray(" p75 "), Span::raw(fmt(Some(s.p75))), gray(" джиттер "), Span::raw(fmt(Some(s.sd)))]),
        ],
        None => vec![Line::from(gray(format!(" {}", "·".repeat(w)))), Line::from(gray(" ждёт…"))],
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn loss_box(f: &mut Frame, area: Rect, d: &Data) {
    let block = boxed(Line::from(vec![bold("≋ Потери пакетов"), gray(" UDP/STUN")]), BLUE);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width.saturating_sub(2) as usize;
    let lines = if d.udp_unreachable {
        vec![Line::from(vec![Span::raw(" "), col("STUN недоступен", RED), gray(" (UDP 3478 закрыт по пути)")])]
    } else if let Some(u) = result::udp(d) {
        let lab = stats::loss_label(u.loss);
        let lc = match lab {
            "Отлично" | "Хорошо" => GREEN,
            "Приемлемо" => YELLOW,
            _ => RED,
        };
        let (rtt, jit) = (u.rtt.map(|s| s.med), u.rtt.map(|s| s.sd));
        let mos = match (rtt, jit) {
            (Some(r), Some(j)) => format!("{:.1}", stats::mos(r, j, u.loss)),
            _ => "—".into(),
        };
        let ok = (u.recv as f64 / u.sent as f64 * w as f64 + 0.5) as usize;
        vec![
            Line::from(vec![
                Span::raw(" "), col(lab, lc).add_modifier(Modifier::BOLD),
                gray("  MOS "), Span::raw(mos),
                gray("  потери "), col(format!("{}%", u.loss), lc),
                gray("  RTT "), Span::raw(format!("{} мс", fmt(rtt))),
                gray("  джиттер "), Span::raw(format!("{} мс", fmt(jit))),
                gray("  пакетов "), Span::raw(format!("{}/{}", u.recv, u.sent)),
            ]),
            Line::from(vec![Span::raw(" "), col("▰".repeat(ok), GREEN), col("▱".repeat(w.saturating_sub(ok)), RED)]),
        ]
    } else {
        vec![Line::from(gray(" ждёт…"))]
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn final_boxes(f: &mut Frame, areas: (Rect, Rect), v: &View) {
    let d = v.data;
    let net = d.net.clone().unwrap_or_default();
    let meta = d.meta.clone().unwrap_or_default();
    let mut conn = net.family.clone();
    if net.iface != "?" && !net.iface.is_empty() {
        conn += &format!(" · {}", net.iface);
    }
    let left = vec![
        Line::from(vec![gray(" Подключение  "), Span::raw(conn)]),
        Line::from(vec![gray(" Провайдер    "), Span::raw(if meta.org.is_empty() { "?".into() } else { meta.org.clone() }), gray(format!(" AS{}", meta.asn))]),
        Line::from(vec![gray(" DNS          "), Span::raw(format!("{} мс", fmt(net.dns_ms))), gray("   TLS "), Span::raw(format!("{} мс {}", fmt(net.tls_ms), net.tls))]),
    ];
    let bb = result::bufferbloat(d);
    let (cvd, cvu) = result::cvs(d, v.plan);
    let worst = match (cvd, cvu) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let bg = bb.map(stats::bloat_grade).unwrap_or("-");
    let sg = worst.map(stats::stab_grade).unwrap_or("-");
    let right = vec![
        Line::from(vec![gray(" Bufferbloat   "), col(bg, grade_color(bg)).add_modifier(Modifier::BOLD), gray(format!(" +{} мс под нагрузкой", fmt(bb)))]),
        Line::from(vec![gray(" Стабильность  "), col(sg, grade_color(sg)).add_modifier(Modifier::BOLD), gray(format!(" разброс ↓{}% ↑{}%", fmt(cvd), fmt(cvu)))]),
        Line::from(vec![gray(" История       "), Span::raw(if v.saved == Some(true) { "сохранено · f2d speed history" } else { "не сохранено" })]),
    ];
    for (area, title, lines) in [(areas.0, "Сеть", left), (areas.1, "Оценка", right)] {
        let b = boxed(Line::from(bold(title)), GRAY);
        let inner = b.inner(area);
        f.render_widget(b, area);
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn keys_line(v: &View) -> Line<'static> {
    let k = |s: &str| Span::styled(s.to_string(), Style::new().fg(YELLOW).add_modifier(Modifier::BOLD));
    let mut l = vec![Span::raw(" "), k("A"), Span::raw(" автосохранение: "),
        if v.autosave { col("вкл", GREEN) } else { col("выкл", RED) }];
    if let Some(s) = v.saved {
        l.push(gray(if s { " (замер сохранён)" } else { " (замер не сохранён)" }));
    }
    l.extend([Span::raw("   "), k("R"), Span::raw(" заново   "), k("H"), Span::raw(" история   "), k("Q"), Span::raw(" выход")]);
    Line::from(l)
}

fn phase_marks(p: Phase) -> Vec<Span<'static>> {
    let order = [(Phase::Idle, "Простой"), (Phase::Download, "Скачивание"), (Phase::Upload, "Отдача"), (Phase::Loss, "Потери")];
    let rank = |x: Phase| match x {
        Phase::Net => 0,
        Phase::Idle => 1,
        Phase::Download => 2,
        Phase::Upload => 3,
        Phase::Loss => 4,
        Phase::Done => 5,
    };
    let mut out = vec![];
    for (ph, name) in order {
        let s = if ph == p {
            Span::styled(format!("◉ {name}"), Style::new().fg(YELLOW).add_modifier(Modifier::BOLD))
        } else if rank(p) > rank(ph) {
            col(format!("● {name}"), GREEN)
        } else {
            gray(format!("○ {name}"))
        };
        out.push(s);
        out.push(Span::raw("  "));
    }
    out
}

pub fn draw(f: &mut Frame, v: &View) {
    let full = f.area();
    let area = Rect { width: full.width.min(150), ..full };
    let d = v.data;
    let wide = area.width >= 100;
    let fin = v.saved.is_some();
    let tp_h = if wide { 11 } else { 22 };
    let lat_h = if wide { 4 } else { 12 };
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(tp_h),
        Constraint::Length(lat_h),
        Constraint::Length(4),
        Constraint::Length(if fin { if wide { 5 } else { 10 } } else { 0 }),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(area);

    let mut head = vec![
        Span::raw(" "),
        Span::styled("☁ Cloudflare Speedtest", Style::new().fg(MAGENTA).add_modifier(Modifier::BOLD)),
        gray(format!(" fail2detect v{}", v.version)),
        Span::raw("   "),
    ];
    head.extend(phase_marks(d.phase));
    f.render_widget(Paragraph::new(Line::from(head)), rows[0]);
    if let Some(m) = &d.meta {
        let mut s = String::new();
        if !m.colo.is_empty() {
            s += &format!("Cloudflare {}", m.colo);
            if !m.colo_city.is_empty() {
                s += &format!(" ({})", m.colo_city);
            }
        }
        if !m.asn.is_empty() {
            s += &format!(" · AS{} {}", m.asn, m.org);
        }
        f.render_widget(Paragraph::new(Line::from(vec![Span::raw(" "), gray(s), gray(" · "), col(m.ip.clone(), MAGENTA)])), rows[1]);
    }

    let tp = if wide { Layout::horizontal([Constraint::Ratio(1, 2); 2]).spacing(1).split(rows[2]) }
             else { Layout::vertical([Constraint::Ratio(1, 2); 2]).split(rows[2]) };
    tp_box(f, tp[0], v, true);
    tp_box(f, tp[1], v, false);

    // общая шкала трёх полос: от минимума до p95 с запасом
    let all: Vec<f64> = d.idle.iter().chain(&d.down_lat).chain(&d.up_lat).copied().collect();
    let (lo, hi) = match stats::stats(&all) {
        Some(s) => {
            let mut hi = s.p95 * 1.15;
            if hi > s.max || hi <= s.min {
                hi = s.max;
            }
            let pad = (hi - s.min) * 0.08 + 1.0;
            ((s.min - pad).max(0.0), hi + pad)
        }
        None => (0.0, 1.0),
    };
    let lat = if wide { Layout::horizontal([Constraint::Ratio(1, 3); 3]).spacing(1).split(rows[3]) }
              else { Layout::vertical([Constraint::Ratio(1, 3); 3]).split(rows[3]) };
    lat_box(f, lat[0], &d.idle, "◷ Простой", CYAN, lo, hi);
    lat_box(f, lat[1], &d.down_lat, "◷ При скачивании", GREEN, lo, hi);
    lat_box(f, lat[2], &d.up_lat, "◷ При отдаче", MAGENTA, lo, hi);
    loss_box(f, rows[4], d);
    if fin {
        let fb = if wide { Layout::horizontal([Constraint::Ratio(1, 2); 2]).spacing(1).split(rows[5]) }
                 else { Layout::vertical([Constraint::Ratio(1, 2); 2]).split(rows[5]) };
        final_boxes(f, (fb[0], fb[1]), v);
    }
    f.render_widget(Paragraph::new(keys_line(v)), rows[7]);
}

pub fn draw_history(f: &mut Frame, dir: &Path) {
    let rows = result::history_rows(dir);
    let mut lines = vec![
        Line::from(Span::styled(" История замеров (Cloudflare)", Style::new().fg(MAGENTA).add_modifier(Modifier::BOLD))),
        Line::from(gray(format!(" {}", "─".repeat(60)))),
        Line::from(bold(format!("  {:<17} {:<6} {:>10} {:>10} {:>9} {:>9} {:>6} {:>4} {:>4}",
            "Время", "Точка", "↓ Мбит/с", "↑ Мбит/с", "Простой", "Нагрузка", "Потери", "BB", "Стб"))),
    ];
    for r in &rows {
        lines.push(Line::from(vec![
            Span::raw(format!("  {:<17} {:<6} ", r[0], r[1])),
            col(format!("{:>10}", r[2]), GREEN),
            Span::raw(" "),
            col(format!("{:>10}", r[3]), MAGENTA),
            Span::raw(format!(" {:>6} мс {:>6} мс {:>6} ", r[4], r[5], r[6])),
            col(format!("{:>4}", r[7]), grade_color(&r[7])),
            Span::raw(" "),
            col(format!("{:>4}", r[8]), grade_color(&r[8])),
        ]));
    }
    if rows.is_empty() {
        lines.push(Line::from(vec![col("➜", CYAN), Span::raw(" Замеров ещё нет")]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(gray(" любая клавиша — назад")));
    f.render_widget(Paragraph::new(lines), f.area());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_size_and_blocks() {
        let c = chart(&[10.0, 50.0, 100.0, 30.0], 20, 5, 100.0);
        assert_eq!(c.len(), 5);
        assert!(c.iter().all(|l| l.chars().count() == 20));
        assert!(c.iter().any(|l| l.contains('█')));
        assert!(chart(&[], 8, 2, 1.0)[1].chars().all(|ch| ch == '·'));
    }

    #[test]
    fn strip_shape() {
        let s = stats::stats(&[10.0, 20.0, 25.0, 30.0, 40.0]).unwrap();
        let l: String = strip(30, &s, 0.0, 50.0, GREEN).spans.iter().map(|x| x.content.to_string()).collect();
        assert_eq!(l.chars().count(), 30);
        let (a, b, c, d) = (l.find('├').unwrap(), l.find('▓').unwrap(), l.find('┃').unwrap(), l.find('┤').unwrap());
        assert!(a < b && b < c && c < d, "{l}");
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::engine::{Data, Meta, Net, Phase, Plan};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    pub fn sample() -> Data {
        let mut d = Data::default();
        d.phase = Phase::Done;
        d.meta = Some(Meta { ip: "203.0.113.5".into(), asn: "64500".into(), org: "Test Net".into(), colo: "AMS".into(), colo_city: "Amsterdam".into(), ..Default::default() });
        d.net = Some(Net { family: "IPv4".into(), iface: "eth0".into(), dns_ms: Some(0.5), tls_ms: Some(8.1), tls: "TLSv1.3".into() });
        d.idle = vec![35.0, 36.0, 34.0, 40.0, 90.0, 35.5];
        d.down_lat = vec![38.0, 42.0, 41.0, 50.0];
        d.up_lat = vec![36.0, 45.0, 44.0, 54.0];
        d.down = (0..40).map(|i| 3800.0 + (i % 7) as f64 * 120.0).collect();
        d.up = (0..40).map(|i| 1400.0 + (i % 5) as f64 * 90.0).collect();
        d.udp = (0..50).map(|_| Some(1.2)).collect();
        d
    }

    fn render(w: u16, saved: Option<bool>) -> (String, usize) {
        let d = sample();
        let plan = Plan::new(false);
        let mut t = Terminal::new(TestBackend::new(w, 42)).unwrap();
        t.draw(|f| draw(f, &View { data: &d, plan: &plan, version: "1.0.4", autosave: true, saved })).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol().to_string()).collect();
            out += line.trim_end();
            out.push('\n');
        }
        let width = out.lines().map(|l| l.chars().count()).max().unwrap_or(0);
        (out, width)
    }

    #[test]
    fn final_screen_fits() {
        let (out, w) = render(160, Some(true));
        if std::env::var_os("SHOW").is_some() {
            println!("{out}");
        }
        assert!(w <= 150, "шире 150: {w}");
        assert!(out.contains("Bufferbloat") && out.contains("Отлично") && out.contains("сохранено"));
        let (out80, w80) = render(80, None);
        assert!(w80 <= 80, "{out80}");
    }
}
