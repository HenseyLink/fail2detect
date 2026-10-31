//! Итог замера: JSON (тот же формат, что пишет bash-версия, — история общая),
//! сохранение в историю, текстовая сводка.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::engine::{Data, Plan, BUCKET};
use crate::stats::{self, Stats};

fn r2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn tp_json(s: Option<Stats>) -> Value {
    match s {
        Some(s) => json!({"mean": r2(s.mean), "med": r2(s.med), "p25": r2(s.p25), "p75": r2(s.p75), "p95": r2(s.p95), "max": r2(s.max)}),
        None => Value::Null,
    }
}

fn lat_json(s: Option<Stats>) -> Value {
    match s {
        Some(s) => json!({"n": s.n, "mean": r2(s.mean), "med": r2(s.med), "p25": r2(s.p25), "p75": r2(s.p75),
                          "p95": r2(s.p95), "min": r2(s.min), "max": r2(s.max), "jitter": r2(s.sd)}),
        None => Value::Null,
    }
}

/// Скорость фазы без разгона (если окон мало — по всем).
pub fn tp_stats(v: &[f64], dur: f64) -> Option<Stats> {
    stats::stats(stats::steady(v, dur, BUCKET)).or_else(|| stats::stats(v))
}

pub struct Udp {
    pub sent: usize,
    pub recv: usize,
    pub loss: f64,
    pub rtt: Option<Stats>,
}

pub fn udp(d: &Data) -> Option<Udp> {
    if d.udp.is_empty() {
        return None;
    }
    let ok: Vec<f64> = d.udp.iter().flatten().copied().collect();
    let sent = d.udp.len();
    let loss = ((sent - ok.len()) as f64 * 1000.0 / sent as f64).round() / 10.0;
    Some(Udp { sent, recv: ok.len(), loss, rtt: stats::stats(&ok) })
}

pub fn bufferbloat(d: &Data) -> Option<f64> {
    let idle = stats::stats(&d.idle)?.med;
    [stats::stats(&d.down_lat), stats::stats(&d.up_lat)]
        .iter()
        .flatten()
        .map(|s| s.med - idle)
        .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))))
        .map(|x| x.max(0.0))
}

pub fn cvs(d: &Data, plan: &Plan) -> (Option<f64>, Option<f64>) {
    (
        stats::cv(stats::steady(&d.down, plan.download, BUCKET)),
        stats::cv(stats::steady(&d.up, plan.upload, BUCKET)),
    )
}

pub fn to_json(d: &Data, plan: &Plan) -> Value {
    let meta = d.meta.clone().unwrap_or_default();
    let net = d.net.clone().unwrap_or_default();
    let (cvd, cvu) = cvs(d, plan);
    let udp = match udp(d) {
        Some(u) if u.recv > 0 => {
            let rtt = u.rtt.unwrap();
            json!({"sent": u.sent, "recv": u.recv, "loss": u.loss, "rtt": r2(rtt.med), "jitter": r2(rtt.sd),
                   "mos": stats::mos(rtt.med, rtt.sd, u.loss), "label": stats::loss_label(u.loss)})
        }
        _ if d.udp_unreachable => json!({"unreachable": true}),
        _ => Value::Null,
    };
    let opt = |v: Option<f64>| v.map(|x| json!(r2(x))).unwrap_or(Value::Null);
    let worst = match (cvd, cvu) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    // net — строками, как в bash-версии
    let f2 = |v: Option<f64>| v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "?".into());
    json!({
        "time": utc_now(),
        "meta": {"ip": meta.ip, "asn": meta.asn.parse::<u64>().map(Value::from).unwrap_or(Value::from(meta.asn.clone())),
                 "org": meta.org, "colo": meta.colo, "colo_city": meta.colo_city, "city": meta.city, "country": meta.country},
        "net": {"family": net.family, "iface": net.iface, "dns": f2(net.dns_ms), "tls_ms": f2(net.tls_ms), "tls": if net.tls.is_empty() { "?".into() } else { net.tls }},
        "download": tp_json(tp_stats(&d.down, plan.download)),
        "upload": tp_json(tp_stats(&d.up, plan.upload)),
        "idle_latency": lat_json(stats::stats(&d.idle)),
        "loaded_latency_download": lat_json(stats::stats(&d.down_lat)),
        "loaded_latency_upload": lat_json(stats::stats(&d.up_lat)),
        "udp": udp,
        "cv_download": opt(cvd.map(|x| (x * 10.0).round() / 10.0)),
        "cv_upload": opt(cvu.map(|x| (x * 10.0).round() / 10.0)),
        "bufferbloat_ms": opt(bufferbloat(d)),
        "cv_worst": opt(worst.map(|x| (x * 10.0).round() / 10.0)),
        "engine": "rust",
    })
}

// ------------------------------------------------------------------ время

fn tm(local: bool) -> libc::tm {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut out: libc::tm = std::mem::zeroed();
        if local {
            libc::localtime_r(&t, &mut out);
        } else {
            libc::gmtime_r(&t, &mut out);
        }
        out
    }
}

fn utc_now() -> String {
    let t = tm(false);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
}

fn local_stamp() -> String {
    let t = tm(true);
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
}

// ------------------------------------------------------------------ история

/// Сохранить замер (имя — местное время, как у bash-версии); хранить 100 последних.
pub fn save(dir: &Path, result: &Value) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    let path = dir.join(format!("{}.json", local_stamp()));
    std::fs::write(&path, result.to_string()).ok()?;
    let mut all = list(dir);
    if all.len() > 100 {
        all.truncate(all.len() - 100);
        for p in all {
            let _ = std::fs::remove_file(p);
        }
    }
    Some(path)
}

pub fn list(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// Строки таблицы истории (новые сверху, до 20): время, точка, ↓, ↑, простой, нагрузка, потери, BB, стабильность.
pub fn history_rows(dir: &Path) -> Vec<[String; 9]> {
    let mut rows = vec![];
    for p in list(dir).iter().rev().take(20) {
        let Ok(txt) = std::fs::read_to_string(p) else { continue };
        let Ok(j) = serde_json::from_str::<Value>(&txt) else { continue };
        let f = |v: &Value| v.as_f64();
        let time = j["time"].as_str().unwrap_or("?").replace('T', " ");
        let time = time.trim_end_matches('Z').rsplit_once(':').map(|x| x.0.to_string()).unwrap_or(time);
        let floor = |v: Option<f64>| format!("{}", v.unwrap_or(0.0).floor() as i64);
        let loaded = [f(&j["loaded_latency_download"]["med"]), f(&j["loaded_latency_upload"]["med"])]
            .iter()
            .map(|x| x.unwrap_or(0.0))
            .fold(0.0, f64::max);
        let loss = f(&j["udp"]["loss"]).map(|x| format!("{x}%")).unwrap_or_else(|| "—".into());
        let bb = f(&j["bufferbloat_ms"]).map(|x| stats::bloat_grade(x).to_string()).unwrap_or_else(|| "-".into());
        let sg = f(&j["cv_worst"]).map(|x| stats::stab_grade(x).to_string()).unwrap_or_else(|| "-".into());
        rows.push([
            time,
            j["meta"]["colo"].as_str().unwrap_or("?").to_string(),
            floor(f(&j["download"]["med"])),
            floor(f(&j["upload"]["med"])),
            floor(f(&j["idle_latency"]["med"])),
            floor(Some(loaded)),
            loss,
            bb,
            sg,
        ]);
    }
    rows
}

// ------------------------------------------------------------------ сводка текстом

pub struct Paint {
    pub on: bool,
}

impl Paint {
    pub fn c(&self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
}

pub fn summary(j: &Value, color: bool) -> String {
    let p = Paint { on: color };
    let f = |v: &Value| stats::fmt(v.as_f64());
    let g = |s: &str| p.c("0;90", s);
    let mut out = String::new();
    let m = &j["meta"];
    out += &format!(" {} {}\n", p.c("1;35", "☁ Cloudflare Speedtest"),
        g(&format!("{} · AS{} {} · {}", m["colo"].as_str().unwrap_or("?"), m["asn"], m["org"].as_str().unwrap_or(""), m["ip"].as_str().unwrap_or(""))));
    out += &format!("  {} {} {}   {} {} {}\n",
        g("↓ Скачивание"), p.c("1;32", &f(&j["download"]["med"])), g("Мбит/с"),
        g("↑ Отдача"), p.c("1;35", &f(&j["upload"]["med"])), g("Мбит/с"));
    out += &format!("  {} {} мс   {} {} мс   {} {} мс\n",
        g("Простой"), f(&j["idle_latency"]["med"]),
        g("при скачивании"), f(&j["loaded_latency_download"]["med"]),
        g("при отдаче"), f(&j["loaded_latency_upload"]["med"]));
    let u = &j["udp"];
    if u["unreachable"].as_bool() == Some(true) {
        out += &format!("  {} {}\n", g("Потери"), p.c("1;31", "STUN недоступен (UDP 3478 закрыт по пути)"));
    } else if !u.is_null() {
        out += &format!("  {} {} ({}%, {} из {}, MOS {})\n", g("Потери"), u["label"].as_str().unwrap_or("?"), u["loss"], u["recv"], u["sent"], u["mos"]);
    }
    let bb = j["bufferbloat_ms"].as_f64();
    let cv = j["cv_worst"].as_f64();
    out += &format!("  {} {} {}   {} {}\n",
        g("Bufferbloat"), bb.map(stats::bloat_grade).unwrap_or("-"), g(&format!("+{} мс", stats::fmt(bb))),
        g("Стабильность"), cv.map(stats::stab_grade).unwrap_or("-"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Data;

    fn sample() -> Data {
        let mut d = Data::default();
        d.idle = vec![20.0, 21.0, 22.0, 20.0, 23.0];
        d.down_lat = vec![40.0, 42.0, 45.0, 41.0];
        d.up_lat = vec![30.0, 31.0, 29.0];
        d.down = vec![100.0; 40];
        d.up = vec![50.0; 40];
        d.udp = (0..49).map(|_| Some(15.0)).chain([None]).collect();
        d
    }

    #[test]
    fn json_matches_bash_format() {
        let j = to_json(&sample(), &Plan::new(false));
        assert_eq!(j["download"]["med"], 100.0);
        assert_eq!(j["upload"]["med"], 50.0);
        assert_eq!(j["idle_latency"]["med"], 21.0);
        assert_eq!(j["bufferbloat_ms"], 20.5);
        assert_eq!(j["udp"]["loss"], 2.0);
        assert_eq!(j["udp"]["recv"], 49);
        assert_eq!(j["udp"]["label"], "Приемлемо");
        assert_eq!(j["cv_worst"], 0.0);
    }

    #[test]
    fn history_roundtrip() {
        let dir = std::env::temp_dir().join(format!("f2d-speed-test-{}", std::process::id()));
        let j = to_json(&sample(), &Plan::new(false));
        let p = save(&dir, &j).unwrap();
        let rows = history_rows(&dir);
        assert_eq!(rows[0][2], "100");
        assert_eq!(rows[0][6], "2%");
        assert_eq!(rows[0][7], "A");
        std::fs::remove_file(p).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }
}
