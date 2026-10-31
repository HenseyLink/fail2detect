//! Статистика замеров — те же формулы, что в bash-версии (lib/speedtest.sh):
//! перцентили с интерполяцией, джиттер — стандартное отклонение (n-1),
//! MOS — упрощённая E-модель ITU-T G.107.

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stats {
    pub n: usize,
    pub mean: f64,
    pub med: f64,
    pub p25: f64,
    pub p75: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
    pub sd: f64,
}

pub fn stats(values: &[f64]) -> Option<Stats> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    let mean = v.iter().sum::<f64>() / n as f64;
    let sd = if n > 1 { (v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt() } else { 0.0 };
    let pct = |p: f64| {
        let pos = p * (n - 1) as f64;
        let lo = pos.floor() as usize;
        let hi = if pos > lo as f64 { lo + 1 } else { lo };
        v[lo] + (pos - lo as f64) * (v[hi] - v[lo])
    };
    Some(Stats { n, mean, med: pct(0.5), p25: pct(0.25), p75: pct(0.75), p95: pct(0.95), min: v[0], max: v[n - 1], sd })
}

/// Коэффициент вариации, % (нужно ≥3 значений).
pub fn cv(values: &[f64]) -> Option<f64> {
    if values.len() < 3 {
        return None;
    }
    let s = stats(values)?;
    if s.mean == 0.0 {
        return None;
    }
    Some(s.sd / s.mean * 100.0)
}

/// MOS (1…5): rtt и джиттер в мс, потери в %.
pub fn mos(rtt: f64, jitter: f64, loss: f64) -> f64 {
    let d = (rtt / 2.0 + 2.0 * jitter).min(177.3);
    let r = (93.2 - d / 40.0 - 30.0 * (loss / 100.0).min(1.0)).clamp(0.0, 100.0);
    let m = 1.0 + 0.035 * r + 7e-6 * r * (r - 60.0) * (100.0 - r);
    (m.clamp(1.0, 5.0) * 10.0).round() / 10.0
}

pub fn loss_label(loss: f64) -> &'static str {
    if loss == 0.0 {
        "Отлично"
    } else if loss < 1.0 {
        "Хорошо"
    } else if loss < 2.5 {
        "Приемлемо"
    } else if loss < 5.0 {
        "Плохо"
    } else {
        "Очень плохо"
    }
}

pub fn bloat_grade(ms: f64) -> &'static str {
    let v = ms.max(0.0);
    match v {
        v if v <= 5.0 => "A+",
        v if v <= 30.0 => "A",
        v if v <= 60.0 => "B",
        v if v <= 200.0 => "C",
        v if v <= 400.0 => "D",
        _ => "F",
    }
}

pub fn stab_grade(cv: f64) -> &'static str {
    match cv {
        v if v <= 5.0 => "A",
        v if v <= 10.0 => "B",
        v if v <= 20.0 => "C",
        v if v <= 35.0 => "D",
        _ => "F",
    }
}

/// Без разгона: первые 20% фазы, но не меньше 1 с.
pub fn steady(buckets: &[f64], dur: f64, bucket: f64) -> &[f64] {
    let skip = ((dur * 0.2).max(1.0) / bucket + 0.5) as usize;
    if buckets.len() > skip { &buckets[skip..] } else { &[] }
}

/// Число для экрана: ≥100 — целое, ≥10 — один знак, иначе два.
pub fn fmt(v: Option<f64>) -> String {
    match v {
        None => "—".into(),
        Some(v) if v >= 100.0 => format!("{v:.0}"),
        Some(v) if v >= 10.0 => format!("{v:.1}"),
        Some(v) => format!("{v:.2}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_like_bash() {
        let s = stats(&[10.0, 20.0, 30.0, 40.0, 50.0]).unwrap();
        assert_eq!((s.n, s.mean, s.med, s.p25, s.p75), (5, 30.0, 30.0, 20.0, 40.0));
        assert!((s.p95 - 48.0).abs() < 1e-9);
        assert!((s.sd - 15.811).abs() < 1e-3);
        assert_eq!(stats(&[7.0]).unwrap().sd, 0.0);
        assert!(stats(&[]).is_none());
    }

    #[test]
    fn cv_mos_grades() {
        assert!((cv(&[90.0, 100.0, 110.0]).unwrap() - 10.0).abs() < 1e-9);
        assert!(cv(&[100.0, 100.0]).is_none());
        assert!(mos(20.0, 2.0, 0.0) >= 4.0);
        assert!(mos(30.0, 5.0, 10.0) < mos(30.0, 5.0, 0.0));
        assert_eq!([bloat_grade(-3.0), bloat_grade(29.0), bloat_grade(800.0)], ["A+", "A", "F"]);
        assert_eq!([stab_grade(3.0), stab_grade(15.0), stab_grade(40.0)], ["A", "C", "F"]);
        assert_eq!(loss_label(2.0), "Приемлемо");
    }

    #[test]
    fn steady_skips_ramp() {
        let v: Vec<f64> = (1..=40).map(f64::from).collect();
        assert_eq!(steady(&v, 10.0, 0.25)[0], 9.0);
        let v: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(steady(&v, 4.0, 0.25)[0], 5.0);
    }
}
