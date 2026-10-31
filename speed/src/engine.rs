//! Замеры speed.cloudflare.com.
//!
//! * задержка в простое: запросы __down?bytes=0 каждые 250 мс по уже открытому
//!   соединению (время до заголовков ответа = круг до сервера);
//! * скачивание и отдача: 6 потоков, у каждого своё TCP-соединение (HTTP/1.1,
//!   keep-alive); скорость — по окнам 250 мс: при скачивании байты считаются
//!   по мере прихода, при отдаче — по завершённым запросам (буфер сокета
//!   глотает мегабайты сразу); размер запроса поток подгоняет под свою
//!   скорость (≈1 с), чтобы ожидание ответа сервера не съедало скорость;
//! * рядом — задержка под нагрузкой (during=download|upload) отдельным соединением;
//! * потери: STUN binding request'ы на stun.cloudflare.com:3478 раз в 100 мс.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use rand::RngCore;

pub const BASE: &str = "https://speed.cloudflare.com";
pub const STUN_HOST: &str = "stun.cloudflare.com:3478";
pub const BUCKET: f64 = 0.25;
pub const WORKERS: usize = 6;
const UA: &str = "Mozilla/5.0 fail2detect";

#[cfg(test)]
mod tests {
    #[test]
    fn series_spreads_bytes_over_windows() {
        // 1 МБ за [0.5; 1.0] с → окна 2 и 3 по 16 Мбит/с, как у bash-версии
        assert_eq!(super::series(&[(0.5, 1.0, 1_000_000)], 8), vec![0.0, 0.0, 16.0, 16.0, 0.0, 0.0, 0.0, 0.0]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Net,
    Idle,
    Download,
    Upload,
    Loss,
    Done,
}

#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub idle: f64,
    pub download: f64,
    pub upload: f64,
    pub udp: usize,
}

impl Plan {
    pub fn new(quick: bool) -> Self {
        if quick {
            Plan { idle: 2.0, download: 5.0, upload: 5.0, udp: 25 }
        } else {
            Plan { idle: 2.0, download: 10.0, upload: 10.0, udp: 50 }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub ip: String,
    pub asn: String,
    pub org: String,
    pub colo: String,
    pub colo_city: String,
    pub city: String,
    pub country: String,
}

#[derive(Clone, Debug, Default)]
pub struct Net {
    pub family: String,
    pub iface: String,
    pub dns_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub tls: String,
}

/// Всё, что намерено к этому моменту; экран берёт копию.
#[derive(Clone, Debug)]
pub struct Data {
    pub phase: Phase,
    pub meta: Option<Meta>,
    pub net: Option<Net>,
    pub idle: Vec<f64>,
    pub down_lat: Vec<f64>,
    pub up_lat: Vec<f64>,
    pub down: Vec<f64>,
    pub up: Vec<f64>,
    /// по одному на отправленный STUN-запрос: Some(rtt мс) или None (потерян)
    pub udp: Vec<Option<f64>>,
    pub udp_unreachable: bool,
}

impl Default for Data {
    fn default() -> Self {
        Data {
            phase: Phase::Net,
            meta: None,
            net: None,
            idle: vec![],
            down_lat: vec![],
            up_lat: vec![],
            down: vec![],
            up: vec![],
            udp: vec![],
            udp_unreachable: false,
        }
    }
}

pub struct Shared {
    pub data: Mutex<Data>,
    /// остановить всё (R — заново, Q — выход)
    pub cancel: AtomicBool,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Shared { data: Mutex::new(Data::default()), cancel: AtomicBool::new(false) })
    }
    pub fn snapshot(&self) -> Data {
        self.data.lock().unwrap().clone()
    }
    fn with<F: FnOnce(&mut Data)>(&self, f: F) {
        f(&mut self.data.lock().unwrap())
    }
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(UA)
        .http1_only()
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(1)
        .tcp_nodelay(true)
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(reqwest::header::REFERER, "https://speed.cloudflare.com/".parse().unwrap());
            h
        })
        .build()
        .expect("http client")
}

pub async fn run(shared: Arc<Shared>, plan: Plan) {
    let s = shared.clone();
    s.with(|d| d.phase = Phase::Net);
    net_info(&s).await;
    if s.cancelled() {
        return;
    }
    s.with(|d| d.phase = Phase::Idle);
    latency_loop(&s, None, plan.idle, |d, v| d.idle.push(v)).await;
    if s.cancelled() {
        return;
    }
    s.with(|d| d.phase = Phase::Download);
    transfer_phase(&s, true, plan.download).await;
    if s.cancelled() {
        return;
    }
    s.with(|d| d.phase = Phase::Upload);
    transfer_phase(&s, false, plan.upload).await;
    if s.cancelled() {
        return;
    }
    s.with(|d| d.phase = Phase::Loss);
    udp_loss(&s, plan.udp).await;
    if s.cancelled() {
        return;
    }
    s.with(|d| d.phase = Phase::Done);
}

// ------------------------------------------------------------------ сеть

async fn net_info(s: &Shared) {
    let c = client();
    let mut meta = Meta::default();
    if let Ok(r) = c.get(format!("{BASE}/meta")).timeout(Duration::from_secs(6)).send().await {
        if let Ok(j) = r.json::<serde_json::Value>().await {
            let st = |k: &str| match &j[k] {
                serde_json::Value::String(x) => x.clone(),
                serde_json::Value::Number(x) => x.to_string(),
                _ => String::new(),
            };
            meta.ip = st("clientIp");
            meta.asn = st("asn");
            meta.org = st("asOrganization");
            meta.city = st("city");
            meta.country = st("country");
            match &j["colo"] {
                serde_json::Value::Object(o) => {
                    meta.colo = o.get("iata").and_then(|v| v.as_str()).unwrap_or("").into();
                    meta.colo_city = o.get("city").and_then(|v| v.as_str()).unwrap_or("").into();
                }
                serde_json::Value::String(x) => meta.colo = x.clone(),
                _ => {}
            }
        }
    }
    if meta.ip.is_empty() {
        // запасной путь — cdn-cgi/trace (ip=…, colo=…, loc=…)
        if let Ok(r) = c.get(format!("{BASE}/cdn-cgi/trace")).timeout(Duration::from_secs(6)).send().await {
            if let Ok(t) = r.text().await {
                for line in t.lines() {
                    match line.split_once('=') {
                        Some(("ip", v)) => meta.ip = v.into(),
                        Some(("colo", v)) => meta.colo = v.into(),
                        Some(("loc", v)) => meta.country = v.into(),
                        _ => {}
                    }
                }
            }
        }
    }
    let v6 = meta.ip.contains(':');
    s.with(|d| d.meta = Some(meta));

    let mut net = Net { family: if v6 { "IPv6" } else { "IPv4" }.into(), ..Default::default() };
    let host = BASE.trim_start_matches("https://");
    let t = Instant::now();
    if let Ok(mut addrs) = tokio::net::lookup_host((host, 443)).await {
        net.dns_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
        if let Some(addr) = addrs.find(|a| a.is_ipv6() == v6).or(None) {
            if let Some((ms, ver)) = tls_handshake(host, addr).await {
                net.tls_ms = Some(ms);
                net.tls = ver;
            }
        }
    }
    net.iface = route_iface(v6).unwrap_or_else(|| "?".into());
    s.with(|d| d.net = Some(net));
}

async fn tls_handshake(host: &str, addr: std::net::SocketAddr) -> Option<(f64, String)> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await.ok()?.ok()?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let t = Instant::now();
    let tls = tokio::time::timeout(Duration::from_secs(5), tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp))
        .await
        .ok()?
        .ok()?;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    let ver = match tls.get_ref().1.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "?",
    };
    Some((ms, ver.into()))
}

fn route_iface(v6: bool) -> Option<String> {
    let dst = if v6 { "2606:4700:4700::1111" } else { "1.1.1.1" };
    let out = std::process::Command::new("ip").args(["route", "get", dst]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.split_whitespace();
    while let Some(w) = it.next() {
        if w == "dev" {
            return it.next().map(String::from);
        }
    }
    None
}

// ------------------------------------------------------------------ задержка

/// Запросы bytes=0 каждые 250 мс по одному соединению; первый (с рукопожатием) не считается.
async fn latency_loop<F>(s: &Shared, during: Option<&str>, secs: f64, mut push: F)
where
    F: FnMut(&mut Data, f64),
{
    let c = client();
    let url = match during {
        Some(d) => format!("{BASE}/__down?bytes=0&during={d}"),
        None => format!("{BASE}/__down?bytes=0"),
    };
    let _ = c.get(&url).timeout(Duration::from_secs(3)).send().await.map(drop);
    let end = Instant::now() + Duration::from_secs_f64(secs);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    while Instant::now() < end && !s.cancelled() {
        tick.tick().await;
        let t = Instant::now();
        if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_secs(2), c.get(&url).send()).await {
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            let _ = r.bytes().await;   // дочитать — иначе соединение не вернётся в пул
            s.with(|d| push(d, (ms * 10.0).round() / 10.0));
        }
    }
}

// ------------------------------------------------------------------ скорость

/// Размер следующего запроса: ≈1 с при скорости потока (байт за секунды).
fn adapt(size: &AtomicU64, bytes: u64, secs: f64, max: u64) {
    if secs > 0.02 && bytes > 0 {
        let want = (bytes as f64 / secs).clamp(256.0 * 1024.0, max as f64) as u64;
        size.store(want, Ordering::Relaxed);
    }
}

/// Скачивание: байты считаются по мере прихода — это и есть скорость приёма.
async fn down_worker(s: Arc<Shared>, stop: Arc<AtomicBool>, counter: Arc<AtomicU64>) {
    let c = client();
    let size = AtomicU64::new(1_000_000);
    while !stop.load(Ordering::Relaxed) && !s.cancelled() {
        let t = Instant::now();
        let url = format!("{BASE}/__down?bytes={}", size.load(Ordering::Relaxed));
        let mut resp = match c.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(_) => {
                // слишком большой запрос сервер может не принять — уменьшаем
                size.store((size.load(Ordering::Relaxed) / 2).max(256 * 1024), Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let mut got = 0u64;
        while let Ok(Some(chunk)) = resp.chunk().await {
            counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            got += chunk.len() as u64;
            if stop.load(Ordering::Relaxed) || s.cancelled() {
                return;
            }
        }
        adapt(&size, got, t.elapsed().as_secs_f64(), 100_000_000);
    }
}

/// Завершённая передача: начало и конец (с от начала фазы), байты.
pub type Event = (f64, f64, u64);

/// Отдача: момент, когда сокет «забрал» байты, ничего не говорит — буфер ядра
/// глотает мегабайты сразу. Поэтому запрос учитывается целиком по завершении:
/// байты раскладываются по окнам его длительности (запрос ≈1 с).
async fn up_worker(s: Arc<Shared>, stop: Arc<AtomicBool>, events: Arc<Mutex<Vec<Event>>>, start: Instant, pool: Bytes) {
    let c = client();
    let size = AtomicU64::new(1_000_000);
    while !stop.load(Ordering::Relaxed) && !s.cancelled() {
        let len = size.load(Ordering::Relaxed);
        let piece = 64 * 1024u64;
        let pool2 = pool.clone();
        let body = futures::stream::iter(0..len.div_ceil(piece)).map(move |i| {
            let take = piece.min(len - i * piece) as usize;
            let off = (i * piece) as usize % (pool2.len() - take);
            Ok::<Bytes, std::io::Error>(pool2.slice(off..off + take))
        });
        let t0 = start.elapsed().as_secs_f64();
        let r = c
            .post(format!("{BASE}/__up"))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, len)
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await;
        match r {
            Ok(r) if r.status().is_success() => {
                let t1 = start.elapsed().as_secs_f64();
                let _ = r.bytes().await;
                if !s.cancelled() {
                    events.lock().unwrap().push((t0, t1, len));
                }
                adapt(&size, len, t1 - t0, 50_000_000);
            }
            Ok(_) => size.store((len / 2).max(256 * 1024), Ordering::Relaxed),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// Мбит/с по окнам: байты каждой передачи — равномерно по её длительности.
pub fn series(events: &[Event], buckets: usize) -> Vec<f64> {
    let mut acc = vec![0f64; buckets];
    for &(s, e, by) in events {
        let s = if e <= s { e - 0.001 } else { s };
        let len = e - s;
        let mut i = (s.max(0.0) / BUCKET) as usize;
        while i < buckets && (i as f64) * BUCKET < e {
            let lo = s.max(i as f64 * BUCKET);
            let hi = e.min((i + 1) as f64 * BUCKET);
            if hi > lo {
                acc[i] += by as f64 * (hi - lo) / len;
            }
            i += 1;
        }
    }
    acc.iter().map(|b| b * 8.0 / BUCKET / 1e6).collect()
}

async fn transfer_phase(s: &Arc<Shared>, down: bool, secs: f64) {
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(vec![]));
    let pool = if down {
        Bytes::new()
    } else {
        let mut b = vec![0u8; 4 * 1024 * 1024];
        rand::thread_rng().fill_bytes(&mut b);
        Bytes::from(b)
    };
    let start = Instant::now();
    let tstart = tokio::time::Instant::now();
    let mut tasks = vec![];
    for _ in 0..WORKERS {
        let (s2, st) = (s.clone(), stop.clone());
        tasks.push(if down {
            tokio::spawn(down_worker(s2, st, counter.clone()))
        } else {
            tokio::spawn(up_worker(s2, st, events.clone(), start, pool.clone()))
        });
    }
    let s3 = s.clone();
    let lat = tokio::spawn(async move {
        if down {
            latency_loop(&s3, Some("download"), secs, |d, v| d.down_lat.push(v)).await
        } else {
            latency_loop(&s3, Some("upload"), secs, |d, v| d.up_lat.push(v)).await
        }
    });
    // окна по 250 мс от начала фазы
    let buckets = (secs / BUCKET).round() as usize;
    let mut last = 0u64;
    for i in 1..=buckets {
        tokio::time::sleep_until(tstart + Duration::from_secs_f64(BUCKET * i as f64)).await;
        if s.cancelled() {
            break;
        }
        if down {
            let now = counter.load(Ordering::Relaxed);
            let mbps = (now - last) as f64 * 8.0 / BUCKET / 1e6;
            last = now;
            s.with(|d| d.down.push(mbps));
        } else {
            // по ходу — окна, которые уже не дополнят запросы в полёте (≈1 с)
            let ready = i.saturating_sub((1.0 / BUCKET) as usize);
            let v = series(&events.lock().unwrap(), ready);
            s.with(|d| d.up = v);
        }
    }
    stop.store(true, Ordering::Relaxed);
    if !down {
        // дать завершиться запросам в полёте: их байты есть и в последних окнах фазы
        let grace = tokio::time::Instant::now() + Duration::from_millis(2500);
        while tasks.iter().any(|t| !t.is_finished()) && tokio::time::Instant::now() < grace && !s.cancelled() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let v = series(&events.lock().unwrap(), buckets);
        s.with(|d| d.up = v);
    }
    for t in tasks {
        t.abort();
    }
    let _ = lat.await;
}

// ------------------------------------------------------------------ потери

async fn udp_loss(s: &Shared, n: usize) {
    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(x) => x,
        Err(_) => return s.with(|d| d.udp_unreachable = true),
    };
    if sock.connect(STUN_HOST).await.is_err() {
        return s.with(|d| d.udp_unreachable = true);
    }
    let sock = Arc::new(sock);
    // id транзакции STUN → (номер запроса, время отправки)
    type Sent = HashMap<[u8; 12], (usize, Instant)>;
    let sent: Arc<Mutex<Sent>> = Arc::new(Mutex::new(HashMap::new()));
    let rtts: Arc<Mutex<Vec<Option<f64>>>> = Arc::new(Mutex::new(vec![None; n]));
    let (rs, rsent, rrtt) = (sock.clone(), sent.clone(), rtts.clone());
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok(len) = rs.recv(&mut buf).await {
            if len < 20 {
                continue;
            }
            let mut id = [0u8; 12];
            id.copy_from_slice(&buf[8..20]);
            if let Some((i, t)) = rsent.lock().unwrap().get(&id) {
                rrtt.lock().unwrap()[*i] = Some((t.elapsed().as_secs_f64() * 10000.0).round() / 10.0);
            }
        }
    });
    for i in 0..n {
        if s.cancelled() {
            break;
        }
        let id: [u8; 12] = rand::random();
        let mut pkt = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        pkt.extend_from_slice(&id);
        sent.lock().unwrap().insert(id, (i, Instant::now()));
        let _ = sock.send(&pkt).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        // на экране — ответы, пришедшие к этому моменту (опоздавшие досчитаются в конце)
        let cur = rtts.lock().unwrap()[..=i].to_vec();
        s.with(|d| d.udp = cur);
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;
    reader.abort();
    let fin = rtts.lock().unwrap().clone();
    let none = fin.iter().all(|x| x.is_none());
    s.with(|d| {
        d.udp = fin;
        d.udp_unreachable = none;
    });
}
