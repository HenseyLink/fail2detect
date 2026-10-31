//! f2d-speed — Cloudflare Speedtest для fail2detect (f2d speed).
//!
//! Запускается из lib/speedtest.sh; без бинарника fail2detect работает на
//! bash-версии. Формат итога и истории у обеих версий общий.
//!
//!   f2d-speed [--quick] [--plain | --json] [--no-save] [--history-dir DIR]
//!             [--f2d-version X] [--state-out FILE]
//!   f2d-speed history [--history-dir DIR]
//!   f2d-speed --version

mod engine;
mod result;
mod stats;
mod ui;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use engine::{Phase, Plan, Shared};

pub const VERSION: &str = match option_env!("F2D_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

struct Args {
    quick: bool,
    plain: bool,
    json: bool,
    save: bool,
    history: bool,
    dir: PathBuf,
    f2d_version: String,
    state_out: Option<PathBuf>,
}

fn parse() -> Args {
    let mut a = Args {
        quick: false,
        plain: false,
        json: false,
        save: true,
        history: false,
        dir: PathBuf::from("/var/lib/fail2detect/speedtest"),
        f2d_version: VERSION.into(),
        state_out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--version" | "-V" => {
                println!("{VERSION}");
                std::process::exit(0);
            }
            "--quick" => a.quick = true,
            "--plain" => a.plain = true,
            "--json" => a.json = true,
            "--no-save" => a.save = false,
            "--tui" => {}
            "history" | "hist" => a.history = true,
            "--history-dir" => a.dir = it.next().map(PathBuf::from).unwrap_or(a.dir),
            "--f2d-version" => a.f2d_version = it.next().unwrap_or(a.f2d_version),
            "--state-out" => a.state_out = it.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("f2d-speed {VERSION}: Cloudflare Speedtest (fail2detect)\n  --quick  --plain  --json  --no-save  --history-dir DIR  history");
                std::process::exit(0);
            }
            other => {
                eprintln!("f2d-speed: неизвестный параметр {other}");
                std::process::exit(2);
            }
        }
    }
    if a.json || !std::io::stdout().is_terminal() {
        a.plain = true;
    }
    a
}

#[derive(PartialEq)]
enum Key {
    Quit,
    Restart,
    History,
    Autosave,
    Enter,
    Other,
}

fn key_action(code: KeyCode, mods: KeyModifiers) -> Key {
    match code {
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => Key::Quit,
        KeyCode::Char('q' | 'Q' | 'й' | 'Й') | KeyCode::Esc => Key::Quit,
        KeyCode::Char('r' | 'R' | 'к' | 'К') => Key::Restart,
        KeyCode::Char('h' | 'H' | 'р' | 'Р') => Key::History,
        KeyCode::Char('a' | 'A' | 'ф' | 'Ф') => Key::Autosave,
        KeyCode::Enter => Key::Enter,
        _ => Key::Other,
    }
}

/// SIGTERM/SIGHUP (kill, обрыв SSH): выйти, вернув терминал в обычный режим.
static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    TERMINATE.store(true, Ordering::Relaxed);
}

fn next_key(timeout: Duration) -> Option<Key> {
    if TERMINATE.load(Ordering::Relaxed) {
        return Some(Key::Quit);
    }
    match event::poll(timeout) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(_) => {
            std::thread::sleep(timeout);   // терминал недоступен — не крутиться вхолостую
            return None;
        }
    }
    match event::read().ok()? {
        Event::Key(k) if k.kind == KeyEventKind::Press => Some(key_action(k.code, k.modifiers)),
        _ => None,
    }
}

fn start(rt: &tokio::runtime::Runtime, plan: Plan) -> Arc<Shared> {
    let shared = Shared::new();
    rt.spawn(engine::run(shared.clone(), plan));
    shared
}

fn write_state(a: &Args, save: bool) {
    if let Some(p) = &a.state_out {
        let _ = std::fs::write(p, format!("SPEEDTEST_SAVE={}\n", if save { "yes" } else { "no" }));
    }
}

fn plain(a: &Args, rt: &tokio::runtime::Runtime, plan: Plan) {
    let shared = start(rt, plan);
    let spin = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let show = !a.json && std::io::stderr().is_terminal();
    let mut i = 0;
    loop {
        let p = shared.snapshot().phase;
        if p == Phase::Done {
            break;
        }
        if show {
            let name = match p {
                Phase::Net => "Сеть",
                Phase::Idle => "Простой",
                Phase::Download => "Скачивание",
                Phase::Upload => "Отдача",
                Phase::Loss => "Потери",
                Phase::Done => "Итог",
            };
            eprint!("\r  {} {name}…\x1b[K", spin[i % 10]);
            i += 1;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    if show {
        eprint!("\r\x1b[K");
    }
    let j = result::to_json(&shared.snapshot(), &plan);
    if a.save {
        result::save(&a.dir, &j);
    }
    if a.json {
        println!("{j}");
    } else {
        print!("{}", result::summary(&j, std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()));
    }
}

fn tui(a: &Args, rt: &tokio::runtime::Runtime, plan: Plan) -> std::io::Result<()> {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
    }
    let mut term = ratatui::init();
    let mut autosave = a.save;
    let mut last: Option<serde_json::Value> = None;
    'run: loop {
        let shared = start(rt, plan);
        let mut saved: Option<Option<PathBuf>> = None;   // Some — итог показан
        let mut j = serde_json::Value::Null;
        loop {
            let d = shared.snapshot();
            if saved.is_none() && d.phase == Phase::Done {
                j = result::to_json(&d, &plan);
                saved = Some(if autosave { result::save(&a.dir, &j) } else { None });
                last = Some(j.clone());
            }
            let view = ui::View {
                data: &d,
                plan: &plan,
                version: &a.f2d_version,
                autosave,
                saved: saved.as_ref().map(|s| s.is_some()),
            };
            term.draw(|f| ui::draw(f, &view))?;
            let Some(k) = next_key(Duration::from_millis(if saved.is_some() { 1000 } else { 120 })) else { continue };
            match k {
                Key::Quit => {
                    shared.cancel.store(true, Ordering::Relaxed);
                    break 'run;
                }
                Key::Enter if saved.is_some() => break 'run,
                Key::Restart => {
                    shared.cancel.store(true, Ordering::Relaxed);
                    continue 'run;
                }
                Key::History => {
                    term.draw(|f| ui::draw_history(f, &a.dir))?;
                    while next_key(Duration::from_millis(500)).is_none() {}
                }
                Key::Autosave => {
                    autosave = !autosave;
                    // на итоговом экране — сразу сохранить или убрать этот замер
                    if let Some(s) = saved.as_mut() {
                        match (autosave, s.take()) {
                            (true, None) => *s = result::save(&a.dir, &j),
                            (false, Some(p)) => {
                                let _ = std::fs::remove_file(p);
                            }
                            (_, keep) => *s = keep,
                        }
                    }
                }
                _ => {}
            }
        }
    }
    ratatui::restore();
    write_state(a, autosave);
    if let Some(j) = last {
        print!("{}", result::summary(&j, std::env::var_os("NO_COLOR").is_none()));
        let _ = std::io::stdout().flush();
    }
    Ok(())
}

fn main() {
    let a = parse();
    if a.history {
        let rows = result::history_rows(&a.dir);
        if rows.is_empty() {
            println!("➜ Замеров ещё нет: f2d speed");
        }
        for r in rows {
            println!("  {:<17} {:<6} {:>10} {:>10} {:>6} мс {:>6} мс {:>6} {:>4} {:>4}", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);
        }
        return;
    }
    let plan = Plan::new(a.quick);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
    if a.plain {
        plain(&a, &rt, plan);
        write_state(&a, a.save);
    } else if let Err(e) = tui(&a, &rt, plan) {
        ratatui::restore();
        eprintln!("f2d-speed: {e}");
        std::process::exit(1);
    }
    rt.shutdown_timeout(Duration::from_millis(200));
}
