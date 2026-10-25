//! Collector registry: every area by name, run in parallel with a deadline.

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use agenticdisk_core::{Kb, Section, cleanup, trace};

pub type Collector = (&'static str, Box<dyn FnOnce() -> Section + Send>);

#[cfg(windows)]
pub const AREAS: [&str; 8] = ["system", "cleanup", "drivers", "privacy", "startup", "apps", "security", "stability"];
#[cfg(not(windows))]
pub const AREAS: [&str; 1] = ["cleanup"];

#[cfg(windows)]
pub fn collector(kb: &'static Kb, name: &'static str, detail: bool) -> Option<Collector> {
    use agenticdisk_windows::*;
    let run: Box<dyn FnOnce() -> Section + Send> = match name {
        "system" => Box::new(move || system::collect(detail)),
        "cleanup" => Box::new(move || cleanup::section(kb)),
        "drivers" => Box::new(move || drivers::collect(detail)),
        "privacy" => Box::new(move || privacy::collect(detail)),
        "startup" => Box::new(move || startup::collect(detail)),
        "apps" => Box::new(move || apps::collect(detail)),
        "security" => Box::new(move || security::collect(detail)),
        "stability" => Box::new(move || stability::collect(detail)),
        _ => return None,
    };
    Some((name, run))
}

#[cfg(not(windows))]
pub fn collector(kb: &'static Kb, name: &'static str, _detail: bool) -> Option<Collector> {
    (name == "cleanup").then(|| (name, Box::new(move || cleanup::section(kb)) as Box<dyn FnOnce() -> Section + Send>))
}

/// Runs collectors on their own threads (WMI/COM is per-thread) and waits at most `timeout`: a
/// stuck collector becomes a blind spot instead of hanging the agent. Leftover threads die when
/// main returns.
pub fn run(collectors: Vec<Collector>, timeout: Duration) -> Vec<(&'static str, Section)> {
    let order: Vec<&'static str> = collectors.iter().map(|(name, _)| *name).collect();
    let (tx, rx) = mpsc::channel();
    for (name, job) in collectors {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _t = trace::span(format!("collector {name}"));
            let section = panic::catch_unwind(AssertUnwindSafe(job))
                .unwrap_or_else(|_| Section { blind_spots: vec!["collector crashed".into()], ..Default::default() });
            let _ = tx.send((name, section));
        });
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut done: HashMap<&'static str, Section> = HashMap::new();
    while done.len() < order.len() {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok((name, section)) => {
                done.insert(name, section);
            }
            Err(_) => break,
        }
    }
    order
        .into_iter()
        .map(|name| {
            let section = done.remove(name).unwrap_or_else(|| Section {
                blind_spots: vec![format!(
                    "timed out after {}s; run `agenticdisk {name}` on its own",
                    timeout.as_secs()
                )],
                ..Default::default()
            });
            (name, section)
        })
        .collect()
}

pub fn named(kb: &'static Kb, names: &[&str], detail: bool) -> Vec<Collector> {
    AREAS.iter().filter(|a| names.contains(a)).filter_map(|a| collector(kb, a, detail)).collect()
}
