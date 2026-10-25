//! `--trace`: per-step timings on stderr, so a slow run explains itself without a profiler.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Prints `[trace] <name> <ms>` when dropped. Steps faster than `min_ms` stay silent.
pub struct Span {
    name: String,
    started: Instant,
    min_ms: u128,
}

pub fn span(name: impl Into<String>) -> Option<Span> {
    span_over(name, 0)
}

pub fn span_over(name: impl Into<String>, min_ms: u128) -> Option<Span> {
    enabled().then(|| Span { name: name.into(), started: Instant::now(), min_ms })
}

impl Drop for Span {
    fn drop(&mut self) {
        let ms = self.started.elapsed().as_millis();
        if ms >= self.min_ms {
            eprintln!("[trace] {:>6}ms {}", ms, self.name);
        }
    }
}
