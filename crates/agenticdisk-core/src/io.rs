//! Thread pool for filesystem walks. Cold directory enumeration is latency-bound (one small
//! random read per directory), so an SSD/NVMe keeps far more requests in flight than there are
//! cores; a spinning disk wants few. `--threads` overrides the default.

use std::sync::atomic::{AtomicUsize, Ordering};

static THREADS: AtomicUsize = AtomicUsize::new(0);

pub fn set_threads(n: usize) {
    THREADS.store(n, Ordering::Relaxed);
}

/// Measured on NVMe with a cold cache (C:\Users, 2M files, two rounds): 12 threads ~24 s, 64 ~15.5 s.
/// A spinning disk thrashes its head with that many outstanding requests.
pub fn default_threads(rotational: Option<bool>) -> usize {
    match rotational {
        Some(true) => 4,
        _ => 64,
    }
}

pub fn threads() -> usize {
    match THREADS.load(Ordering::Relaxed) {
        0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8),
        n => n,
    }
}

pub fn pool() -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new().num_threads(threads()).stack_size(16 * 1024 * 1024).build().expect("thread pool")
}
