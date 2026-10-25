use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Byte count that serializes as a short human string (`"12.4G"`): agents reason about it as well
/// as a raw integer, and it costs fewer tokens. `--bytes` switches to exact integers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub u64);

static EXACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_exact_bytes(exact: bool) {
    EXACT.store(exact, std::sync::atomic::Ordering::Relaxed);
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
        let mut value = self.0 as f64;
        let mut unit = 0;
        while value >= 1024.0 && unit < UNITS.len() - 1 {
            value /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            write!(f, "{}B", self.0)
        } else if value >= 100.0 {
            write!(f, "{value:.0}{}", UNITS[unit])
        } else {
            write!(f, "{value:.1}{}", UNITS[unit])
        }
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if EXACT.load(std::sync::atomic::Ordering::Relaxed) {
            serializer.serialize_u64(self.0)
        } else {
            serializer.collect_str(self)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u64::deserialize(deserializer).map(Bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Bytes;

    #[test]
    fn formats_compactly() {
        assert_eq!(Bytes(512).to_string(), "512B");
        assert_eq!(Bytes(1536).to_string(), "1.5K");
        assert_eq!(Bytes(250 * 1024 * 1024).to_string(), "250M");
        assert_eq!(Bytes(12_884_901_888).to_string(), "12.0G");
    }
}
