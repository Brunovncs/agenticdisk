use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Byte count that serializes as a short human string (`"12.4G"`): agents reason about it as well
/// as a raw integer, and it costs fewer tokens. `--bytes` switches to exact integers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(pub u64);

const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];

static EXACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    static FORCE_EXACT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn set_exact_bytes(exact: bool) {
    EXACT.store(exact, std::sync::atomic::Ordering::Relaxed);
}

/// Runs `f` with exact integers: files agenticdisk reads back (plans, journals) must round-trip.
pub fn with_exact_bytes<T>(f: impl FnOnce() -> T) -> T {
    let before = FORCE_EXACT.replace(true);
    let out = f();
    FORCE_EXACT.set(before);
    out
}

fn exact() -> bool {
    EXACT.load(std::sync::atomic::Ordering::Relaxed) || FORCE_EXACT.get()
}

/// Inverse of `Display` (within its rounding), for plan files written before `with_exact_bytes`.
fn parse_human(s: &str) -> Option<u64> {
    let unit = s.find(|c: char| c.is_ascii_alphabetic())?;
    let value: f64 = s[..unit].parse().ok()?;
    let power = UNITS.iter().position(|u| *u == &s[unit..])?;
    Some((value * 1024f64.powi(power as i32)) as u64)
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        if exact() { serializer.serialize_u64(self.0) } else { serializer.collect_str(self) }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Exact(u64),
            Human(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Exact(n) => Ok(Bytes(n)),
            Raw::Human(s) => {
                parse_human(&s).map(Bytes).ok_or_else(|| serde::de::Error::custom(format!("invalid size `{s}`")))
            }
        }
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

    #[test]
    fn saved_files_round_trip() {
        let json = super::with_exact_bytes(|| serde_json::to_string(&Bytes(11_918_534_246)).unwrap());
        assert_eq!(json, "11918534246");
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), Bytes(11_918_534_246));
        let legacy: Bytes = serde_json::from_str("\"11.1G\"").unwrap();
        assert!(legacy.0 > 11_900_000_000 && legacy.0 < 11_930_000_000);
        assert!(serde_json::from_str::<Bytes>("\"lots\"").is_err());
    }
}
