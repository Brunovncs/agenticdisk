//! Windows side of the write path (`agenticdisk_core::action::Platform`). Writes are limited to
//! the values the knowledge base sets and Task Manager's StartupApproved entries.

use agenticdisk_core::action::{Platform, RegData};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

pub struct Windows;

fn split(path: &str) -> Result<(RegKey, &str), String> {
    let (hive, sub) = path.split_once('\\').ok_or_else(|| format!("bad key {path}"))?;
    let root = match hive {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKCU" => HKEY_CURRENT_USER,
        _ => return Err(format!("unsupported hive {hive}")),
    };
    Ok((RegKey::predef(root), sub))
}

fn startup_approved(key: &str) -> bool {
    ["HKCU", "HKLM"].iter().any(|hive| {
        ["Run", "Run32", "StartupFolder"]
            .iter()
            .any(|list| key.eq_ignore_ascii_case(&format!("{hive}\\{}\\{list}", crate::startup::APPROVED)))
    })
}

impl Platform for Windows {
    fn elevated(&self) -> bool {
        crate::elevated()
    }

    fn reg_allowed(&self, key: &str, name: &str) -> bool {
        startup_approved(key) || crate::privacy::allowed(key, name)
    }

    fn reg_read(&self, key: &str, name: &str) -> Result<Option<RegData>, String> {
        let (root, sub) = split(key)?;
        let k = match root.open_subkey_with_flags(sub, KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{key}: {e}")),
        };
        match k.get_raw_value(name) {
            Ok(v) => Ok(Some(match v.vtype {
                REG_DWORD => RegData::Dword(u32::from_le_bytes(
                    v.bytes.get(..4).and_then(|b| b.try_into().ok()).unwrap_or([0; 4]),
                )),
                REG_SZ | REG_EXPAND_SZ => RegData::String(v.to_string()),
                _ => RegData::Binary(v.bytes.into_owned()),
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{key}\\{name}: {e}")),
        }
    }

    fn reg_write(&self, key: &str, name: &str, data: &RegData) -> Result<(), String> {
        let (root, sub) = split(key)?;
        // create_subkey opens an existing key untouched (unlike PowerShell's New-Item -Force).
        let (k, _) = root.create_subkey_with_flags(sub, KEY_WRITE).map_err(|e| format!("{key}: {e}"))?;
        let result = match data {
            RegData::Dword(v) => k.set_value(name, v),
            RegData::String(s) => k.set_value(name, s),
            RegData::Binary(b) => k.set_raw_value(name, &RegValue { bytes: b.clone().into(), vtype: REG_BINARY }),
        };
        result.map_err(|e| format!("{key}\\{name}: {e}"))
    }

    fn reg_delete(&self, key: &str, name: &str) -> Result<(), String> {
        let (root, sub) = split(key)?;
        let k = root.open_subkey_with_flags(sub, KEY_SET_VALUE).map_err(|e| format!("{key}: {e}"))?;
        match k.delete_value(name) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{key}\\{name}: {e}")),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_restore_roundtrip_in_a_scratch_key() {
        // A scratch key outside the allow-list: exercises the primitives, not the policy.
        let key = format!("HKCU\\Software\\agenticdisk-test-{}", std::process::id());
        let w = Windows;
        assert_eq!(w.reg_read(&key, "v").unwrap(), None);
        w.reg_write(&key, "v", &RegData::Dword(7)).unwrap();
        w.reg_write(&key, "keep", &RegData::String("x".into())).unwrap();
        w.reg_write(&key, "v", &RegData::Dword(1)).unwrap();
        assert_eq!(w.reg_read(&key, "keep").unwrap(), Some(RegData::String("x".into())), "sibling values survive");
        w.reg_write(&key, "b", &RegData::Binary(vec![3, 0, 0])).unwrap();
        assert_eq!(w.reg_read(&key, "b").unwrap(), Some(RegData::Binary(vec![3, 0, 0])));
        w.reg_delete(&key, "v").unwrap();
        assert_eq!(w.reg_read(&key, "v").unwrap(), None);
        RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(key.trim_start_matches("HKCU\\")).unwrap();
        assert!(!w.reg_allowed(&key, "v"));
        assert!(w.reg_allowed(r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled"));
    }
}
