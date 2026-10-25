//! Registry access by full path (`HKLM\SOFTWARE\...`), the way the knowledge base writes it.

use std::io;

use winreg::RegKey;
use winreg::enums::*;

fn try_open(path: &str) -> io::Result<RegKey> {
    let (hive, sub) = path.split_once('\\').unwrap_or((path, ""));
    let root = match hive {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown hive")),
    };
    RegKey::predef(root).open_subkey_with_flags(sub, KEY_READ)
}

pub fn open(path: &str) -> Option<RegKey> {
    try_open(path).ok()
}

/// `Some(false)` when the key exists but access is denied, so collectors can tell "absent" from
/// "hidden from us" and report a blind spot instead of a false all-clear.
pub fn readable(path: &str) -> Option<bool> {
    match try_open(path) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Some(false),
        Err(_) => None,
    }
}

pub fn string(path: &str, name: &str) -> Option<String> {
    open(path)?.get_value::<String, _>(name).ok()
}

pub fn dword(path: &str, name: &str) -> Option<u32> {
    open(path)?.get_value::<u32, _>(name).ok()
}

/// Any value type rendered as text (DWORD as decimal, strings as-is), for rule comparisons.
pub fn text(path: &str, name: &str) -> Option<String> {
    let value = open(path)?.get_raw_value(name).ok()?;
    Some(match value.vtype {
        REG_DWORD => u32::from_le_bytes(value.bytes.get(..4)?.try_into().ok()?).to_string(),
        REG_QWORD => u64::from_le_bytes(value.bytes.get(..8)?.try_into().ok()?).to_string(),
        _ => value.to_string(),
    })
}

pub fn subkeys(path: &str) -> Vec<String> {
    open(path).map(|k| k.enum_keys().flatten().collect()).unwrap_or_default()
}

pub fn values(path: &str) -> Vec<(String, String)> {
    open(path).map(|k| k.enum_values().flatten().map(|(n, v)| (n, v.to_string())).collect()).unwrap_or_default()
}
