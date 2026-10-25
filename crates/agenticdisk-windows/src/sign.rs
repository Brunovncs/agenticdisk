//! Authenticode checks. Catalog-signed Windows binaries report as unsigned here, so callers only
//! ask about third-party executables.
//!
//! Full verification hashes the whole file: ~1s for a 200 MB Electron app, far more on a cold
//! disk. So `assess` reads only the PE header (has an embedded signature or not) unless the caller
//! asks for the full check, which is reserved for files whose location or command already looks
//! suspicious. Results are cached per process (startup and security ask about the same files).

use std::collections::HashMap;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::Serialize;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::WinTrust::*;
use windows::core::PCWSTR;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Signature {
    /// Embedded signature verified.
    Valid,
    /// Embedded signature present, not verified (fast path).
    Signed,
    Unsigned,
    /// Signed, but the certificate is expired or its chain is not trusted here. Common for old
    /// legit software signed without a timestamp: a weak signal on its own.
    Untrusted,
    /// The file was modified after signing, or the certificate is revoked / explicitly distrusted.
    Invalid,
    /// Ships in the Windows folder: catalog-signed, not checked individually.
    System,
    /// Could not be read (access denied, locked, cloud-only placeholder). Not a verdict.
    Unknown,
    Missing,
}

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100_u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x80096010_u32 as i32;
const CERT_E_REVOKED: i32 = 0x800B010C_u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003_u32 as i32;
const CERT_E_EXPIRED: i32 = 0x800B0101_u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109_u32 as i32;
const CERT_E_CHAINING: i32 = 0x800B010A_u32 as i32;

/// Cloud-only placeholders (OneDrive "online-only"): opening them downloads the whole file.
pub fn is_cloud_placeholder(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const RECALL_ON_OPEN: u32 = 0x40000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x400000;
    const OFFLINE: u32 = 0x1000;
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_attributes() & (RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS | OFFLINE) != 0)
}

fn cache() -> &'static Mutex<HashMap<(PathBuf, bool), Signature>> {
    static CACHE: OnceLock<Mutex<HashMap<(PathBuf, bool), Signature>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// `deep` = verify the signature cryptographically; otherwise only check that one is present.
pub fn assess(path: &Path, deep: bool) -> Signature {
    let key = (path.to_path_buf(), deep);
    if let Some(&cached) = cache().lock().unwrap().get(&key) {
        return cached;
    }
    let result = if !path.exists() && std::fs::symlink_metadata(path).is_err() {
        Signature::Missing
    } else if is_cloud_placeholder(path) {
        Signature::Unknown
    } else if deep {
        verify(path)
    } else {
        presence(path)
    };
    cache().lock().unwrap().insert(key, result);
    result
}

/// Reads the PE optional header's security data directory (a file offset + size). Non-PE files
/// (scripts, shortcuts) are reported as unsigned.
fn presence(path: &Path) -> Signature {
    let Ok(mut file) = std::fs::File::open(path) else {
        return if path.exists() { Signature::Unknown } else { Signature::Missing };
    };
    let mut header = [0u8; 4096];
    let Ok(read) = file.read(&mut header) else { return Signature::Unsigned };
    let header = &header[..read];
    let u16_at = |o: usize| header.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| header.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let has_signature = (|| {
        if header.get(..2)? != b"MZ" {
            return None;
        }
        let pe = u32_at(0x3C)? as usize;
        if header.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let optional = pe + 24;
        let directories = match u16_at(optional)? {
            0x10b => optional + 96,
            0x20b => optional + 112,
            _ => return None,
        };
        // Data directory 4 = IMAGE_DIRECTORY_ENTRY_SECURITY.
        Some(u32_at(directories + 4 * 8 + 4)? > 0)
    })();
    if has_signature == Some(true) { Signature::Signed } else { Signature::Unsigned }
}

fn verify(path: &Path) -> Signature {
    if !path.is_file() {
        return Signature::Missing;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `file` and `wide` outlive both calls; the CLOSE call releases the state VERIFY opened.
    let status = unsafe {
        let status = WinVerifyTrust(HWND::default(), &mut action, (&raw mut data).cast());
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, (&raw mut data).cast());
        status
    };
    match status {
        0 => Signature::Valid,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN => Signature::Unsigned,
        TRUST_E_BAD_DIGEST | CERT_E_REVOKED | TRUST_E_EXPLICIT_DISTRUST => Signature::Invalid,
        CERT_E_EXPIRED | CERT_E_UNTRUSTEDROOT | CERT_E_CHAINING => Signature::Untrusted,
        // File access errors and anything unrecognized are not a verdict about the file.
        _ => Signature::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_agrees_with_full_check_on_system_binaries() {
        // explorer.exe is catalog-signed on recent builds; any embedded-signed tool works too.
        let notepad = PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        let fast = assess(&notepad, false);
        assert!(matches!(fast, Signature::Signed | Signature::Unsigned));
        assert_eq!(assess(Path::new("C:\\definitely\\missing.exe"), false), Signature::Missing);
    }
}
