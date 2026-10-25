//! Heuristics for "this autostart / process looks like malware or a PUP". Tuned for precision:
//! AppData\Local is where many legit apps live (Discord, Spotify), so it is not flagged by itself.

use std::path::{Path, PathBuf};

use agenticdisk_core::Severity;

use crate::sign::Signature;

/// Folders any process can write to and installers never target on purpose.
pub fn user_writable(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    const DIRS: [&str; 6] = [
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\users\\public\\",
        "\\$recycle.bin\\",
        "\\windows\\temp\\",
        "\\perflogs\\",
    ];
    if DIRS.iter().any(|d| p.contains(d)) {
        return true;
    }
    // An executable sitting directly in Roaming or ProgramData (no vendor folder).
    let parent = path.parent().map(|d| d.to_string_lossy().to_lowercase()).unwrap_or_default();
    parent.ends_with("\\appdata\\roaming") || parent.ends_with(":\\programdata")
}

/// Inside the real Windows folder, compared by path components: `C:\Windows.old`, `C:\WindowsX`
/// and the `C:\Windows \System32` mock-folder trick do not count. Folders under Windows that any
/// user can write to (Temp, Tasks, Tracing) do not count either.
pub fn windows_dir(path: &Path) -> bool {
    let root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()));
    if !agenticdisk_core::kb::is_within(path, &root) {
        return false;
    }
    const WRITABLE: [&str; 5] = ["temp", "tasks", "tracing", "debug", "registration\\crmlog"];
    !WRITABLE.iter().any(|w| agenticdisk_core::kb::is_within(path, &root.join(w)))
}

fn normalize_raw(raw: &str) -> String {
    let raw = raw.trim().trim_matches('"');
    let raw = raw.strip_prefix("\\??\\").unwrap_or(raw);
    let lower = raw.to_ascii_lowercase();
    let raw = if let Some(rest) = lower.strip_prefix("\\systemroot\\") {
        format!("%SystemRoot%\\{}", &raw[raw.len() - rest.len()..])
    } else if lower.starts_with("system32\\") {
        format!("%SystemRoot%\\{raw}")
    } else {
        raw.to_string()
    };
    agenticdisk_core::kb::expand_env(&raw).unwrap_or(raw)
}

fn system32() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32")
}

/// Executable a command line launches, resolved the way CreateProcess does for unquoted paths:
/// try `C:\Program`, `C:\Program Files\App\start.bat`, ... until a prefix exists (with the usual
/// extensions). Falls back to the text up to a known extension, so a missing file stays visible.
pub fn image_of(command: &str) -> Option<PathBuf> {
    let cmd = command.trim();
    if cmd.is_empty() {
        return None;
    }
    if let Some(rest) = cmd.strip_prefix('"') {
        let quoted = normalize_raw(rest.split('"').next()?);
        return (!quoted.is_empty()).then(|| bare_to_system32(PathBuf::from(quoted)));
    }
    const EXTS: [&str; 7] = ["", ".exe", ".com", ".bat", ".cmd", ".sys", ".dll"];
    let words: Vec<&str> = cmd.split(' ').collect();
    for end in 1..=words.len() {
        let candidate = normalize_raw(&words[..end].join(" "));
        for ext in EXTS {
            let p = PathBuf::from(format!("{candidate}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let lower = cmd.to_ascii_lowercase();
    let cut = [".exe", ".com", ".bat", ".cmd", ".sys", ".dll", ".ps1", ".vbs", ".js"]
        .iter()
        .filter_map(|ext| lower.find(ext).map(|i| i + ext.len()))
        .min()
        .unwrap_or(cmd.len());
    let raw = normalize_raw(&cmd[..cut]);
    (!raw.is_empty()).then(|| bare_to_system32(PathBuf::from(raw)))
}

/// Bare names (`rundll32.exe`) resolve through System32.
fn bare_to_system32(path: PathBuf) -> PathBuf {
    if path.parent().is_none_or(|p| p.as_os_str().is_empty()) { system32().join(path) } else { path }
}

/// `-e`, `-ec`, `-enc`... any unambiguous prefix of `-EncodedCommand` (but not `-Encoding`).
fn has_encoded_switch(command: &str) -> bool {
    command.split_whitespace().any(|token| {
        let t = token.to_ascii_lowercase();
        let t = t.trim_start_matches('/').trim_start_matches('-');
        !t.is_empty() && (t == "ec" || "encodedcommand".starts_with(t)) && token.starts_with(['-', '/'])
    })
}
/// Markers for a command line. Stable strings: agents and tests key off them.
pub fn command_flags(command: &str) -> Vec<&'static str> {
    let c = command.to_lowercase();
    let mut flags = Vec::new();
    let powershell = c.contains("powershell") || c.contains("pwsh");
    if powershell && (has_encoded_switch(&c) || c.contains("frombase64string")) {
        flags.push("encoded_powershell");
    }
    if powershell && (c.contains("-w hidden") || c.contains("-windowstyle hidden") || c.contains("-win hidden")) {
        flags.push("hidden_window");
    }
    const CRADLES: [&str; 7] = [
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "iwr ",
        "bitsadmin /transfer",
        "certutil -urlcache",
        "start-bitstransfer",
    ];
    if CRADLES.iter().any(|k| c.contains(k)) {
        flags.push("download_cradle");
    }
    if (c.contains("mshta") && (c.contains("http") || c.contains("javascript:") || c.contains("vbscript:")))
        || ((c.contains("wscript") || c.contains("cscript"))
            && (c.contains(".js") || c.contains(".vbs") || c.contains(".jse") || c.contains(".vbe")))
    {
        flags.push("script_host");
    }
    if c.contains("rundll32")
        && (c.contains("javascript:")
            || c.contains("\\appdata\\")
            || c.contains("\\temp\\")
            || c.contains("\\users\\public\\"))
    {
        flags.push("rundll32_unusual");
    }
    if c.contains("regsvr32") && (c.contains("/i:http") || c.contains("scrobj")) {
        flags.push("regsvr32_remote");
    }
    flags
}

pub fn path_flags(image: &Path, signature: Option<Signature>) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if user_writable(image) {
        flags.push("user_writable_path");
    }
    match signature {
        Some(Signature::Missing) => flags.push("missing_target"),
        Some(Signature::Unsigned) => flags.push("unsigned"),
        Some(Signature::Untrusted) => flags.push("untrusted_signature"),
        Some(Signature::Invalid) => flags.push("invalid_signature"),
        _ => {}
    }
    flags
}

/// None = nothing worth reporting.
pub fn severity(flags: &[&str]) -> Option<Severity> {
    let has = |f: &str| flags.contains(&f);
    if has("encoded_powershell") || has("download_cradle") || has("regsvr32_remote") || has("rundll32_unusual") {
        return Some(Severity::High);
    }
    if has("invalid_signature") || (has("user_writable_path") && (has("unsigned") || has("untrusted_signature"))) {
        return Some(Severity::High);
    }
    if has("user_writable_path") || has("script_host") {
        return Some(Severity::Medium);
    }
    if has("hidden_window") {
        return Some(Severity::Low);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_images() {
        assert_eq!(
            image_of(r#""C:\Program Files\App\app.exe" --min"#),
            Some(PathBuf::from(r"C:\Program Files\App\app.exe"))
        );
        assert_eq!(image_of(r"C:\Tools\x.exe /silent"), Some(PathBuf::from(r"C:\Tools\x.exe")));
    }

    #[test]
    fn flags_classic_persistence() {
        let flags = command_flags("powershell.exe -w hidden -enc SQBFAFgA");
        assert!(flags.contains(&"encoded_powershell") && flags.contains(&"hidden_window"));
        assert_eq!(severity(&flags), Some(Severity::High));
        assert!(command_flags("powershell -Command \"Get-Date | Out-File x.txt -Encoding utf8\"").is_empty());
        assert!(command_flags("pwsh -ec SQBFAFgA").contains(&"encoded_powershell"));
        assert!(command_flags(r#""C:\Program Files\Discord\Update.exe" --processStart Discord.exe"#).is_empty());
    }

    #[test]
    fn expired_certificate_alone_is_not_an_alert() {
        let flags = path_flags(Path::new(r"C:\Program Files\Parsec\parsecd.exe"), Some(Signature::Untrusted));
        assert_eq!(severity(&flags), None);
        let tampered = path_flags(Path::new(r"C:\Program Files\App\app.exe"), Some(Signature::Invalid));
        assert_eq!(severity(&tampered), Some(Severity::High));
    }

    #[test]
    fn unquoted_paths_with_spaces_resolve_like_createprocess() {
        let program_files = std::env::var("ProgramFiles").unwrap();
        let candidates = std::fs::read_dir(&program_files).unwrap().flatten().filter_map(|d| {
            std::fs::read_dir(d.path())
                .ok()?
                .flatten()
                .find(|f| f.path().extension().is_some_and(|e| e == "exe"))
                .map(|f| f.path())
        });
        if let Some(exe) = candidates.into_iter().next() {
            let command = format!("{} --flag value", exe.display());
            assert_eq!(image_of(&command), Some(exe));
        }
        assert_eq!(
            image_of(r"\SystemRoot\System32\drivers\x.sys").unwrap().to_string_lossy().to_lowercase(),
            format!("{}\\system32\\drivers\\x.sys", std::env::var("SystemRoot").unwrap().to_lowercase())
        );
    }

    #[test]
    fn lookalike_windows_folders_are_not_trusted() {
        let root = std::env::var("SystemRoot").unwrap();
        assert!(windows_dir(Path::new(&format!("{root}\\System32\\svchost.exe"))));
        assert!(!windows_dir(Path::new(&format!("{root}.old\\System32\\svchost.exe"))));
        assert!(!windows_dir(Path::new(&format!("{root} \\System32\\svchost.exe"))));
        assert!(!windows_dir(Path::new(&format!("{root}\\Temp\\x.exe"))));
    }

    #[test]
    fn local_appdata_is_not_suspicious_by_itself() {
        assert!(!user_writable(Path::new(r"C:\Users\x\AppData\Local\Discord\Update.exe")));
        assert!(user_writable(Path::new(r"C:\Users\x\AppData\Roaming\svch0st.exe")));
        assert!(user_writable(Path::new(r"C:\Users\x\AppData\Local\Temp\a\b.exe")));
    }
}
