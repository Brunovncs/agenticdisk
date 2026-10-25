//! Measures the knowledge base's known locations directly (no full scan needed) and empties them
//! on request. Deletion is opt-in per rule, dry-run by default, and guarded against bad paths.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use rayon::prelude::*;
use serde::Serialize;

use crate::kb::{CleanMode, Kb, Rule, home_dir};
use crate::model::{Area, Finding, Safety, Section};
use crate::scan::{du, rule_fix, space_severity};
use crate::size::Bytes;

const MIN_REPORTED: u64 = 50 * 1024 * 1024;

pub struct Measured<'a> {
    pub rule: &'a Rule,
    pub paths: Vec<(PathBuf, u64)>,
    pub unreadable: u64,
}

impl Measured<'_> {
    pub fn total(&self) -> u64 {
        self.paths.iter().map(|p| p.1).sum()
    }
}

pub fn measure(kb: &Kb) -> Vec<Measured<'_>> {
    let targets: Vec<(usize, PathBuf)> = kb
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.measure && !r.paths.is_empty())
        .flat_map(|(i, r)| Kb::resolve(r).into_iter().map(move |p| (i, p)))
        .collect();
    // Own pool: this is heavy directory I/O and must not queue ahead of other collectors' work
    // on the global pool when everything runs at once.
    let pool = crate::io::pool();
    let sized: Vec<(usize, PathBuf, (u64, u64, u64))> = pool.install(|| {
        targets
            .into_par_iter()
            .map(|(i, p)| {
                let _t = crate::trace::span_over(format!("cleanup: {} {}", kb.rules[i].id, p.display()), 250);
                let rule = &kb.rules[i];
                // Report what `clean` would actually free, not the folder's full size.
                let age_filtered =
                    rule.clean == CleanMode::Contents && (rule.min_age_days > 0 || !rule.keep.is_empty());
                let mut s = if age_filtered { (0, 0, 0) } else { du(&p) };
                if age_filtered {
                    let keep: Vec<globset::GlobMatcher> = rule
                        .keep
                        .iter()
                        .filter_map(|g| globset::GlobBuilder::new(g).case_insensitive(true).build().ok())
                        .map(|g| g.compile_matcher())
                        .collect();
                    let age = Duration::from_secs(u64::from(rule.min_age_days) * 86_400);
                    s.0 = eligible(&p, &keep, age).iter().map(|e| e.1).sum();
                }
                (i, p, s)
            })
            .collect()
    });

    let mut out: Vec<Measured> = Vec::new();
    for (i, path, (bytes, _, unreadable)) in sized {
        let rule = &kb.rules[i];
        match out.iter_mut().find(|m| std::ptr::eq(m.rule, rule)) {
            Some(m) => {
                m.paths.push((path, bytes));
                m.unreadable += unreadable;
            }
            None => out.push(Measured { rule, paths: vec![(path, bytes)], unreadable }),
        }
    }
    out.sort_unstable_by_key(|m| std::cmp::Reverse(m.total()));
    out
}

#[derive(Serialize)]
struct Totals {
    safe: Bytes,
    caution: Bytes,
    manual: Bytes,
    locations_checked: usize,
}

pub fn section(kb: &Kb) -> Section {
    let started = Instant::now();
    let measured = measure(kb);
    let mut totals = Totals { safe: Bytes(0), caution: Bytes(0), manual: Bytes(0), locations_checked: 0 };
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();
    for m in &measured {
        totals.locations_checked += m.paths.len();
        let total = m.total();
        match m.rule.safety {
            _ if !m.rule.reclaimable => {}
            Safety::Safe => totals.safe.0 += total,
            Safety::Caution => totals.caution.0 += total,
            Safety::Manual => totals.manual.0 += total,
            Safety::Never => {}
        }
        if m.unreadable > 0 && m.rule.admin {
            blind_spots.push(format!(
                "{}: {} folders unreadable without admin; size is a lower bound",
                m.rule.id, m.unreadable
            ));
        }
        if total < MIN_REPORTED {
            continue;
        }
        let mut paths = m.paths.clone();
        paths.sort_unstable_by_key(|x| std::cmp::Reverse(x.1));
        let mut finding = Finding::new(
            format!("cleanup.{}", m.rule.id),
            Area::Cleanup,
            space_severity(total),
            format!("{}: {}", m.rule.what, Bytes(total)),
        )
        .evidence(paths.iter().take(5).map(|(p, s)| format!("{} {}", Bytes(*s), p.display())))
        .space(total, m.rule.reclaimable);
        if let Some(fix) = rule_fix(m.rule) {
            finding = finding.fix(fix);
        }
        findings.push(finding);
    }
    let mut section = Section {
        data: serde_json::to_value(&totals).expect("totals serialize"),
        findings,
        blind_spots,
        took_ms: started.elapsed().as_millis() as u64,
    };
    section.sort_findings();
    section
}

#[derive(Serialize)]
pub struct CleanItem {
    pub rule: String,
    pub path: String,
    pub before: Bytes,
    pub freed: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Serialize)]
pub struct CleanReport {
    pub applied: bool,
    pub freed: Bytes,
    pub items: Vec<CleanItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
}

/// Only rules with `clean = "contents"` and safety safe/caution are eligible. Without `apply`
/// nothing is deleted and `freed` is what would be freed. Entries newer than the rule's
/// `min_age_days` and names in its `keep` list are left alone.
pub fn clean(kb: &Kb, ids: &[String], apply: bool) -> CleanReport {
    let mut report = CleanReport { applied: apply, freed: Bytes(0), items: Vec::new(), refused: Vec::new() };
    let mut seen_ids: Vec<&String> = Vec::new();
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    for id in ids {
        if seen_ids.contains(&id) {
            continue;
        }
        seen_ids.push(id);
        let Some(rule) = kb.get(id) else {
            report.refused.push(format!("{id}: unknown rule"));
            continue;
        };
        if rule.clean != CleanMode::Contents {
            let how = rule.command.as_deref().map(|c| format!("; run `{c}` instead")).unwrap_or_default();
            report.refused.push(format!("{id}: not auto-cleanable{how}"));
            continue;
        }
        if !matches!(rule.safety, Safety::Safe | Safety::Caution) {
            report.refused.push(format!("{id}: safety is {:?}, needs a human", rule.safety));
            continue;
        }
        let keep: Vec<globset::GlobMatcher> = rule
            .keep
            .iter()
            .filter_map(|g| globset::GlobBuilder::new(g).case_insensitive(true).build().ok())
            .map(|g| g.compile_matcher())
            .collect();
        let min_age = Duration::from_secs(u64::from(rule.min_age_days) * 86_400);
        for path in Kb::resolve(rule) {
            let canonical = match guard(&path) {
                Ok(c) => c,
                Err(reason) => {
                    report.items.push(CleanItem {
                        rule: id.clone(),
                        path: path.display().to_string(),
                        before: Bytes(0),
                        freed: Bytes(0),
                        skipped: Some(reason),
                    });
                    continue;
                }
            };
            if seen_paths.iter().any(|p| crate::kb::is_within(&canonical, p)) {
                continue;
            }
            seen_paths.push(canonical.clone());
            let targets = eligible(&canonical, &keep, min_age);
            let before = du(&canonical).0;
            let eligible_bytes: u64 = targets.iter().map(|t| t.1).sum();
            let mut item = CleanItem {
                rule: id.clone(),
                path: canonical.display().to_string(),
                before: Bytes(before),
                freed: Bytes(eligible_bytes),
                skipped: (eligible_bytes < before).then(|| {
                    format!(
                        "{} kept (newer than {} days or protected name)",
                        Bytes(before - eligible_bytes),
                        rule.min_age_days
                    )
                }),
            };
            if apply {
                let failures = remove_all(&targets);
                let after = du(&canonical).0;
                item.freed = Bytes(before.saturating_sub(after));
                if failures > 0 {
                    item.skipped = Some(format!("{failures} entries in use or access denied; the rest was removed"));
                }
            }
            report.freed.0 += item.freed.0;
            report.items.push(item);
        }
    }
    report
}

/// Windows returns `\\?\C:\...` from canonicalize; strip it so paths compare and print normally.
fn simplify(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p,
    }
}

fn is_link(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return false };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    meta.file_type().is_symlink()
}

/// Locations that are never emptied, whatever a rule or an environment variable resolves to.
pub fn protected(path: &Path) -> bool {
    let home = home_dir().map(PathBuf::from);
    let var = |v: &str| std::env::var_os(v).map(PathBuf::from);
    let mut exact: Vec<PathBuf> = Vec::new();
    if let Some(h) = &home {
        exact.push(h.clone());
        for sub in [
            "Documents",
            "Desktop",
            "Pictures",
            "Videos",
            "Music",
            "OneDrive",
            "Downloads",
            "AppData",
            "AppData\\Local",
            "AppData\\Roaming",
            "AppData\\LocalLow",
        ] {
            exact.push(h.join(sub));
        }
        if let Some(users) = h.parent() {
            exact.push(users.to_path_buf());
        }
    }
    for v in [
        "SystemRoot",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "LOCALAPPDATA",
        "APPDATA",
        "PUBLIC",
        "OneDrive",
    ] {
        exact.extend(var(v));
    }
    let never_inside: Vec<PathBuf> = var("SystemRoot")
        .map(|r| vec![r.join("WinSxS"), r.join("Installer"), r.join("System32"), r.join("SysWOW64")])
        .unwrap_or_default();
    let same = |a: &Path, b: &Path| crate::kb::is_within(a, b) && crate::kb::is_within(b, a);
    let lower = path.to_string_lossy().to_lowercase();
    path.components().count() < 3
        || exact.iter().any(|e| same(path, e))
        || never_inside.iter().any(|n| crate::kb::is_within(path, n))
        || lower.contains("\\.ssh")
        || path.components().any(|c| c.as_os_str().eq_ignore_ascii_case(".git"))
}

/// Resolves where a cleanup target really points and refuses anything unsafe: links/junctions as
/// the root (their contents live elsewhere), relative paths, and protected locations.
fn guard(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("refused: not an absolute path".into());
    }
    if is_link(path) {
        return Err("refused: the folder is a link/junction to somewhere else".into());
    }
    let canonical = std::fs::canonicalize(path).map(simplify).map_err(|e| format!("refused: {e}"))?;
    if protected(&canonical) || protected(path) {
        return Err(format!("refused: {} is a protected location", canonical.display()));
    }
    Ok(canonical)
}

/// Newest modification time anywhere under `path` (a folder's own mtime ignores deep changes).
/// (bytes, newest modification) of a folder in one walk. Sizes and times come from the directory
/// listing itself (no per-file metadata call), which is what keeps this as fast as `du`.
fn stats(path: &Path) -> (u64, Option<SystemTime>) {
    let Ok(read) = std::fs::read_dir(path) else {
        let meta = std::fs::symlink_metadata(path).ok();
        return (meta.as_ref().map(|m| m.len()).unwrap_or(0), meta.and_then(|m| m.modified().ok()));
    };
    let mut bytes = 0;
    let mut newest: Option<SystemTime> = None;
    let mut subdirs = Vec::new();
    for entry in read.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let meta = entry.metadata().ok();
        newest = newest.max(meta.as_ref().and_then(|m| m.modified().ok()));
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            subdirs.push(entry.path());
        } else {
            bytes += meta.map(|m| m.len()).unwrap_or(0);
        }
    }
    let (sub_bytes, sub_newest) =
        subdirs.into_par_iter().map(|d| stats(&d)).reduce(|| (0, None), |a, b| (a.0 + b.0, a.1.max(b.1)));
    (bytes + sub_bytes, newest.max(sub_newest))
}

/// Top-level entries that may go: not kept by name, and untouched for `min_age`.
fn eligible(dir: &Path, keep: &[globset::GlobMatcher], min_age: Duration) -> Vec<(PathBuf, u64)> {
    if dir.is_file() {
        return vec![(dir.to_path_buf(), du(dir).0)];
    }
    let Ok(read) = std::fs::read_dir(dir) else { return Vec::new() };
    let cutoff = SystemTime::now().checked_sub(min_age).unwrap_or(SystemTime::UNIX_EPOCH);
    let entries: Vec<PathBuf> =
        read.flatten().filter(|e| !keep.iter().any(|k| k.is_match(e.file_name()))).map(|e| e.path()).collect();
    entries
        .into_par_iter()
        .filter_map(|p| {
            let (size, newest) = stats(&p);
            (min_age.is_zero() || newest.is_none_or(|t| t <= cutoff)).then_some((p, size))
        })
        .collect()
}

/// Removes the given entries without following links (a junction is removed, never its target).
/// Returns how many could not be removed.
fn remove_all(targets: &[(PathBuf, u64)]) -> usize {
    targets
        .par_iter()
        .map(|(p, _)| {
            let result = if is_link(p) {
                std::fs::remove_dir(p).or_else(|_| std::fs::remove_file(p))
            } else if p.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            };
            usize::from(result.is_err())
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn guard_refuses_broad_and_linked_targets() {
        let home = PathBuf::from(home_dir().unwrap());
        assert!(guard(&home).is_err());
        assert!(guard(&home.join("Documents")).is_err());
        assert!(guard(Path::new("C:\\")).is_err());
        assert!(guard(Path::new("relative\\dir")).is_err());
        assert!(protected(&PathBuf::from(std::env::var("SystemRoot").unwrap()).join("WinSxS").join("Temp")));
        assert!(guard(&std::env::temp_dir()).is_ok());
    }

    #[test]
    fn recent_entries_and_kept_names_survive() {
        let root = std::env::temp_dir().join(format!("agenticdisk-test-{}", std::process::id()));
        std::fs::create_dir_all(root.join("Content.Outlook")).unwrap();
        std::fs::write(root.join("fresh.tmp"), b"x").unwrap();
        let keep = vec![globset::Glob::new("Content.Outlook").unwrap().compile_matcher()];
        let picked = eligible(&root, &keep, Duration::from_secs(7 * 86_400));
        assert!(picked.is_empty(), "fresh file and kept folder must not be eligible: {picked:?}");
        let picked = eligible(&root, &keep, Duration::ZERO);
        assert_eq!(picked.len(), 1);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
