//! Parallel directory walker that keeps only what an agent needs: a pruned size tree, the largest
//! files, an extension breakdown and knowledge-base matches. Portable (std + rayon); a raw NTFS MFT
//! reader can replace `walk` on Windows later without changing the output.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use serde::Serialize;

use crate::kb::{CleanMode, Kb, expand_env};
use crate::model::{Area, Finding, Fix, Safety, Section, Severity};
use crate::size::Bytes;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Children shown per tree level.
    pub top: usize,
    /// Tree levels below the root.
    pub depth: usize,
    /// A subtree is shown only if it holds at least this % of the scanned total.
    pub min_share: f64,
    pub largest_files: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { top: 8, depth: 3, min_share: 1.0, largest_files: 15 }
    }
}

const BIG_FILE: u64 = 64 * 1024 * 1024;

fn idle_days(newest: u64) -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    (newest > 0).then(|| now.saturating_sub(newest) / 86_400)
}

/// OneDrive "online-only" files report their full size but occupy nothing on this disk.
#[cfg(windows)]
fn cloud_placeholder(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x40000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x400000;
    meta.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}

#[cfg(not(windows))]
fn cloud_placeholder(_: &std::fs::Metadata) -> bool {
    false
}

struct Node {
    path: PathBuf,
    size: u64,
    /// Newest file modification inside (unix seconds). A folder's own mtime ignores deep changes,
    /// which is how "unused since 2024" gets claimed for a game played last week.
    newest: u64,
    files: u64,
    dirs: u64,
    rule: Option<usize>,
    children: Vec<Node>,
}

struct Ctx<'a> {
    kb: &'a Kb,
    static_dirs: HashMap<String, usize>,
    static_files: HashMap<String, usize>,
    static_file_parents: HashSet<String>,
    big_files: Mutex<Vec<(u64, PathBuf)>>,
    exts: Mutex<HashMap<String, (u64, u64)>>,
    hits: Mutex<Vec<(usize, PathBuf, u64, u64)>>,
    /// Logical size of cloud-only placeholders (OneDrive online-only): listed, not on this disk.
    cloud_only: AtomicU64,
    inaccessible: AtomicU64,
    links: AtomicU64,
    denied_samples: Mutex<Vec<String>>,
}

fn key(p: &Path) -> String {
    p.to_string_lossy().trim_end_matches(['\\', '/']).to_lowercase()
}

impl<'a> Ctx<'a> {
    fn new(kb: &'a Kb) -> Self {
        let mut static_dirs = HashMap::new();
        let mut static_files = HashMap::new();
        let mut static_file_parents = HashSet::new();
        for (i, rule) in kb.rules.iter().enumerate() {
            for path in Kb::resolve(rule) {
                if path.is_dir() {
                    static_dirs.insert(key(&path), i);
                } else {
                    if let Some(parent) = path.parent() {
                        static_file_parents.insert(key(parent));
                    }
                    static_files.insert(key(&path), i);
                }
            }
        }
        Self {
            kb,
            static_dirs,
            static_files,
            static_file_parents,
            big_files: Mutex::default(),
            exts: Mutex::default(),
            hits: Mutex::default(),
            cloud_only: AtomicU64::new(0),
            inaccessible: AtomicU64::new(0),
            links: AtomicU64::new(0),
            denied_samples: Mutex::default(),
        }
    }

    fn denied(&self, path: &Path) {
        self.inaccessible.fetch_add(1, Ordering::Relaxed);
        let mut samples = self.denied_samples.lock().unwrap();
        if samples.len() < 5 {
            samples.push(path.display().to_string());
        }
    }
}

fn extension(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && name.len() - i <= 12 => name[i..].to_ascii_lowercase(),
        _ => "(none)".into(),
    }
}

/// `candidate` is a name rule this directory matched by name in its parent; it is confirmed here
/// once the directory's own files are known (for `contains` checks).
fn walk(ctx: &Ctx, path: PathBuf, candidate: Option<usize>, inside_match: bool) -> Node {
    let mut node = Node { path, size: 0, newest: 0, files: 0, dirs: 0, rule: None, children: Vec::new() };
    let read = match std::fs::read_dir(&node.path) {
        Ok(read) => read,
        Err(_) => {
            ctx.denied(&node.path);
            return node;
        }
    };

    let mut names: Vec<OsString> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut exts: HashMap<String, (u64, u64)> = HashMap::new();
    for entry in read.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        // Symlinks and junctions are not followed: they point at space counted elsewhere (or on
        // another volume) and can form cycles.
        if ft.is_symlink() {
            ctx.links.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if ft.is_dir() {
            subdirs.push(entry.path());
            continue;
        }
        let meta = entry.metadata().ok();
        let mut len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        if meta.as_ref().is_some_and(cloud_placeholder) {
            ctx.cloud_only.fetch_add(len, Ordering::Relaxed);
            len = 0;
        }
        if let Some(t) = meta.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(UNIX_EPOCH).ok()) {
            node.newest = node.newest.max(t.as_secs());
        }
        node.size += len;
        node.files += 1;
        let name = entry.file_name();
        let lossy = name.to_string_lossy();
        let slot = exts.entry(extension(&lossy)).or_default();
        slot.0 += len;
        slot.1 += 1;
        if len >= BIG_FILE {
            ctx.big_files.lock().unwrap().push((len, entry.path()));
        }
        names.push(name);
    }

    let lossy_names: Vec<std::borrow::Cow<str>> = names.iter().map(|n| n.to_string_lossy()).collect();
    let dir_key = key(&node.path);
    if ctx.static_file_parents.contains(&dir_key) {
        for name in &lossy_names {
            let file = node.path.join(name.as_ref());
            if let Some(&rule) = ctx.static_files.get(&key(&file)) {
                let len = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
                ctx.hits.lock().unwrap().push((rule, file, len, node.newest));
            }
        }
    }

    node.rule = ctx.static_dirs.get(&dir_key).copied().or_else(|| {
        let nr = &ctx.kb.name_rules[candidate?];
        nr.contains_ok(lossy_names.iter().map(|n| n.as_ref())).then_some(nr.rule)
    });
    // Only a name-rule match (node_modules, target...) hides nested matches; a known location like
    // Downloads still gets its project build folders reported.
    let inside_match = inside_match || node.rule.is_some_and(|r| ctx.kb.rules[r].dir_name.is_some());

    let jobs: Vec<(PathBuf, Option<usize>)> = subdirs
        .into_iter()
        .map(|sub| {
            let candidate = if inside_match {
                None
            } else {
                let name = sub.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
                ctx.kb
                    .name_rules
                    .iter()
                    .position(|nr| nr.matches_name(&name) && nr.parent_ok(lossy_names.iter().map(|n| n.as_ref())))
            };
            (sub, candidate)
        })
        .collect();
    drop(lossy_names);

    {
        let mut global = ctx.exts.lock().unwrap();
        for (ext, (size, count)) in exts {
            let slot = global.entry(ext).or_default();
            slot.0 += size;
            slot.1 += count;
        }
    }

    node.children = jobs.into_par_iter().map(|(sub, cand)| walk(ctx, sub, cand, inside_match)).collect();
    for child in &node.children {
        node.newest = node.newest.max(child.newest);
        node.size += child.size;
        node.files += child.files;
        node.dirs += child.dirs + 1;
    }
    if let Some(rule) = node.rule {
        ctx.hits.lock().unwrap().push((rule, node.path.clone(), node.size, node.newest));
    }
    node
}

#[derive(Serialize)]
pub struct TreeNode {
    pub path: String,
    pub size: Bytes,
    /// Days since anything inside changed (newest file, not the folder's own date).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_days: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub: Vec<TreeNode>,
}

#[derive(Serialize)]
pub struct PathSize {
    pub path: String,
    pub size: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_days: Option<u64>,
}

#[derive(Serialize)]
pub struct ExtStat {
    pub ext: String,
    pub size: Bytes,
    pub files: u64,
}

#[derive(Serialize)]
pub struct RuleHit {
    pub rule: String,
    pub what: String,
    pub safety: Safety,
    pub total: Bytes,
    pub count: usize,
    /// Part of `total` in places untouched for 90+ days: the low-regret share.
    pub idle_90d: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub top: Vec<PathSize>,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub root: String,
    pub size: Bytes,
    pub files: u64,
    pub dirs: u64,
    pub tree: TreeNode,
    pub largest_files: Vec<PathSize>,
    pub by_extension: Vec<ExtStat>,
    pub kb_hits: Vec<RuleHit>,
    pub inaccessible_dirs: u64,
    pub skipped_links: u64,
}

fn prune(ctx: &Ctx, node: &Node, threshold: u64, depth: usize, opts: &ScanOptions) -> TreeNode {
    let mut sub = Vec::new();
    if depth < opts.depth {
        let mut children: Vec<&Node> = node.children.iter().filter(|c| c.size >= threshold).collect();
        children.sort_unstable_by_key(|x| std::cmp::Reverse(x.size));
        sub = children.into_iter().take(opts.top).map(|c| prune(ctx, c, threshold, depth + 1, opts)).collect();
    }
    TreeNode {
        path: node.path.display().to_string(),
        size: Bytes(node.size),
        idle_days: idle_days(node.newest),
        kb: node.rule.map(|r| ctx.kb.rules[r].id.clone()),
        sub,
    }
}

pub fn scan(kb: &Kb, root: &Path, opts: &ScanOptions) -> Section {
    let started = Instant::now();
    let root = expand_env(&root.to_string_lossy()).map(PathBuf::from).unwrap_or_else(|| root.to_path_buf());
    let ctx = Ctx::new(kb);

    let pool = crate::io::pool();
    let tree = {
        let _t = crate::trace::span(format!("disk: walk {}", root.display()));
        pool.install(|| walk(&ctx, root.clone(), None, false))
    };

    let threshold = ((tree.size as f64) * opts.min_share / 100.0) as u64;
    let pruned = prune(&ctx, &tree, threshold.max(1), 0, opts);

    let mut big = ctx.big_files.into_inner().unwrap();
    big.sort_unstable_by_key(|x| std::cmp::Reverse(x.0));
    let largest_files = big
        .into_iter()
        .take(opts.largest_files)
        .map(|(size, path)| PathSize { path: path.display().to_string(), size: Bytes(size), idle_days: None })
        .collect();

    let mut exts: Vec<_> = ctx.exts.into_inner().unwrap().into_iter().collect();
    exts.sort_unstable_by_key(|x| std::cmp::Reverse(x.1.0));
    let by_extension =
        exts.into_iter().take(12).map(|(ext, (size, files))| ExtStat { ext, size: Bytes(size), files }).collect();

    let mut grouped: HashMap<usize, Vec<(PathBuf, u64, u64)>> = HashMap::new();
    for (rule, path, size, newest) in ctx.hits.into_inner().unwrap() {
        grouped.entry(rule).or_default().push((path, size, newest));
    }
    let mut kb_hits: Vec<RuleHit> = grouped
        .into_iter()
        .filter_map(|(rule, mut paths)| {
            let total: u64 = paths.iter().map(|p| p.1).sum();
            if total < 1024 * 1024 {
                return None;
            }
            paths.sort_unstable_by_key(|x| std::cmp::Reverse(x.1));
            let r = &kb.rules[rule];
            let idle_90d = paths.iter().filter(|p| idle_days(p.2).is_some_and(|d| d >= 90)).map(|p| p.1).sum();
            Some(RuleHit {
                rule: r.id.clone(),
                what: r.what.clone(),
                safety: r.safety,
                total: Bytes(total),
                count: paths.len(),
                idle_90d: Bytes(idle_90d),
                command: r.command.clone(),
                note: r.note.clone(),
                top: paths
                    .into_iter()
                    .take(5)
                    .map(|(p, s, newest)| PathSize {
                        path: p.display().to_string(),
                        size: Bytes(s),
                        idle_days: idle_days(newest),
                    })
                    .collect(),
            })
        })
        .collect();
    kb_hits.sort_unstable_by_key(|x| std::cmp::Reverse(x.total));

    let findings = kb_hits
        .iter()
        .filter(|h| matches!(h.safety, Safety::Safe | Safety::Caution) && h.total.0 >= 500 * 1024 * 1024)
        .map(|h| {
            let r = kb.get(&h.rule).expect("hit refers to a known rule");
            let mut finding = Finding::new(
                format!("disk.{}", h.rule),
                Area::Disk,
                space_severity(h.total.0),
                if h.idle_90d.0 > 0 {
                    format!("{} ({} in {} places, {} untouched for 90+ days)", h.what, h.total, h.count, h.idle_90d)
                } else {
                    format!("{} ({} in {} places)", h.what, h.total, h.count)
                },
            )
            .evidence(h.top.iter().map(|p| match p.idle_days {
                Some(d) => format!("{} {} (idle {d}d)", p.size, p.path),
                None => format!("{} {}", p.size, p.path),
            }))
            .space(h.total.0, r.reclaimable);
            if let Some(fix) = rule_fix(r) {
                finding = finding.fix(fix);
            }
            finding
        })
        .collect();

    let inaccessible = ctx.inaccessible.load(Ordering::Relaxed);
    let mut blind_spots =
        vec!["Sizes are logical (not on-disk); hardlinked files such as WinSxS are counted once per link.".to_string()];
    if inaccessible > 0 {
        let samples = ctx.denied_samples.into_inner().unwrap().join(", ");
        blind_spots.push(format!(
            "{inaccessible} directories could not be read (e.g. {samples}). Run elevated for a complete view."
        ));
    }

    let result = ScanResult {
        root: root.display().to_string(),
        size: Bytes(tree.size),
        files: tree.files,
        dirs: tree.dirs,
        tree: pruned,
        largest_files,
        by_extension,
        kb_hits,
        inaccessible_dirs: inaccessible,
        skipped_links: ctx.links.load(Ordering::Relaxed),
    };
    let mut section = Section {
        data: serde_json::to_value(result).expect("scan result serializes"),
        findings,
        blind_spots,
        took_ms: started.elapsed().as_millis() as u64,
    };
    section.sort_findings();
    section
}

/// Space alone never goes above Medium: High/Critical are for things that are broken or unsafe.
pub fn space_severity(bytes: u64) -> Severity {
    const G: u64 = 1024 * 1024 * 1024;
    match bytes {
        b if b >= 5 * G => Severity::Medium,
        b if b >= 500 * 1024 * 1024 => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn rule_fix(rule: &crate::kb::Rule) -> Option<Fix> {
    let mut fix = match (&rule.clean, &rule.command) {
        (CleanMode::Contents, _) => {
            let mut fix = Fix::command(rule.safety, format!("agenticdisk clean {} --apply", rule.id))
                .op(crate::action::Op::EmptyDir { rule: rule.id.clone() });
            fix.clean_rule = Some(rule.id.clone());
            fix
        }
        (CleanMode::None, Some(cmd)) => Fix::command(rule.safety, cmd.clone()),
        (CleanMode::None, None) => Fix::manual(rule.note.clone().unwrap_or_default()),
    };
    fix.safety = rule.safety;
    fix.consent = rule.consent();
    fix.admin = rule.admin;
    fix.note = rule.note.clone();
    Some(fix)
}

/// Parallel recursive size of a file or directory: (bytes, files, unreadable dirs).
pub fn du(path: &Path) -> (u64, u64, u64) {
    let Ok(read) = std::fs::read_dir(path) else {
        return match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => (m.len(), 1, 0),
            _ => match file_len_via_parent(path) {
                Some(len) => (len, 1, 0),
                None => (0, 0, 1),
            },
        };
    };
    let mut bytes = 0;
    let mut files = 0;
    let mut subdirs = Vec::new();
    for entry in read.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            subdirs.push(entry.path());
        } else {
            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            files += 1;
        }
    }
    let (sub_bytes, sub_files, unreadable) =
        subdirs.into_par_iter().map(|d| du(&d)).reduce(|| (0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
    (bytes + sub_bytes, files + sub_files, unreadable)
}

/// Size of files that cannot be opened at all (pagefile.sys, hiberfil.sys), read from the parent
/// directory listing.
fn file_len_via_parent(path: &Path) -> Option<u64> {
    let (parent, name) = (path.parent()?, path.file_name()?);
    std::fs::read_dir(parent)
        .ok()?
        .flatten()
        .find(|e| e.file_name().eq_ignore_ascii_case(name))
        .and_then(|e| e.metadata().ok())
        .map(|m| m.len())
}
