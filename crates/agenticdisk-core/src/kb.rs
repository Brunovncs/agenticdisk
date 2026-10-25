//! Curated knowledge about what occupies space and whether it is safe to remove.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobMatcher};
use serde::Deserialize;

use crate::model::Safety;

const COMMON: &str = include_str!("../kb/common.toml");
#[cfg(windows)]
const PLATFORM: &str = include_str!("../kb/windows.toml");
#[cfg(not(windows))]
const PLATFORM: &str = "";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanMode {
    /// `agenticdisk clean` may delete everything inside the folder (or the file itself).
    Contents,
    None,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_has: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    pub what: String,
    pub safety: Safety,
    pub clean: CleanMode,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admin: bool,
    #[serde(default = "yes", skip_serializing)]
    pub measure: bool,
    /// False when the fix frees only part of the size (VM disks, model stores, user folders).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub reclaimable: bool,
    /// Overrides the consent class implied by `category`.
    #[serde(default, rename = "consent", skip_serializing_if = "Option::is_none")]
    pub consent_override: Option<crate::model::Consent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// `clean` keeps entries modified more recently than this (in-progress installs, open work).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub min_age_days: u32,
    /// Child names (globs) `clean` never deletes, e.g. Outlook's edited attachments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep: Vec<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn yes() -> bool {
    true
}

impl Rule {
    pub fn consent(&self) -> crate::model::Consent {
        use crate::model::Consent;
        self.consent_override.unwrap_or(match self.category.as_str() {
            "logs" => Consent::Evidence,
            "user" => Consent::UserData,
            "system" => Consent::Rollback,
            _ => Consent::Cache,
        })
    }
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// Dynamic (name-based) rule compiled for the scanner.
pub struct NameRule {
    pub rule: usize,
    name: GlobMatcher,
    parent_has: Option<GlobMatcher>,
    contains: Option<GlobMatcher>,
}

impl NameRule {
    pub fn matches_name(&self, name: &str) -> bool {
        self.name.is_match(name)
    }

    pub fn parent_ok<'a>(&self, mut parent_files: impl Iterator<Item = &'a str>) -> bool {
        self.parent_has.as_ref().is_none_or(|g| parent_files.any(|f| g.is_match(f)))
    }

    pub fn contains_ok<'a>(&self, mut files: impl Iterator<Item = &'a str>) -> bool {
        self.contains.as_ref().is_none_or(|g| files.any(|f| g.is_match(f)))
    }

    pub fn needs_contains(&self) -> bool {
        self.contains.is_some()
    }
}

pub struct Kb {
    pub rules: Vec<Rule>,
    pub name_rules: Vec<NameRule>,
}

fn matcher(pattern: &str) -> GlobMatcher {
    GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(true)
        .build()
        .unwrap_or_else(|_| Glob::new(&globset::escape(pattern)).expect("escaped glob"))
        .compile_matcher()
}

impl Kb {
    pub fn load() -> Self {
        let mut rules = Vec::new();
        for src in [COMMON, PLATFORM] {
            let file: RuleFile = toml::from_str(src).expect("embedded knowledge base must parse");
            rules.extend(file.rule);
        }
        let name_rules = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                Some(NameRule {
                    rule: i,
                    name: matcher(r.dir_name.as_deref()?),
                    parent_has: r.parent_has.as_deref().map(matcher),
                    contains: r.contains.as_deref().map(matcher),
                })
            })
            .collect();
        Self { rules, name_rules }
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// The rule that covers `path` and the folder it matched: the deepest known location that
    /// contains it, else the nearest ancestor whose name matches a name rule (markers checked).
    pub fn explain(&self, path: &Path) -> Option<(&Rule, PathBuf)> {
        let path = normalize(path);
        let by_location = self
            .rules
            .iter()
            .flat_map(|r| Self::resolve(r).into_iter().map(move |p| (r, p)))
            .filter(|(_, p)| is_within(&path, p))
            .max_by_key(|(_, p)| p.components().count());
        if by_location.is_some() {
            return by_location;
        }

        for dir in path.ancestors() {
            let Some(name) = dir.file_name().map(|n| n.to_string_lossy()) else { continue };
            for nr in &self.name_rules {
                if !nr.matches_name(&name) {
                    continue;
                }
                let names = |d: Option<&Path>| -> Vec<String> {
                    d.and_then(|d| std::fs::read_dir(d).ok())
                        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
                        .unwrap_or_default()
                };
                let parent_files = names(dir.parent());
                let own_files = names(Some(dir));
                if nr.parent_ok(parent_files.iter().map(String::as_str))
                    && nr.contains_ok(own_files.iter().map(String::as_str))
                {
                    return Some((&self.rules[nr.rule], dir.to_path_buf()));
                }
            }
        }
        None
    }

    /// Concrete existing paths for a rule's `paths` (env vars expanded, `*` globs resolved).
    pub fn resolve(rule: &Rule) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for raw in &rule.paths {
            let Some(expanded) = expand_env(raw) else { continue };
            if expanded.contains('*') {
                let opts = glob::MatchOptions { case_sensitive: false, ..Default::default() };
                if let Ok(paths) = glob::glob_with(&expanded, opts) {
                    out.extend(paths.flatten());
                }
            } else {
                let p = PathBuf::from(expanded);
                if exists(&p) {
                    out.push(p);
                }
            }
        }
        out
    }
}

/// `exists()` fails on files Windows holds open exclusively (pagefile.sys, hiberfil.sys);
/// listing the parent directory still sees them.
pub fn exists(p: &Path) -> bool {
    if p.exists() {
        return true;
    }
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else { return false };
    std::fs::read_dir(parent).map(|rd| rd.flatten().any(|e| e.file_name().eq_ignore_ascii_case(name))).unwrap_or(false)
}

/// Expands `%VAR%` (any OS) and a leading `~`. Returns None if a variable is unset, so a
/// rule never resolves to a half-expanded path like `\Temp`.
pub fn expand_env(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len() + 32);
    let mut rest = input;
    if let Some(stripped) = rest.strip_prefix('~') {
        out.push_str(&home_dir()?);
        rest = stripped;
    }
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        // An empty variable would turn `%LOCALAPPDATA%\X` into the drive-relative `\X`.
        out.push_str(&std::env::var(&after[..end]).ok().filter(|v| !v.trim().is_empty())?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Absolute path with `.` and `..` resolved lexically, so `Temp\..\..\Documents` is judged as
/// Documents. Does not touch the filesystem (works for paths that no longer exist).
pub fn normalize(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Component-wise, case-insensitive "child is base or inside it" (no string-prefix tricks).
pub fn is_within(child: &Path, base: &Path) -> bool {
    let lower = |p: &Path| -> Vec<String> {
        normalize(p).components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect()
    };
    let (child, base) = (lower(child), lower(base));
    !base.is_empty() && child.len() >= base.len() && child[..base.len()] == base[..]
}

pub fn home_dir() -> Option<String> {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_kb_parses_and_ids_are_unique() {
        let kb = Kb::load();
        let mut ids: Vec<_> = kb.rules.iter().map(|r| r.id.as_str()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate rule id");
        assert!(kb.rules.iter().all(|r| !r.paths.is_empty() || r.dir_name.is_some()));
    }

    #[test]
    fn unset_variable_does_not_expand() {
        assert_eq!(expand_env("%AGENTICDISK_DOES_NOT_EXIST%\\Temp"), None);
    }

    #[test]
    fn parent_segments_cannot_escape_a_known_location() {
        let kb = Kb::load();
        let temp = std::env::temp_dir();
        let escaped = temp.join("..").join("..").join("..").join("Documents");
        assert!(kb.explain(&escaped).is_none_or(|(r, _)| r.id != "win.temp_user"));
        if cfg!(windows) {
            assert!(is_within(Path::new("C:\\A\\B\\..\\B\\c"), Path::new("c:/a/b")));
            assert!(!is_within(Path::new("C:\\A\\Bc"), Path::new("C:\\A\\B")));
        } else {
            assert!(is_within(Path::new("/a/b/../b/c"), Path::new("/a/b")));
            assert!(!is_within(Path::new("/a/bc"), Path::new("/a/b")));
        }
    }
}
