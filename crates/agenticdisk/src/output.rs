//! The JSON envelope every report command prints.

use std::time::Instant;

use agenticdisk_core::model::sort_findings;
use agenticdisk_core::{Bytes, Finding, Safety, Section, Severity};
use serde_json::{Value, json};

pub const DISCLAIMER: &str = "agenticdisk is provided AS IS, without warranty of any kind (MIT License). It never deletes personal files and only changes what you explicitly approve; you remain responsible for what you choose to apply.";

/// Totals are computed on everything the collectors found, before filtering or truncating, so the
/// summary never under-reports because of display options.
pub fn summary(all: &[Finding], below_min: usize, truncated: usize) -> Value {
    let count = |s: Severity| all.iter().filter(|f| f.severity == s).count();
    let reclaim = |safety: Safety| {
        Bytes(
            all.iter()
                .filter(|f| f.fix.as_ref().is_some_and(|x| x.safety == safety))
                .filter_map(|f| f.reclaim)
                .map(|b| b.0)
                .sum(),
        )
    };
    json!({
        "critical": count(Severity::Critical),
        "high": count(Severity::High),
        "medium": count(Severity::Medium),
        "low": count(Severity::Low),
        "info": count(Severity::Info),
        "hidden_below_min_severity": below_min,
        "truncated_by_max_findings": truncated,
        "reclaimable": { "safe": reclaim(Safety::Safe), "caution": reclaim(Safety::Caution) },
    })
}

pub fn merge(sections: Vec<(&str, Section)>) -> (Vec<Finding>, Vec<String>, serde_json::Map<String, Value>) {
    let mut findings = Vec::new();
    let mut blind_spots = Vec::new();
    let mut out = serde_json::Map::new();
    for (name, section) in sections {
        findings.extend(section.findings);
        blind_spots.extend(section.blind_spots.into_iter().map(|b| format!("{name}: {b}")));
        let mut data = section.data;
        if let Value::Object(map) = &mut data {
            map.insert("took_ms".into(), section.took_ms.into());
        }
        out.insert(name.to_string(), data);
    }
    sort_findings(&mut findings);
    (findings, blind_spots, out)
}

pub struct View {
    pub min: Severity,
    pub max: Option<usize>,
}

pub fn envelope(
    command: &str,
    sections: Vec<(&str, Section)>,
    view: View,
    next: Vec<String>,
    started: Instant,
) -> Value {
    let (all, blind_spots, sections) = merge(sections);
    let below_min = all.iter().filter(|f| f.severity < view.min).count();
    let mut shown: Vec<&Finding> = all.iter().filter(|f| f.severity >= view.min).collect();
    let truncated = view.max.map(|m| shown.len().saturating_sub(m)).unwrap_or(0);
    if let Some(max) = view.max {
        shown.truncate(max);
    }
    json!({
        "tool": "agenticdisk",
        "version": env!("CARGO_PKG_VERSION"),
        "command": command,
        "elevated": crate::elevated(),
        "took_ms": started.elapsed().as_millis() as u64,
        "summary": summary(&all, below_min, truncated),
        "findings": shown,
        "sections": sections,
        "blind_spots": blind_spots,
        "next": next,
    })
}
