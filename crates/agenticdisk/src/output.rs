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

/// A fix agenticdisk can apply itself shows `auto: true` instead of its `reg add` text and `op`:
/// the agent goes through plan/apply (journaled, undoable) and never pastes the command by hand.
fn finding_view(f: &Finding) -> Value {
    let mut v = serde_json::to_value(f).expect("finding serializes");
    if let Some(fix) = v.get_mut("fix").and_then(Value::as_object_mut)
        && fix.remove("op").is_some()
    {
        fix.remove("command");
        fix.remove("clean_rule");
        fix.insert("auto".into(), true.into());
    }
    v
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
        "findings": shown.into_iter().map(finding_view).collect::<Vec<_>>(),
        "sections": sections,
        "blind_spots": blind_spots,
        "next": next,
    })
}

#[cfg(test)]
mod tests {
    use agenticdisk_core::action::Op;
    use agenticdisk_core::model::{Area, Fix};

    use super::*;

    #[test]
    fn fixes_agenticdisk_applies_hide_their_command() {
        let auto = Finding::new("cleanup.x", Area::Cleanup, Severity::Low, "x")
            .fix(Fix::command(Safety::Safe, "agenticdisk clean x --apply").op(Op::EmptyDir { rule: "x".into() }));
        let v = finding_view(&auto);
        assert_eq!(v["fix"]["auto"], true);
        assert!(v["fix"].get("op").is_none() && v["fix"].get("command").is_none());
        let manual = Finding::new("cleanup.y", Area::Cleanup, Severity::Low, "y")
            .fix(Fix::command(Safety::Safe, "npm cache clean --force"));
        assert_eq!(finding_view(&manual)["fix"]["command"], "npm cache clean --force");
    }
}
