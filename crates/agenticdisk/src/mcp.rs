//! `agenticdisk mcp`: Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0).
//!
//! Every tool is translated into the equivalent command line and run through the same `run()` the
//! CLI uses, so the MCP server can never drift from the CLI. Values that come from the client are
//! placed after `--`, so a path or rule id can never be parsed as a flag such as `--apply`.

use std::io::{BufRead, Write};
use std::time::Instant;

use clap::Parser;
use serde_json::{Value, json};

use crate::{Cli, run};

const PROTOCOLS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "agenticdisk inspects this Windows PC and applies only changes the user approves. \
For any question about this PC, use these tools before shell commands: they are faster, read what a non-admin shell cannot, and know what is safe to delete. \
Which tool: disk full / free space -> pc_plan(space) (includes build folders per project with idle days); slow PC -> pc_plan(speed); \
blue screens, crashes, freezes -> pc_inspect(stability); privacy, telemetry, ads -> pc_plan(privacy); bloatware -> pc_plan(debloat); \
malware or hijack worries -> pc_plan(security); 'what is this folder / can I delete it?' -> pc_explain(path); vague 'check my PC' -> pc_overview, then pc_plan for what matters. \
Flow: pc_plan returns numbered actions and `questions`; ask the user those questions and let them choose, never answer them yourself. \
Then pc_preview (read-only) returns `confirm` and a `token`: show `confirm` to the user word for word, \
and call pc_apply(token) only after they say yes to it. pc_apply is the only tool that changes anything. Actions that come back as a script are for the user to review and run. \
If the plan's `coverage` shows space it does not list, offer pc_disk on that drive. \
If a tool returns an error, report it; do not redo the change with shell commands. \
Personal files are never deleted. `blind_spots` mean 'not checked', not 'fine'. Answer in the user's language.";

const AGENTS_MD: &str = include_str!("../../../AGENTS.md");
const SAFETY_MD: &str = include_str!("../../../SAFETY.md");

const AREAS: [&str; 8] = ["system", "cleanup", "drivers", "privacy", "startup", "apps", "security", "stability"];
const GOALS: [&str; 8] = ["space", "speed", "privacy", "debloat", "security", "stability", "gaming", "all"];
const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

fn report_props() -> Value {
    json!({
        "max_findings": { "type": "integer", "minimum": 1, "description": "Keep at most this many findings (summary totals still count all)." },
        "min_severity": { "type": "string", "enum": SEVERITIES, "description": "Hide findings below this severity." }
    })
}

fn with_report_props(mut props: Value) -> Value {
    if let (Value::Object(p), Value::Object(r)) = (&mut props, report_props()) {
        p.extend(r);
    }
    with_bytes(props)
}

fn with_bytes(mut props: Value) -> Value {
    if let Value::Object(p) = &mut props {
        p.insert(
            "bytes".into(),
            json!({ "type": "boolean", "description": "Sizes as exact byte integers instead of \"12.4G\" (for arithmetic)." }),
        );
    }
    props
}

fn tool(name: &str, title: &str, description: &str, properties: Value, required: &[&str], read_only: bool) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": { "type": "object", "properties": properties, "required": required, "additionalProperties": false },
        "annotations": {
            "title": title,
            "readOnlyHint": read_only,
            "destructiveHint": !read_only && name == "pc_apply",
            "idempotentHint": read_only,
            "openWorldHint": false
        }
    })
}

fn tools() -> Value {
    json!([
        tool(
            "pc_goals",
            "What can be fixed",
            "The goals a user can ask for (space, speed, privacy, debloat, security, stability, gaming, all), with the phrasing users typically use and a question to ask them. Call this first when the user's request is vague.",
            json!({}),
            &[],
            true
        ),
        tool(
            "pc_overview",
            "PC overview",
            "Health check of every area at once in ~2 s: ranked findings (most severe and largest first), per-area summaries, blind spots. Read-only. For acting on a goal, pc_plan is more direct. Use max_findings (e.g. 15) to keep it short.",
            with_report_props(json!({
                "only": { "type": "array", "items": { "type": "string", "enum": AREAS }, "description": "Limit to these areas." }
            })),
            &[],
            true
        ),
        tool(
            "pc_plan",
            "Plan for a goal",
            "Numbered actions for one goal, the questions to ask the user before choosing, advice only a human can act on, and blind spots. Actions of one kind (build folders, virtual disks) come as one group whose `items` hold the per-folder id, path, size and idle_days (`active` = changed in the last 2 weeks). The space goal also scans the user profile for build folders per project, which can take ~15 s the first time, and reports `coverage`: how much of the drive's used space the plan lists. Saves the plan (valid 24 h); changes nothing.",
            with_bytes(json!({
                "goal": { "type": "string", "enum": GOALS }
            })),
            &["goal"],
            true
        ),
        tool(
            "pc_preview",
            "Preview chosen actions",
            "Read-only: the exact text of what applying these actions would change (`confirm`), current values and sizes, and a one-use `token` for pc_apply (valid 1 h). Show `confirm` to the user verbatim. Never choose actions in consent classes project, software, rollback, evidence or user_data without the user naming them; `safe` selects only safe cache/setting actions.",
            with_bytes(json!({
                "plan": { "type": "string", "description": "Plan id from pc_plan." },
                "actions": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Action ids such as a1, a4, or the single value `safe`." }
            })),
            &["plan", "actions"],
            true
        ),
        tool(
            "pc_apply",
            "Apply previewed actions",
            "The only tool that changes the PC: applies exactly what pc_preview showed for this token. Call it only after the user agreed to that `confirm` text. Writes are journaled; registry changes can be reverted with pc_undo. Admin-only and external steps come back as a script for the user to run.",
            json!({
                "token": { "type": "string", "description": "Token from pc_preview, after the user agreed to its `confirm` text." }
            }),
            &["token"],
            false
        ),
        tool(
            "pc_undo",
            "Undo an apply",
            "Restores the registry values an apply run changed (cache deletions regenerate on their own).",
            json!({
                "journal": { "type": "string", "description": "Journal id from pc_apply or pc_history." }
            }),
            &["journal"],
            false
        ),
        tool(
            "pc_history",
            "Past apply runs",
            "Previous apply runs, newest first, with whether each can be undone.",
            json!({}),
            &[],
            true
        ),
        tool(
            "pc_inspect",
            "Inspect one area",
            "Full inventory and findings for one area: system, cleanup, drivers, privacy, startup, apps, security or stability. stability = blue screens with stop codes and dump paths, unexpected shutdowns, hardware (WHEA) errors, boot service failures.",
            with_report_props(json!({
                "area": { "type": "string", "enum": AREAS },
                "full": { "type": "boolean", "description": "drivers only: also list every third-party driver (slower)." }
            })),
            &["area"],
            true
        ),
        tool(
            "pc_disk",
            "Disk space tree",
            "Size tree of a folder or drive with largest files, extensions and known caches/build folders (with idle days: when anything inside last changed). A whole drive can take a minute the first time.",
            with_report_props(json!({
                "path": { "type": "string", "description": "Folder or drive, e.g. C:\\ or C:\\Users\\me (default: system drive)." },
                "depth": { "type": "integer", "minimum": 0, "maximum": 8 },
                "top": { "type": "integer", "minimum": 1, "maximum": 50 },
                "min_share": { "type": "number", "minimum": 0, "description": "Hide subtrees smaller than this % of the total." },
                "files": { "type": "integer", "minimum": 0, "maximum": 100, "description": "How many largest files to list." }
            })),
            &[],
            true
        ),
        tool(
            "pc_explain",
            "What is this folder?",
            "What a file or folder is, whether it is protected, whether it is safe to delete, its size, when anything inside last changed (idle_days), its largest children and the known locations inside it. Use it whenever the user asks about a specific path, and before touching anything unknown.",
            with_bytes(json!({
                "path": { "type": "string" }
            })),
            &["path"],
            true
        ),
        tool(
            "pc_clean_preview",
            "Preview a cleanup",
            "Dry run: what emptying these knowledge-base cache locations would free, honoring age windows and kept names. Never deletes; deletion goes through pc_plan + pc_apply.",
            json!({
                "rules": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Rule ids such as win.temp_user (from fix.clean_rule)." }
            }),
            &["rules"],
            true
        ),
        tool(
            "pc_rules",
            "Knowledge base",
            "The space knowledge base: every known location, what it is, its safety level and fix. Optionally one rule.",
            json!({
                "id": { "type": "string" }
            }),
            &[],
            true
        ),
    ])
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn list_arg(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn ensure(values: &[String], what: &str, ok: impl Fn(&str) -> bool) -> Result<(), String> {
    match values.iter().find(|v| !ok(v)) {
        Some(bad) => Err(format!("invalid {what}: {bad}")),
        None => Ok(()),
    }
}

fn is_id(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Tool call -> command line. Client values go after `--` (positional) or into a flag's value.
fn argv(name: &str, args: &Value) -> Result<Vec<String>, String> {
    let mut v: Vec<String> = vec!["agenticdisk".into()];
    if args.get("bytes").and_then(Value::as_bool) == Some(true) {
        v.push("--bytes".into());
    }
    let report_flags = |v: &mut Vec<String>| {
        if let Some(n) = args.get("max_findings").and_then(Value::as_u64) {
            v.extend(["--max-findings".into(), n.to_string()]);
        }
        if let Some(s) = str_arg(args, "min_severity").filter(|s| SEVERITIES.contains(s)) {
            v.extend(["--min-severity".into(), s.into()]);
        }
    };
    match name {
        "pc_goals" => v.push("goals".into()),
        "pc_history" => v.push("history".into()),
        "pc_overview" => {
            v.push("overview".into());
            let only = list_arg(args, "only");
            ensure(&only, "area", |a| AREAS.contains(&a))?;
            if !only.is_empty() {
                v.extend(["--only".into(), only.join(",")]);
            }
            report_flags(&mut v);
        }
        "pc_plan" => {
            let goal =
                str_arg(args, "goal").filter(|g| GOALS.contains(g)).ok_or("goal must be one of the listed goals")?;
            v.extend(["plan".into(), "--".into(), goal.into()]);
        }
        "pc_preview" => {
            let plan = str_arg(args, "plan").filter(|p| is_id(p)).ok_or("plan must be a plan id from pc_plan")?;
            let actions = list_arg(args, "actions");
            if actions.is_empty() {
                return Err("actions must name at least one action id".into());
            }
            ensure(&actions, "action id", is_id)?;
            v.extend(["preview".into(), "--actions".into(), actions.join(","), "--".into(), plan.into()]);
        }
        "pc_apply" => {
            let token = str_arg(args, "token").filter(|t| is_id(t)).ok_or("token must be the token from pc_preview")?;
            v.extend(["apply".into(), "--token".into(), token.into()]);
        }
        "pc_undo" => {
            let journal = str_arg(args, "journal").filter(|j| is_id(j)).ok_or("journal must be a journal id")?;
            v.extend(["undo".into(), "--".into(), journal.into()]);
        }
        "pc_inspect" => {
            let area =
                str_arg(args, "area").filter(|a| AREAS.contains(a)).ok_or("area must be one of the listed areas")?;
            v.push(area.into());
            if area == "drivers" && args.get("full").and_then(Value::as_bool) == Some(true) {
                v.push("--full".into());
            }
            report_flags(&mut v);
        }
        "pc_disk" => {
            v.push("disk".into());
            for (key, flag) in [("depth", "--depth"), ("top", "--top"), ("files", "--files")] {
                if let Some(n) = args.get(key).and_then(Value::as_u64) {
                    v.extend([flag.into(), n.to_string()]);
                }
            }
            if let Some(n) = args.get("min_share").and_then(Value::as_f64).filter(|n| n.is_finite() && *n >= 0.0) {
                v.extend(["--min-share".into(), n.to_string()]);
            }
            report_flags(&mut v);
            if let Some(path) = str_arg(args, "path").filter(|p| !p.trim().is_empty()) {
                v.extend(["--".into(), path.into()]);
            }
        }
        "pc_explain" => {
            let path = str_arg(args, "path").filter(|p| !p.trim().is_empty()).ok_or("path is required")?;
            v.extend(["explain".into(), "--".into(), path.into()]);
        }
        "pc_clean_preview" => {
            let rules = list_arg(args, "rules");
            if rules.is_empty() {
                return Err("rules must name at least one rule id".into());
            }
            ensure(&rules, "rule id", is_id)?;
            // Never `--apply` here: deletion only happens through pc_apply.
            v.extend(["clean".into(), "--".into()]);
            v.extend(rules);
        }
        "pc_rules" => {
            v.push("rules".into());
            if let Some(id) = str_arg(args, "id").filter(|i| is_id(i)) {
                v.extend(["--".into(), id.into()]);
            }
        }
        other => return Err(format!("unknown tool {other}")),
    }
    Ok(v)
}

fn call_tool(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let outcome = argv(name, &args).and_then(|argv| {
        let cli = Cli::try_parse_from(&argv).map_err(|e| e.to_string())?;
        agenticdisk_core::size::set_exact_bytes(cli.bytes);
        run(cli, Instant::now()).map_err(|e| e.to_string())
    });
    match outcome {
        Ok(value) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&value).unwrap_or_default() }],
            "isError": false
        }),
        Err(message) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true
        }),
    }
}

fn prompts() -> Value {
    json!([{
        "name": "fix_my_pc",
        "title": "Fix my PC",
        "description": "Diagnose this PC for a goal, ask the right questions, and apply only what the user approves.",
        "arguments": [{ "name": "problem", "description": "What the user wants, in their words (e.g. 'my disk is full', 'it's slow', 'blue screens').", "required": false }]
    }])
}

fn get_prompt(params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
    if name != "fix_my_pc" {
        return Err((-32602, format!("unknown prompt {name}")));
    }
    let problem = params.pointer("/arguments/problem").and_then(Value::as_str).filter(|p| !p.trim().is_empty());
    let opening = match problem {
        Some(p) => format!("My problem: {p}\n\nMap it to a goal with pc_goals (or directly), then run pc_plan for it."),
        None => "Call pc_goals and ask me what I want to fix, then run pc_plan for that goal.".into(),
    };
    let text = format!(
        "Help me fix this Windows PC with the agenticdisk tools.\n\n{opening}\n\n\
1. Ask me the plan's `questions` (they are grouped) and wait for my answers.\n\
2. Propose the actions in plain words, grouped by what they touch, with how much space each frees.\n\
3. Call pc_preview with the actions I chose, show me its `confirm` text exactly, and only after I say yes call pc_apply with its token.\n\
4. If it returns a script, tell me how to run it (as administrator when needed).\n\
5. Re-check with pc_plan or pc_overview and tell me the before/after numbers.\n\n\
Never delete personal files. Treat blind spots as 'not checked'. Answer in the language of my request."
    );
    Ok(
        json!({ "description": "Diagnose, ask, then apply only what the user approves.", "messages": [{ "role": "user", "content": { "type": "text", "text": text } }] }),
    )
}

fn resources() -> Value {
    json!([
        { "uri": "agenticdisk://docs/agents", "name": "agents", "title": "Agent playbook", "description": "How an agent should use agenticdisk.", "mimeType": "text/markdown" },
        { "uri": "agenticdisk://docs/safety", "name": "safety", "title": "Safety model", "description": "What agenticdisk will and will not change.", "mimeType": "text/markdown" }
    ])
}

fn read_resource(params: &Value) -> Result<Value, (i64, String)> {
    let uri = params.get("uri").and_then(Value::as_str).unwrap_or_default();
    let text = match uri {
        "agenticdisk://docs/agents" => AGENTS_MD,
        "agenticdisk://docs/safety" => SAFETY_MD,
        _ => return Err((-32002, format!("resource not found: {uri}"))),
    };
    Ok(json!({ "contents": [{ "uri": uri, "mimeType": "text/markdown", "text": text }] }))
}

fn handle(method: &str, params: &Value) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOLS[0]);
            let version = PROTOCOLS.iter().find(|p| **p == asked).copied().unwrap_or(PROTOCOLS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": {}, "prompts": {}, "resources": {} },
                "serverInfo": { "name": "agenticdisk", "title": "agenticdisk", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => Ok(call_tool(params)),
        "prompts/list" => Ok(json!({ "prompts": prompts() })),
        "prompts/get" => get_prompt(params),
        "resources/list" => Ok(json!({ "resources": resources() })),
        "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
        "resources/read" => read_resource(params),
        _ => Err((-32601, format!("method not found: {method}"))),
    }
}

/// Serves until stdin closes. Nothing but protocol messages is ever written to stdout.
pub fn serve() {
    crate::MCP_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                let reply = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("parse error: {e}") } });
                let _ = writeln!(stdout, "{reply}");
                let _ = stdout.flush();
                continue;
            }
        };
        // Notifications (no id) never get a reply.
        let Some(id) = message.get("id").cloned() else { continue };
        let method = message.get("method").and_then(Value::as_str).unwrap_or_default();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        let reply = match handle(method, &params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_values_can_never_become_flags() {
        let a = argv("pc_clean_preview", &json!({ "rules": ["--apply"] }));
        assert!(a.is_err(), "flag-looking rule ids are rejected");
        let a = argv("pc_clean_preview", &json!({ "rules": ["win.temp_user"] })).unwrap();
        assert!(!a.iter().any(|x| x == "--apply"));
        let a = argv("pc_explain", &json!({ "path": "--yes" })).unwrap();
        assert_eq!(a[a.len() - 2..], ["--", "--yes"]);
        let cli = Cli::try_parse_from(&a).unwrap();
        assert!(matches!(cli.command, Some(crate::Cmd::Explain { .. })));
        let a = argv("pc_preview", &json!({ "plan": "space-1234", "actions": ["a1", "a2"] })).unwrap();
        assert!(!a.iter().any(|x| x == "--yes" || x == "--token"), "a preview can never apply");
        assert!(argv("pc_preview", &json!({ "plan": "x;rm", "actions": ["a1"] })).is_err());
        assert!(argv("pc_apply", &json!({ "token": "--yes" })).is_err());
        assert!(argv("pc_apply", &json!({ "plan": "space-1234", "actions": ["a1"] })).is_err(), "apply needs a token");
    }

    #[test]
    fn only_pc_apply_and_pc_undo_can_change_anything() {
        for t in tools().as_array().unwrap() {
            let name = t["name"].as_str().unwrap();
            let read_only = t["annotations"]["readOnlyHint"] == true;
            assert_eq!(read_only, !["pc_apply", "pc_undo"].contains(&name), "{name}");
        }
    }

    #[test]
    fn every_tool_parses_into_a_valid_command() {
        let samples = [
            ("pc_goals", json!({})),
            ("pc_overview", json!({ "only": ["system"], "max_findings": 5, "min_severity": "low" })),
            ("pc_plan", json!({ "goal": "space", "bytes": true })),
            ("pc_preview", json!({ "plan": "space-1234", "actions": ["safe"] })),
            ("pc_apply", json!({ "token": "t-0123456789abcdef" })),
            ("pc_undo", json!({ "journal": "space-1-2" })),
            ("pc_history", json!({})),
            ("pc_inspect", json!({ "area": "drivers", "full": true })),
            ("pc_disk", json!({ "path": "C:\\Users", "depth": 2, "min_share": 0.5 })),
            ("pc_rules", json!({ "id": "win.temp_user" })),
        ];
        for (name, args) in samples {
            let a = argv(name, &args).unwrap();
            Cli::try_parse_from(&a).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        assert_eq!(tools().as_array().unwrap().len(), 12);
    }
}
