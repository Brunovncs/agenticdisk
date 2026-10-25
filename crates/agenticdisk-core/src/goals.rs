//! User goals ("I want more space", "make it faster") mapped onto collectors and findings. A user
//! states an outcome, not a list of registry keys; the goal decides what is relevant.

use serde::Serialize;

use crate::action::{Action, Plan};
use crate::model::{Area, Consent, Finding, Safety, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Goal {
    Space,
    Speed,
    Privacy,
    Debloat,
    Security,
    Stability,
    Gaming,
    All,
}

pub struct GoalInfo {
    pub goal: Goal,
    pub name: &'static str,
    pub title: &'static str,
    /// How a non-technical user would phrase it; agents match the user's words against these.
    pub user_says: &'static str,
    pub covers: &'static str,
    /// Collectors the plan needs.
    pub collectors: &'static [&'static str],
}

pub const GOALS: [GoalInfo; 8] = [
    GoalInfo {
        goal: Goal::Space,
        name: "space",
        title: "Free disk space",
        user_says: "disk full, no space, C: is red, need room for a game",
        covers: "temp files, app/browser/GPU caches, developer build folders and package caches, old drivers, update leftovers, hibernation file",
        collectors: &["system", "cleanup", "drivers"],
    },
    GoalInfo {
        goal: Goal::Speed,
        name: "speed",
        title: "Faster, lighter PC",
        user_says: "slow, takes forever to boot, laggy, fans always on, uses too much RAM",
        covers: "apps that launch at sign-in, background services, memory pressure, pending restarts, failing devices, slow boot causes",
        collectors: &["system", "startup", "drivers", "stability", "apps"],
    },
    GoalInfo {
        goal: Goal::Privacy,
        name: "privacy",
        title: "Less telemetry and tracking",
        user_says: "stop Microsoft spying, disable telemetry, privacy",
        covers: "diagnostic data, advertising ID, activity history, Bing in Start, inking/typing collection, feedback prompts",
        collectors: &["privacy"],
    },
    GoalInfo {
        goal: Goal::Debloat,
        name: "debloat",
        title: "Remove bloat and ads",
        user_says: "remove junk apps, Candy Crush, ads in Start, preinstalled crap",
        covers: "preinstalled apps, OEM trialware, silent app installs, Start/lock screen/Settings ads, sign-in apps",
        collectors: &["apps", "privacy", "startup"],
    },
    GoalInfo {
        goal: Goal::Security,
        name: "security",
        title: "Check for malware and weak spots",
        user_says: "virus, hacked, popups, browser hijacked, is my PC safe",
        covers: "antivirus state, active threats, persistence and hijacks, suspicious processes, PUPs, firewall/UAC/SmartScreen, kernel driver protections",
        collectors: &["security", "startup", "drivers"],
    },
    GoalInfo {
        goal: Goal::Stability,
        name: "stability",
        title: "Crashes, freezes and blue screens",
        user_says: "blue screen, PC restarts by itself, freezes, crashes",
        covers: "blue-screen history and stop codes, unexpected shutdowns, hardware errors (WHEA), failing devices, driver problems, boot timeouts",
        collectors: &["stability", "drivers", "system"],
    },
    GoalInfo {
        goal: Goal::Gaming,
        name: "gaming",
        title: "Better gaming performance",
        user_says: "FPS drops, stutter, game lag",
        covers: "background recording, sign-in apps competing for CPU, memory pressure, GPU driver age, shader cache health",
        collectors: &["system", "startup", "privacy", "stability"],
    },
    GoalInfo {
        goal: Goal::All,
        name: "all",
        title: "Full checkup",
        user_says: "check everything, general cleanup, make it like new",
        covers: "all of the above",
        collectors: &["system", "cleanup", "drivers", "privacy", "startup", "apps", "security", "stability"],
    },
];

impl Goal {
    pub fn parse(s: &str) -> Option<Goal> {
        GOALS.iter().find(|g| g.name.eq_ignore_ascii_case(s)).map(|g| g.goal)
    }

    pub fn info(self) -> &'static GoalInfo {
        GOALS.iter().find(|g| g.goal == self).expect("every goal has info")
    }

    pub fn matches(self, f: &Finding) -> bool {
        let id = f.id.as_str();
        match self {
            Goal::All => true,
            Goal::Space => {
                matches!(f.area, Area::Cleanup | Area::Disk)
                    || id.starts_with("system.low_space")
                    || id == "drivers.superseded_packages"
            }
            Goal::Speed => {
                id.starts_with("startup.")
                    || id.starts_with("system.hdd")
                    || id.starts_with("system.memory")
                    || id.starts_with("system.long_uptime")
                    || id.starts_with("system.pending_reboot")
                    || id.starts_with("drivers.problem")
                    || id.starts_with("stability.boot")
                    || id.starts_with("perf.")
                    || id == "apps.preinstalled_bloat"
            }
            Goal::Privacy => id.starts_with("privacy.") || id.starts_with("ads."),
            Goal::Debloat => {
                f.area == Area::Apps
                    || id.starts_with("ads.")
                    || id.starts_with("startup.login")
                    || id.starts_with("startup.app.")
            }
            Goal::Security => f.area == Area::Security,
            Goal::Stability => {
                f.area == Area::Stability
                    || id.starts_with("drivers.problem")
                    || id.starts_with("drivers.user_writable")
                    || id.starts_with("system.pending_reboot")
                    || id.starts_with("system.gpu_driver_age")
            }
            Goal::Gaming => {
                id.starts_with("perf.")
                    || id.starts_with("startup.login")
                    || id.starts_with("startup.app.")
                    || id.starts_with("system.memory")
                    || id.starts_with("system.gpu_driver_age")
                    || id.starts_with("stability.")
            }
        }
    }
}

#[derive(Serialize)]
pub struct Question {
    /// Action ids the answer decides.
    pub about: Vec<String>,
    pub ask: String,
}

/// (key, question, [(action id, title)])
type Family = (&'static str, &'static str, Vec<(String, String)>);

/// Families of near-identical actions get one question listing them all, not one each: a
/// questionnaire of twenty prompts gets no honest answers.
fn family(finding: &str) -> Option<(&'static str, &'static str)> {
    if finding.starts_with("startup.app.") {
        Some((
            "startup.app",
            "Which of these apps do you need to start automatically when you sign in? The others can be disabled (reversible):",
        ))
    } else if finding.starts_with("apps.optional.") {
        Some((
            "apps.optional",
            "Which of these preinstalled apps do you use? The ones you don't can be removed (reinstallable from the Store):",
        ))
    } else {
        None
    }
}

#[derive(Serialize)]
pub struct Advice {
    pub finding: String,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub struct Built {
    pub plan: Plan,
    pub advice: Vec<Advice>,
    pub questions: Vec<Question>,
}

/// Turns the goal's findings into numbered actions (anything with a fix), advice (no fix: things
/// only a human can do) and the questions the agent should ask before choosing actions.
pub fn build(goal: Goal, findings: &[Finding]) -> Built {
    let relevant: Vec<&Finding> = findings.iter().filter(|f| goal.matches(f)).collect();
    let mut actions = Vec::new();
    let mut advice = Vec::new();
    let mut questions: Vec<Question> = Vec::new();
    let mut families: Vec<Family> = Vec::new();
    for f in &relevant {
        let id = format!("a{}", actions.len() + 1);
        match Action::from_finding(id, f) {
            Some(action) => {
                if let Some((key, ask)) = family(&action.finding) {
                    match families.iter_mut().find(|(k, _, _)| *k == key) {
                        Some((_, _, members)) => members.push((action.id.clone(), action.title.clone())),
                        None => families.push((key, ask, vec![(action.id.clone(), action.title.clone())])),
                    }
                } else if let Some(q) = question_for(&action) {
                    questions.push(q);
                }
                actions.push(action);
            }
            None => advice.push(Advice {
                finding: f.id.clone(),
                severity: f.severity,
                title: f.title.clone(),
                note: f.fix.as_ref().and_then(|x| x.note.clone()).or_else(|| f.detail.clone()),
            }),
        }
    }
    for (_, ask, members) in families {
        let list = members.iter().map(|(id, title)| format!("{id}: {title}")).collect::<Vec<_>>().join("; ");
        questions
            .push(Question { about: members.into_iter().map(|(id, _)| id).collect(), ask: format!("{ask} {list}") });
    }
    Built { plan: Plan::new(goal.info().name, actions), advice, questions }
}

fn question_for(a: &Action) -> Option<Question> {
    let why = a.note.as_deref().map(|n| format!(" {n}")).unwrap_or_default();
    let ask = match (a.consent, a.safety) {
        (Consent::UserData, _) => {
            format!("{}: these are your files. Do you want to review and delete some of them yourself?{why}", a.title)
        }
        (Consent::Rollback, _) => {
            format!("{}: removing it means you cannot roll back. Do you still need that?{why}", a.title)
        }
        (Consent::Evidence, _) => {
            format!("{}: are you still investigating crashes? These files are the evidence.{why}", a.title)
        }
        (Consent::Software, _) => format!("{}: do you use any of these?{why}", a.title),
        (_, Safety::Manual | Safety::Caution) => format!("{}: OK to apply?{why}", a.title),
        _ => return None,
    };
    Some(Question { about: vec![a.id.clone()], ask })
}
