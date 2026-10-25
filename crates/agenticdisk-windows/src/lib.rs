//! Windows collectors for agenticdisk. Each `collect` returns a `Section`; `detail = false` keeps
//! `data` to a summary (for `overview`), `true` adds the full inventory (for the area's command).
#![cfg(windows)]

pub mod apps;
pub mod drivers;
mod events;
pub mod platform;
pub mod privacy;
mod reg;
pub mod security;
mod sign;
pub mod stability;
pub mod startup;
mod suspicious;
pub mod system;
mod tasks;

pub fn elevated() -> bool {
    // SAFETY: no arguments, no preconditions.
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}
