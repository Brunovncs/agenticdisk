//! Platform-independent core of agenticdisk: the output model, the space knowledge base, the
//! parallel disk scanner and the cleanup engine. Platform crates add system collectors on top.

pub mod action;
pub mod cleanup;
pub mod goals;
pub mod io;
pub mod kb;
pub mod model;
pub mod scan;
pub mod size;
pub mod trace;

pub use kb::Kb;
pub use model::{Area, Consent, Finding, Fix, Safety, Section, Severity};
pub use size::Bytes;
