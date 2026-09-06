//! ChainCheck native scanner.
//!
//! Read-only Linux/WSL scanner for retrospective local evidence of known
//! malicious software supply-chain activity.

pub mod campaign;
pub mod cli;
pub mod coverage;
pub mod credentials;
pub mod discovery;
pub mod error;
pub mod evidence;
pub mod fsutil;
pub mod git;
pub mod host;
pub mod intelligence;
pub mod model;
pub mod npm;
pub mod processutil;
pub mod progress;
pub mod python;
pub mod report;
pub mod scan;
pub mod self_test;
