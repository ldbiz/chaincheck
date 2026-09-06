//! Terminal scan progress via [`indicatif`].

use std::fmt::Write;
use std::io::{self, IsTerminal};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle};

use crate::cli::ProcessConfig;

pub const MSG_INTEL: &str = "Acquiring malware intelligence…";
pub const MSG_SCAN: &str = "Scanning…";
pub const MSG_REPORT: &str = "Writing reports…";

/// Progress sink for the main scan. Object-safe so the CLI can box TTY vs silent.
pub trait ScanProgress {
    fn set_message(&self, message: &str);
    fn tick(&self);
    fn finish(&self);
}

/// No drawing, no counters. Library callers and tests use this by default.
pub struct NoProgress;

impl ScanProgress for NoProgress {
    fn set_message(&self, _message: &str) {}
    fn tick(&self) {}
    fn finish(&self) {}
}

/// stderr spinner with an entry count once the walk has started.
pub struct TerminalProgress {
    bar: ProgressBar,
}

impl TerminalProgress {
    pub fn new() -> Self {
        Self::with_target(ProgressDrawTarget::stderr())
    }

    fn with_target(target: ProgressDrawTarget) -> Self {
        let bar = ProgressBar::with_draw_target(None, target);
        bar.set_style(spinner_style());
        if !bar.is_hidden() {
            bar.enable_steady_tick(Duration::from_millis(80));
        }
        Self { bar }
    }

    pub fn for_scan(config: &ProcessConfig) -> Box<dyn ScanProgress> {
        if should_draw_progress(config, io::stderr().is_terminal()) {
            Box::new(Self::new())
        } else {
            Box::new(NoProgress)
        }
    }
}

impl ScanProgress for TerminalProgress {
    fn set_message(&self, message: &str) {
        self.bar.set_position(0);
        self.bar.set_message(message.to_owned());
    }

    fn tick(&self) {
        self.bar.inc(1);
    }

    fn finish(&self) {
        self.bar.finish_and_clear();
    }
}

impl Drop for TerminalProgress {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

pub fn should_draw_progress(config: &ProcessConfig, stderr_is_terminal: bool) -> bool {
    !config.no_progress && stderr_is_terminal
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg} {entries}")
        .expect("static progress template")
        .with_key("entries", |state: &ProgressState, w: &mut dyn Write| {
            if state.pos() > 0 {
                let _ = write!(w, "{} entries", state.pos());
            }
        })
}

#[cfg(test)]
pub(crate) struct TickCount {
    ticks: std::sync::atomic::AtomicU64,
    messages: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl TickCount {
    pub(crate) fn new() -> Self {
        Self {
            ticks: std::sync::atomic::AtomicU64::new(0),
            messages: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn tick_count(&self) -> u64 {
        use std::sync::atomic::Ordering;
        self.ticks.load(Ordering::Relaxed)
    }

    pub(crate) fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl ScanProgress for TickCount {
    fn set_message(&self, message: &str) {
        self.messages.lock().unwrap().push(message.to_owned());
    }

    fn tick(&self) {
        use std::sync::atomic::Ordering;
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    fn finish(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draw_requires_tty_and_unset_no_progress() {
        let enabled = ProcessConfig::default();
        let mut disabled = ProcessConfig::default();
        disabled.no_progress = true;
        assert!(should_draw_progress(&enabled, true));
        assert!(!should_draw_progress(&enabled, false));
        assert!(!should_draw_progress(&disabled, true));
        assert!(!should_draw_progress(&disabled, false));
    }

    #[test]
    fn hidden_terminal_progress_accepts_ticks() {
        let progress = TerminalProgress::with_target(ProgressDrawTarget::hidden());
        progress.set_message(MSG_SCAN);
        progress.tick();
        progress.tick();
        assert_eq!(progress.bar.position(), 2);
        progress.set_message(MSG_REPORT);
        assert_eq!(progress.bar.position(), 0);
        progress.finish();
    }

    #[test]
    fn tick_count_records_messages_and_ticks() {
        let progress = TickCount::new();
        progress.set_message(MSG_SCAN);
        progress.tick();
        progress.tick();
        progress.tick();
        assert_eq!(progress.tick_count(), 3);
        assert_eq!(progress.messages(), [MSG_SCAN]);
    }
}
