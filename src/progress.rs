//! Live scan progress. Rendering uses `indicatif`; library callers can no-op.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Progress events for the main scan.
pub trait Progress {
    fn stage(&self, label: &'static str);
    fn tick(&self);
    fn finish(&self);
}

/// Silent sink used by tests and non-interactive scans.
pub(crate) struct NoProgress;

impl Progress for NoProgress {
    fn stage(&self, _label: &'static str) {}
    fn tick(&self) {}
    fn finish(&self) {}
}

/// stderr spinner that counts filesystem entries as they are examined.
///
/// The walk has no cheap total, so this is unbounded: a spinner plus an entry
/// count, not a percentage bar. Disabled instances hold no bar.
pub struct TerminalProgress {
    bar: Option<ProgressBar>,
}

impl TerminalProgress {
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self { bar: None };
        }
        let bar = ProgressBar::no_length();
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {pos} {msg}")
                .expect("valid progress template"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));
        Self { bar: Some(bar) }
    }

    #[cfg(test)]
    fn hidden() -> Self {
        let bar = ProgressBar::no_length();
        bar.set_draw_target(ProgressDrawTarget::hidden());
        bar.set_style(
            ProgressStyle::with_template("{spinner} [{elapsed_precise}] {pos} {msg}")
                .expect("valid progress template"),
        );
        Self { bar: Some(bar) }
    }
}

impl Progress for TerminalProgress {
    fn stage(&self, label: &'static str) {
        if let Some(bar) = &self.bar {
            bar.set_message(label);
        }
    }

    fn tick(&self) {
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

impl Drop for TerminalProgress {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}

/// Test double that records stages and tick count.
pub(crate) struct CountingProgress {
    pub stages: Mutex<Vec<&'static str>>,
    pub ticks: AtomicU64,
}

impl CountingProgress {
    pub fn new() -> Self {
        Self {
            stages: Mutex::new(Vec::new()),
            ticks: AtomicU64::new(0),
        }
    }

    pub fn tick_count(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    pub fn staged(&self) -> Vec<&'static str> {
        self.stages.lock().expect("progress stages").clone()
    }
}

impl Default for CountingProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress for CountingProgress {
    fn stage(&self, label: &'static str) {
        self.stages.lock().expect("progress stages").push(label);
    }

    fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    fn finish(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_terminal_progress_is_silent() {
        let progress = TerminalProgress::new(false);
        progress.stage("Fetching npm intelligence");
        progress.tick();
        progress.finish();
    }

    #[test]
    fn hidden_bar_accepts_stage_and_ticks() {
        let progress = TerminalProgress::hidden();
        progress.stage("Walking filesystem (npm)");
        progress.tick();
        progress.tick();
        progress.finish();
    }

    #[test]
    fn counting_progress_records_stages_and_ticks() {
        let progress = CountingProgress::new();
        progress.stage("Fetching npm intelligence");
        progress.tick();
        progress.stage("Walking filesystem (npm)");
        progress.tick();
        progress.tick();
        assert_eq!(
            progress.staged(),
            ["Fetching npm intelligence", "Walking filesystem (npm)"]
        );
        assert_eq!(progress.tick_count(), 3);
    }
}
