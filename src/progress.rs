//! Live scan progress. Rendering uses `indicatif`; library callers can no-op.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Progress events for the main scan.
pub trait Progress {
    fn is_live(&self) -> bool {
        false
    }
    fn stage(&self, label: &'static str);
    fn begin(&self, total: u64);
    fn add_work(&self, extra: u64);
    fn tick(&self);
    fn finish(&self);
}

/// Silent sink used by tests and non-interactive scans.
pub(crate) struct NoProgress;

impl Progress for NoProgress {
    fn stage(&self, _label: &'static str) {}
    fn begin(&self, _total: u64) {}
    fn add_work(&self, _extra: u64) {}
    fn tick(&self) {}
    fn finish(&self) {}
}

/// stderr percentage bar driven by a pre-counted work budget.
pub struct TerminalProgress {
    bar: Option<ProgressBar>,
}

impl TerminalProgress {
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self { bar: None };
        }
        let bar = ProgressBar::new(1);
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{bar:40.cyan/blue}] {percent:>3}% {elapsed_precise} {msg}",
            )
            .expect("valid progress template")
            .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        bar.enable_steady_tick(Duration::from_millis(100));
        Self { bar: Some(bar) }
    }

    #[cfg(test)]
    fn hidden() -> Self {
        let bar = ProgressBar::new(1);
        bar.set_draw_target(ProgressDrawTarget::hidden());
        bar.set_style(
            ProgressStyle::with_template("{spinner} [{bar:40}] {percent:>3}% {msg}")
                .expect("valid progress template"),
        );
        Self { bar: Some(bar) }
    }
}

impl Progress for TerminalProgress {
    fn is_live(&self) -> bool {
        self.bar.is_some()
    }

    fn stage(&self, label: &'static str) {
        if let Some(bar) = &self.bar {
            bar.set_message(label);
        }
    }

    fn begin(&self, total: u64) {
        if let Some(bar) = &self.bar {
            bar.set_length(total.max(1));
            bar.set_position(0);
        }
    }

    fn add_work(&self, extra: u64) {
        if extra > 0 {
            if let Some(bar) = &self.bar {
                bar.inc_length(extra);
            }
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

/// Test double that records stages, budget, and tick count.
pub(crate) struct CountingProgress {
    pub stages: Mutex<Vec<&'static str>>,
    pub budget: AtomicU64,
    pub ticks: AtomicU64,
}

impl CountingProgress {
    pub fn new() -> Self {
        Self {
            stages: Mutex::new(Vec::new()),
            budget: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
        }
    }

    pub fn tick_count(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    pub fn total_budget(&self) -> u64 {
        self.budget.load(Ordering::Relaxed)
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
    fn is_live(&self) -> bool {
        true
    }

    fn stage(&self, label: &'static str) {
        self.stages.lock().expect("progress stages").push(label);
    }

    fn begin(&self, total: u64) {
        self.budget.store(total, Ordering::Relaxed);
    }

    fn add_work(&self, extra: u64) {
        self.budget.fetch_add(extra, Ordering::Relaxed);
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
        progress.begin(10);
        progress.stage("Fetching npm intelligence");
        progress.tick();
        progress.finish();
    }

    #[test]
    fn hidden_bar_tracks_budget_and_ticks() {
        let progress = TerminalProgress::hidden();
        progress.begin(5);
        progress.stage("Walking filesystem (npm)");
        progress.tick();
        progress.tick();
        progress.add_work(2);
        progress.tick();
        progress.finish();
    }

    #[test]
    fn counting_progress_records_stages_budget_and_ticks() {
        let progress = CountingProgress::new();
        progress.begin(4);
        progress.stage("Fetching npm intelligence");
        progress.tick();
        progress.add_work(2);
        progress.stage("Walking filesystem (npm)");
        progress.tick();
        progress.tick();
        assert_eq!(progress.total_budget(), 6);
        assert_eq!(progress.tick_count(), 3);
        assert_eq!(
            progress.staged(),
            ["Fetching npm intelligence", "Walking filesystem (npm)"]
        );
    }
}
