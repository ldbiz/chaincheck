//! Live scan progress. Rendering uses `indicatif`; library callers can no-op.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Cap approximate walk progress below completion until the phase actually ends.
pub(crate) const WALK_PHASE_DISPLAY_CAP_PERCENT: u64 = 95;

/// Progress events for the main scan.
pub trait Progress {
    fn stage(&self, label: &'static str);
    /// Begin a filesystem walk phase using an approximate entry budget.
    fn begin_walk_phase(&self, label: &'static str, estimated_entries: u64);
    fn tick(&self);
    /// Mark the current walk phase complete at 100%.
    fn end_walk_phase(&self);
    fn finish(&self);
}

/// Silent sink used by tests and non-interactive scans.
pub(crate) struct NoProgress;

impl Progress for NoProgress {
    fn stage(&self, _label: &'static str) {}
    fn begin_walk_phase(&self, _label: &'static str, _estimated_entries: u64) {}
    fn tick(&self) {}
    fn end_walk_phase(&self) {}
    fn finish(&self) {}
}

/// stderr progress: indeterminate spinner between walks; approximate bar during walks.
pub struct TerminalProgress {
    bar: Option<ProgressBar>,
    walk_label: Mutex<Option<&'static str>>,
    walk_ticks: AtomicU64,
    walk_estimate: AtomicU64,
    walk_display_percent: AtomicU64,
    in_walk_phase: AtomicU64,
}

impl TerminalProgress {
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self::disabled();
        }
        let bar = ProgressBar::no_length();
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_style(indeterminate_style());
        bar.enable_steady_tick(Duration::from_millis(100));
        Self {
            bar: Some(bar),
            walk_label: Mutex::new(None),
            walk_ticks: AtomicU64::new(0),
            walk_estimate: AtomicU64::new(1),
            walk_display_percent: AtomicU64::new(0),
            in_walk_phase: AtomicU64::new(0),
        }
    }

    fn disabled() -> Self {
        Self {
            bar: None,
            walk_label: Mutex::new(None),
            walk_ticks: AtomicU64::new(0),
            walk_estimate: AtomicU64::new(1),
            walk_display_percent: AtomicU64::new(0),
            in_walk_phase: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn hidden() -> Self {
        let bar = ProgressBar::no_length();
        bar.set_draw_target(ProgressDrawTarget::hidden());
        bar.set_style(indeterminate_style());
        Self {
            bar: Some(bar),
            walk_label: Mutex::new(None),
            walk_ticks: AtomicU64::new(0),
            walk_estimate: AtomicU64::new(1),
            walk_display_percent: AtomicU64::new(0),
            in_walk_phase: AtomicU64::new(0),
        }
    }
}

impl Progress for TerminalProgress {
    fn stage(&self, label: &'static str) {
        if self.in_walk_phase.load(Ordering::Relaxed) != 0 {
            self.end_walk_phase();
        }
        if let Some(bar) = &self.bar {
            bar.set_length(0);
            bar.set_position(0);
            bar.set_style(indeterminate_style());
            bar.set_message(label);
        }
    }

    fn begin_walk_phase(&self, label: &'static str, estimated_entries: u64) {
        let estimate = estimated_entries.max(1);
        *self.walk_label.lock().expect("walk label") = Some(label);
        self.walk_ticks.store(0, Ordering::Relaxed);
        self.walk_estimate.store(estimate, Ordering::Relaxed);
        self.walk_display_percent.store(0, Ordering::Relaxed);
        self.in_walk_phase.store(1, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.set_style(walk_phase_style());
            bar.set_length(100);
            bar.set_position(0);
            bar.set_message(format!("{label} (0 entries)"));
        }
    }

    fn tick(&self) {
        if self.in_walk_phase.load(Ordering::Relaxed) == 0 {
            if let Some(bar) = &self.bar {
                bar.inc(1);
            }
            return;
        }
        let ticks = self.walk_ticks.fetch_add(1, Ordering::Relaxed) + 1;
        let estimate = self.walk_estimate.load(Ordering::Relaxed).max(1);
        let previous = self.walk_display_percent.load(Ordering::Relaxed);
        let display = walk_phase_display_percent(ticks, estimate, previous);
        self.walk_display_percent.store(display, Ordering::Relaxed);
        if let Some(bar) = &self.bar {
            bar.set_position(display);
            if let Some(label) = *self.walk_label.lock().expect("walk label") {
                bar.set_message(format!("{label} ({ticks} entries)"));
            }
        }
    }

    fn end_walk_phase(&self) {
        if self.in_walk_phase.swap(0, Ordering::Relaxed) == 0 {
            return;
        }
        *self.walk_label.lock().expect("walk label") = None;
        if let Some(bar) = &self.bar {
            bar.set_position(100);
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

/// Monotonic approximate percent for a walk phase.
pub(crate) fn walk_phase_display_percent(ticks: u64, estimate: u64, previous_display: u64) -> u64 {
    let est = estimate.max(1);
    let raw = ticks
        .saturating_mul(100)
        .saturating_div(est)
        .min(WALK_PHASE_DISPLAY_CAP_PERCENT);
    raw.max(previous_display)
}

fn indeterminate_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {pos} {msg}")
        .expect("valid progress template")
}

fn walk_phase_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.green} [{bar:40.cyan/blue}] ~{percent}% [{elapsed_precise}] {msg}",
    )
    .expect("valid progress template")
    .progress_chars("█▉▊▋▌▍▎▏  ")
}

/// Test double that records stages, walk phases, and tick count.
pub(crate) struct CountingProgress {
    pub stages: Mutex<Vec<&'static str>>,
    pub walk_estimates: Mutex<Vec<u64>>,
    pub walk_display_percents: Mutex<Vec<u64>>,
    walk_ticks: AtomicU64,
    ticks: AtomicU64,
    walk_estimate: AtomicU64,
    walk_display_percent: AtomicU64,
    in_walk_phase: AtomicU64,
}

impl CountingProgress {
    pub fn new() -> Self {
        Self {
            stages: Mutex::new(Vec::new()),
            walk_estimates: Mutex::new(Vec::new()),
            walk_display_percents: Mutex::new(Vec::new()),
            walk_ticks: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            walk_estimate: AtomicU64::new(1),
            walk_display_percent: AtomicU64::new(0),
            in_walk_phase: AtomicU64::new(0),
        }
    }

    pub fn tick_count(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    pub fn staged(&self) -> Vec<&'static str> {
        self.stages.lock().expect("progress stages").clone()
    }

    pub fn display_percents(&self) -> Vec<u64> {
        self.walk_display_percents.lock().expect("percents").clone()
    }
}

impl Default for CountingProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress for CountingProgress {
    fn stage(&self, label: &'static str) {
        if self.in_walk_phase.load(Ordering::Relaxed) != 0 {
            self.end_walk_phase();
        }
        self.stages.lock().expect("progress stages").push(label);
    }

    fn begin_walk_phase(&self, label: &'static str, estimated_entries: u64) {
        self.stages.lock().expect("progress stages").push(label);
        self.walk_estimates
            .lock()
            .expect("walk estimates")
            .push(estimated_entries);
        self.walk_ticks.store(0, Ordering::Relaxed);
        self.walk_estimate
            .store(estimated_entries.max(1), Ordering::Relaxed);
        self.walk_display_percent.store(0, Ordering::Relaxed);
        self.in_walk_phase.store(1, Ordering::Relaxed);
    }

    fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
        if self.in_walk_phase.load(Ordering::Relaxed) == 0 {
            return;
        }
        let ticks = self.walk_ticks.fetch_add(1, Ordering::Relaxed) + 1;
        let estimate = self.walk_estimate.load(Ordering::Relaxed);
        let previous = self.walk_display_percent.load(Ordering::Relaxed);
        let display = walk_phase_display_percent(ticks, estimate, previous);
        self.walk_display_percent.store(display, Ordering::Relaxed);
        self.walk_display_percents
            .lock()
            .expect("percents")
            .push(display);
    }

    fn end_walk_phase(&self) {
        if self.in_walk_phase.swap(0, Ordering::Relaxed) == 0 {
            return;
        }
        self.walk_display_percents
            .lock()
            .expect("percents")
            .push(100);
    }

    fn finish(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_terminal_progress_is_silent() {
        let progress = TerminalProgress::new(false);
        progress.begin_walk_phase("Walking filesystem (npm)", 10);
        progress.tick();
        progress.end_walk_phase();
        progress.finish();
    }

    #[test]
    fn hidden_walk_phase_reaches_full_at_end() {
        let progress = TerminalProgress::hidden();
        progress.begin_walk_phase("Walking filesystem (npm)", 5);
        for _ in 0..20 {
            progress.tick();
        }
        progress.end_walk_phase();
        let bar = progress.bar.as_ref().expect("bar");
        assert_eq!(bar.position(), bar.length().unwrap_or(0));
    }

    #[test]
    fn walk_display_percent_is_monotonic_and_capped() {
        let mut previous = 0;
        let mut percents = Vec::new();
        for ticks in 1..=50 {
            previous = walk_phase_display_percent(ticks, 10, previous);
            percents.push(previous);
        }
        assert!(percents.windows(2).all(|w| w[0] <= w[1]));
        assert!(*percents.last().expect("percents") <= WALK_PHASE_DISPLAY_CAP_PERCENT);
    }

    #[test]
    fn walk_display_percent_never_regresses_when_estimate_too_small() {
        let mut previous = 0;
        for ticks in 1..=200 {
            previous = walk_phase_display_percent(ticks, 10, previous);
            assert!(previous <= WALK_PHASE_DISPLAY_CAP_PERCENT);
        }
        assert_eq!(previous, WALK_PHASE_DISPLAY_CAP_PERCENT);
    }

    #[test]
    fn counting_progress_records_walk_phase_and_ticks() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 4);
        progress.tick();
        progress.tick();
        progress.end_walk_phase();
        progress.stage("Checking host artefacts");
        assert_eq!(progress.tick_count(), 2);
        assert_eq!(progress.walk_estimates.lock().unwrap().as_slice(), &[4]);
        assert_eq!(progress.display_percents(), vec![25, 50, 100]);
    }

    #[test]
    fn walk_phase_percent_monotonic_until_end() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 2);
        for _ in 0..20 {
            progress.tick();
        }
        let percents = progress.display_percents();
        assert!(percents.windows(2).all(|w| w[0] <= w[1]));
        assert!(*percents.last().expect("percents") < 100);
        progress.end_walk_phase();
        assert_eq!(progress.display_percents().last(), Some(&100));
    }

    #[test]
    fn walk_phase_not_complete_until_end_walk_phase() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (Python)", 1);
        for _ in 0..100 {
            progress.tick();
        }
        assert!(
            *progress.display_percents().last().expect("percents")
                <= WALK_PHASE_DISPLAY_CAP_PERCENT
        );
        progress.end_walk_phase();
        assert_eq!(progress.display_percents().last(), Some(&100));
    }
}
