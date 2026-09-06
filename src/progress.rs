//! Live scan progress. Rendering uses `indicatif`; library callers can no-op.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Cap approximate walk progress below completion until the phase actually ends.
pub(crate) const WALK_PHASE_DISPLAY_CAP_PERCENT: u64 = 95;

const WALK_ESTIMATE_CAP: u64 = 1_000_000;
const ETA_MIN_ENTRIES: u64 = 384;
const ETA_MIN_ELAPSED: Duration = Duration::from_millis(2_500);
const ETA_SNAPSHOT_EVERY: u64 = 64;
const ETA_STABLE_SNAPSHOTS: usize = 4;

/// One real-walk observation. `directory_finished` is not an examined entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkTick {
    pub pending_dirs: u32,
    pub entries_in_current_dir: u32,
    pub directory_finished: bool,
}

/// Progress events for the main scan.
pub trait Progress {
    fn stage(&self, label: &'static str);
    /// Begin a filesystem walk phase using an approximate entry budget.
    fn begin_walk_phase(&self, label: &'static str, estimated_entries: u64);
    fn tick(&self);
    /// Combined entry tick and structural observation from the real walk.
    fn tick_walk(&self, tick: WalkTick) {
        let _ = tick;
        self.tick();
    }
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

#[derive(Clone)]
struct ProgressClock {
    origin: Instant,
    fake_ms: Option<Arc<AtomicU64>>,
}

impl ProgressClock {
    fn real() -> Self {
        Self {
            origin: Instant::now(),
            fake_ms: None,
        }
    }

    #[cfg(test)]
    fn fake(offset_ms: Arc<AtomicU64>) -> Self {
        Self {
            origin: Instant::now(),
            fake_ms: Some(offset_ms),
        }
    }

    fn now(&self) -> Instant {
        match &self.fake_ms {
            None => Instant::now(),
            Some(ms) => self.origin + Duration::from_millis(ms.load(Ordering::Relaxed)),
        }
    }
}

struct WalkPhaseState {
    label: &'static str,
    ticks: u64,
    estimate: u64,
    display_percent: u64,
    pending_dirs: u32,
    entries_in_current_dir: u32,
    in_open_directory: bool,
    finished_dir_count: u64,
    ewma_dir_entries: u64,
    first_entry_at: Option<Instant>,
    last_entry_at: Option<Instant>,
    ewma_us_per_entry: u64,
    snapshots: Vec<(u64, u64)>,
    ticks_since_snapshot: u64,
    eta: Option<Duration>,
}

impl WalkPhaseState {
    fn new(label: &'static str, estimated_entries: u64) -> Self {
        Self {
            label,
            ticks: 0,
            estimate: estimated_entries.max(1),
            display_percent: 0,
            pending_dirs: 0,
            entries_in_current_dir: 0,
            in_open_directory: false,
            finished_dir_count: 0,
            ewma_dir_entries: 0,
            first_entry_at: None,
            last_entry_at: None,
            ewma_us_per_entry: 0,
            snapshots: Vec::new(),
            ticks_since_snapshot: 0,
            eta: None,
        }
    }

    fn on_event(&mut self, tick: WalkTick, now: Instant) {
        let previous_estimate = self.estimate;
        self.pending_dirs = tick.pending_dirs;
        self.entries_in_current_dir = tick.entries_in_current_dir;

        if tick.directory_finished {
            self.in_open_directory = false;
            if tick.entries_in_current_dir > 0 {
                let sample = u64::from(tick.entries_in_current_dir);
                if self.ewma_dir_entries == 0 {
                    self.ewma_dir_entries = sample;
                } else {
                    let n = (self.finished_dir_count + 8).min(32).max(1);
                    self.ewma_dir_entries = (self.ewma_dir_entries * (n - 1) + sample) / n;
                }
                self.finished_dir_count = self.finished_dir_count.saturating_add(1);
            }
            self.refine_estimate();
            self.maybe_reset_eta(previous_estimate);
            self.update_display();
            self.refresh_eta(now, false);
            return;
        }

        self.in_open_directory = true;
        self.ticks = self.ticks.saturating_add(1);
        if self.first_entry_at.is_none() {
            self.first_entry_at = Some(now);
        }
        if let Some(prev) = self.last_entry_at {
            if let Some(dt) = now.checked_duration_since(prev) {
                let sample = u64::try_from(dt.as_micros()).unwrap_or(u64::MAX);
                if sample > 0 {
                    if self.ewma_us_per_entry == 0 {
                        self.ewma_us_per_entry = sample;
                    } else {
                        let n = self.ticks.clamp(8, 256);
                        self.ewma_us_per_entry =
                            (self.ewma_us_per_entry.saturating_mul(n - 1) + sample) / n;
                    }
                }
            }
        }
        self.last_entry_at = Some(now);
        self.refine_estimate();
        self.maybe_reset_eta(previous_estimate);
        self.update_display();
        self.refresh_eta(now, true);
    }

    fn avg_per_dir(&self) -> u64 {
        if self.ewma_dir_entries > 0 {
            self.ewma_dir_entries
        } else {
            u64::from(self.entries_in_current_dir).max(8)
        }
    }

    fn refine_estimate(&mut self) {
        let avg = self.avg_per_dir().max(1);
        let current = u64::from(self.entries_in_current_dir);
        let headroom = if self.in_open_directory {
            avg.saturating_sub(current).max(current / 4).max(1)
        } else if self.pending_dirs == 0 {
            1
        } else {
            0
        };
        let pending = u64::from(self.pending_dirs).saturating_mul(avg);
        let mut target = self
            .ticks
            .saturating_add(pending)
            .saturating_add(headroom)
            .max(self.ticks.saturating_add(1));
        target = target.min(WALK_ESTIMATE_CAP);
        if target >= self.estimate {
            self.estimate = target;
        } else {
            self.estimate = (self.estimate.saturating_mul(3).saturating_add(target)) / 4;
            self.estimate = self.estimate.max(self.ticks.saturating_add(1));
        }
    }

    fn maybe_reset_eta(&mut self, previous_estimate: u64) {
        if previous_estimate == 0 {
            return;
        }
        let sharp = self.estimate >= previous_estimate.saturating_mul(2)
            || previous_estimate >= self.estimate.saturating_mul(2);
        if sharp {
            self.snapshots.clear();
            self.ticks_since_snapshot = 0;
            self.eta = None;
        }
    }

    fn update_display(&mut self) {
        self.display_percent =
            walk_phase_display_percent(self.ticks, self.estimate, self.display_percent);
    }

    fn refresh_eta(&mut self, now: Instant, is_entry: bool) {
        if is_entry && self.ewma_us_per_entry > 0 {
            self.ticks_since_snapshot = self.ticks_since_snapshot.saturating_add(1);
            if self.ticks_since_snapshot >= ETA_SNAPSHOT_EVERY {
                self.ticks_since_snapshot = 0;
                self.snapshots.push((self.estimate, self.ewma_us_per_entry));
                if self.snapshots.len() > ETA_STABLE_SNAPSHOTS {
                    self.snapshots.remove(0);
                }
            }
        }
        let Some(start) = self.first_entry_at else {
            self.eta = None;
            return;
        };
        let elapsed = now.checked_duration_since(start).unwrap_or(Duration::ZERO);
        if self.ticks < ETA_MIN_ENTRIES || elapsed < ETA_MIN_ELAPSED || self.ewma_us_per_entry == 0
        {
            self.eta = None;
            return;
        }
        if self.snapshots.len() < ETA_STABLE_SNAPSHOTS || !snapshots_stable(&self.snapshots) {
            self.eta = None;
            return;
        }
        let remaining = self.estimate.saturating_sub(self.ticks);
        let micros = remaining.saturating_mul(self.ewma_us_per_entry);
        self.eta = Some(Duration::from_micros(micros));
    }

    fn message(&self) -> String {
        let mut msg = format!("{} ({} entries)", self.label, self.ticks);
        if let Some(eta) = self.eta {
            msg.push(' ');
            msg.push_str(&format_eta(eta));
        }
        msg
    }
}

fn snapshots_stable(snapshots: &[(u64, u64)]) -> bool {
    if snapshots.len() < ETA_STABLE_SNAPSHOTS {
        return false;
    }
    let est_min = snapshots.iter().map(|s| s.0).min().unwrap_or(1).max(1);
    let est_max = snapshots.iter().map(|s| s.0).max().unwrap_or(1);
    let rate_min = snapshots.iter().map(|s| s.1).min().unwrap_or(1).max(1);
    let rate_max = snapshots.iter().map(|s| s.1).max().unwrap_or(1);
    est_max <= est_min.saturating_mul(3) / 2 && rate_max <= rate_min.saturating_mul(3) / 2
}

fn format_eta(duration: Duration) -> String {
    let secs = duration.as_secs().max(1);
    if secs < 60 {
        format!("~{secs}s remaining")
    } else if secs < 3600 {
        format!("~{}m remaining", secs.div_ceil(60))
    } else {
        format!("~{}h remaining", secs.div_ceil(3600))
    }
}

/// stderr progress: indeterminate spinner between walks; approximate bar during walks.
pub struct TerminalProgress {
    bar: Option<ProgressBar>,
    walk: Mutex<Option<WalkPhaseState>>,
    clock: ProgressClock,
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
            walk: Mutex::new(None),
            clock: ProgressClock::real(),
        }
    }

    fn disabled() -> Self {
        Self {
            bar: None,
            walk: Mutex::new(None),
            clock: ProgressClock::real(),
        }
    }

    #[cfg(test)]
    fn hidden() -> Self {
        let bar = ProgressBar::no_length();
        bar.set_draw_target(ProgressDrawTarget::hidden());
        bar.set_style(indeterminate_style());
        Self {
            bar: Some(bar),
            walk: Mutex::new(None),
            clock: ProgressClock::real(),
        }
    }

    fn apply_walk_ui(&self, state: &WalkPhaseState) {
        if let Some(bar) = &self.bar {
            bar.set_position(state.display_percent);
            bar.set_message(state.message());
        }
    }
}

impl Progress for TerminalProgress {
    fn stage(&self, label: &'static str) {
        if self.walk.lock().expect("walk phase").is_some() {
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
        let state = WalkPhaseState::new(label, estimated_entries);
        if let Some(bar) = &self.bar {
            bar.set_style(walk_phase_style());
            bar.set_length(100);
            bar.set_position(0);
            bar.set_message(state.message());
        }
        *self.walk.lock().expect("walk phase") = Some(state);
    }

    fn tick(&self) {
        let mut guard = self.walk.lock().expect("walk phase");
        if let Some(state) = guard.as_mut() {
            state.on_event(
                WalkTick {
                    pending_dirs: state.pending_dirs,
                    entries_in_current_dir: state.entries_in_current_dir.saturating_add(1),
                    directory_finished: false,
                },
                self.clock.now(),
            );
            self.apply_walk_ui(state);
            return;
        }
        drop(guard);
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    fn tick_walk(&self, tick: WalkTick) {
        let mut guard = self.walk.lock().expect("walk phase");
        if let Some(state) = guard.as_mut() {
            state.on_event(tick, self.clock.now());
            self.apply_walk_ui(state);
            return;
        }
        drop(guard);
        if !tick.directory_finished {
            self.tick();
        }
    }

    fn end_walk_phase(&self) {
        let mut guard = self.walk.lock().expect("walk phase");
        if guard.take().is_none() {
            return;
        }
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
    walk: Mutex<Option<WalkPhaseState>>,
    ticks: AtomicU64,
    clock: ProgressClock,
}

impl CountingProgress {
    pub fn new() -> Self {
        Self::with_clock(ProgressClock::real())
    }

    fn with_clock(clock: ProgressClock) -> Self {
        Self {
            stages: Mutex::new(Vec::new()),
            walk_estimates: Mutex::new(Vec::new()),
            walk_display_percents: Mutex::new(Vec::new()),
            walk: Mutex::new(None),
            ticks: AtomicU64::new(0),
            clock,
        }
    }

    #[cfg(test)]
    pub fn with_fake_clock() -> (Self, Arc<AtomicU64>) {
        let offset = Arc::new(AtomicU64::new(0));
        (
            Self::with_clock(ProgressClock::fake(offset.clone())),
            offset,
        )
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

    pub fn latest_estimate(&self) -> u64 {
        self.walk
            .lock()
            .expect("walk phase")
            .as_ref()
            .map(|s| s.estimate)
            .unwrap_or(0)
    }

    pub fn eta(&self) -> Option<Duration> {
        self.walk
            .lock()
            .expect("walk phase")
            .as_ref()
            .and_then(|s| s.eta)
    }

    fn record_display(&self, state: &WalkPhaseState) {
        self.walk_display_percents
            .lock()
            .expect("percents")
            .push(state.display_percent);
    }
}

impl Default for CountingProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress for CountingProgress {
    fn stage(&self, label: &'static str) {
        if self.walk.lock().expect("walk phase").is_some() {
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
        *self.walk.lock().expect("walk phase") =
            Some(WalkPhaseState::new(label, estimated_entries));
    }

    fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.walk.lock().expect("walk phase");
        let Some(state) = guard.as_mut() else {
            return;
        };
        state.ticks = state.ticks.saturating_add(1);
        state.update_display();
        self.record_display(state);
    }

    fn tick_walk(&self, tick: WalkTick) {
        if !tick.directory_finished {
            self.ticks.fetch_add(1, Ordering::Relaxed);
        }
        let mut guard = self.walk.lock().expect("walk phase");
        let Some(state) = guard.as_mut() else {
            return;
        };
        state.on_event(tick, self.clock.now());
        if !tick.directory_finished {
            self.record_display(state);
        }
    }

    fn end_walk_phase(&self) {
        let mut guard = self.walk.lock().expect("walk phase");
        if guard.take().is_none() {
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

    fn entry(pending: u32, current: u32) -> WalkTick {
        WalkTick {
            pending_dirs: pending,
            entries_in_current_dir: current,
            directory_finished: false,
        }
    }

    fn dir_done(pending: u32, current: u32) -> WalkTick {
        WalkTick {
            pending_dirs: pending,
            entries_in_current_dir: current,
            directory_finished: true,
        }
    }

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

    #[test]
    fn displayed_percent_does_not_regress_when_estimate_grows() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 20);
        for i in 1..=10 {
            progress.tick_walk(entry(0, i));
        }
        let before = *progress.display_percents().last().expect("percent");
        for i in 11..=20 {
            progress.tick_walk(entry(80, i));
        }
        let percents = progress.display_percents();
        assert!(percents.windows(2).all(|w| w[0] <= w[1]));
        assert!(*percents.last().expect("percent") >= before);
        assert!(*percents.last().expect("percent") < 100);
        assert!(progress.latest_estimate() > 20);
    }

    #[test]
    fn estimate_can_fall_after_overestimate_without_percent_regression() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 50_000);
        for i in 1..=80 {
            progress.tick_walk(entry(0, i));
        }
        progress.tick_walk(dir_done(0, 80));
        let percents = progress.display_percents();
        assert!(percents.windows(2).all(|w| w[0] <= w[1]));
        assert!(progress.latest_estimate() < 50_000);
        assert!(progress.latest_estimate() > 80);
        assert!(*percents.last().expect("percent") < 100);
    }

    #[test]
    fn severe_underestimate_does_not_pin_at_cap_for_whole_scan() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 512);
        let mut at_2k = 0;
        let mut at_8k = 0;
        for i in 1..=10_000u32 {
            progress.tick_walk(entry(0, i));
            if i == 2_000 {
                at_2k = *progress.display_percents().last().expect("percent");
            }
            if i == 8_000 {
                at_8k = *progress.display_percents().last().expect("percent");
            }
        }
        assert!(
            at_2k < WALK_PHASE_DISPLAY_CAP_PERCENT,
            "pinned too early: {at_2k}"
        );
        assert!(
            at_8k < WALK_PHASE_DISPLAY_CAP_PERCENT,
            "pinned at 8k: {at_8k}"
        );
        assert!(at_8k >= at_2k);
        let last = *progress.display_percents().last().expect("percent");
        assert!(last <= WALK_PHASE_DISPLAY_CAP_PERCENT);
        progress.end_walk_phase();
        assert_eq!(progress.display_percents().last(), Some(&100));
    }

    #[test]
    fn eta_absent_during_small_warmup() {
        let (progress, clock) = CountingProgress::with_fake_clock();
        progress.begin_walk_phase("Walking filesystem (npm)", 10_000);
        for i in 1..=100 {
            clock.store(u64::from(i) * 10, Ordering::Relaxed);
            progress.tick_walk(entry(20, i));
        }
        assert!(progress.eta().is_none());
    }

    #[test]
    fn eta_uses_real_scan_clock_after_stable_warmup() {
        let (progress, clock) = CountingProgress::with_fake_clock();
        progress.begin_walk_phase("Walking filesystem (npm)", 20_000);
        for i in 1..=600 {
            clock.store(u64::from(i) * 8, Ordering::Relaxed);
            progress.tick_walk(entry(40, (i % 50) + 1));
            if i % 50 == 0 {
                progress.tick_walk(dir_done(40, 50));
            }
        }
        let eta = progress.eta();
        assert!(eta.is_some(), "expected ETA after 600 entries and ~4.8s");
        assert!(eta.expect("eta") >= Duration::from_secs(1));
    }

    #[test]
    fn eta_hides_when_estimate_jumps() {
        let (progress, clock) = CountingProgress::with_fake_clock();
        progress.begin_walk_phase("Walking filesystem (npm)", 2_000);
        for i in 1..=600 {
            clock.store(u64::from(i) * 8, Ordering::Relaxed);
            progress.tick_walk(entry(4, (i % 40) + 1));
            if i % 40 == 0 {
                progress.tick_walk(dir_done(4, 40));
            }
        }
        assert!(progress.eta().is_some());
        clock.store(5_000, Ordering::Relaxed);
        progress.tick_walk(entry(8_000, 1));
        assert!(progress.eta().is_none());
    }

    #[test]
    fn tick_walk_directory_finished_does_not_count_as_entry() {
        let progress = CountingProgress::new();
        progress.begin_walk_phase("Walking filesystem (npm)", 10);
        progress.tick_walk(entry(1, 1));
        progress.tick_walk(dir_done(1, 1));
        assert_eq!(progress.tick_count(), 1);
    }
}
