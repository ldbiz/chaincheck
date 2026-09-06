//! Bounded adaptive sampling for approximate walk progress only.
//!
//! This module never affects scan findings, coverage, or exit codes.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{self, FileType, ReadDir};
use std::path::{Path, PathBuf};

use crate::discovery::WalkLimits;

/// First sample, and size of each extra tranche.
pub const SHALLOW_ESTIMATE_TRANCHE_ENTRIES: u32 = 512;

/// Absolute cap on unique directory entries examined by the estimator.
pub const SHALLOW_ESTIMATE_HARD_CEILING: u32 = 8_192;

/// Maximum depth for the initial shallow tranche (roots at depth 0).
pub const SHALLOW_ESTIMATE_INITIAL_MAX_DEPTH: u32 = 4;

/// Hard maximum depth for later targeted sampling.
pub const SHALLOW_ESTIMATE_HARD_MAX_DEPTH: u32 = 8;

const SMALL_UNRESOLVED: usize = 2;
const LARGE_UNRESOLVED: usize = 8;
const PROMOTE_PER_TRANCHE: usize = 32;
const MIN_TRANCHES_BEFORE_DIMINISHING: u32 = 2;

/// Outcome of a bounded sample. UX-only; not evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkEntryEstimate {
    pub sample_entries: u32,
    pub estimated_total: u64,
    pub truncated: bool,
}

struct OpenDir {
    parent: PathBuf,
    depth: u32,
    iter: ReadDir,
}

struct Sampler<F> {
    prune: F,
    queue: VecDeque<(PathBuf, u32)>,
    open: Option<OpenDir>,
    depth_frontier: VecDeque<(PathBuf, u32)>,
    allowed_depth: u32,
    hard_max_depth: u32,
    sample_entries: u32,
    dirs_opened: u32,
    child_dirs: u32,
}

impl<F: FnMut(&Path, &OsStr) -> bool> Sampler<F> {
    fn new(
        roots: impl IntoIterator<Item = impl AsRef<Path>>,
        prune: F,
        initial_depth: u32,
    ) -> Self {
        Self {
            prune,
            queue: roots
                .into_iter()
                .map(|r| (r.as_ref().to_path_buf(), 0))
                .collect(),
            open: None,
            depth_frontier: VecDeque::new(),
            allowed_depth: initial_depth,
            hard_max_depth: initial_depth,
            sample_entries: 0,
            dirs_opened: 0,
            child_dirs: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.open.is_none() && self.queue.is_empty() && self.depth_frontier.is_empty()
    }

    fn has_promotable_frontier(&self) -> bool {
        self.depth_frontier
            .iter()
            .any(|(_, depth)| *depth <= self.hard_max_depth)
    }

    fn unresolved_count(&self) -> usize {
        let mut n = self.queue.len();
        if self.open.is_some() {
            n = n.saturating_add(1);
        }
        n.saturating_add(
            self.depth_frontier
                .iter()
                .filter(|(_, depth)| *depth <= self.hard_max_depth)
                .count(),
        )
    }

    fn remaining_unknown_small(&self, estimate: u64) -> bool {
        if self.open.is_some() || !self.queue.is_empty() || self.has_promotable_frontier() {
            return false;
        }
        if self.unresolved_count() > SMALL_UNRESOLVED {
            return false;
        }
        let sample = u64::from(self.sample_entries.max(1));
        estimate <= sample.saturating_mul(3) / 2
    }

    fn frontier_work(&self) -> u32 {
        let mut n = u32::try_from(self.queue.len().saturating_add(self.depth_frontier.len()))
            .unwrap_or(u32::MAX);
        if self.open.is_some() {
            n = n.saturating_add(1);
        }
        n
    }

    fn estimate(&self, limits: WalkLimits) -> u64 {
        if self.is_complete() {
            return u64::from(self.sample_entries.max(1));
        }
        extrapolate(
            self.sample_entries,
            self.dirs_opened,
            self.frontier_work(),
            self.open.is_some(),
            limits,
        )
    }

    fn prepare_tranche(&mut self) {
        if self.open.is_some() || !self.queue.is_empty() {
            return;
        }
        if !self.has_promotable_frontier() {
            return;
        }
        self.allowed_depth = self.hard_max_depth;
        let mut rest = VecDeque::new();
        let mut promoted = 0usize;
        while let Some((path, depth)) = self.depth_frontier.pop_front() {
            if depth <= self.hard_max_depth && promoted < PROMOTE_PER_TRANCHE {
                self.queue.push_back((path, depth));
                promoted += 1;
            } else {
                rest.push_back((path, depth));
            }
        }
        self.depth_frontier = rest;
    }

    fn consume_entries(&mut self, budget: u32, ceiling: u32) {
        let stop_at = self.sample_entries.saturating_add(budget).min(ceiling);
        while self.sample_entries < stop_at {
            if !self.step_one() {
                break;
            }
        }
    }

    fn step_one(&mut self) -> bool {
        if let Some(mut open) = self.open.take() {
            match open.iter.next() {
                None => true,
                Some(entry) => {
                    self.sample_entries = self.sample_entries.saturating_add(1);
                    if let Ok(entry) = entry {
                        self.consider_entry(&open.parent, open.depth, &entry);
                    }
                    self.open = Some(open);
                    true
                }
            }
        } else if let Some((dir, depth)) = self.queue.pop_front() {
            match fs::read_dir(&dir) {
                Ok(iter) => {
                    self.dirs_opened = self.dirs_opened.saturating_add(1);
                    self.open = Some(OpenDir {
                        parent: dir,
                        depth,
                        iter,
                    });
                    true
                }
                Err(_) => true,
            }
        } else {
            false
        }
    }

    fn consider_entry(&mut self, parent: &Path, parent_depth: u32, entry: &fs::DirEntry) {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => return,
        };
        if !file_type.is_dir() {
            return;
        }
        if is_symlink_dir(file_type, &path) {
            return;
        }
        let name = entry.file_name();
        if (self.prune)(parent, &name) {
            return;
        }
        let child_depth = parent_depth.saturating_add(1);
        self.child_dirs = self.child_dirs.saturating_add(1);
        if parent_depth >= self.allowed_depth {
            self.depth_frontier.push_back((path, child_depth));
            return;
        }
        self.queue.push_back((path, child_depth));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrancheSnapshot {
    estimate: u64,
    sample_entries: u32,
    queue_len: usize,
    frontier_len: usize,
    child_dirs: u32,
    promotable_frontier: bool,
}

impl TrancheSnapshot {
    fn capture<F: FnMut(&Path, &OsStr) -> bool>(sampler: &Sampler<F>, limits: WalkLimits) -> Self {
        Self {
            estimate: sampler.estimate(limits),
            sample_entries: sampler.sample_entries,
            queue_len: sampler.queue.len(),
            frontier_len: sampler.depth_frontier.len(),
            child_dirs: sampler.child_dirs,
            promotable_frontier: sampler.has_promotable_frontier(),
        }
    }

    /// Whether another tranche is worth taking.
    ///
    /// `before` and `self` must be snapshots from two different completed
    /// tranche states. Comparing a snapshot to itself is never worth sampling.
    fn still_worth_sampling(&self, before: &Self) -> bool {
        if self.promotable_frontier || self.queue_len >= LARGE_UNRESOLVED {
            return true;
        }
        if self.child_dirs > before.child_dirs || self.frontier_len > before.frontier_len {
            return true;
        }
        !estimate_close(Some(before.estimate), self.estimate)
    }
}

/// Sample scan roots with the same prune predicate as the corresponding real walk.
///
/// Adaptive, resumable, and strictly bounded. Never reads file contents. On any
/// failure, returns a conservative estimate derived from whatever sample completed.
pub fn estimate_walk_entries_shallow(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
) -> WalkEntryEstimate {
    estimate_with_config(roots, prune_dir, limits, SampleConfig::production())
}

#[derive(Clone, Copy)]
struct SampleConfig {
    tranche_entries: u32,
    hard_ceiling: u32,
    initial_max_depth: u32,
    hard_max_depth: u32,
}

impl SampleConfig {
    fn production() -> Self {
        Self {
            tranche_entries: SHALLOW_ESTIMATE_TRANCHE_ENTRIES,
            hard_ceiling: SHALLOW_ESTIMATE_HARD_CEILING,
            initial_max_depth: SHALLOW_ESTIMATE_INITIAL_MAX_DEPTH,
            hard_max_depth: SHALLOW_ESTIMATE_HARD_MAX_DEPTH,
        }
    }
}

fn estimate_with_config(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
    cfg: SampleConfig,
) -> WalkEntryEstimate {
    let mut sampler = Sampler::new(roots, prune_dir, cfg.initial_max_depth);
    sampler.hard_max_depth = cfg.hard_max_depth;
    let mut tranches = 0u32;

    loop {
        if sampler.sample_entries >= cfg.hard_ceiling {
            break;
        }
        if sampler.is_complete() {
            break;
        }
        if sampler.remaining_unknown_small(sampler.estimate(limits)) {
            break;
        }

        // Snapshot the completed state *before* this tranche mutates the sampler.
        // Stability must compare two genuine tranche states, not an estimate with itself.
        let before = TrancheSnapshot::capture(&sampler, limits);
        sampler.prepare_tranche();
        let before_entries = sampler.sample_entries;
        sampler.consume_entries(cfg.tranche_entries, cfg.hard_ceiling);
        if sampler.sample_entries == before_entries
            && sampler.open.is_none()
            && sampler.queue.is_empty()
            && !sampler.has_promotable_frontier()
        {
            break;
        }
        let after = TrancheSnapshot::capture(&sampler, limits);
        tranches = tranches.saturating_add(1);

        if sampler.is_complete() || sampler.sample_entries >= cfg.hard_ceiling {
            break;
        }
        if sampler.remaining_unknown_small(after.estimate) {
            break;
        }
        if tranches >= MIN_TRANCHES_BEFORE_DIMINISHING && !after.still_worth_sampling(&before) {
            break;
        }
    }

    let truncated = !sampler.is_complete();
    let estimated_total = if truncated {
        sampler.estimate(limits)
    } else {
        u64::from(sampler.sample_entries.max(1))
    };
    WalkEntryEstimate {
        sample_entries: sampler.sample_entries,
        estimated_total,
        truncated,
    }
}

fn estimate_close(previous: Option<u64>, current: u64) -> bool {
    let Some(prev) = previous else {
        return false;
    };
    let base = prev.max(1);
    let delta = current.abs_diff(prev);
    delta.saturating_mul(5) < base
}

fn extrapolate(
    sample_entries: u32,
    dirs_opened: u32,
    frontier: u32,
    unfinished_directory: bool,
    limits: WalkLimits,
) -> u64 {
    let sample = u64::from(sample_entries.max(1));
    let dirs = u64::from(dirs_opened.max(1));
    let avg_per_dir = sample.saturating_div(dirs).max(1);
    let extra = u64::from(frontier).saturating_mul(avg_per_dir);
    let mut estimated = sample.saturating_add(extra);
    if unfinished_directory {
        estimated = estimated.max(sample.saturating_mul(2));
    }
    estimated.clamp(sample, u64::from(limits.max_entries))
}

fn is_symlink_dir(file_type: FileType, path: &Path) -> bool {
    if file_type.is_symlink() {
        return true;
    }
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::campaign_prune_dir;
    use crate::discovery::WalkLimits;
    use crate::npm::npm_prune_dir;
    use crate::python::python_prune_dir;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "chaincheck-walk-est-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn estimate_capped(root: &Path, ceiling: u32, hard_max_depth: u32) -> WalkEntryEstimate {
        estimate_with_config(
            [root],
            |_p, _n| false,
            WalkLimits::production(),
            SampleConfig {
                tranche_entries: SHALLOW_ESTIMATE_TRANCHE_ENTRIES,
                hard_ceiling: ceiling,
                initial_max_depth: SHALLOW_ESTIMATE_INITIAL_MAX_DEPTH,
                hard_max_depth,
            },
        )
    }

    #[test]
    fn stability_compares_distinct_completed_tranche_states() {
        let same = TrancheSnapshot {
            estimate: 2_048,
            sample_entries: 1_024,
            queue_len: 0,
            frontier_len: 0,
            child_dirs: 0,
            promotable_frontier: false,
        };
        assert!(
            !same.still_worth_sampling(&same),
            "comparing a snapshot to itself must not count as useful new sampling"
        );
        let before = TrancheSnapshot {
            estimate: 1_024,
            sample_entries: 512,
            ..same
        };
        let after = TrancheSnapshot {
            estimate: 2_048,
            sample_entries: 1_024,
            ..same
        };
        assert!(
            after.still_worth_sampling(&before),
            "a later tranche with a materially different estimate must remain worth sampling"
        );
    }

    #[test]
    fn small_tree_stops_cheaply() {
        let root = tmp();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/package.json"), b"{}").unwrap();
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(!estimate.truncated);
        assert!(estimate.sample_entries < SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert_eq!(
            estimate.estimated_total,
            u64::from(estimate.sample_entries.max(1))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn large_uncertain_tree_samples_beyond_first_tranche() {
        let root = tmp();
        for i in 0..1_200 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
            fs::write(root.join(format!("d{i}/f.dat")), b"n").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert!(estimate.sample_entries <= SHALLOW_ESTIMATE_HARD_CEILING);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sampling_resumes_without_recounting_consumed_entries() {
        let root = tmp();
        for i in 0..900 {
            fs::write(root.join(format!("f{i}.dat")), b"n").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(!estimate.truncated);
        assert_eq!(estimate.sample_entries, 900);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn hard_ceiling_always_wins_on_huge_tree() {
        let root = tmp();
        for i in 0..20_000 {
            fs::write(root.join(format!("f{i}.dat")), b"n").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.truncated);
        assert!(estimate.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert!(
            estimate.sample_entries < SHALLOW_ESTIMATE_HARD_CEILING,
            "file-only diminishing value should stop before the hard ceiling: {estimate:?}"
        );
        assert!(estimate.sample_entries < 20_000);
        assert!(
            estimate.estimated_total > u64::from(estimate.sample_entries),
            "{estimate:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn hard_ceiling_wins_when_new_directories_keep_appearing() {
        let root = tmp();
        for i in 0..9_000 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.truncated);
        assert_eq!(estimate.sample_entries, SHALLOW_ESTIMATE_HARD_CEILING);
        assert!(estimate.sample_entries < 9_000);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn depth_cutoff_is_incomplete_for_narrow_deep_tree() {
        let root = tmp();
        let mut current = root.clone();
        for i in 0..SHALLOW_ESTIMATE_HARD_MAX_DEPTH + 8 {
            current = current.join(format!("d{i}"));
            fs::create_dir_all(&current).unwrap();
            fs::write(current.join("leaf.txt"), b"x").unwrap();
        }
        let shallow = estimate_capped(&root, SHALLOW_ESTIMATE_HARD_CEILING, 4);
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(
            estimate.truncated,
            "depth-limited remainder must not count as a complete sample: {estimate:?}"
        );
        assert!(
            estimate.estimated_total > u64::from(estimate.sample_entries),
            "{estimate:?}"
        );
        assert!(
            estimate.sample_entries > shallow.sample_entries
                || estimate.estimated_total >= shallow.estimated_total,
            "later tranches should gain deeper information: full={estimate:?} shallow={shallow:?}"
        );
        assert!(
            estimate.sample_entries < 80,
            "must not restart and re-enumerate ancestors: {estimate:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn adaptive_later_sampling_inspects_depth_frontier() {
        let root = tmp();
        let mut current = root.clone();
        for i in 0..SHALLOW_ESTIMATE_HARD_MAX_DEPTH + 3 {
            current = current.join(format!("n{i}"));
            fs::create_dir_all(&current).unwrap();
            fs::write(current.join(format!("m{i}.txt")), b"x").unwrap();
        }
        let depth4_only = estimate_capped(&root, 64, 4);
        let deeper = estimate_capped(&root, 64, SHALLOW_ESTIMATE_HARD_MAX_DEPTH);
        assert!(deeper.sample_entries > depth4_only.sample_entries);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wide_file_only_directory_is_incomplete_until_known() {
        let root = tmp();
        for i in 0..4_000 {
            fs::write(root.join(format!("f{i}.dat")), b"n").unwrap();
        }
        let partial = estimate_capped(&root, SHALLOW_ESTIMATE_TRANCHE_ENTRIES, 4);
        assert!(partial.truncated);
        assert!(partial.estimated_total > u64::from(partial.sample_entries));
        let full = estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(full.truncated);
        assert!(full.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert!(
            full.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES * 2,
            "must take more than two tranches when the estimate is still moving (would fail if stability compared a tranche to itself): {full:?}"
        );
        assert!(
            full.sample_entries < 4_000,
            "must stop before enumerating the whole directory: {full:?}"
        );
        assert!(
            full.sample_entries < SHALLOW_ESTIMATE_HARD_CEILING,
            "diminishing value must stop before the hard ceiling: {full:?}"
        );
        assert!(full.estimated_total > u64::from(full.sample_entries));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wide_directory_tree_samples_past_initial_tranche() {
        let root = tmp();
        for i in 0..400 {
            let dir = root.join(format!("d{i}"));
            fs::create_dir_all(&dir).unwrap();
            for j in 0..4 {
                fs::write(dir.join(format!("f{j}.dat")), b"n").unwrap();
            }
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert!(estimate.sample_entries <= SHALLOW_ESTIMATE_HARD_CEILING);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mixed_broad_and_deep_tree_is_incomplete_or_larger_than_first_tranche() {
        let root = tmp();
        for i in 0..40 {
            fs::create_dir_all(root.join(format!("wide{i}"))).unwrap();
            fs::write(root.join(format!("wide{i}/a.txt")), b"a").unwrap();
        }
        let mut deep = root.join("deep");
        fs::create_dir_all(&deep).unwrap();
        for i in 0..SHALLOW_ESTIMATE_HARD_MAX_DEPTH + 6 {
            deep = deep.join(format!("n{i}"));
            fs::create_dir_all(&deep).unwrap();
            fs::write(deep.join("x.txt"), b"x").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(
            estimate.truncated || estimate.sample_entries > SHALLOW_ESTIMATE_INITIAL_MAX_DEPTH * 4
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn false_stability_does_not_stop_while_depth_frontier_remains() {
        let root = tmp();
        for i in 0..80 {
            let mut current = root.join(format!("b{i}"));
            fs::create_dir_all(&current).unwrap();
            for d in 0..SHALLOW_ESTIMATE_HARD_MAX_DEPTH + 2 {
                current = current.join(format!("d{d}"));
                fs::create_dir_all(&current).unwrap();
                fs::write(current.join("x.txt"), b"x").unwrap();
            }
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES);
        assert!(
            estimate.truncated || estimate.sample_entries > SHALLOW_ESTIMATE_TRANCHE_ENTRIES * 2
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn additional_tranches_reach_diminishing_value_on_modest_tree() {
        let root = tmp();
        for i in 0..60 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
            fs::write(root.join(format!("d{i}/a.txt")), b"a").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries < SHALLOW_ESTIMATE_HARD_CEILING);
        assert!(
            !estimate.truncated
                || estimate.estimated_total < u64::from(SHALLOW_ESTIMATE_HARD_CEILING)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_lookahead_prunes_venv_like_npm_walk() {
        let root = tmp();
        fs::create_dir_all(root.join("visible")).unwrap();
        fs::write(root.join("visible/package.json"), b"{}").unwrap();
        for i in 0..300 {
            fs::create_dir_all(root.join(format!(".venv/lib/d{i}"))).unwrap();
            fs::write(root.join(format!(".venv/lib/d{i}/x.py")), b"x").unwrap();
        }
        let with_prune =
            estimate_walk_entries_shallow([&root], npm_prune_dir, WalkLimits::production());
        let visible_only = estimate_walk_entries_shallow(
            [&root.join("visible")],
            npm_prune_dir,
            WalkLimits::production(),
        );
        assert!(
            with_prune.estimated_total <= visible_only.estimated_total.saturating_add(8),
            "npm lookahead should not treat pruned .venv as remaining work: {with_prune:?} vs {visible_only:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn python_lookahead_still_descends_venv() {
        let root = tmp();
        fs::create_dir_all(root.join("visible")).unwrap();
        fs::write(root.join("visible/requirements.txt"), b"ok").unwrap();
        for i in 0..80 {
            fs::create_dir_all(root.join(format!(".venv/lib/d{i}"))).unwrap();
            fs::write(root.join(format!(".venv/lib/d{i}/x.py")), b"x").unwrap();
        }
        let python =
            estimate_walk_entries_shallow([&root], python_prune_dir, WalkLimits::production());
        let npm = estimate_walk_entries_shallow([&root], npm_prune_dir, WalkLimits::production());
        assert!(
            python.estimated_total > npm.estimated_total,
            "Python discovery keeps .venv traversable; npm prunes it: python={python:?} npm={npm:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn campaign_lookahead_prunes_venv_like_campaign_walk() {
        let root = tmp();
        fs::write(root.join("keep.txt"), b"k").unwrap();
        for i in 0..200 {
            fs::create_dir_all(root.join(format!(".venv/d{i}"))).unwrap();
        }
        let campaign =
            estimate_walk_entries_shallow([&root], campaign_prune_dir, WalkLimits::production());
        assert!(
            !campaign.truncated || campaign.estimated_total < 50,
            "campaign lookahead must prune .venv: {campaign:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn python_lookahead_prunes_node_modules() {
        let root = tmp();
        fs::write(root.join("requirements.txt"), b"ok").unwrap();
        for i in 0..200 {
            fs::create_dir_all(root.join(format!("node_modules/p{i}"))).unwrap();
        }
        let python =
            estimate_walk_entries_shallow([&root], python_prune_dir, WalkLimits::production());
        let npm = estimate_walk_entries_shallow([&root], npm_prune_dir, WalkLimits::production());
        assert!(
            python.estimated_total < npm.estimated_total,
            "Python prunes node_modules; npm does not: python={python:?} npm={npm:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unreadable_root_does_not_panic() {
        let estimate = estimate_walk_entries_shallow(
            [PathBuf::from(
                "/chaincheck-oracle-nonexistent-estimate-root",
            )],
            |_p, _n| false,
            WalkLimits::production(),
        );
        assert_eq!(estimate.sample_entries, 0);
        assert_eq!(estimate.estimated_total, 1);
    }
}
