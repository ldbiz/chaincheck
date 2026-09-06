//! Shallow filesystem sampling for approximate walk progress only.
//!
//! This module never affects scan findings, coverage, or exit codes.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::{self, FileType};
use std::path::{Path, PathBuf};

use crate::discovery::WalkLimits;

/// Maximum directory entries examined by the shallow estimator.
pub const SHALLOW_ESTIMATE_MAX_ENTRIES: u32 = 512;

/// Maximum directory depth descended by the shallow estimator (roots at depth 0).
pub const SHALLOW_ESTIMATE_MAX_DEPTH: u32 = 4;

/// Outcome of a bounded shallow sample. UX-only; not evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkEntryEstimate {
    pub sample_entries: u32,
    pub estimated_total: u64,
    pub truncated: bool,
}

/// Sample scan roots with the same prune predicate as the corresponding real walk.
///
/// Breadth-first and strictly bounded. Never reads file contents. On any failure,
/// returns a conservative estimate derived from whatever sample completed.
pub fn estimate_walk_entries_shallow(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    mut prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
) -> WalkEntryEstimate {
    let mut queue: VecDeque<(PathBuf, u32)> = roots
        .into_iter()
        .map(|r| (r.as_ref().to_path_buf(), 0))
        .collect();
    let mut sample_entries = 0u32;
    let mut dirs_opened = 0u32;
    let mut frontier = 0u32;
    let mut truncated = false;
    let mut unfinished_directory = false;

    'sample: while let Some((dir, depth)) = queue.pop_front() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        dirs_opened += 1;
        for entry in entries {
            if sample_entries >= SHALLOW_ESTIMATE_MAX_ENTRIES {
                truncated = true;
                unfinished_directory = true;
                break 'sample;
            }
            sample_entries += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !file_type.is_dir() {
                continue;
            }
            if is_symlink_dir(file_type, &path) {
                continue;
            }
            let name = entry.file_name();
            if prune_dir(&dir, &name) {
                continue;
            }
            if depth >= SHALLOW_ESTIMATE_MAX_DEPTH {
                truncated = true;
                frontier = frontier.saturating_add(1);
                continue;
            }
            queue.push_back((path, depth + 1));
        }
    }

    if unfinished_directory {
        frontier = frontier
            .saturating_add(1)
            .saturating_add(u32::try_from(queue.len()).unwrap_or(u32::MAX));
    } else {
        frontier = frontier.saturating_add(u32::try_from(queue.len()).unwrap_or(u32::MAX));
        if !queue.is_empty() {
            truncated = true;
        }
    }

    let estimated_total = if truncated {
        extrapolate(
            sample_entries,
            dirs_opened,
            frontier,
            unfinished_directory,
            limits,
        )
    } else {
        u64::from(sample_entries.max(1))
    };

    WalkEntryEstimate {
        sample_entries,
        estimated_total,
        truncated,
    }
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

    #[test]
    fn respects_entry_budget_constant() {
        let root = tmp();
        for i in 0..800 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert_eq!(estimate.sample_entries, SHALLOW_ESTIMATE_MAX_ENTRIES);
        assert!(estimate.truncated);
        assert!(estimate.estimated_total >= u64::from(SHALLOW_ESTIMATE_MAX_ENTRIES));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn does_not_traverse_entire_large_tree() {
        let root = tmp();
        for i in 0..800 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries < 800);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn small_tree_estimate_matches_sample() {
        let root = tmp();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/package.json"), b"{}").unwrap();
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(!estimate.truncated);
        assert_eq!(
            estimate.estimated_total,
            u64::from(estimate.sample_entries.max(1))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn respects_depth_budget_constant() {
        let root = tmp();
        let mut current = root.clone();
        for i in 0..=SHALLOW_ESTIMATE_MAX_DEPTH + 2 {
            current = current.join(format!("d{i}"));
            fs::create_dir_all(&current).unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.sample_entries <= SHALLOW_ESTIMATE_MAX_ENTRIES);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn depth_cutoff_is_incomplete_for_narrow_deep_tree() {
        let root = tmp();
        let mut current = root.clone();
        for i in 0..SHALLOW_ESTIMATE_MAX_DEPTH + 8 {
            current = current.join(format!("d{i}"));
            fs::create_dir_all(&current).unwrap();
            fs::write(current.join("leaf.txt"), b"x").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(
            estimate.truncated,
            "depth cutoff must mark the sample incomplete"
        );
        assert!(
            estimate.estimated_total > u64::from(estimate.sample_entries),
            "deep unsampled content must not be treated as a complete tiny tree: {estimate:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wide_file_only_directory_is_incomplete() {
        let root = tmp();
        for i in 0..4_000 {
            fs::write(root.join(format!("f{i}.dat")), b"n").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert_eq!(estimate.sample_entries, SHALLOW_ESTIMATE_MAX_ENTRIES);
        assert!(estimate.truncated);
        assert!(
            estimate.estimated_total > u64::from(SHALLOW_ESTIMATE_MAX_ENTRIES),
            "unfinished wide directory must not look like a complete 512-entry tree: {estimate:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wide_directory_tree_is_incomplete_and_not_tiny() {
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
        assert!(estimate.truncated);
        assert!(estimate.sample_entries <= SHALLOW_ESTIMATE_MAX_ENTRIES);
        assert!(
            estimate.estimated_total > u64::from(estimate.sample_entries),
            "{estimate:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mixed_broad_and_deep_tree_is_incomplete() {
        let root = tmp();
        for i in 0..40 {
            fs::create_dir_all(root.join(format!("wide{i}"))).unwrap();
            fs::write(root.join(format!("wide{i}/a.txt")), b"a").unwrap();
        }
        let mut deep = root.join("deep");
        fs::create_dir_all(&deep).unwrap();
        for i in 0..SHALLOW_ESTIMATE_MAX_DEPTH + 6 {
            deep = deep.join(format!("n{i}"));
            fs::create_dir_all(&deep).unwrap();
            fs::write(deep.join("x.txt"), b"x").unwrap();
        }
        let estimate =
            estimate_walk_entries_shallow([&root], |_p, _n| false, WalkLimits::production());
        assert!(estimate.truncated);
        assert!(estimate.estimated_total > u64::from(estimate.sample_entries.max(1)));
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
