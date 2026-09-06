//! Shallow filesystem sampling for approximate walk progress only.
//!
//! This module never affects scan findings, coverage, or exit codes.

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
/// Never reads file contents or descends without bound. On any failure, returns a
/// conservative estimate derived from whatever sample completed.
pub fn estimate_walk_entries_shallow(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    mut prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
) -> WalkEntryEstimate {
    let mut stack: Vec<(PathBuf, u32)> = roots
        .into_iter()
        .map(|r| (r.as_ref().to_path_buf(), 0))
        .collect();
    let mut sample_entries = 0u32;
    let mut dirs_seen = 0u32;
    let mut truncated = false;

    'sample: while let Some((dir, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            if sample_entries >= SHALLOW_ESTIMATE_MAX_ENTRIES {
                truncated = true;
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
            dirs_seen += 1;
            if depth >= SHALLOW_ESTIMATE_MAX_DEPTH {
                continue;
            }
            let name = entry.file_name();
            if prune_dir(&dir, &name) {
                continue;
            }
            stack.push((path, depth + 1));
        }
    }

    let estimated_total = if truncated {
        extrapolate(sample_entries, dirs_seen, stack.len(), limits)
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
    dirs_seen: u32,
    pending_dirs: usize,
    limits: WalkLimits,
) -> u64 {
    let sample = u64::from(sample_entries.max(1));
    let dirs = u64::from(dirs_seen.max(1));
    let avg_per_dir = sample.saturating_div(dirs).max(1);
    let pending = u64::try_from(pending_dirs).unwrap_or(u64::MAX);
    sample
        .saturating_add(pending.saturating_mul(avg_per_dir))
        .clamp(sample, u64::from(limits.max_entries))
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
    use crate::discovery::WalkLimits;
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
