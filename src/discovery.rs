//! Generic safe filesystem traversal.
//!
//! This module does not decide which directories are relevant to a detector.
//! Callers supply a prune predicate. Directory symlinks are never descended.

use std::ffi::OsStr;
use std::fs::{self, FileType};
use std::path::{Path, PathBuf};

use crate::coverage::{ArtifactStatus, DetectorCoverage, DetectorId};
use crate::progress::{NoProgress, Progress};

pub const DET_FILESYSTEM_WALK: DetectorId = DetectorId::from_static("filesystem-walk");

pub const DEFAULT_WALK_MAX_ENTRIES: u32 = 1_000_000;
pub const DEFAULT_WALK_MAX_FILES: u32 = 100_000;

/// Per-walk bounds on directory entries examined and matching files retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkLimits {
    pub max_entries: u32,
    pub max_files: u32,
}

impl WalkLimits {
    pub const fn production() -> Self {
        Self {
            max_entries: DEFAULT_WALK_MAX_ENTRIES,
            max_files: DEFAULT_WALK_MAX_FILES,
        }
    }
}

/// Entry-work counter for recursive walkers that are not the generic matcher.
#[derive(Clone, Debug)]
pub struct EntryBudget {
    max_entries: u32,
    seen: u32,
}

impl EntryBudget {
    pub fn new(max_entries: u32) -> Self {
        Self {
            max_entries,
            seen: 0,
        }
    }

    /// Record one directory entry. Returns false when the budget is exhausted.
    pub fn try_consume(&mut self) -> bool {
        if self.seen >= self.max_entries {
            return false;
        }
        self.seen += 1;
        true
    }

    pub fn consumed(&self) -> u32 {
        self.seen
    }
}

/// Outcome of a bounded, non-following directory walk.
pub struct WalkOutcome {
    pub files: Vec<PathBuf>,
    pub coverage: DetectorCoverage,
}

/// Walk `roots` without following directory symlinks.
///
/// `prune_dir(parent, name)` returns true when a directory should not be
/// descended into. The walker itself has no package-manager skip list.
/// Every regular file and non-directory symlink is collected.
pub fn walk_files(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
) -> WalkOutcome {
    walk_matching_files(roots, prune_dir, |_path, _name| true)
}

/// Walk `roots` without following directory symlinks, retaining only files
/// for which `keep_file(path, name)` is true.
///
/// Classification happens during the walk so callers do not accumulate every
/// encountered path. Directory names are compared as [`OsStr`]; a non-UTF-8
/// name is never treated as a prune match.
pub fn walk_matching_files(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    keep_file: impl FnMut(&Path, &OsStr) -> bool,
) -> WalkOutcome {
    walk_matching_files_with_progress(roots, prune_dir, keep_file, &NoProgress)
}

/// Same as [`walk_matching_files`], reporting each examined directory entry.
pub fn walk_matching_files_with_progress(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    keep_file: impl FnMut(&Path, &OsStr) -> bool,
    progress: &dyn Progress,
) -> WalkOutcome {
    walk_matching_files_for_with_progress(
        DET_FILESYSTEM_WALK,
        roots,
        prune_dir,
        keep_file,
        progress,
    )
}

/// Same as [`walk_matching_files`], with caller-supplied coverage identity.
pub fn walk_matching_files_for(
    detector: DetectorId,
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    keep_file: impl FnMut(&Path, &OsStr) -> bool,
) -> WalkOutcome {
    walk_matching_files_for_with_progress(detector, roots, prune_dir, keep_file, &NoProgress)
}

/// Same as [`walk_matching_files_for`], reporting each examined directory entry.
pub fn walk_matching_files_for_with_progress(
    detector: DetectorId,
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    keep_file: impl FnMut(&Path, &OsStr) -> bool,
    progress: &dyn Progress,
) -> WalkOutcome {
    walk_matching_files_for_limited_with_progress(
        detector,
        roots,
        prune_dir,
        keep_file,
        WalkLimits::production(),
        progress,
    )
}

/// Same as [`walk_matching_files_for`], with explicit traversal limits.
pub fn walk_matching_files_for_limited(
    detector: DetectorId,
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    keep_file: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
) -> WalkOutcome {
    walk_matching_files_for_limited_with_progress(
        detector,
        roots,
        prune_dir,
        keep_file,
        limits,
        &NoProgress,
    )
}

/// Same as [`walk_matching_files_for_limited`], reporting each examined entry.
pub fn walk_matching_files_for_limited_with_progress(
    detector: DetectorId,
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    mut prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    mut keep_file: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
    progress: &dyn Progress,
) -> WalkOutcome {
    let mut coverage = DetectorCoverage::attempted(detector);
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = roots
        .into_iter()
        .map(|r| r.as_ref().to_path_buf())
        .collect();
    let mut budget = EntryBudget::new(limits.max_entries);
    let mut exhausted: Option<&'static str> = None;

    'walk: while let Some(dir) = stack.pop() {
        if exhausted.is_some() {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                coverage.record_artifact(dir, ArtifactStatus::StatFailed);
                continue;
            }
        };
        for entry in entries {
            if !budget.try_consume() {
                exhausted = Some("directory entries");
                break 'walk;
            }
            progress.tick();
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    coverage.record_artifact(dir.clone(), ArtifactStatus::StatFailed);
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => {
                    coverage.record_artifact(path, ArtifactStatus::StatFailed);
                    continue;
                }
            };
            if file_type.is_dir() {
                if file_type_is_symlink(file_type, &path) {
                    continue;
                }
                let name = entry.file_name();
                if prune_dir(&dir, &name) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() || file_type.is_symlink() {
                let name = entry.file_name();
                if keep_file(&path, &name) {
                    if files.len() >= limits.max_files as usize {
                        exhausted = Some("matching files");
                        break 'walk;
                    }
                    files.push(path);
                }
            }
        }
    }

    if let Some(kind) = exhausted {
        coverage.mark_cap_reached();
        let limit = if kind == "matching files" {
            limits.max_files
        } else {
            limits.max_entries
        };
        coverage.set_detail(format!("stopped after {limit} {kind}"));
    }

    WalkOutcome { files, coverage }
}

/// Count directory entries that a bounded matching walk would examine.
pub(crate) fn count_matching_entries_for_limited_with(
    roots: impl IntoIterator<Item = impl AsRef<Path>>,
    mut prune_dir: impl FnMut(&Path, &OsStr) -> bool,
    limits: WalkLimits,
) -> u32 {
    let mut stack: Vec<PathBuf> = roots
        .into_iter()
        .map(|r| r.as_ref().to_path_buf())
        .collect();
    let mut budget = EntryBudget::new(limits.max_entries);
    let mut exhausted = false;

    'walk: while let Some(dir) = stack.pop() {
        if exhausted {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            if !budget.try_consume() {
                exhausted = true;
                break 'walk;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if file_type_is_symlink(file_type, &path) {
                    continue;
                }
                let name = entry.file_name();
                if prune_dir(&dir, &name) {
                    continue;
                }
                stack.push(path);
            }
        }
    }

    budget.consumed()
}

/// Count directory entries under `roots` up to `max_entries`.
pub(crate) fn count_directory_entries_bounded(roots: &[PathBuf], max_entries: u32) -> u32 {
    let mut budget = EntryBudget::new(max_entries);
    let mut exhausted = false;

    'roots: for root in roots {
        if exhausted {
            break;
        }
        match fs::symlink_metadata(root) {
            Err(_) => continue,
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    continue;
                }
            }
        }
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries {
                if !budget.try_consume() {
                    exhausted = true;
                    break 'roots;
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if file_type.is_dir() {
                    if file_type.is_symlink()
                        || fs::symlink_metadata(&path)
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    stack.push(path);
                }
            }
        }
    }

    budget.consumed()
}

fn file_type_is_symlink(file_type: FileType, path: &Path) -> bool {
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
    use crate::coverage::CoverageStatus;
    use crate::progress::CountingProgress;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::symlink;
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
            "chaincheck-walk-{}-{}-{n}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn no_op_prune_visits_venv_and_node_modules() {
        let root = tmp();
        fs::create_dir_all(root.join(".venv/lib")).unwrap();
        fs::write(root.join(".venv/lib/hidden.txt"), b"x").unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/package.json"), b"{}").unwrap();

        let walked = walk_files([&root], |_parent, _name| false);
        let names: Vec<_> = walked
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert!(names.contains(&"hidden.txt"), "{names:?}");
        assert!(names.contains(&"package.json"), "{names:?}");
        assert_eq!(walked.coverage.status(), CoverageStatus::Completed);
        cleanup(&root);
    }

    #[test]
    fn caller_prune_can_skip_venv_without_making_it_global() {
        let root = tmp();
        fs::create_dir_all(root.join(".venv/lib")).unwrap();
        fs::write(root.join(".venv/lib/hidden.txt"), b"x").unwrap();
        fs::write(root.join("visible.txt"), b"y").unwrap();

        let pruned = walk_files([&root], |_parent, name| name == ".venv");
        let pruned_names: Vec<_> = pruned
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert_eq!(pruned_names, ["visible.txt"]);

        let open = walk_files([&root], |_parent, _name| false);
        let open_names: Vec<_> = open
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert!(open_names.contains(&"hidden.txt"));
        cleanup(&root);
    }

    #[test]
    fn does_not_descend_directory_symlink() {
        let root = tmp();
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("secret.txt"), b"s").unwrap();
        symlink(&real, root.join("link")).unwrap();
        fs::write(root.join("ok.txt"), b"o").unwrap();

        let walked = walk_files([&root], |_p, _n| false);
        let names: Vec<_> = walked
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert!(names.contains(&"ok.txt"));
        assert!(names.contains(&"secret.txt"));
        assert!(!walked.files.iter().any(|p| {
            p.components().any(|c| c.as_os_str() == "link")
                && p.file_name().is_some_and(|n| n == "secret.txt")
        }));
        cleanup(&root);
    }

    #[test]
    fn matching_walk_retains_only_kept_files() {
        let root = tmp();
        fs::create_dir_all(root.join("nested/deep")).unwrap();
        fs::write(root.join("keep.dat"), b"k").unwrap();
        fs::write(root.join("nested/deep/keep.dat"), b"k").unwrap();
        for i in 0..40 {
            fs::write(root.join(format!("noise-{i}.txt")), b"n").unwrap();
        }

        let walked = walk_matching_files([&root], |_p, _n| false, |_p, name| name == "keep.dat");
        assert_eq!(walked.files.len(), 2, "{:?}", walked.files);
        assert!(
            walked
                .files
                .iter()
                .all(|p| p.file_name().is_some_and(|n| n == "keep.dat"))
        );
        cleanup(&root);
    }

    #[test]
    fn non_utf8_directory_name_is_descended() {
        use std::os::unix::ffi::OsStrExt;
        let root = tmp();
        let odd = OsStr::from_bytes(b"not-utf8-\xff-dir");
        let nested = root.join(odd).join("node_modules").join("keyv");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("package.json"),
            br#"{"name":"keyv","version":"6.0.0"}"#,
        )
        .unwrap();

        let walked = walk_matching_files(
            [&root],
            |_p, name| name == ".venv",
            |_p, name| name == "package.json",
        );
        assert!(
            walked.files.iter().any(|p| {
                p.file_name().is_some_and(|n| n == "package.json")
                    && p.components().any(|c| c.as_os_str() == odd)
            }),
            "missed package.json under non-UTF-8 directory: {:?}",
            walked.files
        );
        assert_eq!(walked.coverage.status(), CoverageStatus::Completed);
        cleanup(&root);
    }

    #[test]
    fn matching_file_cap_stops_and_is_partial() {
        let root = tmp();
        fs::write(root.join("keep.dat"), b"0").unwrap();
        fs::create_dir_all(root.join("d1/d2")).unwrap();
        fs::write(root.join("d1/keep.dat"), b"1").unwrap();
        fs::write(root.join("d1/d2/keep.dat"), b"2").unwrap();
        let walked = walk_matching_files_for_limited(
            DET_FILESYSTEM_WALK,
            [&root],
            |_p, _n| false,
            |_p, name| name == "keep.dat",
            WalkLimits {
                max_entries: 1_000,
                max_files: 2,
            },
        );
        assert_eq!(walked.files.len(), 2);
        assert_eq!(walked.coverage.status(), CoverageStatus::Partial);
        assert!(walked.coverage.cap_reached());
        assert!(walked.coverage.detail().contains("matching files"));
        cleanup(&root);
    }

    #[test]
    fn entry_cap_stops_wide_noise_from_unbounded_collection() {
        let root = tmp();
        fs::create_dir_all(root.join("chain/a/b")).unwrap();
        fs::write(root.join("chain/a/b/keep.dat"), b"k").unwrap();
        for i in 0..40 {
            fs::write(root.join(format!("noise-{i}.txt")), b"n").unwrap();
        }
        let walked = walk_matching_files_for_limited(
            DET_FILESYSTEM_WALK,
            [&root],
            |_p, _n| false,
            |_p, name| name == "keep.dat",
            WalkLimits {
                max_entries: 8,
                max_files: 100,
            },
        );
        assert!(walked.files.len() <= 1);
        assert_eq!(walked.coverage.status(), CoverageStatus::Partial);
        assert!(walked.coverage.cap_reached());
        assert!(walked.coverage.detail().contains("directory entries"));
        cleanup(&root);
    }

    #[test]
    fn file_cap_cannot_retain_more_than_limit() {
        let root = tmp();
        for i in 0..20 {
            fs::write(root.join(format!("keep-{i}.dat")), b"k").unwrap();
        }
        let walked = walk_matching_files_for_limited(
            DET_FILESYSTEM_WALK,
            [&root],
            |_p, _n| false,
            |_p, name| {
                name.to_str()
                    .is_some_and(|n| n.starts_with("keep-") && n.ends_with(".dat"))
            },
            WalkLimits {
                max_entries: 1_000,
                max_files: 5,
            },
        );
        assert_eq!(walked.files.len(), 5);
        assert!(walked.coverage.cap_reached());
        cleanup(&root);
    }

    #[test]
    fn walk_ticks_once_per_examined_entry() {
        let root = tmp();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("b.txt"), b"b").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/c.txt"), b"c").unwrap();
        let progress = CountingProgress::new();
        let walked =
            walk_matching_files_with_progress([&root], |_p, _n| false, |_p, _n| true, &progress);
        assert_eq!(walked.files.len(), 3, "{:?}", walked.files);
        assert_eq!(progress.tick_count(), 4);
        cleanup(&root);
    }
}
