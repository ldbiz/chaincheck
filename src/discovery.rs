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

const CHAINCHECK_FIXTURE_DETAIL: &str =
    "skipped ChainCheck's own tests/fixtures synthetic test data";
const SELF_REPO_METADATA_MAX_BYTES: u64 = 1_000_000;

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
    let mut skipped_chaincheck_fixtures = false;

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
                if is_chaincheck_owned_fixture_dir(&dir, &name) {
                    skipped_chaincheck_fixtures = true;
                    continue;
                }
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
    } else if skipped_chaincheck_fixtures {
        coverage.set_detail(CHAINCHECK_FIXTURE_DETAIL);
    }

    WalkOutcome { files, coverage }
}

/// Return true only for the synthetic fixture tree in an actual checkout of
/// the upstream ChainCheck repository. A generic `tests/fixtures` directory is
/// never excluded: both the package identity and Git remote must match.
fn is_chaincheck_owned_fixture_dir(parent: &Path, name: &OsStr) -> bool {
    if name != OsStr::new("fixtures") || parent.file_name() != Some(OsStr::new("tests")) {
        return false;
    }
    let Some(repo_root) = parent.parent() else {
        return false;
    };
    chaincheck_package_identity(repo_root) && chaincheck_upstream_remote(repo_root)
}

fn chaincheck_package_identity(repo_root: &Path) -> bool {
    let Some(cargo) = read_small_utf8(&repo_root.join("Cargo.toml")) else {
        return false;
    };
    let mut in_package = false;
    for line in cargo.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package && line == "name = \"chaincheck\"" {
            return true;
        }
    }
    false
}

fn chaincheck_upstream_remote(repo_root: &Path) -> bool {
    let Some(config) = read_small_utf8(&repo_root.join(".git").join("config")) else {
        return false;
    };
    config.lines().any(|line| {
        let line = line.trim();
        line.starts_with("url =")
            && (line.contains("github.com/ldbiz/chaincheck")
                || line.contains("github.com:ldbiz/chaincheck"))
    })
}

fn read_small_utf8(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > SELF_REPO_METADATA_MAX_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
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
    fn chaincheck_checkout_skips_only_its_owned_fixture_tree() {
        let root = tmp();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("tests/fixtures/nested")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname = \"chaincheck\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(
            root.join(".git/config"),
            b"[remote \"origin\"]\n\turl = https://github.com/ldbiz/chaincheck.git\n",
        )
        .unwrap();
        fs::write(root.join("tests/fixtures/nested/synthetic.dat"), b"fixture").unwrap();
        fs::write(root.join("tests/ordinary.dat"), b"ordinary").unwrap();

        let walked = walk_files([&root], |_p, _n| false);
        assert!(
            walked.files.iter().any(|p| p.ends_with("tests/ordinary.dat")),
            "ordinary test data should still be scanned: {:?}",
            walked.files
        );
        assert!(
            !walked
                .files
                .iter()
                .any(|p| p.ends_with("tests/fixtures/nested/synthetic.dat")),
            "owned synthetic fixture tree should be skipped: {:?}",
            walked.files
        );
        assert_eq!(walked.coverage.status(), CoverageStatus::Completed);
        assert_eq!(walked.coverage.detail(), CHAINCHECK_FIXTURE_DETAIL);
        cleanup(&root);
    }

    #[test]
    fn lookalike_fixture_tree_without_chaincheck_upstream_is_scanned() {
        let root = tmp();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("tests/fixtures")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname = \"chaincheck\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(
            root.join(".git/config"),
            b"[remote \"origin\"]\n\turl = https://github.com/example/chaincheck.git\n",
        )
        .unwrap();
        fs::write(root.join("tests/fixtures/synthetic.dat"), b"fixture").unwrap();

        let walked = walk_files([&root], |_p, _n| false);
        assert!(
            walked
                .files
                .iter()
                .any(|p| p.ends_with("tests/fixtures/synthetic.dat")),
            "non-upstream lookalike must not create an exclusion: {:?}",
            walked.files
        );
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
