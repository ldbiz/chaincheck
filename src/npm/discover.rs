//! npm-specific discovery on top of generic traversal.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::ProcessConfig;
use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::discovery::{WalkOutcome, walk_matching_files_with};
use crate::fsutil::{HostDirKind, TextReadOutcome, classify_host_dir, read_utf8_bounded};
use crate::progress::{NoProgress, ScanProgress};
use crate::scan::ScanScope;

/// Directories the npm walk does not descend. This is not a global policy:
/// Python environment trees remain visitable through [`walk_files`] with a
/// different prune function.
const NPM_PRUNE_DIRS: &[&str] = &[
    ".Trash",
    "$RECYCLE.BIN",
    "System Volume Information",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".git",
    ".venv",
    "venv",
    ".tox",
    ".gradle",
    ".m2",
    ".nuget",
    "_cacache",
];

pub struct NpmArtifacts {
    pub manifests: Vec<PathBuf>,
    pub npm_locks: Vec<PathBuf>,
    pub yarn_locks: Vec<PathBuf>,
    pub pnpm_locks: Vec<PathBuf>,
    pub bun_locks: Vec<PathBuf>,
    pub bun_lockb: Vec<PathBuf>,
    pub logs: Vec<PathBuf>,
    pub log_dir_failures: Vec<(PathBuf, ArtifactStatus)>,
    pub cache_index_roots: Vec<PathBuf>,
    pub cache_root_failures: Vec<(PathBuf, ArtifactStatus)>,
    pub walk_coverage: DetectorCoverage,
}

pub fn npm_prune_dir(_parent: &Path, name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| NPM_PRUNE_DIRS.contains(&name))
}

pub fn npm_keep_file(path: &Path, name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "bun.lock"
            | "bun.lockb"
    ) || (name.ends_with(".log") && path.components().any(|c| c.as_os_str() == "_logs"))
}

/// Filesystem roots for a retrospective scan of local and globally installed
/// npm package trees. This is root **selection** only: callers apply their own
/// prune/keep policy via [`walk_matching_files`].
pub struct PackageRoots {
    pub dirs: Vec<PathBuf>,
    pub failures: Vec<(PathBuf, ArtifactStatus)>,
}

pub fn npm_package_roots(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
) -> PackageRoots {
    match scope {
        ScanScope::ExplicitRoot { root } => PackageRoots {
            dirs: vec![root.clone()],
            failures: Vec::new(),
        },
        ScanScope::WholeUser { home: scope_home } => {
            let home = home.unwrap_or(scope_home);
            let extra = extra_npm_module_roots(home, config);
            let mut dirs = extra.dirs;
            dirs.push(scope_home.clone());
            PackageRoots {
                dirs,
                failures: extra.failures,
            }
        }
    }
}

pub fn discover_npm(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
) -> NpmArtifacts {
    discover_npm_with_progress(scope, config, home, &NoProgress)
}

pub(crate) fn discover_npm_with_progress(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    progress: &dyn ScanProgress,
) -> NpmArtifacts {
    let walk_roots = npm_package_roots(scope, config, home);
    let extra_failures = walk_roots.failures;
    let WalkOutcome {
        files,
        mut coverage,
    } = walk_matching_files_with(walk_roots.dirs, npm_prune_dir, npm_keep_file, progress);
    for (path, status) in extra_failures {
        coverage.record_artifact(path, status);
    }

    let mut artifacts = NpmArtifacts {
        manifests: Vec::new(),
        npm_locks: Vec::new(),
        yarn_locks: Vec::new(),
        pnpm_locks: Vec::new(),
        bun_locks: Vec::new(),
        bun_lockb: Vec::new(),
        logs: Vec::new(),
        log_dir_failures: Vec::new(),
        cache_index_roots: Vec::new(),
        cache_root_failures: Vec::new(),
        walk_coverage: coverage,
    };

    for path in files {
        classify_npm_path(path, &mut artifacts);
    }

    collect_host_cache_roots(home, config.npm_config_cache.as_deref(), &mut artifacts);
    collect_host_npm_logs(home, &mut artifacts);
    artifacts
}

fn classify_npm_path(path: PathBuf, artifacts: &mut NpmArtifacts) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    match name {
        "package-lock.json" | "npm-shrinkwrap.json" => artifacts.npm_locks.push(path),
        "yarn.lock" => artifacts.yarn_locks.push(path),
        "pnpm-lock.yaml" => artifacts.pnpm_locks.push(path),
        "bun.lock" => artifacts.bun_locks.push(path),
        "bun.lockb" => artifacts.bun_lockb.push(path),
        "package.json" => artifacts.manifests.push(path),
        other if other.ends_with(".log") => artifacts.logs.push(path),
        _ => {}
    }
}

fn collect_host_npm_logs(home: Option<&Path>, artifacts: &mut NpmArtifacts) {
    let Some(home) = home else {
        return;
    };
    let default_logs = home.join(".npm").join("_logs");
    match classify_host_dir(&default_logs) {
        HostDirKind::Absent => {}
        HostDirKind::DirectorySymlink => artifacts
            .log_dir_failures
            .push((default_logs, ArtifactStatus::Unreadable)),
        HostDirKind::Failed(status) => artifacts.log_dir_failures.push((default_logs, status)),
        HostDirKind::RealDirectory => match fs::read_dir(&default_logs) {
            Err(_) => artifacts
                .log_dir_failures
                .push((default_logs, ArtifactStatus::Unreadable)),
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let path = entry.path();
                            if path.extension().is_some_and(|e| e == "log")
                                && !artifacts.logs.iter().any(|p| p == &path)
                            {
                                artifacts.logs.push(path);
                            }
                        }
                        Err(_) => artifacts
                            .log_dir_failures
                            .push((default_logs.clone(), ArtifactStatus::StatFailed)),
                    }
                }
            }
        },
    }
}

struct ExtraRoots {
    dirs: Vec<PathBuf>,
    failures: Vec<(PathBuf, ArtifactStatus)>,
}

fn extra_npm_module_roots(home: &Path, config: &ProcessConfig) -> ExtraRoots {
    let mut extra = ExtraRoots {
        dirs: Vec::new(),
        failures: Vec::new(),
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(prefix) = &config.npm_config_prefix {
        candidates.push(prefix.join("lib").join("node_modules"));
    }
    if let Some(prefix) = user_npmrc_prefix(home) {
        candidates.push(prefix.join("lib").join("node_modules"));
    }
    candidates.push(home.join(".npm-global").join("lib").join("node_modules"));
    candidates.push(home.join(".local").join("lib").join("node_modules"));
    candidates.push(PathBuf::from("/usr/local/lib/node_modules"));
    candidates.push(PathBuf::from("/usr/lib/node_modules"));
    for candidate in candidates {
        if extra.dirs.iter().any(|r| r == &candidate) {
            continue;
        }
        match classify_host_dir(&candidate) {
            HostDirKind::Absent => {}
            HostDirKind::RealDirectory => extra.dirs.push(candidate),
            HostDirKind::DirectorySymlink => {
                extra.failures.push((candidate, ArtifactStatus::Unreadable))
            }
            HostDirKind::Failed(status) => extra.failures.push((candidate, status)),
        }
    }
    extra
}

fn user_npmrc_prefix(home: &Path) -> Option<PathBuf> {
    let path = home.join(".npmrc");
    let TextReadOutcome::Text(text) = read_utf8_bounded(&path, 1_000_000) else {
        return None;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "prefix" {
            continue;
        }
        let value = value.trim();
        if value.contains("${") || value.is_empty() {
            continue;
        }
        return Some(PathBuf::from(value));
    }
    None
}

fn collect_host_cache_roots(
    home: Option<&Path>,
    npm_config_cache: Option<&Path>,
    artifacts: &mut NpmArtifacts,
) {
    let mut candidates = Vec::new();
    if let Some(home) = home {
        candidates.push(home.join(".npm").join("_cacache").join("index-v5"));
    }
    if let Some(cache) = npm_config_cache {
        candidates.push(cache.join("_cacache").join("index-v5"));
    }
    for candidate in candidates {
        consider_host_cache_dir(
            candidate,
            &mut artifacts.cache_index_roots,
            &mut artifacts.cache_root_failures,
        );
    }
}

fn consider_host_cache_dir(
    candidate: PathBuf,
    roots: &mut Vec<PathBuf>,
    failures: &mut Vec<(PathBuf, ArtifactStatus)>,
) {
    if roots.iter().any(|r| r == &candidate) || failures.iter().any(|(p, _)| p == &candidate) {
        return;
    }
    match classify_host_dir(&candidate) {
        HostDirKind::Absent => {}
        HostDirKind::RealDirectory => roots.push(candidate),
        HostDirKind::DirectorySymlink => failures.push((candidate, ArtifactStatus::Unreadable)),
        HostDirKind::Failed(status) => failures.push((candidate, status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ProcessConfig;
    use crate::discovery::{walk_files, walk_matching_files};
    use crate::scan::ScanScope;
    use std::ffi::OsStr;
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
            "chaincheck-npm-disc-{}-{}-{n}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn npm_prune_skips_venv_but_generic_walk_does_not() {
        let root = tmp();
        fs::create_dir_all(root.join(".venv/lib")).unwrap();
        fs::write(root.join(".venv/lib/hidden.txt"), b"x").unwrap();
        fs::write(root.join("visible.txt"), b"y").unwrap();

        let npm = walk_files([&root], npm_prune_dir);
        let npm_names: Vec<_> = npm
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert_eq!(npm_names, ["visible.txt"]);

        let open = walk_files([&root], |_p, _n| false);
        let open_names: Vec<_> = open
            .files
            .iter()
            .filter_map(|p| p.file_name()?.to_str())
            .collect();
        assert!(open_names.contains(&"hidden.txt"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_prune_does_not_skip_node_modules() {
        let root = tmp();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/package.json"), b"{}").unwrap();
        let walked = walk_matching_files([&root], npm_prune_dir, npm_keep_file);
        assert!(
            walked
                .files
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n == "package.json"))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn discover_npm_retains_only_relevant_artefacts() {
        let root = tmp();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join("_cacache/index-v5/aa")).unwrap();
        fs::write(root.join("node_modules/pkg/package.json"), b"{}").unwrap();
        fs::write(root.join("package-lock.json"), b"{}").unwrap();
        fs::write(root.join("docs/readme.md"), b"n").unwrap();
        fs::write(root.join("_cacache/index-v5/aa/entry"), b"cache").unwrap();
        for i in 0..50 {
            fs::write(root.join(format!("noise-{i}.txt")), b"n").unwrap();
        }
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let artifacts = discover_npm(
            &ScanScope::ExplicitRoot { root: root.clone() },
            &ProcessConfig::default(),
            Some(&home),
        );
        assert_eq!(artifacts.manifests.len(), 1);
        assert_eq!(artifacts.npm_locks.len(), 1);
        assert!(artifacts.yarn_locks.is_empty());
        assert!(artifacts.logs.is_empty());
        let collected = artifacts.manifests.len()
            + artifacts.npm_locks.len()
            + artifacts.yarn_locks.len()
            + artifacts.pnpm_locks.len()
            + artifacts.bun_locks.len()
            + artifacts.bun_lockb.len()
            + artifacts.logs.len();
        assert_eq!(collected, 2);
        assert!(
            artifacts
                .walk_coverage
                .examples()
                .iter()
                .all(|e| !e.path.components().any(|c| c.as_os_str() == "_cacache"))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn discover_npm_finds_package_json_under_non_utf8_directory() {
        use std::os::unix::ffi::OsStrExt;
        let root = tmp();
        let odd = OsStr::from_bytes(b"not-utf8-\xff-dir");
        let nested = root.join(odd).join("node_modules").join("keyv");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("package.json"), b"{}").unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let artifacts = discover_npm(
            &ScanScope::ExplicitRoot { root: root.clone() },
            &ProcessConfig::default(),
            Some(&home),
        );
        assert_eq!(artifacts.manifests.len(), 1);
        assert!(
            artifacts.manifests[0]
                .components()
                .any(|c| c.as_os_str() == odd)
        );
        assert_eq!(
            artifacts.walk_coverage.status(),
            crate::coverage::CoverageStatus::Completed
        );
        let _ = fs::remove_dir_all(&root);
    }
}
