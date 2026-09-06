//! Python environment discovery and artefact collection.

use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::ProcessConfig;
use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::discovery::{WalkLimits, WalkOutcome, walk_matching_files_for_with_progress};
use crate::fsutil::{HostDirKind, classify_host_dir};
use crate::progress::{NoProgress, Progress};
use crate::scan::ScanScope;
use crate::walk_estimate::estimate_walk_entries_shallow;

use super::{DET_DISCOVERY, DIST_INFO_CAP};

const PYTHON_PRUNE_DIRS: &[&str] = &[
    ".Trash",
    "$RECYCLE.BIN",
    "System Volume Information",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".git",
    "node_modules",
    "_cacache",
    ".gradle",
    ".m2",
    ".nuget",
    ".cache",
];

/// Injectable host-root layout for production vs test discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonHostLayout {
    pub lib_prefixes: Vec<PathBuf>,
    pub pipx_global_home: PathBuf,
}

impl PythonHostLayout {
    pub fn production(config: &ProcessConfig) -> Self {
        let pipx_global = config
            .pipx_global_home
            .clone()
            .unwrap_or_else(|| PathBuf::from("/opt/pipx"));
        Self {
            lib_prefixes: vec![
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/local/lib"),
                PathBuf::from("/usr/lib64"),
                PathBuf::from("/usr/local/lib64"),
            ],
            pipx_global_home: pipx_global,
        }
    }
}

pub struct PythonArtifacts {
    pub metadata: Vec<PathBuf>,
    pub requirements: Vec<PathBuf>,
    pub pyprojects: Vec<PathBuf>,
    pub pipfiles: Vec<PathBuf>,
    pub setup_cfgs: Vec<PathBuf>,
    pub pylock_tomls: Vec<PathBuf>,
    pub uv_locks: Vec<PathBuf>,
    pub poetry_locks: Vec<PathBuf>,
    pub pipfile_locks: Vec<PathBuf>,
    pub pdm_locks: Vec<PathBuf>,
    pub pip_wheel_roots: Vec<PathBuf>,
    pub pip_wheel_root_failures: Vec<(PathBuf, ArtifactStatus)>,
    pub walk_coverage: DetectorCoverage,
    pub include_roots: Vec<PathBuf>,
}

pub fn discover_python(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
) -> PythonArtifacts {
    let layout = PythonHostLayout::production(config);
    discover_python_with_layout(scope, config, home, &layout)
}

pub fn discover_python_with_progress(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    progress: &dyn Progress,
) -> PythonArtifacts {
    let layout = PythonHostLayout::production(config);
    discover_python_with_layout_progress(scope, config, home, &layout, progress)
}

pub fn discover_python_with_layout(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    layout: &PythonHostLayout,
) -> PythonArtifacts {
    discover_python_with_layout_progress(scope, config, home, layout, &NoProgress)
}

pub fn discover_python_with_layout_progress(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    layout: &PythonHostLayout,
    progress: &dyn Progress,
) -> PythonArtifacts {
    let walk_roots = python_walk_roots(scope, config, home, layout);
    let pip_wheel = collect_pip_wheel_roots(scope, home, config);
    let install_locations: RefCell<Vec<PathBuf>> = RefCell::new(Vec::new());
    for root in &walk_roots.dirs {
        if is_package_install_dir(root)
            && matches!(classify_host_dir(root), HostDirKind::RealDirectory)
        {
            let mut locs = install_locations.borrow_mut();
            if !locs.iter().any(|p| p == root) {
                locs.push(root.clone());
            }
        }
    }
    let prune_state = PruneState {
        install_locations: &install_locations,
    };
    let estimate = estimate_walk_entries_shallow(
        walk_roots.dirs.iter(),
        |parent, name| prune_state.prune_dir(parent, name),
        WalkLimits::production(),
    );
    progress.begin_walk_phase("Walking filesystem (Python)", estimate.estimated_total);

    let WalkOutcome {
        files,
        mut coverage,
    } = walk_matching_files_for_with_progress(
        DET_DISCOVERY,
        walk_roots.dirs.clone(),
        |parent, name| prune_state.prune_dir(parent, name),
        python_keep_file,
        progress,
    );
    progress.end_walk_phase();

    for (path, status) in &walk_roots.failures {
        coverage.record_artifact(path.clone(), *status);
    }

    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let mut artifacts = PythonArtifacts {
        metadata: Vec::new(),
        requirements: Vec::new(),
        pyprojects: Vec::new(),
        pipfiles: Vec::new(),
        setup_cfgs: Vec::new(),
        pylock_tomls: Vec::new(),
        uv_locks: Vec::new(),
        poetry_locks: Vec::new(),
        pipfile_locks: Vec::new(),
        pdm_locks: Vec::new(),
        pip_wheel_roots: pip_wheel.dirs,
        pip_wheel_root_failures: pip_wheel.failures,
        walk_coverage: coverage,
        include_roots: walk_roots.dirs,
    };

    for path in files {
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        classify_python_path(&path, &mut artifacts);
    }

    let mut dist_info_seen: HashSet<PathBuf> = HashSet::new();
    let mut cap_reached = false;
    for location in install_locations.into_inner() {
        if cap_reached {
            break;
        }
        collect_dist_info_metadata(
            &location,
            &mut artifacts.metadata,
            &mut dist_info_seen,
            &mut cap_reached,
            &mut artifacts.walk_coverage,
        );
    }
    if cap_reached {
        artifacts.walk_coverage.mark_cap_reached();
    }

    dedup_vec(&mut artifacts.metadata);
    dedup_vec(&mut artifacts.requirements);
    dedup_vec(&mut artifacts.pyprojects);
    dedup_vec(&mut artifacts.pipfiles);
    dedup_vec(&mut artifacts.setup_cfgs);
    dedup_vec(&mut artifacts.pylock_tomls);
    dedup_vec(&mut artifacts.uv_locks);
    dedup_vec(&mut artifacts.poetry_locks);
    dedup_vec(&mut artifacts.pipfile_locks);
    dedup_vec(&mut artifacts.pdm_locks);

    artifacts
}

struct WalkRoots {
    dirs: Vec<PathBuf>,
    failures: Vec<(PathBuf, ArtifactStatus)>,
}

struct PruneState<'a> {
    install_locations: &'a RefCell<Vec<PathBuf>>,
}

impl PruneState<'_> {
    fn prune_dir(&self, parent: &Path, name: &OsStr) -> bool {
        let Some(name) = name.to_str() else {
            return false;
        };
        if PYTHON_PRUNE_DIRS.contains(&name) {
            return true;
        }
        if name == "site-packages" || name == "dist-packages" {
            let path = parent.join(name);
            if matches!(classify_host_dir(&path), HostDirKind::RealDirectory) {
                let mut locs = self.install_locations.borrow_mut();
                if !locs.iter().any(|p| p == &path) {
                    locs.push(path);
                }
            }
            return true;
        }
        if has_pyvenv_cfg(parent) {
            return name != "lib" && name != "local";
        }
        false
    }
}

fn is_package_install_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "site-packages" || n == "dist-packages")
}

fn has_pyvenv_cfg(dir: &Path) -> bool {
    let cfg = dir.join("pyvenv.cfg");
    matches!(
        fs::symlink_metadata(&cfg),
        Ok(meta) if meta.file_type().is_file()
    )
}

pub fn python_keep_file(_path: &Path, name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(
        name,
        "pyvenv.cfg"
            | "pyproject.toml"
            | "Pipfile"
            | "Pipfile.lock"
            | "setup.cfg"
            | "uv.lock"
            | "poetry.lock"
            | "pdm.lock"
            | "pylock.toml"
    ) || super::lockfile::is_pylock_filename(name)
        || (name.starts_with("requirements") && name.ends_with(".txt"))
}

fn classify_python_path(path: &Path, artifacts: &mut PythonArtifacts) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    match name {
        "pyproject.toml" => artifacts.pyprojects.push(path.to_path_buf()),
        "Pipfile" => artifacts.pipfiles.push(path.to_path_buf()),
        "Pipfile.lock" => artifacts.pipfile_locks.push(path.to_path_buf()),
        "setup.cfg" => artifacts.setup_cfgs.push(path.to_path_buf()),
        "uv.lock" => artifacts.uv_locks.push(path.to_path_buf()),
        "poetry.lock" => artifacts.poetry_locks.push(path.to_path_buf()),
        "pdm.lock" => artifacts.pdm_locks.push(path.to_path_buf()),
        other if other.starts_with("requirements") && other.ends_with(".txt") => {
            artifacts.requirements.push(path.to_path_buf());
        }
        other if other == "pylock.toml" || super::lockfile::is_pylock_filename(other) => {
            artifacts.pylock_tomls.push(path.to_path_buf());
        }
        _ => {}
    }
}

fn collect_dist_info_metadata(
    location: &Path,
    metadata: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    cap_reached: &mut bool,
    coverage: &mut DetectorCoverage,
) {
    let entries = match fs::read_dir(location) {
        Ok(entries) => entries,
        Err(_) => {
            coverage.record_artifact(location.to_path_buf(), ArtifactStatus::Unreadable);
            return;
        }
    };
    for entry in entries {
        if *cap_reached {
            return;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                coverage.record_artifact(location.to_path_buf(), ArtifactStatus::StatFailed);
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
        if file_type.is_symlink() {
            continue;
        }
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".egg-info") {
            continue;
        }
        if !name.ends_with(".dist-info") {
            continue;
        }
        let meta = path.join("METADATA");
        if meta.is_file() && seen.insert(meta.clone()) {
            metadata.push(meta);
            if metadata.len() >= DIST_INFO_CAP as usize {
                *cap_reached = true;
                return;
            }
        }
    }
}

fn python_walk_roots(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    layout: &PythonHostLayout,
) -> WalkRoots {
    match scope {
        ScanScope::ExplicitRoot { root } => WalkRoots {
            dirs: vec![root.clone()],
            failures: Vec::new(),
        },
        ScanScope::WholeUser { home: scope_home } => {
            let home = home.unwrap_or(scope_home);
            let mut dirs = vec![scope_home.clone()];
            let mut failures = Vec::new();
            let walk_roots = vec![scope_home.clone()];
            for candidate in extra_python_roots(home, config, layout) {
                if should_suppress_extra_root(&candidate, &walk_roots) {
                    continue;
                }
                match classify_host_dir(&candidate) {
                    HostDirKind::Absent => {}
                    HostDirKind::DirectorySymlink => {
                        failures.push((candidate, ArtifactStatus::Unreadable));
                    }
                    HostDirKind::Failed(status) => failures.push((candidate, status)),
                    HostDirKind::RealDirectory => {
                        if candidate
                            .file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n == "site-packages" || n == "dist-packages")
                        {
                            // Will be enumerated via walk or direct collection
                        }
                        dirs.push(candidate);
                    }
                }
            }
            WalkRoots { dirs, failures }
        }
    }
}

fn extra_python_roots(
    home: &Path,
    config: &ProcessConfig,
    layout: &PythonHostLayout,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    collect_user_local_site_roots(home, &mut candidates);
    collect_layout_lib_roots(layout, &mut candidates);
    collect_pipx_user_roots(home, config, &mut candidates);
    candidates.push(layout.pipx_global_home.join("venvs"));
    collect_uv_tool_roots(home, config, &mut candidates);
    collect_poetry_virtualenv_roots(home, config, &mut candidates);
    candidates
}

fn collect_poetry_virtualenv_roots(home: &Path, config: &ProcessConfig, out: &mut Vec<PathBuf>) {
    if let Some(path) = &config.poetry_virtualenvs_path {
        out.push(path.clone());
        return;
    }
    if let Some(cache) = &config.poetry_cache_dir {
        out.push(cache.join("virtualenvs"));
        return;
    }
    let default_cache = home.join(".cache");
    let cache_home = config.xdg_cache_home.as_ref().unwrap_or(&default_cache);
    out.push(cache_home.join("pypoetry").join("virtualenvs"));
}

struct PipWheelRoots {
    dirs: Vec<PathBuf>,
    failures: Vec<(PathBuf, ArtifactStatus)>,
}

fn collect_pip_wheel_roots(
    scope: &ScanScope,
    home: Option<&Path>,
    config: &ProcessConfig,
) -> PipWheelRoots {
    let mut result = PipWheelRoots {
        dirs: Vec::new(),
        failures: Vec::new(),
    };
    let home = match scope {
        ScanScope::WholeUser { home: scope_home } => Some(home.unwrap_or(scope_home)),
        ScanScope::ExplicitRoot { .. } => home,
    };
    let candidate = if let Some(pip_cache) = &config.pip_cache_dir {
        pip_cache.join("wheels")
    } else {
        let Some(home) = home else {
            return result;
        };
        let default_cache = home.join(".cache");
        let cache_home = config.xdg_cache_home.as_ref().unwrap_or(&default_cache);
        cache_home.join("pip").join("wheels")
    };
    consider_pip_wheel_root(candidate, &mut result);
    result
}

fn consider_pip_wheel_root(candidate: PathBuf, out: &mut PipWheelRoots) {
    if out.dirs.iter().any(|r| r == &candidate) || out.failures.iter().any(|(p, _)| p == &candidate)
    {
        return;
    }
    match classify_host_dir(&candidate) {
        HostDirKind::Absent => {}
        HostDirKind::RealDirectory => out.dirs.push(candidate),
        HostDirKind::DirectorySymlink => out.failures.push((candidate, ArtifactStatus::Unreadable)),
        HostDirKind::Failed(status) => out.failures.push((candidate, status)),
    }
}

fn collect_user_local_site_roots(home: &Path, out: &mut Vec<PathBuf>) {
    let base = home.join(".local").join("lib");
    collect_python_package_dirs(&base, out);
}

fn collect_layout_lib_roots(layout: &PythonHostLayout, out: &mut Vec<PathBuf>) {
    for prefix in &layout.lib_prefixes {
        let py3 = prefix.join("python3");
        for kind in ["site-packages", "dist-packages"] {
            out.push(py3.join(kind));
        }
        if let Ok(entries) = fs::read_dir(prefix) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if !name.starts_with("python") || name == "python3" {
                    continue;
                }
                let path = entry.path();
                for kind in ["site-packages", "dist-packages"] {
                    out.push(path.join(kind));
                }
            }
        }
    }
}

fn collect_python_package_dirs(base: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("python") {
            continue;
        }
        for kind in ["site-packages", "dist-packages"] {
            out.push(path.join(kind));
        }
    }
}

fn collect_pipx_user_roots(home: &Path, config: &ProcessConfig, out: &mut Vec<PathBuf>) {
    if let Some(pipx_home) = &config.pipx_home {
        out.push(pipx_home.join("venvs"));
    } else {
        let default_data = home.join(".local/share");
        let data_home = config.xdg_data_home.as_ref().unwrap_or(&default_data);
        out.push(data_home.join("pipx").join("venvs"));
    }
    let legacy = home.join(".local").join("pipx").join("venvs");
    if legacy.exists() {
        out.push(legacy);
    }
}

fn collect_uv_tool_roots(home: &Path, config: &ProcessConfig, out: &mut Vec<PathBuf>) {
    if let Some(uv) = &config.uv_tool_dir {
        out.push(uv.clone());
    } else {
        let default_data = home.join(".local/share");
        let data_home = config.xdg_data_home.as_ref().unwrap_or(&default_data);
        out.push(data_home.join("uv").join("tools"));
    }
}

fn should_suppress_extra_root(candidate: &Path, walk_roots: &[PathBuf]) -> bool {
    walk_roots
        .iter()
        .any(|root| candidate == root || is_reachable_through_pruned_walk(candidate, root))
}

/// True when the home/project walk would already visit `child` under the same
/// prune rules as [`PruneState::prune_dir`]: [`PYTHON_PRUNE_DIRS`], the
/// site-packages prune hook, and `pyvenv.cfg` children other than `lib`/`local`.
fn is_reachable_through_pruned_walk(child: &Path, parent: &Path) -> bool {
    let Ok(relative) = child.strip_prefix(parent) else {
        return false;
    };
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return false;
    }
    let last = components.len() - 1;
    let mut current = parent.to_path_buf();
    for (i, component) in components.iter().enumerate() {
        let Some(name) = component.as_os_str().to_str() else {
            current.push(component);
            continue;
        };
        if PYTHON_PRUNE_DIRS.contains(&name) {
            return false;
        }
        if (name == "site-packages" || name == "dist-packages") && i != last {
            return false;
        }
        if has_pyvenv_cfg(&current) && name != "lib" && name != "local" {
            return false;
        }
        current.push(component);
    }
    true
}

fn dedup_vec(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ProcessConfig;
    use crate::coverage::{ArtifactStatus, CoverageStatus};
    use crate::scan::ScanScope;

    fn tmp() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "chaincheck-py-disc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn layout_with(prefix: PathBuf) -> PythonHostLayout {
        let pipx = prefix.join("opt/pipx");
        PythonHostLayout {
            lib_prefixes: vec![prefix],
            pipx_global_home: pipx,
        }
    }

    #[test]
    fn explicit_root_does_not_add_host_extras() {
        let base = tmp();
        let home = base.join("home");
        let root = base.join("project");
        std::fs::create_dir_all(&home.join(
            ".local/share/pipx/venvs/tool/lib/python3.12/site-packages/cool_pkg-1.0.0.dist-info",
        ))
        .unwrap();
        std::fs::write(
            home.join(".local/share/pipx/venvs/tool/lib/python3.12/site-packages/cool_pkg-1.0.0.dist-info/METADATA"),
            "Name: cool-pkg\nVersion: 1.0.0\n",
        ).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let layout = layout_with(base.join("usr"));
        let artifacts = discover_python_with_layout(
            &ScanScope::ExplicitRoot { root: root.clone() },
            &ProcessConfig::default(),
            Some(&home),
            &layout,
        );
        assert!(artifacts.metadata.is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn site_packages_not_walked_for_module_files() {
        let base = tmp();
        let home = base.join("home");
        let site = home.join(".local/lib/python3.12/site-packages");
        std::fs::create_dir_all(&site.join("numpy")).unwrap();
        std::fs::write(site.join("numpy/__init__.py"), b"print('big')\n").unwrap();
        std::fs::create_dir_all(&site.join("cool_pkg-1.0.0.dist-info")).unwrap();
        std::fs::write(
            site.join("cool_pkg-1.0.0.dist-info/METADATA"),
            "Name: cool-pkg\nVersion: 1.0.0\n",
        )
        .unwrap();
        let layout = layout_with(base.join("usr"));
        let artifacts = discover_python_with_layout(
            &ScanScope::WholeUser { home: home.clone() },
            &ProcessConfig::default(),
            Some(&home),
            &layout,
        );
        assert_eq!(artifacts.metadata.len(), 1);
        assert!(
            artifacts
                .walk_coverage
                .status()
                .eq(&CoverageStatus::Completed)
                || artifacts.walk_coverage.status() == CoverageStatus::Partial
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn relocated_global_pipx_is_discovered() {
        let base = tmp();
        let home = base.join("home");
        let pipx_global = base.join("opt/pipx");
        let site = pipx_global.join("venvs/tool/lib/python3.12/site-packages");
        std::fs::create_dir_all(&site.join("evil-1.0.0.dist-info")).unwrap();
        std::fs::write(
            site.join("evil-1.0.0.dist-info/METADATA"),
            "Name: evil\nVersion: 1.0.0\n",
        )
        .unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let layout = PythonHostLayout {
            lib_prefixes: vec![base.join("usr/lib")],
            pipx_global_home: pipx_global,
        };
        let artifacts = discover_python_with_layout(
            &ScanScope::WholeUser { home: home.clone() },
            &ProcessConfig::default(),
            Some(&home),
            &layout,
        );
        assert_eq!(artifacts.metadata.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn dedup_overlapping_home_and_pipx_extra_root() {
        let base = tmp();
        let home = base.join("home");
        let site = home.join(".local/share/pipx/venvs/tool/lib/python3.12/site-packages");
        std::fs::create_dir_all(&site.join("dup-1.0.0.dist-info")).unwrap();
        std::fs::write(
            site.join("dup-1.0.0.dist-info/METADATA"),
            "Name: dup\nVersion: 1.0.0\n",
        )
        .unwrap();
        let layout = layout_with(base.join("usr"));
        let artifacts = discover_python_with_layout(
            &ScanScope::WholeUser { home: home.clone() },
            &ProcessConfig::default(),
            Some(&home),
            &layout,
        );
        assert_eq!(artifacts.metadata.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unreadable_install_location_is_recorded_once() {
        use std::os::unix::fs::PermissionsExt;

        let base = tmp();
        let site = base.join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        let original = std::fs::metadata(&site).unwrap().permissions().mode();
        let mut perms = std::fs::metadata(&site).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&site, perms).unwrap();
        let readable = std::fs::read_dir(&site).is_ok();
        let mut metadata = Vec::new();
        let mut seen = HashSet::new();
        let mut cap = false;
        let mut coverage = DetectorCoverage::attempted(DET_DISCOVERY);
        collect_dist_info_metadata(&site, &mut metadata, &mut seen, &mut cap, &mut coverage);
        let mut restore = std::fs::metadata(&site).unwrap().permissions();
        restore.set_mode(original);
        let _ = std::fs::set_permissions(&site, restore);
        let _ = std::fs::remove_dir_all(&base);
        if readable {
            return;
        }
        assert!(metadata.is_empty());
        assert_eq!(coverage.status(), CoverageStatus::Partial);
        let failures: u32 = coverage.failure_counts().values().sum();
        assert_eq!(failures, 1);
        assert_eq!(
            coverage
                .failure_counts()
                .get(&ArtifactStatus::Unreadable)
                .copied()
                .unwrap_or(0),
            1
        );
    }
}
