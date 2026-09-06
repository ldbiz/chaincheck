//! Campaign-owned discovery: payload names, IDE configs, and Git repositories.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::cli::ProcessConfig;
use crate::coverage::DetectorCoverage;
use crate::discovery::{
    WalkLimits, WalkOutcome, count_matching_entries_for_limited_with,
    walk_matching_files_for_with_progress,
};
use crate::npm::npm_package_roots;
use crate::progress::{NoProgress, Progress};
use crate::scan::ScanScope;

use super::DET_CAMPAIGN_WALK;
use super::intelligence::is_payload_name;

const CAMPAIGN_PRUNE_DIRS: &[&str] = &[
    ".Trash",
    "$RECYCLE.BIN",
    "System Volume Information",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".gradle",
    ".m2",
    ".nuget",
    "_cacache",
    ".venv",
    "venv",
    ".tox",
];

pub struct CampaignArtifacts {
    pub payloads: Vec<PathBuf>,
    pub ide_configs: Vec<PathBuf>,
    pub git_repos: Vec<PathBuf>,
    pub walk_coverage: DetectorCoverage,
}

pub fn campaign_prune_dir(_parent: &Path, name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| CAMPAIGN_PRUNE_DIRS.contains(&name))
}

pub fn campaign_keep_file(path: &Path, name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if is_payload_name(name) {
        return true;
    }
    if name == ".git" {
        return true;
    }
    (name == "tasks.json" && path.components().any(|c| c.as_os_str() == ".vscode"))
        || (name == "settings.json" && path.components().any(|c| c.as_os_str() == ".claude"))
}

pub fn discover_campaign(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
) -> CampaignArtifacts {
    discover_campaign_with_progress(scope, config, home, &NoProgress)
}

pub fn discover_campaign_with_progress(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    progress: &dyn Progress,
) -> CampaignArtifacts {
    progress.stage("Walking filesystem (campaign)");
    let roots = npm_package_roots(scope, config, home);
    let mut git_repos = Vec::new();
    let WalkOutcome {
        files,
        mut coverage,
    } = walk_matching_files_for_with_progress(
        DET_CAMPAIGN_WALK,
        roots.dirs,
        |parent, name| {
            if name == ".git" {
                if !git_repos.iter().any(|p| p == parent) {
                    git_repos.push(parent.to_path_buf());
                }
                return true;
            }
            campaign_prune_dir(parent, name)
        },
        campaign_keep_file,
        progress,
    );

    for (path, status) in roots.failures {
        coverage.record_artifact(path, status);
    }
    let walk_coverage = coverage;

    let mut artifacts = CampaignArtifacts {
        payloads: Vec::new(),
        ide_configs: Vec::new(),
        git_repos,
        walk_coverage,
    };

    for path in files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == ".git" {
            if let Some(parent) = path.parent() {
                if !artifacts.git_repos.iter().any(|p| p == parent) {
                    artifacts.git_repos.push(parent.to_path_buf());
                }
            }
            continue;
        }
        if is_payload_name(name) {
            artifacts.payloads.push(path);
        } else {
            artifacts.ide_configs.push(path);
        }
    }

    progress.add_work(
        count_campaign_scannable_files(&artifacts) + artifacts.git_repos.len() as u64,
    );

    artifacts
}

pub(crate) fn count_campaign_walk_entries(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
) -> u32 {
    let roots = npm_package_roots(scope, config, home);
    count_matching_entries_for_limited_with(
        roots.dirs,
        |parent, name| {
            if name == ".git" {
                return true;
            }
            campaign_prune_dir(parent, name)
        },
        WalkLimits::production(),
    )
}

pub(crate) fn count_campaign_scannable_files(artifacts: &CampaignArtifacts) -> u64 {
    (artifacts.payloads.len() + artifacts.ide_configs.len()) as u64
}
