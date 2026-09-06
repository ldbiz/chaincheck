//! Pre-scan work estimation for percentage progress.

use std::path::Path;

use crate::campaign::{count_campaign_walk_entries};
use crate::cli::ProcessConfig;
use crate::discovery::{WalkLimits, count_directory_entries_bounded};
use crate::npm::{count_npm_walk_entries, npm_host_cache_index_roots};
use crate::progress::Progress;
use crate::python::{count_python_walk_entries, pip_wheel_roots_for_scan, PythonHostLayout};
use crate::scan::ScanScope;

const INTEL_UNITS: u64 = 2;
const HOST_BASE_UNITS: u64 = 3;
const REPORT_UNITS: u64 = 1;

/// Pre-counted work units for the main scan progress bar.
pub struct ScanWorkPlan {
    pub total: u64,
}

impl ScanWorkPlan {
    /// Measure filesystem and cache candidates before the scan body runs.
    ///
    /// Skipped when progress is not live to avoid doubling filesystem I/O.
    pub fn estimate_if_live(
        scope: &ScanScope,
        config: &ProcessConfig,
        home: Option<&Path>,
        progress: &dyn Progress,
    ) -> Self {
        if !progress.is_live() {
            return Self { total: 0 };
        }
        Self::estimate(scope, config, home, progress)
    }

    fn estimate(scope: &ScanScope, config: &ProcessConfig, home: Option<&Path>, progress: &dyn Progress) -> Self {
        progress.stage("Measuring scan scope");
        let layout = PythonHostLayout::production(config);
        let limits = WalkLimits::production();

        let npm_walk = u64::from(count_npm_walk_entries(scope, config, home));
        let python_walk = u64::from(count_python_walk_entries(scope, config, home, &layout));
        let campaign_walk = u64::from(count_campaign_walk_entries(scope, config, home));

        let npm_cache_roots = npm_host_cache_index_roots(home, config.npm_config_cache.as_deref());
        let pip_wheel_roots = pip_wheel_roots_for_scan(scope, home, config);
        let npm_cache = u64::from(count_directory_entries_bounded(
            &npm_cache_roots,
            limits.max_entries,
        ));
        let pip_wheel = u64::from(count_directory_entries_bounded(
            &pip_wheel_roots,
            limits.max_entries,
        ));

        let total = INTEL_UNITS
            + HOST_BASE_UNITS
            + REPORT_UNITS
            + npm_walk
            + python_walk
            + campaign_walk
            + npm_cache
            + pip_wheel;

        Self { total }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
        use crate::progress::CountingProgress;
        use std::path::PathBuf;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> std::path::PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "chaincheck-plan-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn estimate_counts_walk_entries_for_explicit_root() {
        let root = tmp();
        fs::write(root.join("package.json"), b"{}").unwrap();
        let progress = CountingProgress::new();
        let plan = ScanWorkPlan::estimate_if_live(
            &ScanScope::ExplicitRoot { root: root.clone() },
            &ProcessConfig::default(),
            None,
            &progress,
        );
        assert!(plan.total >= INTEL_UNITS + HOST_BASE_UNITS + REPORT_UNITS + 3);
        assert_eq!(progress.staged(), ["Measuring scan scope"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn estimate_skipped_when_not_live() {
        use crate::progress::NoProgress;
        let progress = NoProgress;
        let plan = ScanWorkPlan::estimate_if_live(
            &ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/chaincheck-plan-unused"),
            },
            &ProcessConfig::default(),
            None,
            &progress,
        );
        assert_eq!(plan.total, 0);
    }
}
