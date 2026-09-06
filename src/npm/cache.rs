//! npm cacache `index-v5` registry tarball URL evidence.

use std::fs;
use std::path::Path;

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::EvidenceClass;
use crate::fsutil::{read_text_lossy_bounded, text_artifact_status};
use crate::intelligence::EcosystemIntelligence;
use crate::model::{EvidenceKind, Severity};
use crate::progress::{NoProgress, Progress};
use crate::scan::DetectorOutput;

use super::{
    CACHE_FILE_CAP, CODE_NPM_CACHE, DET_NPM_CACHE, LIMIT_CACHE_ENTRY, emit_exact,
    pairs_from_tarball_urls, skipped,
};
use crate::discovery::{EntryBudget, WalkLimits};

pub fn scan_npm_cache(roots: &[impl AsRef<Path>], intel: &EcosystemIntelligence) -> DetectorOutput {
    scan_npm_cache_with_progress(roots, intel, &NoProgress)
}

pub fn scan_npm_cache_with_progress(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> DetectorOutput {
    scan_npm_cache_bounded_with_progress(
        roots,
        intel,
        CACHE_FILE_CAP,
        WalkLimits::production().max_entries,
        progress,
    )
}

pub(crate) fn scan_npm_cache_limited(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
) -> DetectorOutput {
    scan_npm_cache_bounded(roots, intel, cap, WalkLimits::production().max_entries)
}

pub(crate) fn scan_npm_cache_bounded(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
    max_entries: u32,
) -> DetectorOutput {
    scan_npm_cache_bounded_with_progress(roots, intel, cap, max_entries, &NoProgress)
}

pub(crate) fn scan_npm_cache_bounded_with_progress(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
    max_entries: u32,
    progress: &dyn Progress,
) -> DetectorOutput {
    if roots.is_empty() {
        return skipped(DET_NPM_CACHE);
    }
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_NPM_CACHE);
    let mut scanned = 0u32;
    let mut truncated_files = false;
    let mut truncated_entries = false;
    let mut budget = EntryBudget::new(max_entries);

    'roots: for root in roots {
        let root = root.as_ref();
        match fs::symlink_metadata(root) {
            Err(_) => {
                coverage.record_artifact(root.to_path_buf(), ArtifactStatus::StatFailed);
                continue;
            }
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    coverage.record_artifact(root.to_path_buf(), ArtifactStatus::Unreadable);
                    continue;
                }
            }
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => {
                    coverage.record_artifact(dir, ArtifactStatus::StatFailed);
                    continue;
                }
            };
            for entry in entries {
                if !budget.try_consume() {
                    truncated_entries = true;
                    break 'roots;
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
                    if file_type.is_symlink()
                        || fs::symlink_metadata(&path)
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if scanned >= cap {
                    truncated_files = true;
                    break 'roots;
                }
                scanned += 1;
                match read_text_lossy_bounded(&path, LIMIT_CACHE_ENTRY) {
                    crate::fsutil::TextReadOutcome::Text(text) => {
                        coverage.record_artifact(path.clone(), ArtifactStatus::Inspected);
                        for (name, version) in pairs_from_tarball_urls(&text) {
                            emit_exact(
                                intel,
                                &name,
                                &version,
                                &path,
                                DET_NPM_CACHE,
                                EvidenceClass::Cache,
                                EvidenceKind::PackageCache,
                                CODE_NPM_CACHE,
                                Severity::Medium,
                                &mut findings,
                                &mut evidence,
                            );
                        }
                    }
                    other => {
                        coverage.record_artifact(path, text_artifact_status(&other));
                    }
                }
            }
        }
    }

    if truncated_entries {
        coverage.mark_cap_reached();
        coverage.set_detail(format!("stopped after {max_entries} directory entries"));
    } else if truncated_files {
        coverage.mark_cap_reached();
        coverage.set_detail(format!("stopped at the {cap} file cap"));
    }
    DetectorOutput {
        findings,
        package_evidence: evidence,
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageStatus;
    use crate::intelligence::parse_malware_feed;
    use crate::model::Ecosystem;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TINY_NPM: &[u8] = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "chaincheck-cache-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap())
    }

    #[test]
    fn cache_file_cap_marks_partial_without_findings_from_unscanned_files() {
        let root = tmp();
        for i in 0..4 {
            fs::write(
                root.join(format!("entry-{i}")),
                format!("https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz {i}"),
            )
            .unwrap();
        }
        let output = scan_npm_cache_limited(&[root.as_path()], &intel(), 3);
        assert_eq!(output.coverage.status(), CoverageStatus::Partial);
        assert!(output.coverage.cap_reached());
        assert_eq!(output.coverage.artefacts_inspected(), 3);
        assert_eq!(output.findings.len(), 3);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cache_entry_cap_stops_before_file_cap() {
        let root = tmp();
        for i in 0..12 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
        }
        let output = scan_npm_cache_bounded(&[root.as_path()], &intel(), 200_000, 5);
        assert_eq!(output.coverage.status(), CoverageStatus::Partial);
        assert!(output.coverage.cap_reached());
        assert!(output.coverage.detail().contains("directory entries"));
        assert!(output.coverage.artefacts_inspected() <= 5);
        let _ = fs::remove_dir_all(&root);
    }
}
