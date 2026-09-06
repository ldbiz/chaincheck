//! pip `wheels/` cache evidence from wheel filenames (PEP 427).

use std::fs;
use std::path::Path;

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::intelligence::EcosystemIntelligence;
use crate::model::PackageIdentity;
use crate::progress::{NoProgress, Progress};
use crate::scan::DetectorOutput;

use super::{DET_PIP_WHEEL_CACHE, WHEEL_FILE_CAP, emit_wheel_cache, skipped};
use crate::discovery::{EntryBudget, WalkLimits};

pub fn scan_pip_wheel_cache(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
) -> DetectorOutput {
    scan_pip_wheel_cache_with_progress(roots, intel, &NoProgress)
}

pub fn scan_pip_wheel_cache_with_progress(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> DetectorOutput {
    scan_pip_wheel_cache_bounded_with_progress(
        roots,
        intel,
        WHEEL_FILE_CAP,
        WalkLimits::production().max_entries,
        progress,
    )
}

pub fn scan_pip_wheel_cache_limited(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
) -> DetectorOutput {
    scan_pip_wheel_cache_bounded(roots, intel, cap, WalkLimits::production().max_entries)
}

pub(crate) fn scan_pip_wheel_cache_bounded(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
    max_entries: u32,
) -> DetectorOutput {
    scan_pip_wheel_cache_bounded_with_progress(roots, intel, cap, max_entries, &NoProgress)
}

pub(crate) fn scan_pip_wheel_cache_bounded_with_progress(
    roots: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    cap: u32,
    max_entries: u32,
    progress: &dyn Progress,
) -> DetectorOutput {
    if roots.is_empty() {
        return skipped(DET_PIP_WHEEL_CACHE);
    }
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_PIP_WHEEL_CACHE);
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
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !name.ends_with(".whl") {
                    continue;
                }
                if scanned >= cap {
                    truncated_files = true;
                    break 'roots;
                }
                scanned += 1;
                coverage.record_artifact(path.clone(), ArtifactStatus::Inspected);
                if let Some((distribution, version)) = parse_wheel_filename(name) {
                    emit_wheel_cache(
                        intel,
                        &distribution,
                        &version,
                        &path,
                        &mut findings,
                        &mut evidence,
                    );
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

/// Parse `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`.
pub(crate) fn parse_wheel_filename(name: &str) -> Option<(String, String)> {
    let stem = name.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    let (distribution, version) = match parts.len() {
        5 => {
            let py = parts[2];
            let abi = parts[3];
            let platform = parts[4];
            if py.is_empty() || abi.is_empty() || platform.is_empty() {
                return None;
            }
            (parts[0], parts[1])
        }
        6 => {
            let build = parts[2];
            if build.is_empty() || !build.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return None;
            }
            let py = parts[3];
            let abi = parts[4];
            let platform = parts[5];
            if py.is_empty() || abi.is_empty() || platform.is_empty() {
                return None;
            }
            (parts[0], parts[1])
        }
        _ => return None,
    };
    if distribution.is_empty() || version.is_empty() {
        return None;
    }
    if !valid_distribution(distribution) {
        return None;
    }
    let canonical = PackageIdentity::pypi(distribution)
        .name()
        .as_str()
        .to_owned();
    Some((canonical, version.to_owned()))
}

fn valid_distribution(distribution: &str) -> bool {
    distribution
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_wheel_parses() {
        let parsed = parse_wheel_filename("requests-2.32.3-py3-none-any.whl").unwrap();
        assert_eq!(parsed.0, "requests");
        assert_eq!(parsed.1, "2.32.3");
    }

    #[test]
    fn underscore_distribution_normalises() {
        let parsed =
            parse_wheel_filename("zope_interface-7.2-cp312-cp312-manylinux_2_17_x86_64.whl")
                .unwrap();
        assert_eq!(parsed.0, "zope-interface");
        assert_eq!(parsed.1, "7.2");
    }

    #[test]
    fn legacy_dotted_uppercase_canonicalises() {
        let parsed = parse_wheel_filename("Foo.Bar-1.0-py3-none-any.whl").unwrap();
        assert_eq!(parsed.0, "foo-bar");
        assert_eq!(parsed.1, "1.0");
    }

    #[test]
    fn build_tag_keeps_version() {
        let parsed = parse_wheel_filename("pkg-1.0-1-py3-none-any.whl").unwrap();
        assert_eq!(parsed.0, "pkg");
        assert_eq!(parsed.1, "1.0");
    }

    #[test]
    fn too_few_components_is_ambiguous() {
        assert!(parse_wheel_filename("pkg-1.0-py3-none.whl").is_none());
    }

    #[test]
    fn invalid_build_tag_is_ambiguous() {
        assert!(parse_wheel_filename("pkg-1.0-abc-py3-none-any.whl").is_none());
    }

    #[test]
    fn wheel_entry_cap_stops_empty_directory_tree() {
        use crate::coverage::CoverageStatus;
        use crate::intelligence::parse_malware_feed;
        use crate::model::Ecosystem;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static UNIQUE: AtomicU64 = AtomicU64::new(0);
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "chaincheck-whl-entries-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for i in 0..12 {
            fs::create_dir_all(root.join(format!("d{i}"))).unwrap();
        }
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let output = scan_pip_wheel_cache_bounded(&[&root], &intel, 50_000, 5);
        assert_eq!(output.coverage.status(), CoverageStatus::Partial);
        assert!(output.coverage.cap_reached());
        assert!(output.coverage.detail().contains("directory entries"));
        let _ = fs::remove_dir_all(&root);
    }
}
