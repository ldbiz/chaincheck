//! Generic npm retrospective detectors.
//!
//! Payload, IDE, Git, and host campaign stages live in [`crate::campaign`] and
//! are orchestrated by [`crate::scan::scan`]. [`scan_npm`] remains the
//! generic-only library path. Inspected `package.json` and npm logs may still
//! emit campaign codes from those artefacts.

mod cache;
mod discover;
mod lockfile;
mod logs;
mod manifest;

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::cli::ProcessConfig;
use crate::coverage::{ArtifactStatus, DetectorCoverage, DetectorId};
use crate::evidence::{EvidenceClass, Finding, PackageEvidence, apply_ecosystem_corroboration};
use crate::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, MalwareMatch};
use crate::model::{
    EvidenceKind, FindingCode, FindingSubject, IntelligenceSourceId, PackageIdentity, PackageKey,
    PackageVersion, Severity,
};
use crate::progress::{NoProgress, Progress};
use crate::scan::{DetectorOutput, ScanResult, ScanScope, merge_outputs};

pub use cache::scan_npm_cache;
pub(crate) use discover::{count_npm_walk_entries, discover_npm_with_progress, npm_host_cache_index_roots};
pub use discover::{NpmArtifacts, PackageRoots, discover_npm, npm_package_roots, npm_prune_dir};
pub use logs::{scan_npm_logs, scan_npm_logs_with_progress};

pub const DET_MANIFEST: DetectorId = DetectorId::from_static("manifest");
pub const DET_NPM_LOCKFILE: DetectorId = DetectorId::from_static("npm-lockfile");
pub const DET_YARN_LOCKFILE: DetectorId = DetectorId::from_static("yarn-lockfile");
pub const DET_PNPM_LOCKFILE: DetectorId = DetectorId::from_static("pnpm-lockfile");
pub const DET_TEXT_LOCKFILE: DetectorId = DetectorId::from_static("text-lockfile");
pub const DET_BUN_LOCKB: DetectorId = DetectorId::from_static("bun-lockb");
pub const DET_NPM_LOGS: DetectorId = DetectorId::from_static("npm-logs");
pub const DET_NPM_CACHE: DetectorId = DetectorId::from_static("npm-cache");

pub const CODE_INSTALLED: FindingCode = FindingCode::from_static("installed-package");
pub const CODE_MANIFEST_PACKAGE: FindingCode = FindingCode::from_static("manifest-package");
pub const CODE_MANIFEST_DEPENDENCY: FindingCode = FindingCode::from_static("manifest-dependency");
pub const CODE_LOCKFILE_PACKAGE: FindingCode = FindingCode::from_static("lockfile-package");
pub const CODE_LOCKFILE_TEXT_MATCH: FindingCode = FindingCode::from_static("lockfile-text-match");
pub const CODE_NPM_CACHE: FindingCode = FindingCode::from_static("npm-cache-download");
pub const CODE_NPM_INSTALL_LOG: FindingCode = FindingCode::from_static("npm-install-log");

pub const LIMIT_PACKAGE_LOCK: u64 = 200_000_000;
pub const LIMIT_YARN_PNPM_BUN: u64 = 100_000_000;
pub const LIMIT_PACKAGE_JSON: u64 = 10_000_000;
pub const LIMIT_NPM_LOG: u64 = 30_000_000;
pub const LIMIT_CACHE_ENTRY: u64 = 4_000_000;
pub const CACHE_FILE_CAP: u32 = 200_000;

static SPEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)@([0-9][0-9A-Za-z.+_-]*)")
        .expect("SPEC_RE")
});

static TARBALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"/((?:@[^/\s"']+/)?[^/\s"']+)/-/([^/\s"']+)\.tgz"#).expect("TARBALL_RE")
});

const SPEC_PREV: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.@/-";

pub(crate) struct FileScan {
    pub status: ArtifactStatus,
    pub findings: Vec<Finding>,
    pub evidence: Vec<PackageEvidence>,
}

impl FileScan {
    pub(crate) fn failed(status: ArtifactStatus) -> Self {
        Self {
            status,
            findings: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// Run generic npm discovery, detectors, and corroboration.
///
/// Payload/IDE/Git/host campaign stages are not included. Inspected npm
/// manifests and logs may still emit campaign codes for those artefacts.
pub fn scan_npm(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
) -> ScanResult {
    let artifacts = discover_npm(&scope, config, home);
    let mut outputs = scan_npm_artifacts(&artifacts, &intelligence.npm);
    outputs.push(DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: artifacts.walk_coverage,
    });
    let mut merged = merge_outputs(outputs);
    apply_npm_corroboration(
        &mut merged.findings,
        &merged.package_evidence,
        &intelligence.npm,
    );
    ScanResult::from_merged(scope, merged, intelligence)
}

pub fn scan_npm_artifacts(
    artifacts: &NpmArtifacts,
    intel: &EcosystemIntelligence,
) -> Vec<DetectorOutput> {
    scan_npm_artifacts_with_progress(artifacts, intel, &NoProgress)
}

pub fn scan_npm_artifacts_with_progress(
    artifacts: &NpmArtifacts,
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> Vec<DetectorOutput> {
    vec![
        scan_files_with_progress(
            &artifacts.manifests,
            intel,
            DET_MANIFEST,
            manifest::scan_manifest,
            progress,
        ),
        scan_files_with_progress(
            &artifacts.npm_locks,
            intel,
            DET_NPM_LOCKFILE,
            lockfile::scan_npm_lock,
            progress,
        ),
        scan_files_with_progress(
            &artifacts.yarn_locks,
            intel,
            DET_YARN_LOCKFILE,
            lockfile::scan_yarn_lock,
            progress,
        ),
        scan_files_with_progress(
            &artifacts.pnpm_locks,
            intel,
            DET_PNPM_LOCKFILE,
            lockfile::scan_pnpm_lock,
            progress,
        ),
        scan_files_with_progress(
            &artifacts.bun_locks,
            intel,
            DET_TEXT_LOCKFILE,
            lockfile::scan_bun_lock,
            progress,
        ),
        scan_bun_lockb_with_progress(&artifacts.bun_lockb, progress),
        scan_discovered_logs_with_progress(artifacts, intel, progress),
        scan_discovered_cache_with_progress(artifacts, intel, progress),
    ]
}

/// Scan one named artefact kind. Used by compatibility tests.
pub fn scan_artefact(
    artefact_type: &str,
    path: &Path,
    intel: &EcosystemIntelligence,
) -> Result<DetectorOutput, String> {
    Ok(match artefact_type {
        "package-lock" | "package-lock.json" | "npm-shrinkwrap" => scan_files(
            &[path.to_path_buf()],
            intel,
            DET_NPM_LOCKFILE,
            lockfile::scan_npm_lock,
        ),
        "yarn-lock" => scan_files(
            &[path.to_path_buf()],
            intel,
            DET_YARN_LOCKFILE,
            lockfile::scan_yarn_lock,
        ),
        "pnpm-lock" => scan_files(
            &[path.to_path_buf()],
            intel,
            DET_PNPM_LOCKFILE,
            lockfile::scan_pnpm_lock,
        ),
        "bun-lock" => scan_files(
            &[path.to_path_buf()],
            intel,
            DET_TEXT_LOCKFILE,
            lockfile::scan_bun_lock,
        ),
        "package-json" => scan_files(
            &[path.to_path_buf()],
            intel,
            DET_MANIFEST,
            manifest::scan_manifest,
        ),
        "npm-log" => scan_npm_logs(&[path], intel),
        "npm-cache" => scan_npm_cache(&[path], intel),
        "bun-lockb" => lockfile::scan_bun_lockb(&[path.to_path_buf()]),
        other => return Err(format!("unsupported artefact_type for npm PR4: {other}")),
    })
}

fn scan_discovered_logs(
    artifacts: &discover::NpmArtifacts,
    intel: &EcosystemIntelligence,
) -> DetectorOutput {
    scan_discovered_logs_with_progress(artifacts, intel, &NoProgress)
}

fn scan_discovered_logs_with_progress(
    artifacts: &discover::NpmArtifacts,
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> DetectorOutput {
    if artifacts.logs.is_empty() && artifacts.log_dir_failures.is_empty() {
        return skipped(DET_NPM_LOGS);
    }
    let mut output = if artifacts.logs.is_empty() {
        DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::attempted(DET_NPM_LOGS),
        }
    } else {
        scan_npm_logs_with_progress(&artifacts.logs, intel, progress)
    };
    for (path, status) in &artifacts.log_dir_failures {
        output.coverage.record_artifact(path.clone(), *status);
    }
    output
}

fn scan_discovered_cache(
    artifacts: &discover::NpmArtifacts,
    intel: &EcosystemIntelligence,
) -> DetectorOutput {
    scan_discovered_cache_with_progress(artifacts, intel, &NoProgress)
}

fn scan_discovered_cache_with_progress(
    artifacts: &discover::NpmArtifacts,
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> DetectorOutput {
    if artifacts.cache_index_roots.is_empty() && artifacts.cache_root_failures.is_empty() {
        return skipped(DET_NPM_CACHE);
    }
    let mut output = if artifacts.cache_index_roots.is_empty() {
        DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::attempted(DET_NPM_CACHE),
        }
    } else {
        cache::scan_npm_cache_with_progress(&artifacts.cache_index_roots, intel, progress)
    };
    for (path, status) in &artifacts.cache_root_failures {
        output.coverage.record_artifact(path.clone(), *status);
    }
    output
}

fn scan_files(
    paths: &[PathBuf],
    intel: &EcosystemIntelligence,
    id: DetectorId,
    scan_one: fn(&Path, &EcosystemIntelligence) -> FileScan,
) -> DetectorOutput {
    scan_files_with_progress(paths, intel, id, scan_one, &NoProgress)
}

fn scan_files_with_progress(
    paths: &[PathBuf],
    intel: &EcosystemIntelligence,
    id: DetectorId,
    scan_one: fn(&Path, &EcosystemIntelligence) -> FileScan,
    progress: &dyn Progress,
) -> DetectorOutput {
    if paths.is_empty() {
        return skipped(id);
    }
    let mut findings = Vec::new();
    let mut package_evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(id);
    for path in paths {
        progress.tick();
        let result = scan_one(path, intel);
        coverage.record_artifact(path.clone(), result.status);
        findings.extend(result.findings);
        package_evidence.extend(result.evidence);
    }
    DetectorOutput {
        findings,
        package_evidence,
        coverage,
    }
}

fn scan_bun_lockb_with_progress(paths: &[PathBuf], progress: &dyn Progress) -> DetectorOutput {
    if paths.is_empty() {
        return skipped(DET_BUN_LOCKB);
    }
    for path in paths {
        progress.tick();
        let _ = path;
    }
    lockfile::scan_bun_lockb(paths)
}

pub(crate) fn skipped(id: DetectorId) -> DetectorOutput {
    DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: DetectorCoverage::skipped(id),
    }
}

pub fn apply_npm_corroboration(
    findings: &mut Vec<Finding>,
    evidence: &[PackageEvidence],
    intel: &EcosystemIntelligence,
) {
    apply_ecosystem_corroboration(findings, evidence, intel);
}

pub(crate) fn emit_exact(
    intel: &EcosystemIntelligence,
    name: &str,
    version: &str,
    location: &Path,
    detector: DetectorId,
    class: EvidenceClass,
    kind: EvidenceKind,
    code: FindingCode,
    severity: Severity,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<PackageEvidence>,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let identity = PackageIdentity::npm(name);
    let pkg_version = PackageVersion::exact(version);
    match intel.lookup(&identity, Some(&pkg_version)) {
        Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
            let key = PackageKey::new(identity, pkg_version);
            evidence.push(PackageEvidence {
                package: key.clone(),
                class,
                location: location.to_path_buf(),
                detector,
            });
            findings.push(Finding {
                severity,
                kind,
                code,
                subject: FindingSubject::PackageExact(key),
                location: Some(location.to_path_buf()),
                detail: String::new(),
                intelligence_source: Some(IntelligenceSourceId::NpmMalware),
            });
        }
        Ok(None) | Err(_) => {}
    }
}

pub(crate) fn emit_wildcard_identity(
    intel: &EcosystemIntelligence,
    name: &str,
    location: &Path,
    findings: &mut Vec<Finding>,
) {
    if name.is_empty() {
        return;
    }
    let identity = PackageIdentity::npm(name);
    match intel.lookup(&identity, None) {
        Ok(Some(MalwareMatch::Wildcard)) => {
            findings.push(Finding {
                severity: Severity::Medium,
                kind: EvidenceKind::DependencyDeclaration,
                code: CODE_MANIFEST_DEPENDENCY,
                subject: FindingSubject::PackageIdentity(identity),
                location: Some(location.to_path_buf()),
                detail: String::new(),
                intelligence_source: Some(IntelligenceSourceId::NpmMalware),
            });
        }
        Ok(Some(MalwareMatch::Exact)) | Ok(None) | Err(_) => {}
    }
}

pub(crate) fn pairs_from_tarball_urls(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for cap in TARBALL_RE.captures_iter(text) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let filename = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let basename = name.rsplit('/').next().unwrap_or(name);
        let prefix = format!("{basename}-");
        if let Some(version) = filename.strip_prefix(&prefix) {
            if !version.is_empty() {
                found.push((name.to_owned(), version.to_owned()));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

pub(crate) fn pairs_from_spec_tokens(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for cap in SPEC_RE.captures_iter(text) {
        let whole = cap.get(0).expect("full match");
        if whole.start() > 0 {
            let prev = text[..whole.start()].chars().next_back().unwrap_or('\0');
            if SPEC_PREV.contains(prev) {
                continue;
            }
        }
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let version = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if !name.is_empty() && !version.is_empty() {
            found.push((name.to_owned(), version.to_owned()));
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Split a Yarn/Bun `name@version` (or `@scope/name@version`) descriptor.
pub(crate) fn split_name_version(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim().trim_matches(|c| c == '"' || c == '\'');
    if spec.is_empty() {
        return None;
    }
    if spec.starts_with('@') {
        let slash = spec.find('/')?;
        let at = spec[slash + 1..].find('@')?;
        let split = slash + 1 + at;
        let name = &spec[..split];
        let version = spec[split + 1..].to_owned();
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_owned(), version))
    } else {
        let at = spec.find('@')?;
        if at == 0 {
            return None;
        }
        let name = &spec[..at];
        let version = &spec[at + 1..];
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_owned(), version.to_owned()))
    }
}

pub(crate) fn yarn_name(spec: &str) -> Option<String> {
    let spec = spec.trim().trim_matches(|c| c == '"' || c == '\'');
    if spec.starts_with('@') {
        let slash = spec.find('/')?;
        match spec[slash + 1..].find('@') {
            Some(at) => Some(spec[..slash + 1 + at].to_owned()),
            None => Some(spec.to_owned()),
        }
    } else if let Some(at) = spec.find('@') {
        Some(spec[..at].to_owned())
    } else if spec.is_empty() {
        None
    } else {
        Some(spec.to_owned())
    }
}

pub(crate) fn exact_version_token(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some('0'..='9') => {
            chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'))
        }
        _ => false,
    }
}
