//! Python/PyPI retrospective detectors.

pub mod discover;
pub mod installed;
pub mod lockfile;
pub mod pipfile;
pub mod pyproject;
pub mod requirements;
pub mod setup_cfg;
mod spec;
pub mod wheel_cache;

use std::path::{Path, PathBuf};

pub(crate) use discover::discover_python_with_progress;
pub use discover::{
    PythonArtifacts, PythonHostLayout, discover_python, discover_python_with_layout,
    python_keep_file,
};
pub use wheel_cache::scan_pip_wheel_cache;

use crate::cli::ProcessConfig;
use crate::coverage::{ArtifactStatus, DetectorCoverage, DetectorId};
use crate::evidence::{EvidenceClass, Finding, PackageEvidence, apply_ecosystem_corroboration};
use crate::intelligence::{EcosystemIntelligence, IntelligenceSnapshot, MalwareMatch};
use crate::model::{
    EvidenceKind, FindingCode, FindingSubject, IntelligenceSourceId, PackageIdentity, PackageKey,
    PackageVersion, Severity,
};
use crate::scan::{DetectorOutput, ScanResult, ScanScope, merge_outputs};

pub const DET_DISCOVERY: DetectorId = DetectorId::from_static("python-discovery");
pub const DET_INSTALLED: DetectorId = DetectorId::from_static("python-installed");
pub const DET_REQUIREMENTS: DetectorId = DetectorId::from_static("python-requirements");
pub const DET_PYPROJECT: DetectorId = DetectorId::from_static("python-pyproject");
pub const DET_PIPFILE: DetectorId = DetectorId::from_static("python-pipfile");
pub const DET_SETUP_CFG: DetectorId = DetectorId::from_static("python-setup-cfg");
pub const DET_PYLOCK: DetectorId = DetectorId::from_static("python-pylock");
pub const DET_UV_LOCK: DetectorId = DetectorId::from_static("python-uv-lock");
pub const DET_POETRY_LOCK: DetectorId = DetectorId::from_static("python-poetry-lock");
pub const DET_PIPFILE_LOCK: DetectorId = DetectorId::from_static("python-pipfile-lock");
pub const DET_PDM_LOCK: DetectorId = DetectorId::from_static("python-pdm-lock");
pub const DET_PIP_WHEEL_CACHE: DetectorId = DetectorId::from_static("python-pip-wheel-cache");

pub const CODE_INSTALLED: FindingCode = FindingCode::from_static("installed-package");
pub const CODE_MANIFEST_DEPENDENCY: FindingCode = FindingCode::from_static("manifest-dependency");
pub const CODE_LOCKFILE_PACKAGE: FindingCode = FindingCode::from_static("lockfile-package");
pub const CODE_PIP_WHEEL_CACHE: FindingCode = FindingCode::from_static("pip-wheel-cache");

pub const LIMIT_METADATA: u64 = 1_000_000;
pub const LIMIT_REQUIREMENTS: u64 = 10_000_000;
pub const LIMIT_PYPROJECT: u64 = 10_000_000;
pub const LIMIT_PIPFILE: u64 = 10_000_000;
pub const LIMIT_SETUP_CFG: u64 = 5_000_000;
pub const LIMIT_LOCKFILE: u64 = 100_000_000;
pub const INCLUDE_MAX_DEPTH: usize = 8;
pub const INCLUDE_MAX_FILES: usize = 32;
pub const PEP735_MAX_DEPTH: usize = 8;
pub const DIST_INFO_CAP: u32 = 50_000;
pub const WHEEL_FILE_CAP: u32 = 50_000;

pub struct FileScan {
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

pub fn scan_python(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
) -> ScanResult {
    let artifacts = discover_python(&scope, config, home);
    let mut outputs = scan_python_artifacts(&artifacts, &intelligence.pypi);
    outputs.push(DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: artifacts.walk_coverage,
    });
    let mut merged = merge_outputs(outputs);
    apply_pypi_corroboration(
        &mut merged.findings,
        &merged.package_evidence,
        &intelligence.pypi,
    );
    ScanResult::from_merged(scope, merged, intelligence)
}

pub fn scan_python_artifacts(
    artifacts: &PythonArtifacts,
    intel: &EcosystemIntelligence,
) -> Vec<DetectorOutput> {
    vec![
        scan_metadata_files(&artifacts.metadata, intel),
        scan_requirements_detector(&artifacts.requirements, intel, &artifacts.include_roots),
        scan_files(
            &artifacts.pyprojects,
            intel,
            DET_PYPROJECT,
            pyproject::scan_pyproject,
        ),
        scan_files(
            &artifacts.pipfiles,
            intel,
            DET_PIPFILE,
            pipfile::scan_pipfile,
        ),
        scan_files(
            &artifacts.setup_cfgs,
            intel,
            DET_SETUP_CFG,
            setup_cfg::scan_setup_cfg,
        ),
        scan_files(
            &artifacts.pylock_tomls,
            intel,
            DET_PYLOCK,
            lockfile::scan_pylock,
        ),
        scan_files(
            &artifacts.uv_locks,
            intel,
            DET_UV_LOCK,
            lockfile::scan_uv_lock,
        ),
        scan_files(
            &artifacts.poetry_locks,
            intel,
            DET_POETRY_LOCK,
            lockfile::scan_poetry_lock,
        ),
        scan_files(
            &artifacts.pipfile_locks,
            intel,
            DET_PIPFILE_LOCK,
            lockfile::scan_pipfile_lock,
        ),
        scan_files(
            &artifacts.pdm_locks,
            intel,
            DET_PDM_LOCK,
            lockfile::scan_pdm_lock,
        ),
        scan_discovered_wheel_cache(artifacts, intel),
    ]
}

pub fn apply_pypi_corroboration(
    findings: &mut Vec<Finding>,
    evidence: &[PackageEvidence],
    intel: &EcosystemIntelligence,
) {
    apply_ecosystem_corroboration(findings, evidence, intel);
}

fn scan_metadata_files(paths: &[PathBuf], intel: &EcosystemIntelligence) -> DetectorOutput {
    scan_files(paths, intel, DET_INSTALLED, installed::scan_metadata)
}

fn scan_requirements_detector(
    paths: &[PathBuf],
    intel: &EcosystemIntelligence,
    include_roots: &[PathBuf],
) -> DetectorOutput {
    if paths.is_empty() {
        return skipped(DET_REQUIREMENTS);
    }
    let mut findings = Vec::new();
    let mut package_evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_REQUIREMENTS);
    let scans = requirements::scan_requirements_files(paths, intel, include_roots);
    for (path, result) in scans {
        coverage.record_artifact(path, result.status);
        findings.extend(result.findings);
        package_evidence.extend(result.evidence);
    }
    DetectorOutput {
        findings,
        package_evidence,
        coverage,
    }
}

fn scan_discovered_wheel_cache(
    artifacts: &PythonArtifacts,
    intel: &EcosystemIntelligence,
) -> DetectorOutput {
    if artifacts.pip_wheel_roots.is_empty() && artifacts.pip_wheel_root_failures.is_empty() {
        return skipped(DET_PIP_WHEEL_CACHE);
    }
    let mut output = if artifacts.pip_wheel_roots.is_empty() {
        DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::attempted(DET_PIP_WHEEL_CACHE),
        }
    } else {
        scan_pip_wheel_cache(&artifacts.pip_wheel_roots, intel)
    };
    for (path, status) in &artifacts.pip_wheel_root_failures {
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
    if paths.is_empty() {
        return skipped(id);
    }
    let mut findings = Vec::new();
    let mut package_evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(id);
    for path in paths {
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

fn skipped(id: DetectorId) -> DetectorOutput {
    DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: DetectorCoverage::skipped(id),
    }
}

pub(crate) fn emit_exact_installed(
    intel: &EcosystemIntelligence,
    name: &str,
    version: &str,
    location: &Path,
    detector: DetectorId,
    kind: EvidenceKind,
    code: FindingCode,
    severity: Severity,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<PackageEvidence>,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let identity = PackageIdentity::pypi(name);
    let pkg_version = PackageVersion::exact(version);
    match intel.lookup(&identity, Some(&pkg_version)) {
        Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
            let key = PackageKey::new(identity, pkg_version);
            evidence.push(PackageEvidence {
                package: key.clone(),
                class: EvidenceClass::Installed,
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
                intelligence_source: Some(IntelligenceSourceId::PypiMalware),
            });
        }
        Ok(None) | Err(_) => {}
    }
}

pub(crate) fn emit_resolution(
    intel: &EcosystemIntelligence,
    name: &str,
    version: &str,
    location: &Path,
    detector: DetectorId,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<PackageEvidence>,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let identity = PackageIdentity::pypi(name);
    let pkg_version = PackageVersion::exact(version);
    match intel.lookup(&identity, Some(&pkg_version)) {
        Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
            let key = PackageKey::new(identity, pkg_version);
            evidence.push(PackageEvidence {
                package: key.clone(),
                class: EvidenceClass::Lockfile,
                location: location.to_path_buf(),
                detector,
            });
            findings.push(Finding {
                severity: Severity::Medium,
                kind: EvidenceKind::DependencyResolution,
                code: CODE_LOCKFILE_PACKAGE,
                subject: FindingSubject::PackageExact(key),
                location: Some(location.to_path_buf()),
                detail: String::new(),
                intelligence_source: Some(IntelligenceSourceId::PypiMalware),
            });
        }
        Ok(None) | Err(_) => {}
    }
}

pub(crate) fn emit_wheel_cache(
    intel: &EcosystemIntelligence,
    name: &str,
    version: &str,
    location: &Path,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<PackageEvidence>,
) {
    if name.is_empty() || version.is_empty() {
        return;
    }
    let identity = PackageIdentity::pypi(name);
    let pkg_version = PackageVersion::exact(version);
    match intel.lookup(&identity, Some(&pkg_version)) {
        Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
            let key = PackageKey::new(identity, pkg_version);
            evidence.push(PackageEvidence {
                package: key.clone(),
                class: EvidenceClass::Cache,
                location: location.to_path_buf(),
                detector: DET_PIP_WHEEL_CACHE,
            });
            findings.push(Finding {
                severity: Severity::Medium,
                kind: EvidenceKind::PackageCache,
                code: CODE_PIP_WHEEL_CACHE,
                subject: FindingSubject::PackageExact(key),
                location: Some(location.to_path_buf()),
                detail: String::new(),
                intelligence_source: Some(IntelligenceSourceId::PypiMalware),
            });
        }
        Ok(None) | Err(_) => {}
    }
}

pub(crate) fn emit_declaration(
    intel: &EcosystemIntelligence,
    name: &str,
    exact_version: Option<&str>,
    location: &Path,
    detector: DetectorId,
    findings: &mut Vec<Finding>,
    evidence: &mut Vec<PackageEvidence>,
) {
    let name = spec::base_distribution_name(name);
    if name.is_empty() || !spec::is_valid_distribution_name(name) {
        return;
    }
    let identity = PackageIdentity::pypi(name);
    if let Some(version) = exact_version {
        if version.is_empty() {
            return;
        }
        let pkg_version = PackageVersion::exact(version);
        match intel.lookup(&identity, Some(&pkg_version)) {
            Ok(Some(MalwareMatch::Exact | MalwareMatch::Wildcard)) => {
                let key = PackageKey::new(identity, pkg_version);
                evidence.push(PackageEvidence {
                    package: key.clone(),
                    class: EvidenceClass::Manifest,
                    location: location.to_path_buf(),
                    detector,
                });
                findings.push(Finding {
                    severity: Severity::Medium,
                    kind: EvidenceKind::DependencyDeclaration,
                    code: CODE_MANIFEST_DEPENDENCY,
                    subject: FindingSubject::PackageExact(key),
                    location: Some(location.to_path_buf()),
                    detail: String::new(),
                    intelligence_source: Some(IntelligenceSourceId::PypiMalware),
                });
            }
            Ok(None) | Err(_) => {}
        }
    } else {
        match intel.lookup(&identity, None) {
            Ok(Some(MalwareMatch::Wildcard)) => {
                findings.push(Finding {
                    severity: Severity::Medium,
                    kind: EvidenceKind::DependencyDeclaration,
                    code: CODE_MANIFEST_DEPENDENCY,
                    subject: FindingSubject::PackageIdentity(identity),
                    location: Some(location.to_path_buf()),
                    detail: String::new(),
                    intelligence_source: Some(IntelligenceSourceId::PypiMalware),
                });
            }
            Ok(Some(MalwareMatch::Exact)) | Ok(None) | Err(_) => {}
        }
    }
}
