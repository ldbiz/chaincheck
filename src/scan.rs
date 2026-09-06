//! Scan scope, detector merge, semantic result, and normal-scan exit.

use std::path::{Path, PathBuf};

use crate::campaign::{
    CampaignIntelligence, discover_campaign_with_progress, scan_campaign_artifacts,
};
use crate::campaign::{DET_CREDENTIALS, DET_DNS_CACHE, DET_GIT_HISTORY, DET_HOSTS_FILE};
use crate::cli::ProcessConfig;
use crate::coverage::DetectorCoverage;
use crate::credentials::credential_inventory;
use crate::evidence::{Finding, PackageEvidence};
use crate::git::{scan_git_with_probe, system_git};
use crate::host::{scan_dns_cache_with_probe, scan_hosts_file, system_resolvectl};
use crate::intelligence::IntelligenceSnapshot;
use crate::model::Severity;
use crate::npm::{apply_npm_corroboration, discover_npm_with_progress, scan_npm_artifacts};
use crate::progress::{MSG_SCAN, NoProgress, ScanProgress};
use crate::python::{
    apply_pypi_corroboration, discover_python_with_progress, scan_python_artifacts,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanScope {
    WholeUser { home: PathBuf },
    ExplicitRoot { root: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectorOutput {
    pub findings: Vec<Finding>,
    pub package_evidence: Vec<PackageEvidence>,
    pub coverage: DetectorCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct MergedOutputs {
    pub findings: Vec<Finding>,
    pub package_evidence: Vec<PackageEvidence>,
    pub coverage: Vec<DetectorCoverage>,
}

pub fn merge_outputs(outputs: impl IntoIterator<Item = DetectorOutput>) -> MergedOutputs {
    let mut merged = MergedOutputs::default();
    for output in outputs {
        merged.findings.extend(output.findings);
        merged.package_evidence.extend(output.package_evidence);
        merged.coverage.push(output.coverage);
    }
    merged
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanOutcome {
    Clean,
    MediumEvidence,
    StrongEvidence,
    IncompleteIntelligence,
}

pub fn scan_outcome(findings: &[Finding], intelligence: &IntelligenceSnapshot) -> ScanOutcome {
    let mut strong = false;
    let mut medium = false;
    for finding in findings {
        match finding.severity {
            Severity::Confirmed | Severity::High => strong = true,
            Severity::Medium => medium = true,
            Severity::Exposure | Severity::Info => {}
        }
    }
    if strong {
        ScanOutcome::StrongEvidence
    } else if medium {
        ScanOutcome::MediumEvidence
    } else if !intelligence.required_generic_available() {
        ScanOutcome::IncompleteIntelligence
    } else {
        ScanOutcome::Clean
    }
}

/// Normal scan exits only: 2 → 1 → 4 → 0. Not usage (64), start (3), or self-test.
pub fn normal_scan_exit(outcome: ScanOutcome) -> i32 {
    match outcome {
        ScanOutcome::StrongEvidence => 2,
        ScanOutcome::MediumEvidence => 1,
        ScanOutcome::IncompleteIntelligence => 4,
        ScanOutcome::Clean => 0,
    }
}

/// Semantic scan result for later reporting. Not a rendered report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanResult {
    pub scope: ScanScope,
    pub outcome: ScanOutcome,
    pub intelligence: IntelligenceSnapshot,
    pub findings: Vec<Finding>,
    pub package_evidence: Vec<PackageEvidence>,
    pub coverage: Vec<DetectorCoverage>,
}

impl ScanResult {
    pub fn from_merged(
        scope: ScanScope,
        merged: MergedOutputs,
        intelligence: IntelligenceSnapshot,
    ) -> Self {
        let outcome = scan_outcome(&merged.findings, &intelligence);
        let mut coverage = merged.coverage;
        coverage.extend(intelligence.coverage.clone());
        Self {
            scope,
            outcome,
            intelligence,
            findings: merged.findings,
            package_evidence: merged.package_evidence,
            coverage,
        }
    }
}

/// Host-level detector outputs supplied to scan orchestration.
///
/// Production [`scan`] wires live `/etc/hosts`, Git, `resolvectl`, and process
/// environment. Tests pass synthetic outputs so they never inspect this
/// machine's DNS cache or environment.
pub struct HostDetectorOutputs {
    pub git: DetectorOutput,
    pub hosts: DetectorOutput,
    pub dns: DetectorOutput,
    pub credentials: DetectorOutput,
}

impl HostDetectorOutputs {
    /// Skipped host detectors. Self-test and injected-intel tests must use this
    /// (via [`scan_with_host_outputs`]) instead of inspecting the live host.
    pub fn skipped() -> Self {
        let silent = |detector: crate::coverage::DetectorId| DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::skipped(detector),
        };
        Self {
            git: silent(DET_GIT_HISTORY),
            hosts: silent(DET_HOSTS_FILE),
            dns: silent(DET_DNS_CACHE),
            credentials: silent(DET_CREDENTIALS),
        }
    }
}

/// Full library scan: generic npm plus campaign and host detectors.
///
/// Campaign findings are merged after npm detectors and do not enter package
/// corroboration.
pub fn scan(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
    campaign: &CampaignIntelligence,
) -> ScanResult {
    scan_with_progress(scope, config, home, intelligence, campaign, &NoProgress)
}

/// Same as [`scan`], reporting filesystem-walk progress to `progress`.
pub fn scan_with_progress(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
    campaign: &CampaignIntelligence,
    progress: &dyn ScanProgress,
) -> ScanResult {
    let (npm_artifacts, python_artifacts, campaign_artifacts) =
        discover_artifacts(&scope, config, home, progress);
    let host = HostDetectorOutputs {
        git: scan_git_with_probe(&campaign_artifacts.git_repos, system_git()),
        hosts: scan_hosts_file(Path::new("/etc/hosts")),
        dns: scan_dns_cache_with_probe(system_resolvectl()),
        credentials: credential_inventory(home, std::env::vars_os()),
    };
    complete_scan(
        scope,
        npm_artifacts,
        python_artifacts,
        campaign_artifacts,
        intelligence,
        campaign,
        host,
    )
}

/// Same orchestration as [`scan`], with caller-supplied host detector outputs.
pub fn scan_with_host_outputs(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
    campaign: &CampaignIntelligence,
    host: HostDetectorOutputs,
) -> ScanResult {
    scan_with_host_outputs_progress(
        scope,
        config,
        home,
        intelligence,
        campaign,
        host,
        &NoProgress,
    )
}

pub(crate) fn scan_with_host_outputs_progress(
    scope: ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    intelligence: IntelligenceSnapshot,
    campaign: &CampaignIntelligence,
    host: HostDetectorOutputs,
    progress: &dyn ScanProgress,
) -> ScanResult {
    let (npm_artifacts, python_artifacts, campaign_artifacts) =
        discover_artifacts(&scope, config, home, progress);
    complete_scan(
        scope,
        npm_artifacts,
        python_artifacts,
        campaign_artifacts,
        intelligence,
        campaign,
        host,
    )
}

fn discover_artifacts(
    scope: &ScanScope,
    config: &ProcessConfig,
    home: Option<&Path>,
    progress: &dyn ScanProgress,
) -> (
    crate::npm::NpmArtifacts,
    crate::python::PythonArtifacts,
    crate::campaign::CampaignArtifacts,
) {
    progress.set_message(MSG_SCAN);
    (
        discover_npm_with_progress(scope, config, home, progress),
        discover_python_with_progress(scope, config, home, progress),
        discover_campaign_with_progress(scope, config, home, progress),
    )
}

fn complete_scan(
    scope: ScanScope,
    npm_artifacts: crate::npm::NpmArtifacts,
    python_artifacts: crate::python::PythonArtifacts,
    campaign_artifacts: crate::campaign::CampaignArtifacts,
    intelligence: IntelligenceSnapshot,
    campaign: &CampaignIntelligence,
    host: HostDetectorOutputs,
) -> ScanResult {
    let mut outputs = scan_npm_artifacts(&npm_artifacts, &intelligence.npm);
    outputs.push(DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: npm_artifacts.walk_coverage,
    });
    outputs.extend(scan_python_artifacts(&python_artifacts, &intelligence.pypi));
    outputs.push(DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage: python_artifacts.walk_coverage,
    });
    outputs.extend(scan_campaign_artifacts(&campaign_artifacts, campaign));
    outputs.push(host.git);
    outputs.push(host.hosts);
    outputs.push(host.dns);
    outputs.push(host.credentials);
    let mut merged = merge_outputs(outputs);
    apply_npm_corroboration(
        &mut merged.findings,
        &merged.package_evidence,
        &intelligence.npm,
    );
    apply_pypi_corroboration(
        &mut merged.findings,
        &merged.package_evidence,
        &intelligence.pypi,
    );
    ScanResult::from_merged(scope, merged, intelligence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{ArtifactStatus, CoverageStatus, DetectorCoverage, DetectorId};
    use crate::evidence::{EvidenceClass, Finding, PackageEvidence};
    use crate::intelligence::{
        DET_NPM_INTELLIGENCE, DET_PYPI_INTELLIGENCE, EcosystemIntelligence, FeedFailure,
        IntelligenceSnapshot, parse_malware_feed,
    };
    use crate::model::Ecosystem;
    use crate::model::{
        EvidenceKind, FindingCode, FindingSubject, PackageIdentity, PackageKey, PackageVersion,
        Severity,
    };
    use std::path::PathBuf;

    const TINY_NPM: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;
    const TINY_PYPI: &[u8] = br#"[{"package_name":"t","version":"1","reason":"MALWARE"}]"#;

    fn snapshot(npm_ok: bool, pypi_ok: bool) -> IntelligenceSnapshot {
        IntelligenceSnapshot::new(
            if npm_ok {
                EcosystemIntelligence::Available(
                    parse_malware_feed(TINY_NPM, Ecosystem::Npm).unwrap(),
                )
            } else {
                EcosystemIntelligence::Unavailable(FeedFailure::Network)
            },
            if pypi_ok {
                EcosystemIntelligence::Available(
                    parse_malware_feed(TINY_PYPI, Ecosystem::Pypi).unwrap(),
                )
            } else {
                EcosystemIntelligence::Unavailable(FeedFailure::Timeout)
            },
        )
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            severity,
            kind: EvidenceKind::Context,
            code: FindingCode::from_static("test"),
            subject: FindingSubject::Unspecified,
            location: None,
            detail: String::new(),
            intelligence_source: None,
        }
    }

    fn package_finding(severity: Severity, kind: EvidenceKind, name: &str) -> Finding {
        Finding {
            severity,
            kind,
            code: FindingCode::from_static("test"),
            subject: FindingSubject::PackageExact(PackageKey::new(
                PackageIdentity::new(Ecosystem::Npm, name),
                PackageVersion::exact("1.0.0"),
            )),
            location: None,
            detail: String::new(),
            intelligence_source: None,
        }
    }

    #[test]
    fn exit_precedence_table() {
        let both = snapshot(true, true);
        let cases = [
            (Severity::High, 2),
            (Severity::Confirmed, 2),
            (Severity::Medium, 1),
            (Severity::Info, 0),
            (Severity::Exposure, 0),
        ];
        for (severity, want) in cases {
            let outcome = scan_outcome(&[finding(severity)], &both);
            assert_eq!(normal_scan_exit(outcome), want, "{severity:?}");
        }
        assert_eq!(normal_scan_exit(scan_outcome(&[], &both)), 0);
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::High)],
                &snapshot(true, false)
            )),
            2
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Medium)],
                &snapshot(false, true)
            )),
            1
        );
    }

    #[test]
    fn exit_four_when_any_required_feed_unavailable_without_evidence() {
        assert_eq!(
            normal_scan_exit(scan_outcome(&[], &snapshot(true, false))),
            4
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(&[], &snapshot(false, true))),
            4
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(&[], &snapshot(false, false))),
            4
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Info)],
                &snapshot(true, false)
            )),
            4
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Exposure)],
                &snapshot(false, true)
            )),
            4
        );
    }

    #[test]
    fn findings_beat_unavailable_intelligence() {
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Medium)],
                &snapshot(true, false)
            )),
            1
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::High)],
                &snapshot(false, true)
            )),
            2
        );
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Confirmed)],
                &snapshot(false, false)
            )),
            2
        );
    }

    #[test]
    fn info_only_does_not_override_unavailable_intel() {
        assert_eq!(
            normal_scan_exit(scan_outcome(
                &[finding(Severity::Info)],
                &snapshot(false, false)
            )),
            4
        );
    }

    #[test]
    fn merge_concatenates_collections() {
        let det_a = DetectorId::from_static("a");
        let det_b = DetectorId::from_static("b");
        let key = PackageKey::new(
            PackageIdentity::new(Ecosystem::Npm, "keyv"),
            PackageVersion::exact("6.0.0"),
        );
        let a = DetectorOutput {
            findings: vec![finding(Severity::Medium)],
            package_evidence: vec![PackageEvidence {
                package: key.clone(),
                class: EvidenceClass::Lockfile,
                location: PathBuf::from("/tmp/lock"),
                detector: det_a,
            }],
            coverage: DetectorCoverage::attempted(det_a),
        };
        let b = DetectorOutput {
            findings: vec![package_finding(
                Severity::High,
                EvidenceKind::InstalledPackage,
                "keyv",
            )],
            package_evidence: vec![PackageEvidence {
                package: key,
                class: EvidenceClass::Installed,
                location: PathBuf::from("/tmp/installed"),
                detector: det_b,
            }],
            coverage: DetectorCoverage::attempted(det_b),
        };
        let merged = merge_outputs([a, b]);
        assert_eq!(merged.findings.len(), 2);
        assert_eq!(merged.package_evidence.len(), 2);
        assert_eq!(merged.coverage.len(), 2);
    }

    #[test]
    fn coverage_only_result_does_not_invent_findings() {
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("lockfile"));
        coverage.record_artifact(PathBuf::from("/tmp/bad"), ArtifactStatus::ParseFailed);
        let merged = merge_outputs([DetectorOutput {
            findings: vec![],
            package_evidence: vec![],
            coverage,
        }]);
        let result = ScanResult::from_merged(
            ScanScope::WholeUser {
                home: PathBuf::from("/home/user"),
            },
            merged,
            snapshot(true, true),
        );
        assert!(result.findings.is_empty());
        assert_eq!(result.outcome, ScanOutcome::Clean);
        assert_eq!(normal_scan_exit(result.outcome), 0);
        assert_eq!(result.coverage[0].status(), CoverageStatus::Partial);

        let incomplete = ScanResult::from_merged(
            ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/project"),
            },
            MergedOutputs {
                coverage: result.coverage.clone(),
                ..MergedOutputs::default()
            },
            snapshot(true, false),
        );
        assert!(incomplete.findings.is_empty());
        assert_eq!(normal_scan_exit(incomplete.outcome), 4);
    }

    #[test]
    fn intelligence_coverage_is_merged_into_result() {
        let merged = MergedOutputs::default();
        let mut snap = snapshot(true, true);
        snap.coverage = vec![
            DetectorCoverage::attempted(DET_NPM_INTELLIGENCE),
            DetectorCoverage::attempted(DET_PYPI_INTELLIGENCE),
        ];
        let result = ScanResult::from_merged(
            ScanScope::WholeUser {
                home: PathBuf::from("/home/user"),
            },
            merged,
            snap,
        );
        assert_eq!(result.coverage.len(), 2);
        assert_eq!(result.coverage[0].detector(), DET_NPM_INTELLIGENCE);
        assert_eq!(result.coverage[1].detector(), DET_PYPI_INTELLIGENCE);
    }

    #[test]
    fn scope_variants_preserve_requested_path() {
        let home = PathBuf::from("/home/user");
        let root = PathBuf::from("/tmp/project");
        match (ScanScope::WholeUser { home: home.clone() }) {
            ScanScope::WholeUser { home: stored } => assert_eq!(stored, home),
            ScanScope::ExplicitRoot { .. } => panic!("lost WholeUser"),
        }
        match (ScanScope::ExplicitRoot { root: root.clone() }) {
            ScanScope::ExplicitRoot { root: stored } => assert_eq!(stored, root),
            ScanScope::WholeUser { .. } => panic!("lost ExplicitRoot"),
        }
    }

    #[test]
    fn explicit_root_merges_supplied_host_outputs() {
        use crate::campaign::{
            CampaignIntelligence, DET_CREDENTIALS, DET_DNS_CACHE, DET_GIT_HISTORY, DET_HOSTS_FILE,
        };
        use crate::cli::ProcessConfig;
        use std::fs;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static UNIQUE: AtomicU64 = AtomicU64::new(0);
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "chaincheck-scan-host-{}-{nanos}-{n}",
            std::process::id()
        ));
        let project = base.join("project");
        let home = base.join("home");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::write(project.join("README"), b"ok").unwrap();
        fs::write(home.join("setup.mjs"), b"console.log(1);\n").unwrap();

        let silent = |detector: DetectorId| DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::skipped(detector),
        };
        let result = scan_with_host_outputs(
            ScanScope::ExplicitRoot { root: project },
            &ProcessConfig::default(),
            Some(&home),
            snapshot(true, true),
            &CampaignIntelligence::bundled(),
            HostDetectorOutputs {
                git: silent(DET_GIT_HISTORY),
                hosts: silent(DET_HOSTS_FILE),
                dns: silent(DET_DNS_CACHE),
                credentials: silent(DET_CREDENTIALS),
            },
        );
        let names: Vec<_> = result
            .coverage
            .iter()
            .map(|c| c.detector().as_str())
            .collect();
        assert!(names.contains(&"hosts-file"), "{names:?}");
        assert!(names.contains(&"dns-cache"), "{names:?}");
        assert!(names.contains(&"credentials"), "{names:?}");
        assert!(names.contains(&"git-history"), "{names:?}");
        assert!(
            result
                .findings
                .iter()
                .all(|f| f.code.as_str() != "payload-name"),
            "{:?}",
            result.findings
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_walk_ticks_progress_and_sets_scanning_message() {
        use crate::campaign::{
            CampaignIntelligence, DET_CREDENTIALS, DET_DNS_CACHE, DET_GIT_HISTORY, DET_HOSTS_FILE,
        };
        use crate::cli::ProcessConfig;
        use crate::progress::{MSG_SCAN, TickCount};
        use std::fs;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static UNIQUE: AtomicU64 = AtomicU64::new(0);
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "chaincheck-scan-progress-{}-{nanos}-{n}",
            std::process::id()
        ));
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("README"), b"ok").unwrap();
        fs::write(project.join("package.json"), b"{}\n").unwrap();

        let silent = |detector: DetectorId| DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::skipped(detector),
        };
        let progress = TickCount::new();
        let result = scan_with_host_outputs_progress(
            ScanScope::ExplicitRoot { root: project },
            &ProcessConfig::default(),
            None,
            snapshot(true, true),
            &CampaignIntelligence::bundled(),
            HostDetectorOutputs {
                git: silent(DET_GIT_HISTORY),
                hosts: silent(DET_HOSTS_FILE),
                dns: silent(DET_DNS_CACHE),
                credentials: silent(DET_CREDENTIALS),
            },
            &progress,
        );
        assert_eq!(progress.messages(), [MSG_SCAN]);
        assert!(
            progress.tick_count() >= 2,
            "expected walk ticks, got {}",
            progress.tick_count()
        );
        assert_eq!(result.outcome, ScanOutcome::Clean);
        let _ = fs::remove_dir_all(&base);
    }
}
