//! Semantic `ScanResult` rendered to `summary.txt`, `findings.tsv`, and a bounded console.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::coverage::{ArtifactStatus, CoverageStatus, DetectorCoverage};
use crate::error::StartError;
use crate::evidence::Finding;
use crate::intelligence::{EcosystemIntelligence, FeedFailure, FeedState};
use crate::model::{Ecosystem, Severity};
use crate::scan::{ScanOutcome, ScanResult, ScanScope};

pub const PRIVACY_WARNING: &str =
    "Reports contain local filesystem paths. Review them before sharing.";

const CONSOLE_EVIDENCE_CAP: usize = 10;
const SOURCE_IDENTITY_MAX_BYTES: u64 = 1_000_000;
const FIXTURE_ONLY_HEADLINE_SUFFIX: &str = "likely ChainCheck test fixtures; see note below";
const FIXTURE_MIXED_HEADLINE_NOTE: &str = "see fixture note below";
const FIXTURE_FINDING_TAG: &str = "[likely ChainCheck fixture]";

#[derive(Debug)]
pub struct WrittenReports {
    pub dir: PathBuf,
    pub summary: PathBuf,
    pub findings_tsv: PathBuf,
}

pub fn write_reports(result: &ScanResult, report_dir: &Path) -> Result<WrittenReports, StartError> {
    let findings_tsv = report_dir.join("findings.tsv");
    let summary = report_dir.join("summary.txt");
    write_file(&findings_tsv, &findings_tsv_body(result))?;
    write_file(&summary, &summary_body(result, &findings_tsv))?;
    Ok(WrittenReports {
        dir: report_dir.to_path_buf(),
        summary,
        findings_tsv,
    })
}

pub fn console_brief(result: &ScanResult, reports: &WrittenReports) -> String {
    let (evidence, informational) = split_findings(&result.findings);
    let fixtures = FixtureAnnotation::classify(&evidence);
    let mut lines = Vec::new();
    lines.push("ChainCheck retrospective malware scan".to_owned());
    lines.push(String::new());
    lines.push(format!("Primary root: {}", primary_root(result)));
    lines.push(String::new());
    lines.extend(intelligence_status_lines(result));
    lines.push(String::new());
    lines.extend(major_detector_status_lines(result));
    lines.push(String::new());
    lines.extend(overall_result_lines(result, &fixtures));
    lines.push(String::new());
    lines.push(format!("Evidence findings: {}", evidence.len()));
    lines.extend(fixture_count_lines(&fixtures));
    lines.push(format!(
        "Informational/context observations: {}",
        informational.len()
    ));
    if !fixtures.is_empty() {
        lines.push(String::new());
        lines.extend(chaincheck_fixture_note_lines());
    }
    lines.push(String::new());
    lines.push(format!("Report: {}", reports.dir.display()));
    lines.push(PRIVACY_WARNING.to_owned());
    if !evidence.is_empty() {
        lines.push(String::new());
        lines.push("Evidence findings:".to_owned());
        for finding in evidence.iter().take(CONSOLE_EVIDENCE_CAP) {
            lines.push(format_console_evidence_line(
                finding,
                fixtures.contains(finding),
            ));
        }
        if evidence.len() > CONSOLE_EVIDENCE_CAP {
            lines.push(format!(
                "  ... {} more; see findings.tsv",
                evidence.len() - CONSOLE_EVIDENCE_CAP
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!("Full report: {}", reports.summary.display()));
    lines.join("\n") + "\n"
}

fn write_file(path: &Path, body: &str) -> Result<(), StartError> {
    fs::write(path, body).map_err(|_| StartError::ReportWriteFailed {
        path: path.to_path_buf(),
    })
}

fn findings_tsv_body(result: &ScanResult) -> String {
    let mut rows: Vec<_> = result.findings.iter().collect();
    rows.sort_by_key(|finding| {
        (
            severity_rank(finding.severity),
            finding.code.as_str(),
            location_text(finding),
            finding.detail.as_str(),
        )
    });
    let mut out = String::from("severity\tcategory\tlocation\tdetail\n");
    for finding in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            severity_label(finding.severity),
            sanitize_field(finding.code.as_str()),
            sanitize_field(&location_text(finding)),
            sanitize_field(&finding.detail)
        ));
    }
    out
}

fn summary_body(result: &ScanResult, tsv: &Path) -> String {
    let (evidence, informational) = split_findings(&result.findings);
    let fixtures = FixtureAnnotation::classify(&evidence);
    let mut lines = Vec::new();
    lines.push("ChainCheck retrospective malware scan".to_owned());
    lines.push("=".repeat(39));
    lines.push(format!("Primary root:   {}", primary_root(result)));
    lines.push(String::new());
    lines.extend(overall_result_lines(result, &fixtures));
    lines.push(String::new());
    lines.extend(intelligence_status_lines(result));
    lines.push(String::new());
    lines.extend(major_detector_status_lines(result));
    lines.push(String::new());

    let confirmed = count_severity(&evidence, Severity::Confirmed);
    let high = count_severity(&evidence, Severity::High);
    let medium = count_severity(&evidence, Severity::Medium);
    let exposure = count_severity(&informational, Severity::Exposure);
    let info = count_severity(&informational, Severity::Info);

    lines.push("Evidence findings".to_owned());
    lines.push(format!(
        "  CONFIRMED : {confirmed}   exact campaign payload hash"
    ));
    lines.push(format!(
        "  HIGH      : {high}   strong local package or campaign evidence"
    ));
    lines.push(format!(
        "  MEDIUM    : {medium}   needs review; not proof on its own"
    ));
    lines.extend(fixture_count_lines(&fixtures));
    if !fixtures.is_empty() {
        lines.push(String::new());
        lines.extend(chaincheck_fixture_note_lines());
    }
    lines.push(String::new());
    lines.push("Informational/context observations".to_owned());
    lines.push(format!(
        "  EXPOSURE  : {exposure}   credential inventory or other non-evidentiary context"
    ));
    lines.push(format!(
        "  INFO      : {info}   contextual observations only"
    ));
    lines.push(String::new());
    lines.push("Potential credential sources — informational only".to_owned());
    lines.push(
        "These files/variables are normal and their presence is not evidence of malware."
            .to_owned(),
    );
    lines.push(String::new());

    lines.push("npm coverage".to_owned());
    lines.extend(coverage_lines(result, is_npm_detector));
    lines.push(String::new());
    lines.push("Python/PyPI coverage".to_owned());
    lines.extend(coverage_lines(result, is_python_detector));
    lines.push(String::new());
    lines.push("Campaign/host coverage".to_owned());
    lines.extend(coverage_lines(result, is_campaign_detector));
    lines.push(String::new());

    lines.push("What this scan cannot tell you".to_owned());
    lines.push("  - unknown malware that is not in the loaded intelligence".to_owned());
    lines.push("  - deleted artefacts, or proof that a payload executed".to_owned());
    lines.push("  - remote CI/build machines".to_owned());
    lines.push(String::new());
    lines.push("Interpretation".to_owned());
    lines.push("  CONFIRMED/HIGH : treat this host as potentially compromised. Rotate credentials from a different, trusted machine.".to_owned());
    lines.push("  MEDIUM only    : read each finding; filename or history matches alone are frequently benign.".to_owned());
    lines.push("  Nothing found  : no known evidence was found; this is not proof the machine was never compromised.".to_owned());
    lines.push(format!("  {PRIVACY_WARNING}"));
    lines.push(String::new());
    lines.push(format!("Full findings: {}", tsv.display()));
    lines.join("\n") + "\n"
}

fn overall_result_lines(result: &ScanResult, fixtures: &FixtureAnnotation<'_>) -> Vec<String> {
    let fixture_marker = fixtures.headline_suffix();
    match result.outcome {
        ScanOutcome::StrongEvidence => vec![
            format!("Result: Action recommended — strong malware evidence detected{fixture_marker}"),
            String::new(),
            "ChainCheck found strong local evidence. Treat this host as potentially compromised and rotate relevant credentials from a different, trusted machine. This does not by itself prove payload execution.".to_owned(),
        ],
        ScanOutcome::MediumEvidence => vec![
            format!("Result: Review recommended — MEDIUM evidence detected{fixture_marker}"),
            String::new(),
            "ChainCheck found evidence that requires manual interpretation but does not by itself establish local installation or compromise.".to_owned(),
        ],
        ScanOutcome::IncompleteIntelligence => vec![
            format!("Result: Incomplete scan — required generic malware intelligence unavailable{fixture_marker}"),
            String::new(),
            "ChainCheck could not load or validate required npm and/or PyPI malware intelligence. Campaign-specific local checks still ran where possible, but the scan cannot be reported as clean.".to_owned(),
        ],
        ScanOutcome::Clean => vec![
            "Result: No known malware evidence detected".to_owned(),
            String::new(),
            "ChainCheck found no MEDIUM, HIGH or CONFIRMED evidence.".to_owned(),
            "Informational observations, if any, are listed separately below.".to_owned(),
        ],
    }
}

struct FixtureAnnotation<'a> {
    findings: Vec<&'a Finding>,
    evidence_count: usize,
}

impl<'a> FixtureAnnotation<'a> {
    fn classify(evidence: &[&'a Finding]) -> Self {
        let mut identity_cache = HashMap::new();
        let findings = evidence
            .iter()
            .copied()
            .filter(|finding| is_likely_chaincheck_fixture(finding, &mut identity_cache))
            .collect();
        Self {
            findings,
            evidence_count: evidence.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    fn len(&self) -> usize {
        self.findings.len()
    }

    fn other_count(&self) -> usize {
        self.evidence_count - self.findings.len()
    }

    fn contains(&self, finding: &Finding) -> bool {
        self.findings
            .iter()
            .any(|candidate| std::ptr::eq(*candidate, finding))
    }

    fn headline_suffix(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let unidentified = self.other_count();
        if unidentified == 0 {
            format!(" — {FIXTURE_ONLY_HEADLINE_SUFFIX}")
        } else {
            let noun = if unidentified == 1 {
                "finding"
            } else {
                "findings"
            };
            format!(
                " — including {unidentified} evidence {noun} not identified as a ChainCheck fixture; {FIXTURE_MIXED_HEADLINE_NOTE}"
            )
        }
    }
}

fn fixture_count_lines(fixtures: &FixtureAnnotation<'_>) -> Vec<String> {
    if fixtures.is_empty() {
        return Vec::new();
    }
    vec![
        format!("  Likely ChainCheck test fixtures: {}", fixtures.len()),
        format!(
            "  Evidence findings not identified as ChainCheck fixtures: {}",
            fixtures.other_count()
        ),
    ]
}

fn format_console_evidence_line(finding: &Finding, fixture: bool) -> String {
    let mut line = format!(
        "  [{}] {}: {} - {}",
        severity_label(finding.severity),
        finding.code.as_str(),
        location_text(finding),
        sanitize_field(&finding.detail)
    );
    if fixture {
        line.push(' ');
        line.push_str(FIXTURE_FINDING_TAG);
    }
    line
}

fn is_likely_chaincheck_fixture(
    finding: &Finding,
    identity_cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    let Some(location) = finding.location.as_deref() else {
        return false;
    };
    for ancestor in location.ancestors() {
        if ancestor.file_name().and_then(|name| name.to_str()) != Some("fixtures") {
            continue;
        }
        let Some(tests_dir) = ancestor.parent() else {
            continue;
        };
        if tests_dir.file_name().and_then(|name| name.to_str()) != Some("tests") {
            continue;
        }
        let Some(repo_root) = tests_dir.parent() else {
            continue;
        };
        if looks_like_chaincheck_source_root(repo_root, identity_cache) {
            return true;
        }
    }
    false
}

fn looks_like_chaincheck_source_root(
    root: &Path,
    identity_cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    if let Some(&cached) = identity_cache.get(root) {
        return cached;
    }
    let identified = identify_chaincheck_source_root(root);
    identity_cache.insert(root.to_path_buf(), identified);
    identified
}

fn identify_chaincheck_source_root(root: &Path) -> bool {
    if !root.join("src").join("self_test.rs").is_file()
        || !root.join("tests").join("cases.json").is_file()
    {
        return false;
    }
    let cargo_toml = root.join("Cargo.toml");
    let Ok(metadata) = fs::metadata(&cargo_toml) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > SOURCE_IDENTITY_MAX_BYTES {
        return false;
    }
    let Ok(content) = fs::read_to_string(cargo_toml) else {
        return false;
    };
    cargo_toml_identifies_chaincheck(&content)
}

fn cargo_toml_identifies_chaincheck(content: &str) -> bool {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let Ok(value) = toml::from_str::<toml::Value>(content) else {
        return false;
    };
    value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        == Some("chaincheck")
}

fn chaincheck_fixture_note_lines() -> Vec<String> {
    vec![
        "NOTE: LIKELY CHAINCHECK TEST FIXTURE".to_owned(),
        "Some evidence findings match synthetic malware test data under tests/fixtures in a source tree that identifies itself as the ChainCheck package.".to_owned(),
        "This annotation does not suppress findings, reduce severity, or change the scan exit code. MEDIUM, HIGH, and CONFIRMED still mean the same as for any other evidence.".to_owned(),
        "If this is a ChainCheck source checkout, these fixture findings are expected and do not by themselves show that the malicious package was installed or that the host was compromised.".to_owned(),
        "The installed ChainCheck binary does not require the source checkout. If you cloned or downloaded the source only to install ChainCheck, you may remove that source tree; later system-wide scans will then not encounter its bundled fixtures.".to_owned(),
        "If you did not expect this path to contain ChainCheck test data, investigate the finding normally.".to_owned(),
    ]
}

fn intelligence_status_lines(result: &ScanResult) -> Vec<String> {
    vec![
        ecosystem_status_line(Ecosystem::Npm, &result.intelligence.npm),
        ecosystem_status_line(Ecosystem::Pypi, &result.intelligence.pypi),
    ]
}

fn ecosystem_status_line(ecosystem: Ecosystem, intel: &EcosystemIntelligence) -> String {
    let name = ecosystem.display_name();
    match intel.feed_state() {
        FeedState::Available {
            accepted_records, ..
        } => {
            format!("{name} intelligence: available ({accepted_records} validated MALWARE records)")
        }
        FeedState::Unavailable(failure) => {
            format!(
                "{name} intelligence: unavailable ({})",
                feed_failure_label(failure)
            )
        }
    }
}

fn feed_failure_label(failure: FeedFailure) -> &'static str {
    match failure {
        FeedFailure::Network => "network error",
        FeedFailure::Timeout => "timeout",
        FeedFailure::OversizedResponse => "response exceeds size limit",
        FeedFailure::InvalidJson => "invalid JSON",
        FeedFailure::InvalidTopLevel => "invalid top-level JSON",
        FeedFailure::NoValidMalwareRecords => "no valid MALWARE records",
    }
}

fn major_detector_status_lines(result: &ScanResult) -> Vec<String> {
    vec![
        format!(
            "Filesystem/package checks: {}",
            group_status(result, |name| {
                matches!(
                    name,
                    "filesystem-walk"
                        | "manifest"
                        | "npm-lockfile"
                        | "yarn-lockfile"
                        | "pnpm-lockfile"
                        | "text-lockfile"
                        | "bun-lockb"
                        | "python-discovery"
                        | "python-pylock"
                        | "python-uv-lock"
                        | "python-poetry-lock"
                        | "python-pipfile-lock"
                        | "python-pdm-lock"
                        | "python-pyproject"
                        | "python-requirements"
                        | "python-pipfile"
                        | "python-setup-cfg"
                        | "python-installed"
                )
            })
        ),
        format!(
            "npm cache/log checks: {}",
            group_status(result, |name| matches!(name, "npm-cache" | "npm-logs"))
        ),
        "Campaign-specific checks: attempted; see report for coverage".to_owned(),
    ]
}

fn group_status(result: &ScanResult, pred: impl Fn(&str) -> bool) -> &'static str {
    let statuses: Vec<_> = result
        .coverage
        .iter()
        .filter(|c| pred(c.detector().as_str()))
        .map(DetectorCoverage::status)
        .collect();
    rollup_coverage(&statuses)
}

/// Group roll-up for the bounded console. Per-detector coverage lines are unchanged.
fn rollup_coverage(statuses: &[CoverageStatus]) -> &'static str {
    if statuses.is_empty() {
        return "not run";
    }
    let applicable: Vec<_> = statuses
        .iter()
        .copied()
        .filter(|s| *s != CoverageStatus::NotApplicable)
        .collect();
    if applicable.is_empty() {
        return "not run";
    }
    if applicable.iter().all(|s| *s == CoverageStatus::Skipped) {
        return "skipped";
    }
    if applicable.iter().all(|s| *s == CoverageStatus::Unsupported) {
        return "unsupported";
    }
    if applicable.iter().any(|s| *s == CoverageStatus::Partial) {
        return "partial";
    }
    if applicable.iter().any(|s| *s == CoverageStatus::Unsupported) {
        return "partial";
    }
    "completed"
}

fn coverage_lines(result: &ScanResult, pred: impl Fn(&str) -> bool) -> Vec<String> {
    let mut rows: Vec<_> = result
        .coverage
        .iter()
        .filter(|c| pred(c.detector().as_str()))
        .collect();
    rows.sort_by_key(|c| c.detector().as_str());
    if rows.is_empty() {
        return vec!["  (none)".to_owned()];
    }
    rows.into_iter()
        .map(|coverage| {
            let mut line = format!(
                "  [{:<12}] {:<24}",
                coverage_label(coverage.status()),
                coverage.detector().as_str()
            );
            if coverage.artefacts_encountered() > 0 || coverage.artefacts_inspected() > 0 {
                line.push_str(&format!(
                    " encountered={} inspected={}",
                    coverage.artefacts_encountered(),
                    coverage.artefacts_inspected()
                ));
            }
            for (status, count) in coverage.failure_counts() {
                if *count > 0 {
                    line.push_str(&format!(" {}={count}", artifact_status_label(*status)));
                }
            }
            if coverage.cap_reached() {
                line.push_str(" cap-reached");
            }
            if !coverage.detail().is_empty() {
                line.push(' ');
                line.push_str(coverage.detail());
            }
            if !coverage.examples().is_empty() {
                let example = &coverage.examples()[0];
                line.push_str(&format!(
                    " (e.g. {} {:?})",
                    example.path.display(),
                    example.status
                ));
            }
            line
        })
        .collect()
}

fn artifact_status_label(status: ArtifactStatus) -> &'static str {
    match status {
        ArtifactStatus::Inspected => "inspected",
        ArtifactStatus::StatFailed => "stat-failed",
        ArtifactStatus::Unreadable => "unreadable",
        ArtifactStatus::Oversized => "oversized",
        ArtifactStatus::ParseFailed => "parse-failed",
        ArtifactStatus::UnsupportedFormat => "unsupported-format",
    }
}

fn is_npm_detector(name: &str) -> bool {
    matches!(
        name,
        "filesystem-walk"
            | "manifest"
            | "npm-lockfile"
            | "yarn-lockfile"
            | "pnpm-lockfile"
            | "text-lockfile"
            | "bun-lockb"
            | "npm-cache"
            | "npm-logs"
            | "npm-intelligence"
    )
}

fn is_python_detector(name: &str) -> bool {
    name.starts_with("python-") || name == "pypi-intelligence"
}

fn is_campaign_detector(name: &str) -> bool {
    matches!(
        name,
        "payload-file"
            | "ide-config"
            | "campaign-walk"
            | "git-history"
            | "hosts-file"
            | "dns-cache"
            | "credentials"
    )
}

fn split_findings(findings: &[Finding]) -> (Vec<&Finding>, Vec<&Finding>) {
    let mut evidence = Vec::new();
    let mut informational = Vec::new();
    for finding in findings {
        if finding.severity.is_evidence() {
            evidence.push(finding);
        } else {
            informational.push(finding);
        }
    }
    evidence.sort_by_key(|f| (severity_rank(f.severity), f.code.as_str(), location_text(f)));
    informational.sort_by_key(|f| (severity_rank(f.severity), f.code.as_str(), location_text(f)));
    (evidence, informational)
}

fn count_severity(findings: &[&Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

fn primary_root(result: &ScanResult) -> String {
    match &result.scope {
        ScanScope::WholeUser { home } => home.display().to_string(),
        ScanScope::ExplicitRoot { root } => root.display().to_string(),
    }
}

fn location_text(finding: &Finding) -> String {
    finding
        .location
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn sanitize_field(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Confirmed => "CONFIRMED",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Exposure => "EXPOSURE",
        Severity::Info => "INFO",
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Confirmed => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Exposure => 3,
        Severity::Info => 4,
    }
}

fn coverage_label(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Completed => "completed",
        CoverageStatus::Partial => "partial",
        CoverageStatus::Skipped => "skipped",
        CoverageStatus::Unsupported => "unsupported",
        CoverageStatus::NotApplicable => "n/a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{ArtifactStatus, DetectorId};
    use crate::evidence::Finding;
    use crate::intelligence::{
        EcosystemIntelligence, FeedFailure, IntelligenceSnapshot, parse_malware_feed,
    };
    use crate::model::{
        Ecosystem, EvidenceKind, FindingCode, FindingSubject, PackageIdentity, PackageKey,
        PackageVersion,
    };
    use crate::scan::normal_scan_exit;
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
            "chaincheck-report-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn snap(npm_ok: bool, pypi_ok: bool) -> IntelligenceSnapshot {
        let npm_bytes = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;
        let pypi_bytes = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;
        IntelligenceSnapshot::new(
            if npm_ok {
                EcosystemIntelligence::Available(
                    parse_malware_feed(npm_bytes, Ecosystem::Npm).unwrap(),
                )
            } else {
                EcosystemIntelligence::Unavailable(FeedFailure::Network)
            },
            if pypi_ok {
                EcosystemIntelligence::Available(
                    parse_malware_feed(pypi_bytes, Ecosystem::Pypi).unwrap(),
                )
            } else {
                EcosystemIntelligence::Unavailable(FeedFailure::Timeout)
            },
        )
    }

    fn finding(
        severity: Severity,
        code: &'static str,
        location: Option<&str>,
        detail: &str,
    ) -> Finding {
        Finding {
            severity,
            kind: EvidenceKind::Context,
            code: FindingCode::from_static(code),
            subject: FindingSubject::PackageExact(PackageKey::new(
                PackageIdentity::npm("keyv"),
                PackageVersion::exact("6.0.0"),
            )),
            location: location.map(PathBuf::from),
            detail: detail.to_owned(),
            intelligence_source: None,
        }
    }

    fn chaincheck_source_tree(cargo_toml: &str) -> PathBuf {
        let source = tmp();
        fs::create_dir_all(source.join("src")).unwrap();
        fs::create_dir_all(source.join("tests").join("fixtures").join("npm")).unwrap();
        fs::write(source.join("Cargo.toml"), cargo_toml).unwrap();
        fs::write(source.join("src").join("self_test.rs"), "// marker\n").unwrap();
        fs::write(source.join("tests").join("cases.json"), "[]\n").unwrap();
        source
    }

    fn write_reports_of(result: &ScanResult) -> (WrittenReports, PathBuf) {
        let report_dir = tmp();
        let written = write_reports(result, &report_dir).unwrap();
        (written, report_dir)
    }

    #[test]
    fn tsv_header_and_findings_not_coverage() {
        let dir = tmp();
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("npm-lockfile"));
        coverage.record_artifact(PathBuf::from("/tmp/bad.json"), ArtifactStatus::ParseFailed);
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/project"),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                Some("/tmp/package-lock.json"),
                "keyv@6.0.0",
            )],
            package_evidence: vec![],
            coverage: vec![coverage],
        };
        let written = write_reports(&result, &dir).unwrap();
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        assert!(tsv.starts_with("severity\tcategory\tlocation\tdetail\n"));
        assert!(tsv.contains("MEDIUM\tlockfile-package\t/tmp/package-lock.json\tkeyv@6.0.0\n"));
        assert!(!tsv.contains("npm-lockfile"));
        assert!(!tsv.to_lowercase().contains("parsefailed"));
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(summary.contains(PRIVACY_WARNING));
        assert!(summary.contains("npm intelligence: available"));
        assert!(summary.contains("PyPI intelligence: available"));
        assert!(summary.contains("[partial"));
        let console = console_brief(&result, &written);
        assert!(console.contains(PRIVACY_WARNING));
        assert!(console.contains("Evidence findings: 1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pathological_fields_do_not_break_tsv() {
        let dir = tmp();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/project"),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, false),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                Some("/tmp/a\tb\nc"),
                "line1\nline2\r",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        let written = write_reports(&result, &dir).unwrap();
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        let data_line = tsv.lines().nth(1).unwrap();
        assert_eq!(data_line.split('\t').count(), 4);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(summary.contains("PyPI intelligence: unavailable (timeout)"));
        assert!(summary.contains("npm intelligence: available"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn console_truncates_evidence() {
        let dir = tmp();
        let findings: Vec<_> = (0..12)
            .map(|i| {
                finding(
                    Severity::Medium,
                    "lockfile-package",
                    Some("/tmp/lock"),
                    &format!("pkg{i}"),
                )
            })
            .collect();
        let result = ScanResult {
            scope: ScanScope::WholeUser {
                home: PathBuf::from("/home/user"),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings,
            package_evidence: vec![],
            coverage: vec![],
        };
        let written = write_reports(&result, &dir).unwrap();
        let console = console_brief(&result, &written);
        assert!(console.contains("... 2 more; see findings.tsv"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_headline_suffix_distinguishes_mixed_and_fixture_only() {
        let fixture_finding = finding(Severity::Medium, "lockfile-package", Some("/tmp/x"), "a");
        let fixture_only = FixtureAnnotation {
            findings: vec![&fixture_finding],
            evidence_count: 1,
        };
        assert_eq!(
            fixture_only.headline_suffix(),
            format!(" — {FIXTURE_ONLY_HEADLINE_SUFFIX}")
        );
        let one_other = FixtureAnnotation {
            findings: vec![&fixture_finding],
            evidence_count: 2,
        };
        assert!(
            one_other
                .headline_suffix()
                .contains("including 1 evidence finding not identified as a ChainCheck fixture;")
        );
        let two_other = FixtureAnnotation {
            findings: vec![&fixture_finding],
            evidence_count: 3,
        };
        assert!(
            two_other
                .headline_suffix()
                .contains("including 2 evidence findings not identified as a ChainCheck fixture;")
        );
        let empty = FixtureAnnotation {
            findings: vec![],
            evidence_count: 2,
        };
        assert_eq!(empty.headline_suffix(), "");
    }

    #[test]
    fn cargo_toml_identifies_chaincheck_package_name_forms() {
        assert!(cargo_toml_identifies_chaincheck(
            "[package]\nname = \"chaincheck\"\nversion = \"0.0.0\"\n"
        ));
        assert!(cargo_toml_identifies_chaincheck(
            "[package]\nname=\"chaincheck\"\n"
        ));
        assert!(cargo_toml_identifies_chaincheck(
            "[package]\nname = 'chaincheck'\n"
        ));
        assert!(cargo_toml_identifies_chaincheck(
            "[package] # crate\nname = \"chaincheck\" # pkg\n"
        ));
        assert!(cargo_toml_identifies_chaincheck(
            "\u{feff}[package]\nname = \"chaincheck\"\n"
        ));
        assert!(!cargo_toml_identifies_chaincheck(
            "[package]\nname = \"other\"\n[lib]\nname = \"chaincheck\"\n"
        ));
        assert!(!cargo_toml_identifies_chaincheck(
            "[package]\nname.workspace = true\n"
        ));
        assert!(!cargo_toml_identifies_chaincheck(
            "[package]\nname = \"chaincheck-tools\"\n"
        ));
        assert!(!cargo_toml_identifies_chaincheck("[package]\nname = \n"));
        assert!(!cargo_toml_identifies_chaincheck("not toml {{{"));
    }

    #[test]
    fn chaincheck_fixture_annotation_is_visible_but_does_not_suppress() {
        let source =
            chaincheck_source_tree("[package]\nname = \"chaincheck\"\nversion = \"0.0.0\"\n");
        let fixture = source.join("tests/fixtures/npm/package-lock.json");
        fs::write(&fixture, "{}\n").unwrap();
        let result = ScanResult {
            scope: ScanScope::WholeUser {
                home: source.clone(),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                fixture.to_str(),
                "synthetic fixture",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
        assert_eq!(normal_scan_exit(result.outcome), 1);
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(summary.contains("Result: Review recommended — MEDIUM evidence detected — likely ChainCheck test fixtures; see note below"));
        assert!(!summary.contains("not identified as a ChainCheck fixture;"));
        assert!(summary.contains("NOTE: LIKELY CHAINCHECK TEST FIXTURE"));
        assert!(
            summary.contains(
                "does not suppress findings, reduce severity, or change the scan exit code"
            )
        );
        assert!(summary.contains("Likely ChainCheck test fixtures: 1"));
        assert!(summary.contains("Evidence findings not identified as ChainCheck fixtures: 0"));
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        let expected_row = format!(
            "MEDIUM\tlockfile-package\t{}\tsynthetic fixture\n",
            fixture.display()
        );
        assert!(tsv.starts_with("severity\tcategory\tlocation\tdetail\n"));
        assert!(tsv.contains(&expected_row), "{tsv}");
        assert_eq!(tsv.lines().nth(1).unwrap().split('\t').count(), 4);
        let console = console_brief(&result, &written);
        assert!(console.contains("likely ChainCheck test fixtures; see note below"));
        assert!(console.contains("NOTE: LIKELY CHAINCHECK TEST FIXTURE"));
        assert!(console.contains(FIXTURE_FINDING_TAG));
        assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
        assert_eq!(normal_scan_exit(result.outcome), 1);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn chaincheck_fixture_strong_evidence_keeps_headline_and_exit_code() {
        let source = chaincheck_source_tree("[package]\nname=\"chaincheck\"\n");
        let fixture = source.join("tests/fixtures/npm/package.json");
        fs::write(&fixture, "{}\n").unwrap();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: source.clone(),
            },
            outcome: ScanOutcome::StrongEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::High,
                "installed-package",
                fixture.to_str(),
                "synthetic installed fixture",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        assert_eq!(normal_scan_exit(result.outcome), 2);
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(summary.contains("Result: Action recommended — strong malware evidence detected — likely ChainCheck test fixtures; see note below"));
        assert!(!summary.contains("not identified as a ChainCheck fixture;"));
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        let expected_row = format!(
            "HIGH\tinstalled-package\t{}\tsynthetic installed fixture\n",
            fixture.display()
        );
        assert!(tsv.contains(&expected_row), "{tsv}");
        let console = console_brief(&result, &written);
        assert!(console.contains(&format!(
            "[HIGH] installed-package: {} - synthetic installed fixture {FIXTURE_FINDING_TAG}",
            fixture.display()
        )));
        assert_eq!(normal_scan_exit(result.outcome), 2);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn mixed_fixture_and_other_evidence_headline_does_not_explain_away_the_result() {
        let source = chaincheck_source_tree("[package]\nname = 'chaincheck'\n");
        let fixture = source.join("tests/fixtures/npm/package-lock.json");
        fs::write(&fixture, "{}\n").unwrap();
        let real = PathBuf::from("/tmp/real-project/package-lock.json");
        let result = ScanResult {
            scope: ScanScope::WholeUser {
                home: PathBuf::from("/home/user"),
            },
            outcome: ScanOutcome::StrongEvidence,
            intelligence: snap(true, true),
            findings: vec![
                finding(
                    Severity::Medium,
                    "lockfile-package",
                    fixture.to_str(),
                    "synthetic fixture",
                ),
                finding(
                    Severity::High,
                    "installed-package",
                    real.to_str(),
                    "real installed package",
                ),
            ],
            package_evidence: vec![],
            coverage: vec![],
        };
        assert_eq!(normal_scan_exit(result.outcome), 2);
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(summary.contains("Result: Action recommended — strong malware evidence detected — including 1 evidence finding not identified as a ChainCheck fixture; see fixture note below"));
        assert!(summary.contains("Likely ChainCheck test fixtures: 1"));
        assert!(summary.contains("Evidence findings not identified as ChainCheck fixtures: 1"));
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        assert!(tsv.contains(&format!(
            "MEDIUM\tlockfile-package\t{}\tsynthetic fixture\n",
            fixture.display()
        )));
        assert!(tsv.contains(
            "HIGH\tinstalled-package\t/tmp/real-project/package-lock.json\treal installed package\n"
        ));
        let console = console_brief(&result, &written);
        assert!(console.contains(
            "including 1 evidence finding not identified as a ChainCheck fixture; see fixture note below"
        ));
        assert!(console.contains(&format!(
            "[MEDIUM] lockfile-package: {} - synthetic fixture {FIXTURE_FINDING_TAG}",
            fixture.display()
        )));
        assert!(console.contains(
            "[HIGH] installed-package: /tmp/real-project/package-lock.json - real installed package"
        ));
        assert!(!console.contains(&format!("real installed package {FIXTURE_FINDING_TAG}")));
        assert_eq!(normal_scan_exit(result.outcome), 2);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn lookalike_fixture_path_without_chaincheck_source_markers_is_not_annotated() {
        let source = tmp();
        fs::create_dir_all(source.join("tests/fixtures")).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"chaincheck\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        let fixture = source.join("tests/fixtures/package-lock.json");
        fs::write(&fixture, "{}\n").unwrap();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: source.clone(),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                fixture.to_str(),
                "not enough source identity",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(!summary.contains(FIXTURE_ONLY_HEADLINE_SUFFIX));
        assert!(!summary.contains("NOTE: LIKELY CHAINCHECK TEST FIXTURE"));
        let console = console_brief(&result, &written);
        assert!(!console.contains(FIXTURE_FINDING_TAG));
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn chaincheck_name_outside_package_table_is_not_annotated() {
        let source = chaincheck_source_tree(
            "[package]\nname = \"other\"\nversion = \"0.0.0\"\n[lib]\nname = \"chaincheck\"\n",
        );
        let fixture = source.join("tests/fixtures/npm/package-lock.json");
        fs::write(&fixture, "{}\n").unwrap();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: source.clone(),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                fixture.to_str(),
                "lib name only",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(!summary.contains(FIXTURE_ONLY_HEADLINE_SUFFIX));
        assert!(!summary.contains("NOTE: LIKELY CHAINCHECK TEST FIXTURE"));
        let console = console_brief(&result, &written);
        assert!(!console.contains(FIXTURE_FINDING_TAG));
        assert_eq!(normal_scan_exit(result.outcome), 1);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn malformed_cargo_toml_is_not_annotated_and_does_not_change_the_finding() {
        let source = chaincheck_source_tree("[package]\nname =\n");
        let fixture = source.join("tests/fixtures/npm/package-lock.json");
        fs::write(&fixture, "{}\n").unwrap();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: source.clone(),
            },
            outcome: ScanOutcome::MediumEvidence,
            intelligence: snap(true, true),
            findings: vec![finding(
                Severity::Medium,
                "lockfile-package",
                fixture.to_str(),
                "malformed identity",
            )],
            package_evidence: vec![],
            coverage: vec![],
        };
        assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
        assert_eq!(normal_scan_exit(result.outcome), 1);
        let (written, report_dir) = write_reports_of(&result);
        let summary = fs::read_to_string(&written.summary).unwrap();
        assert!(!summary.contains(FIXTURE_ONLY_HEADLINE_SUFFIX));
        assert!(!summary.contains("NOTE: LIKELY CHAINCHECK TEST FIXTURE"));
        let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
        let expected_row = format!(
            "MEDIUM\tlockfile-package\t{}\tmalformed identity\n",
            fixture.display()
        );
        assert!(tsv.starts_with("severity\tcategory\tlocation\tdetail\n"));
        assert!(tsv.contains(&expected_row), "{tsv}");
        assert_eq!(tsv.lines().nth(1).unwrap().split('\t').count(), 4);
        let console = console_brief(&result, &written);
        assert!(!console.contains(FIXTURE_FINDING_TAG));
        assert_eq!(result.outcome, ScanOutcome::MediumEvidence);
        assert_eq!(normal_scan_exit(result.outcome), 1);
        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn coverage_group_rollup() {
        use CoverageStatus::{Completed, NotApplicable, Partial, Skipped, Unsupported};
        assert_eq!(rollup_coverage(&[]), "not run");
        assert_eq!(rollup_coverage(&[Completed]), "completed");
        assert_eq!(rollup_coverage(&[Completed, Completed]), "completed");
        assert_eq!(rollup_coverage(&[Completed, Unsupported]), "partial");
        assert_eq!(rollup_coverage(&[Unsupported]), "unsupported");
        assert_eq!(rollup_coverage(&[Unsupported, Unsupported]), "unsupported");
        assert_eq!(rollup_coverage(&[Partial, Completed]), "partial");
        assert_eq!(rollup_coverage(&[Skipped]), "skipped");
        assert_eq!(rollup_coverage(&[Skipped, Skipped]), "skipped");
        assert_eq!(rollup_coverage(&[Completed, NotApplicable]), "completed");
        assert_eq!(rollup_coverage(&[NotApplicable]), "not run");
        assert_eq!(rollup_coverage(&[Skipped, NotApplicable]), "skipped");
    }

    #[test]
    fn write_failure_is_report_write_failed() {
        let dir = tmp();
        let blocked = dir.join("findings.tsv");
        fs::create_dir_all(&blocked).unwrap();
        let result = ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/project"),
            },
            outcome: ScanOutcome::Clean,
            intelligence: snap(true, true),
            findings: vec![],
            package_evidence: vec![],
            coverage: vec![],
        };
        let err = write_reports(&result, &dir).unwrap_err();
        assert!(matches!(err, StartError::ReportWriteFailed { .. }));
        assert_eq!(err.exit_code(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    fn result_with(coverage: Vec<DetectorCoverage>) -> ScanResult {
        ScanResult {
            scope: ScanScope::ExplicitRoot {
                root: PathBuf::from("/tmp/project"),
            },
            outcome: ScanOutcome::Clean,
            intelligence: snap(true, true),
            findings: vec![],
            package_evidence: vec![],
            coverage,
        }
    }

    fn summary_of(coverage: Vec<DetectorCoverage>) -> String {
        let dir = tmp();
        let written = write_reports(&result_with(coverage), &dir).unwrap();
        let summary = fs::read_to_string(&written.summary).unwrap();
        let _ = fs::remove_dir_all(&dir);
        summary
    }

    #[test]
    fn coverage_renders_inspected_totals() {
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("npm-lockfile"));
        coverage.record_artifact(PathBuf::from("/tmp/a.json"), ArtifactStatus::Inspected);
        coverage.record_artifact(PathBuf::from("/tmp/b.json"), ArtifactStatus::Inspected);
        let summary = summary_of(vec![coverage]);
        assert!(summary.contains("encountered=2 inspected=2"));
        assert!(!summary.contains("cap-reached"));
    }

    #[test]
    fn coverage_renders_typed_failures() {
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("npm-lockfile"));
        coverage.record_artifact(PathBuf::from("/tmp/a.json"), ArtifactStatus::Inspected);
        coverage.record_artifact(PathBuf::from("/tmp/bad.json"), ArtifactStatus::ParseFailed);
        let summary = summary_of(vec![coverage]);
        assert!(summary.contains("[partial"));
        assert!(summary.contains("encountered=2 inspected=1"));
        assert!(summary.contains("parse-failed=1"));
        assert!(summary.contains("/tmp/bad.json"));
    }

    #[test]
    fn coverage_renders_cap_reached_without_zero_artefact_totals() {
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("filesystem-walk"));
        coverage.mark_cap_reached();
        coverage.set_detail("stopped after 8 directory entries");
        let summary = summary_of(vec![coverage]);
        assert!(summary.contains("[partial"));
        assert!(summary.contains("cap-reached"));
        assert!(summary.contains("stopped after 8 directory entries"));
        assert!(!summary.contains("encountered=0"));
        assert!(!summary.contains("inspected=0"));
    }

    #[test]
    fn coverage_keeps_a_single_bounded_example() {
        let mut coverage = DetectorCoverage::attempted(DetectorId::from_static("npm-lockfile"));
        for i in 0..13 {
            coverage.record_artifact(
                PathBuf::from(format!("/tmp/f{i}.json")),
                ArtifactStatus::Unreadable,
            );
        }
        let summary = summary_of(vec![coverage]);
        assert!(summary.contains("unreadable=13"));
        assert!(summary.contains("(e.g. /tmp/f0.json"));
        assert!(!summary.contains("/tmp/f12.json"));
    }

    #[test]
    fn completed_traversal_does_not_claim_zero_filesystem_entries() {
        let coverage = DetectorCoverage::attempted(DetectorId::from_static("filesystem-walk"));
        let summary = summary_of(vec![coverage]);
        let walk_line = summary
            .lines()
            .find(|line| line.contains("filesystem-walk"))
            .unwrap();
        assert!(walk_line.contains("[completed"));
        assert!(!walk_line.contains("encountered=0"));
        assert!(!walk_line.contains("inspected=0"));
        assert!(!walk_line.to_lowercase().contains("zero"));
    }
}
