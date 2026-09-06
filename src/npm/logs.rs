//! npm debug log install-context vs mention-only evidence.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::EvidenceClass;
use crate::fsutil::{read_text_lossy_bounded, text_artifact_status};
use crate::intelligence::EcosystemIntelligence;
use crate::model::{EvidenceKind, Severity};
use crate::progress::{NoProgress, Progress};
use crate::scan::DetectorOutput;

use crate::campaign::ioc_findings_from_log_text;

use super::{
    CODE_NPM_INSTALL_LOG, DET_NPM_LOGS, LIMIT_NPM_LOG, emit_exact, pairs_from_spec_tokens,
    pairs_from_tarball_urls,
};

static INSTALL_CONTEXT: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?im)^\d+\s+verbose\s+title\s+npm\s+(?:install|ci|i)\b",
        r#"(?im)^\d+\s+verbose\s+argv\s+.*["'](?:install|ci|i)["']"#,
        r#"(?im)^\d+\s+verbose\s+cli\s+.*(?:["'](?:install|ci|i)["']|\b(?:install|ci|i)\b)"#,
        r"(?im)^\d+\s+(?:silly|timing|verbose)\s+reify(?::|\s)",
        r"(?im)^\d+\s+(?:silly|timing|verbose)\s+idealTree(?::|\s)",
        r"(?im)^\d+\s+(?:silly|timing|verbose)\s+placeDep(?::|\s)",
        r"(?im)\bnpm(?:\.cmd)?\s+(?:install|ci|i)\b",
    ]
    .into_iter()
    .map(|p| Regex::new(p).expect("install-context regex"))
    .collect()
});

pub fn scan_npm_logs(paths: &[impl AsRef<Path>], intel: &EcosystemIntelligence) -> DetectorOutput {
    scan_npm_logs_with_progress(paths, intel, &NoProgress)
}

pub fn scan_npm_logs_with_progress(
    paths: &[impl AsRef<Path>],
    intel: &EcosystemIntelligence,
    progress: &dyn Progress,
) -> DetectorOutput {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_NPM_LOGS);
    for path in paths {
        progress.tick();
        let path = path.as_ref();
        match read_text_lossy_bounded(path, LIMIT_NPM_LOG) {
            crate::fsutil::TextReadOutcome::Text(text) => {
                coverage.record_artifact(path.to_path_buf(), ArtifactStatus::Inspected);
                let mut pairs = pairs_from_spec_tokens(&text);
                for pair in pairs_from_tarball_urls(&text) {
                    pairs.push(pair);
                }
                pairs.sort();
                pairs.dedup();
                let install_context = npm_log_install_context(&text);
                let severity = if install_context {
                    Severity::High
                } else {
                    Severity::Medium
                };
                for (name, version) in pairs {
                    emit_exact(
                        intel,
                        &name,
                        &version,
                        path,
                        DET_NPM_LOGS,
                        EvidenceClass::InstallContext,
                        EvidenceKind::InstallContext,
                        CODE_NPM_INSTALL_LOG,
                        severity,
                        &mut findings,
                        &mut evidence,
                    );
                }
                findings.extend(ioc_findings_from_log_text(path, &text));
            }
            other => {
                coverage.record_artifact(path.to_path_buf(), text_artifact_status(&other));
            }
        }
    }
    DetectorOutput {
        findings,
        package_evidence: evidence,
        coverage,
    }
}

pub(crate) fn npm_log_install_context(text: &str) -> bool {
    INSTALL_CONTEXT.iter().any(|re| re.is_match(text))
}
