//! Campaign Git history: reported author/message signature only.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::campaign::intelligence::{SINCE_GIT, WORM_EMAIL, WORM_SUBJECT};
use crate::campaign::{
    CODE_MALICIOUS_GIT_SIGNATURE, CODE_SUSPICIOUS_GIT_AUTHOR, DET_GIT_HISTORY, campaign_finding,
};
use crate::coverage::{ArtifactStatus, DetectorCoverage};
use crate::evidence::Finding;
use crate::model::{EvidenceKind, Severity};
use crate::processutil::{
    BoundedCommand, LIMIT_GIT_STDOUT, ToolProbe, classify_probe, run_bounded,
};
use crate::progress::{NoProgress, Progress};
use crate::scan::DetectorOutput;

const GIT_TIMEOUT: Duration = Duration::from_secs(45);

pub struct GitCommit {
    pub commit: String,
    pub when: String,
    pub author: String,
    pub email: String,
    pub subject: String,
}

/// Parse `git log --format=%H%x09%aI%x09%an%x09%ae%x09%s` output. Malformed
/// lines are skipped.
pub fn parse_git_log(stdout: &str) -> Vec<GitCommit> {
    let mut commits = Vec::new();
    for line in stdout.split_terminator('\n') {
        let mut parts = line.splitn(5, '\t');
        let Some(commit) = parts.next() else {
            continue;
        };
        let Some(when) = parts.next() else {
            continue;
        };
        let Some(author) = parts.next() else {
            continue;
        };
        let Some(email) = parts.next() else {
            continue;
        };
        let Some(subject) = parts.next() else {
            continue;
        };
        commits.push(GitCommit {
            commit: commit.to_owned(),
            when: when.to_owned(),
            author: author.to_owned(),
            email: email.to_owned(),
            subject: subject.to_owned(),
        });
    }
    commits
}

pub fn findings_from_commits(repo: &Path, commits: &[GitCommit]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for commit in commits {
        let email_match = commit.email.eq_ignore_ascii_case(WORM_EMAIL);
        if email_match && commit.subject.trim() == WORM_SUBJECT {
            findings.push(campaign_finding(
                Severity::High,
                EvidenceKind::CampaignIndicator,
                CODE_MALICIOUS_GIT_SIGNATURE,
                Some(repo.to_path_buf()),
                format!(
                    "Commit {} at {} exactly matches the reported ChainDrop/Shai-Hulud \
                     Git author/message signature: {} <{}> '{}'. This is strong campaign \
                     evidence requiring investigation, but does not by itself prove payload \
                     execution on this host",
                    commit.commit, commit.when, commit.author, commit.email, commit.subject
                ),
            ));
        } else if email_match {
            findings.push(campaign_finding(
                Severity::Medium,
                EvidenceKind::CampaignIndicator,
                CODE_SUSPICIOUS_GIT_AUTHOR,
                Some(repo.to_path_buf()),
                format!(
                    "Commit {} at {} uses the reported ChainDrop/Shai-Hulud worm author email; \
                     subject '{}'",
                    commit.commit, commit.when, commit.subject
                ),
            ));
        }
    }
    findings
}

/// `git_program`: `None` means Git is treated as unavailable (Skipped), even if
/// the host actually has Git. `Some("git")` uses the system executable.
pub fn scan_git(repos: &[PathBuf], git_program: Option<&Path>) -> DetectorOutput {
    scan_git_with_program(repos, git_program, &NoProgress)
}

fn scan_git_with_program(
    repos: &[PathBuf],
    git_program: Option<&Path>,
    progress: &dyn Progress,
) -> DetectorOutput {
    let Some(git_program) = git_program else {
        return DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: DetectorCoverage::skipped(DET_GIT_HISTORY),
        };
    };

    let mut findings = Vec::new();
    let mut coverage = DetectorCoverage::attempted(DET_GIT_HISTORY);
    for repo in repos {
        progress.tick();
        let mut cmd = Command::new(git_program);
        cmd.arg("-C")
            .arg(repo)
            .arg("log")
            .arg("--all")
            .arg(format!("--since={SINCE_GIT}"))
            .arg("--format=%H%x09%aI%x09%an%x09%ae%x09%s");
        match run_bounded(cmd, GIT_TIMEOUT, LIMIT_GIT_STDOUT) {
            BoundedCommand::Completed { status, stdout } if status.success() => {
                coverage.record_artifact(repo.clone(), ArtifactStatus::Inspected);
                let text = String::from_utf8_lossy(&stdout);
                findings.extend(findings_from_commits(repo, &parse_git_log(&text)));
            }
            BoundedCommand::Oversized => {
                coverage.record_artifact(repo.clone(), ArtifactStatus::Oversized);
            }
            BoundedCommand::Timeout | BoundedCommand::Io(_) | BoundedCommand::SpawnFailed(_) => {
                coverage.record_artifact(repo.clone(), ArtifactStatus::Unreadable);
            }
            BoundedCommand::Completed { .. } => {
                coverage.record_artifact(repo.clone(), ArtifactStatus::Unreadable);
            }
        }
    }
    DetectorOutput {
        findings,
        package_evidence: Vec::new(),
        coverage,
    }
}

fn empty_git(coverage: DetectorCoverage) -> DetectorOutput {
    DetectorOutput {
        findings: Vec::new(),
        package_evidence: Vec::new(),
        coverage,
    }
}

/// Map a Git availability probe onto [`scan_git`].
///
/// Git has no Unsupported coverage state: only `Missing` is Skipped. Any other
/// non-successful probe, including [`ToolProbe::Unsupported`], is Partial.
pub fn scan_git_with_probe(repos: &[PathBuf], probe: ToolProbe) -> DetectorOutput {
    scan_git_with_progress(repos, probe, &NoProgress)
}

pub fn scan_git_with_progress(
    repos: &[PathBuf],
    probe: ToolProbe,
    progress: &dyn Progress,
) -> DetectorOutput {
    match probe {
        ToolProbe::Present => scan_git_with_program(repos, Some(Path::new("git")), progress),
        ToolProbe::Missing => scan_git_with_program(repos, None, progress),
        ToolProbe::Failed | ToolProbe::Unsupported => {
            let mut coverage = DetectorCoverage::attempted(DET_GIT_HISTORY);
            coverage.record_artifact(PathBuf::from("git"), ArtifactStatus::Unreadable);
            empty_git(coverage)
        }
    }
}

pub fn system_git() -> ToolProbe {
    let mut cmd = Command::new("git");
    cmd.arg("--version");
    classify_probe(&run_bounded(cmd, Duration::from_secs(5), 4096))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_malformed_lines() {
        let stdout = "deadbeef\t2026-08-05T12:00:00Z\tclaude\tclaude@users.noreply.github.com\tchore: update config\nbadline\n";
        let commits = parse_git_log(stdout);
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].subject, "chore: update config");
    }

    #[test]
    fn display_name_is_not_required_for_high() {
        let commit = GitCommit {
            commit: "abc".into(),
            when: "2026-08-05T12:00:00Z".into(),
            author: "not-claude".into(),
            email: "claude@users.noreply.github.com".into(),
            subject: "chore: update config".into(),
        };
        let findings = findings_from_commits(Path::new("/tmp/repo"), &[commit]);
        assert_eq!(findings[0].code.as_str(), "malicious-git-signature");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn email_only_is_medium() {
        let commit = GitCommit {
            commit: "abc".into(),
            when: "when".into(),
            author: "claude".into(),
            email: "Claude@users.noreply.github.com".into(),
            subject: "unrelated".into(),
        };
        let findings = findings_from_commits(Path::new("/tmp/repo"), &[commit]);
        assert_eq!(findings[0].code.as_str(), "suspicious-git-author");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn unavailable_git_is_skipped() {
        let output = scan_git(&[PathBuf::from("/tmp/repo")], None);
        assert_eq!(
            output.coverage.status(),
            crate::coverage::CoverageStatus::Skipped
        );
        assert!(output.findings.is_empty());
    }

    #[test]
    fn probe_missing_is_skipped_and_non_missing_failure_is_partial() {
        let missing = scan_git_with_probe(&[PathBuf::from("/tmp/repo")], ToolProbe::Missing);
        assert_eq!(
            missing.coverage.status(),
            crate::coverage::CoverageStatus::Skipped
        );
        let failed = scan_git_with_probe(&[PathBuf::from("/tmp/repo")], ToolProbe::Failed);
        assert_eq!(
            failed.coverage.status(),
            crate::coverage::CoverageStatus::Partial
        );
        assert!(failed.findings.is_empty());
        let classified_unsupported =
            scan_git_with_probe(&[PathBuf::from("/tmp/repo")], ToolProbe::Unsupported);
        assert_eq!(
            classified_unsupported.coverage.status(),
            crate::coverage::CoverageStatus::Partial
        );
        assert!(classified_unsupported.findings.is_empty());
    }
}
