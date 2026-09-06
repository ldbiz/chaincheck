//! End-to-end CLI, report, and binary self-test paths.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chaincheck::campaign::CampaignIntelligence;
use chaincheck::cli::ProcessConfig;
use chaincheck::error::StartError;
use chaincheck::intelligence::{
    EcosystemIntelligence, FeedFailure, IntelligenceSnapshot, parse_malware_feed,
};
use chaincheck::model::{Ecosystem, Severity};
use chaincheck::report::{PRIVACY_WARNING, write_reports};
use chaincheck::scan::{
    HostDetectorOutputs, ScanOutcome, ScanScope, normal_scan_exit, scan_with_host_outputs,
};

const NPM: &[u8] = br#"[{"package_name":"keyv","version":"6.0.0","reason":"MALWARE"}]"#;
const PYPI: &[u8] = br#"[{"package_name":"evil-pkg","version":"1.2.3","reason":"MALWARE"}]"#;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn tmp() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "chaincheck-cli-int-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn snap(npm_ok: bool, pypi_ok: bool) -> IntelligenceSnapshot {
    IntelligenceSnapshot::new(
        if npm_ok {
            EcosystemIntelligence::Available(parse_malware_feed(NPM, Ecosystem::Npm).unwrap())
        } else {
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        },
        if pypi_ok {
            EcosystemIntelligence::Available(parse_malware_feed(PYPI, Ecosystem::Pypi).unwrap())
        } else {
            EcosystemIntelligence::Unavailable(FeedFailure::Timeout)
        },
    )
}

fn write(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn scan_tree(
    root: PathBuf,
    home: Option<&std::path::Path>,
    intel: IntelligenceSnapshot,
) -> chaincheck::scan::ScanResult {
    scan_with_host_outputs(
        ScanScope::ExplicitRoot { root },
        &ProcessConfig::default(),
        home,
        intel,
        &CampaignIntelligence::bundled(),
        HostDetectorOutputs::skipped(),
    )
}

#[test]
fn clean_both_intel_exit_zero_writes_reports() {
    let base = tmp();
    let root = base.join("project");
    let reports = base.join("reports");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&reports).unwrap();
    write(
        &root.join("package-lock.json"),
        r#"{"name":"clean","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"clean","version":"1.0.0"}}}"#,
    );
    let result = scan_tree(root, None, snap(true, true));
    assert_eq!(result.outcome, ScanOutcome::Clean);
    assert_eq!(normal_scan_exit(result.outcome), 0);
    let written = write_reports(&result, &reports).unwrap();
    assert!(written.summary.exists());
    assert!(written.findings_tsv.exists());
    let summary = fs::read_to_string(&written.summary).unwrap();
    assert!(summary.contains(PRIVACY_WARNING));
    assert!(summary.contains("npm intelligence: available"));
    assert!(summary.contains("PyPI intelligence: available"));
    assert!(summary.contains("Evidence findings"));
    assert!(summary.contains("npm coverage"));
    assert!(summary.contains("Python/PyPI coverage"));
    let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
    assert!(tsv.starts_with("severity\tcategory\tlocation\tdetail\n"));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn medium_lockfile_exit_one() {
    let base = tmp();
    let root = base.join("project");
    write(
        &root.join("package-lock.json"),
        r#"{
  "name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0"},
    "node_modules/keyv": {"version": "6.0.0"}
  }
}"#,
    );
    let result = scan_tree(root, None, snap(true, true));
    assert_eq!(normal_scan_exit(result.outcome), 1);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn high_installed_exit_two() {
    let base = tmp();
    let root = base.join("project");
    write(
        &root.join("node_modules/keyv/package.json"),
        r#"{"name":"keyv","version":"6.0.0"}"#,
    );
    let result = scan_tree(root, None, snap(true, true));
    assert_eq!(normal_scan_exit(result.outcome), 2);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn clean_npm_unavailable_exit_four() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    let result = scan_tree(root, None, snap(false, true));
    assert_eq!(normal_scan_exit(result.outcome), 4);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn clean_pypi_unavailable_exit_four() {
    let base = tmp();
    let root = base.join("project");
    fs::create_dir_all(&root).unwrap();
    let result = scan_tree(root, None, snap(true, false));
    assert_eq!(normal_scan_exit(result.outcome), 4);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn findings_beat_degraded_intel() {
    let base = tmp();
    let root = base.join("project");
    write(
        &root.join("package-lock.json"),
        r#"{
  "name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "fixture", "version": "1.0.0"},
    "node_modules/keyv": {"version": "6.0.0"}
  }
}"#,
    );
    let result = scan_tree(root, None, snap(true, false));
    assert_eq!(normal_scan_exit(result.outcome), 1);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn malformed_artefact_is_coverage_not_tsv_finding() {
    let base = tmp();
    let root = base.join("project");
    let reports = base.join("reports");
    fs::create_dir_all(&reports).unwrap();
    write(&root.join("package-lock.json"), "{ nope");
    let result = scan_tree(root, None, snap(true, true));
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.code.as_str() != "parse-error")
    );
    let written = write_reports(&result, &reports).unwrap();
    let tsv = fs::read_to_string(&written.findings_tsv).unwrap();
    assert!(!tsv.contains("parse-error"));
    let summary = fs::read_to_string(&written.summary).unwrap();
    assert!(summary.contains("[partial") || summary.to_lowercase().contains("partial"));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn explicit_root_does_not_walk_sibling_home() {
    let base = tmp();
    let home = base.join("home");
    let project = base.join("project");
    write(
        &home.join("node_modules/keyv/package.json"),
        r#"{"name":"keyv","version":"6.0.0"}"#,
    );
    fs::create_dir_all(&project).unwrap();
    write(&project.join("README"), "ok");
    let result = scan_tree(project, Some(&home), snap(true, true));
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.severity != Severity::High || f.code.as_str() != "installed-package")
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn report_write_failed_is_exit_three() {
    let base = tmp();
    let root = base.join("project");
    let reports = base.join("reports");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&reports).unwrap();
    fs::create_dir_all(reports.join("findings.tsv")).unwrap();
    let result = scan_tree(root, None, snap(true, true));
    let err = write_reports(&result, &reports).unwrap_err();
    assert!(matches!(err, StartError::ReportWriteFailed { .. }));
    assert_eq!(err.exit_code(), 3);
    let _ = fs::remove_dir_all(&base);
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chaincheck"))
}

#[test]
fn binary_help_exits_zero_and_is_not_foundation() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("rewrite foundation"));
    assert!(!stdout.contains("not the production scanner"));
    assert!(stdout.contains("chaincheck --self-test"));
    assert!(stdout.contains("CHAINCHECK_NO_PROGRESS"));
    assert!(stdout.contains("progress bar"));
}

#[test]
fn binary_unknown_option_exits_64() {
    let status = Command::new(bin())
        .arg("--chaincheck-oracle-not-an-option")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(64));
}

#[test]
fn binary_root_plus_self_test_exits_64() {
    let status = Command::new(bin())
        .args([".", "--self-test"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(64));
}

#[test]
fn binary_missing_root_exits_3() {
    let status = Command::new(bin())
        .arg("/chaincheck-oracle-nonexistent-root-9f3c2a")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
}

#[test]
fn binary_self_test_passes() {
    let out = Command::new(bin())
        .arg("--self-test")
        .output()
        .expect("self-test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "self-test failed: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("SELF-TEST ONLY"));
    assert!(stdout.contains("self-test passed"));
}

#[test]
fn binary_self_test_from_other_cwd() {
    let tmp = std::env::temp_dir();
    let out = Command::new(bin())
        .arg("--self-test")
        .current_dir(&tmp)
        .output()
        .expect("self-test other cwd");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "self-test from {tmp:?} failed: stdout={stdout} stderr={stderr}"
    );
}
