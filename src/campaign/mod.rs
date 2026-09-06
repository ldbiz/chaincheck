//! ChainDrop/Shai-Hulud campaign detectors.
//!
//! Campaign findings use [`FindingSubject::Campaign`] and never write
//! [`PackageEvidence`]. Generic package corroboration is unchanged.

mod config;
mod content;
mod discover;
pub mod intelligence;
mod logs;
mod manifest;
mod payload;

use std::path::{Path, PathBuf};

use crate::coverage::DetectorId;
use crate::evidence::Finding;
use crate::model::{
    CampaignId, EvidenceKind, FindingCode, FindingSubject, IntelligenceSourceId, Severity,
};
use crate::scan::DetectorOutput;

pub use config::scan_ide_config;
pub use content::content_ioc_matches;
pub(crate) use discover::discover_campaign_with_progress;
pub use discover::{CampaignArtifacts, discover_campaign};
pub use intelligence::CampaignIntelligence;
pub use logs::ioc_findings_from_log_text;
pub use manifest::preinstall_hook_finding;
pub use payload::scan_payload;

pub const CAMPAIGN_FAMILY: &str = "ChainDrop/Shai-Hulud";

pub const DET_PAYLOAD: DetectorId = DetectorId::from_static("payload-file");
pub const DET_IDE_CONFIG: DetectorId = DetectorId::from_static("ide-config");
pub const DET_CAMPAIGN_WALK: DetectorId = DetectorId::from_static("campaign-walk");
pub const DET_GIT_HISTORY: DetectorId = DetectorId::from_static("git-history");
pub const DET_HOSTS_FILE: DetectorId = DetectorId::from_static("hosts-file");
pub const DET_DNS_CACHE: DetectorId = DetectorId::from_static("dns-cache");
pub const DET_CREDENTIALS: DetectorId = DetectorId::from_static("credentials");

pub const CODE_SUSPICIOUS_INSTALL_HOOK: FindingCode =
    FindingCode::from_static("suspicious-install-hook");
pub const CODE_MALWARE_HASH: FindingCode = FindingCode::from_static("malware-hash");
pub const CODE_PAYLOAD_PATTERN: FindingCode = FindingCode::from_static("payload-pattern");
pub const CODE_PREINSTALL_PAYLOAD_NAME: FindingCode =
    FindingCode::from_static("preinstall-payload-name");
pub const CODE_PAYLOAD_NAME: FindingCode = FindingCode::from_static("payload-name");
pub const CODE_MALICIOUS_CONFIG_CONTENT: FindingCode =
    FindingCode::from_static("malicious-config-content");
pub const CODE_CONFIG_IOC_REFERENCE: FindingCode = FindingCode::from_static("config-ioc-reference");
pub const CODE_CAMPAIGN_IOC_LOG: FindingCode = FindingCode::from_static("campaign-ioc-log");
pub const CODE_CONTEXT_IOC_LOG: FindingCode = FindingCode::from_static("context-ioc-log");
pub const CODE_MALICIOUS_GIT_SIGNATURE: FindingCode =
    FindingCode::from_static("malicious-git-signature");
pub const CODE_SUSPICIOUS_GIT_AUTHOR: FindingCode =
    FindingCode::from_static("suspicious-git-author");
pub const CODE_HOSTS_FILE_INDICATOR: FindingCode = FindingCode::from_static("hosts-file-indicator");
pub const CODE_DNS_CACHE_INDICATOR: FindingCode = FindingCode::from_static("dns-cache-indicator");
pub const CODE_CREDENTIAL_SOURCE: FindingCode = FindingCode::from_static("credential-source");
pub const CODE_CREDENTIAL_ENVIRONMENT: FindingCode =
    FindingCode::from_static("credential-environment");

pub const LIMIT_PAYLOAD: u64 = 10_000_000;
pub const LIMIT_PARENT_MANIFEST: u64 = 2_000_000;
pub const LIMIT_IDE_CONFIG: u64 = 5_000_000;
pub const LIMIT_HOSTS: u64 = 5_000_000;

pub fn campaign_id() -> CampaignId {
    CampaignId::new(CAMPAIGN_FAMILY)
}

pub fn campaign_finding(
    severity: Severity,
    kind: EvidenceKind,
    code: FindingCode,
    location: Option<PathBuf>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        kind,
        code,
        subject: FindingSubject::Campaign(campaign_id()),
        location,
        detail: detail.into(),
        intelligence_source: Some(IntelligenceSourceId::CampaignBundled),
    }
}

pub fn host_finding(
    severity: Severity,
    kind: EvidenceKind,
    code: FindingCode,
    location: Option<PathBuf>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        kind,
        code,
        subject: FindingSubject::Host,
        location,
        detail: detail.into(),
        intelligence_source: None,
    }
}

pub fn host_campaign_finding(
    severity: Severity,
    kind: EvidenceKind,
    code: FindingCode,
    location: Option<PathBuf>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        kind,
        code,
        subject: FindingSubject::Host,
        location,
        detail: detail.into(),
        intelligence_source: Some(IntelligenceSourceId::CampaignBundled),
    }
}

pub fn scan_campaign_artifacts(
    artifacts: &CampaignArtifacts,
    intel: &CampaignIntelligence,
) -> Vec<DetectorOutput> {
    vec![
        payload::scan_payloads(&artifacts.payloads, intel),
        config::scan_ide_configs(&artifacts.ide_configs),
        DetectorOutput {
            findings: Vec::new(),
            package_evidence: Vec::new(),
            coverage: artifacts.walk_coverage.clone(),
        },
    ]
}

pub fn is_ide_config_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    (name == "tasks.json" && path.components().any(|c| c.as_os_str() == ".vscode"))
        || (name == "settings.json" && path.components().any(|c| c.as_os_str() == ".claude"))
}
