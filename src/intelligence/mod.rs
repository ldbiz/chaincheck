//! Generic npm and PyPI malware intelligence.
//!
//! Feeds are fetched, parsed, and stored independently. An unavailable feed
//! has no [`MalwareIndex`]; callers must not treat that as an empty clean database.

mod fetch;
mod parse;

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

use crate::coverage::{ArtifactStatus, DetectorCoverage, DetectorId};
use crate::model::{Ecosystem, PackageIdentity, PackageKey, PackageVersion};
use crate::progress::{NoProgress, Progress};

pub use fetch::{FETCH_TIMEOUT, fetch_feed_url};
pub use parse::parse_malware_feed;

pub const MAX_FEED_BYTES: u64 = 50 * 1024 * 1024;
pub const NPM_MALWARE_FEED_URL: &str = "https://malware-list.aikido.dev/malware_predictions.json";
pub const PYPI_MALWARE_FEED_URL: &str = "https://malware-list.aikido.dev/malware_pypi.json";

pub const DET_NPM_INTELLIGENCE: DetectorId = DetectorId::from_static("npm-intelligence");
pub const DET_PYPI_INTELLIGENCE: DetectorId = DetectorId::from_static("pypi-intelligence");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchLimits {
    pub max_body_bytes: u64,
    pub timeout: std::time::Duration,
}

impl FetchLimits {
    pub fn production() -> Self {
        Self {
            max_body_bytes: MAX_FEED_BYTES,
            timeout: FETCH_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedFailure {
    Network,
    Timeout,
    OversizedResponse,
    InvalidJson,
    InvalidTopLevel,
    NoValidMalwareRecords,
}

impl fmt::Display for FeedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Network => "network error",
            Self::Timeout => "timeout",
            Self::OversizedResponse => "response exceeds size limit",
            Self::InvalidJson => "invalid JSON",
            Self::InvalidTopLevel => "invalid top-level JSON",
            Self::NoValidMalwareRecords => "no valid MALWARE records",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeedState {
    Available {
        accepted_records: usize,
        rejected_malformed: usize,
        rejected_non_malware: usize,
        etag: Option<String>,
    },
    Unavailable(FeedFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalwareMatch {
    Exact,
    Wildcard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntelligenceProvenance {
    Live,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalwareIndex {
    ecosystem: Ecosystem,
    pub(crate) exact: HashSet<PackageKey>,
    pub(crate) wildcard: HashSet<PackageIdentity>,
}

impl MalwareIndex {
    pub(crate) fn new(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            exact: HashSet::new(),
            wildcard: HashSet::new(),
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    pub fn matches(
        &self,
        identity: &PackageIdentity,
        version: Option<&PackageVersion>,
    ) -> Option<MalwareMatch> {
        if identity.ecosystem() != self.ecosystem {
            return None;
        }
        if let Some(version) = version {
            let key = PackageKey::new(identity.clone(), version.clone());
            if self.exact.contains(&key) {
                return Some(MalwareMatch::Exact);
            }
        }
        if self.wildcard.contains(identity) {
            Some(MalwareMatch::Wildcard)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableFeed {
    pub(crate) index: MalwareIndex,
    pub(crate) accepted_records: usize,
    pub(crate) rejected_malformed: usize,
    pub(crate) rejected_non_malware: usize,
    pub(crate) etag: Option<String>,
    pub(crate) provenance: IntelligenceProvenance,
}

impl AvailableFeed {
    pub fn index(&self) -> &MalwareIndex {
        &self.index
    }

    pub fn accepted_records(&self) -> usize {
        self.accepted_records
    }

    pub fn rejected_malformed(&self) -> usize {
        self.rejected_malformed
    }

    pub fn rejected_non_malware(&self) -> usize {
        self.rejected_non_malware
    }

    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    pub fn provenance(&self) -> &IntelligenceProvenance {
        &self.provenance
    }

    pub(crate) fn with_etag(mut self, etag: Option<String>) -> Self {
        self.etag = etag;
        self
    }

    pub(crate) fn with_provenance(mut self, provenance: IntelligenceProvenance) -> Self {
        self.provenance = provenance;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcosystemIntelligence {
    Available(AvailableFeed),
    Unavailable(FeedFailure),
}

impl EcosystemIntelligence {
    pub fn lookup(
        &self,
        identity: &PackageIdentity,
        version: Option<&PackageVersion>,
    ) -> Result<Option<MalwareMatch>, FeedFailure> {
        match self {
            Self::Available(feed) => Ok(feed.index.matches(identity, version)),
            Self::Unavailable(failure) => Err(*failure),
        }
    }

    pub fn feed_state(&self) -> FeedState {
        match self {
            Self::Available(feed) => FeedState::Available {
                accepted_records: feed.accepted_records,
                rejected_malformed: feed.rejected_malformed,
                rejected_non_malware: feed.rejected_non_malware,
                etag: feed.etag.clone(),
            },
            Self::Unavailable(failure) => FeedState::Unavailable(*failure),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntelligenceSnapshot {
    pub npm: EcosystemIntelligence,
    pub pypi: EcosystemIntelligence,
    pub coverage: Vec<DetectorCoverage>,
}

impl IntelligenceSnapshot {
    pub fn new(npm: EcosystemIntelligence, pypi: EcosystemIntelligence) -> Self {
        Self {
            npm,
            pypi,
            coverage: Vec::new(),
        }
    }

    pub fn required_generic_available(&self) -> bool {
        ecosystem_is_current(&self.npm) && ecosystem_is_current(&self.pypi)
    }
}

fn ecosystem_is_current(intel: &EcosystemIntelligence) -> bool {
    matches!(intel, EcosystemIntelligence::Available(_))
}

pub(crate) fn synthesize_coverage(
    ecosystem: Ecosystem,
    intel: &EcosystemIntelligence,
) -> DetectorCoverage {
    let detector = match ecosystem {
        Ecosystem::Npm => DET_NPM_INTELLIGENCE,
        Ecosystem::Pypi => DET_PYPI_INTELLIGENCE,
    };
    let feed_label = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
    };

    match intel {
        EcosystemIntelligence::Available(_) => DetectorCoverage::attempted(detector),
        EcosystemIntelligence::Unavailable(failure) => {
            let mut coverage = DetectorCoverage::attempted(detector);
            coverage.record_artifact(
                PathBuf::from(format!("intelligence/{feed_label}")),
                ArtifactStatus::ParseFailed,
            );
            coverage.set_detail(failure.to_string());
            coverage
        }
    }
}

/// Live npm and PyPI fetches. No persistent cache and no offline fallback.
pub fn load_generic_intelligence() -> IntelligenceSnapshot {
    load_generic_intelligence_with_progress(&NoProgress)
}

/// Live npm and PyPI fetches, reporting each feed as a progress stage.
pub fn load_generic_intelligence_with_progress(progress: &dyn Progress) -> IntelligenceSnapshot {
    load_generic_intelligence_from_with_progress(
        NPM_MALWARE_FEED_URL,
        PYPI_MALWARE_FEED_URL,
        FetchLimits::production(),
        progress,
    )
}

/// Uncached direct fetch of both feeds.
pub fn load_generic_intelligence_from(
    npm_url: &str,
    pypi_url: &str,
    limits: FetchLimits,
) -> IntelligenceSnapshot {
    load_generic_intelligence_from_with_progress(npm_url, pypi_url, limits, &NoProgress)
}

fn load_generic_intelligence_from_with_progress(
    npm_url: &str,
    pypi_url: &str,
    limits: FetchLimits,
    progress: &dyn Progress,
) -> IntelligenceSnapshot {
    progress.stage("Fetching npm intelligence");
    let npm = fetch_feed_url(npm_url, Ecosystem::Npm, limits);
    progress.stage("Fetching PyPI intelligence");
    let pypi = fetch_feed_url(pypi_url, Ecosystem::Pypi, limits);
    let coverage = vec![
        synthesize_coverage(Ecosystem::Npm, &npm),
        synthesize_coverage(Ecosystem::Pypi, &pypi),
    ];
    IntelligenceSnapshot {
        npm,
        pypi,
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    const VALID_NPM: &str = include_str!("../../tests/fixtures/feeds/valid-npm.json");
    const VALID_PYPI: &str = include_str!("../../tests/fixtures/feeds/valid-pypi.json");

    fn tiny_limits(max_body_bytes: u64, timeout_ms: u64) -> FetchLimits {
        FetchLimits {
            max_body_bytes,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[test]
    fn lookup_distinguishes_unavailable_from_no_match() {
        let available = EcosystemIntelligence::Available(
            parse_malware_feed(VALID_NPM.as_bytes(), Ecosystem::Npm).unwrap(),
        );
        let unavailable = EcosystemIntelligence::Unavailable(FeedFailure::Network);
        assert_eq!(
            available.lookup(
                &PackageIdentity::npm("not-listed"),
                Some(&PackageVersion::exact("1.0.0")),
            ),
            Ok(None)
        );
        assert_eq!(
            unavailable.lookup(
                &PackageIdentity::npm("not-listed"),
                Some(&PackageVersion::exact("1.0.0")),
            ),
            Err(FeedFailure::Network)
        );
    }

    #[test]
    fn snapshot_states_are_independent() {
        let npm_ok = EcosystemIntelligence::Available(
            parse_malware_feed(VALID_NPM.as_bytes(), Ecosystem::Npm).unwrap(),
        );
        let pypi_ok = EcosystemIntelligence::Available(
            parse_malware_feed(VALID_PYPI.as_bytes(), Ecosystem::Pypi).unwrap(),
        );
        let npm_bad = EcosystemIntelligence::Unavailable(FeedFailure::Timeout);
        let pypi_bad = EcosystemIntelligence::Unavailable(FeedFailure::InvalidJson);

        let both = IntelligenceSnapshot {
            npm: npm_ok.clone(),
            pypi: pypi_ok.clone(),
            coverage: vec![],
        };
        assert!(both.required_generic_available());

        let npm_only = IntelligenceSnapshot {
            npm: npm_ok.clone(),
            pypi: pypi_bad.clone(),
            coverage: vec![],
        };
        assert!(!npm_only.required_generic_available());
        assert!(matches!(npm_only.npm, EcosystemIntelligence::Available(_)));
        assert_eq!(
            npm_only.pypi.feed_state(),
            FeedState::Unavailable(FeedFailure::InvalidJson)
        );

        let pypi_only = IntelligenceSnapshot {
            npm: npm_bad.clone(),
            pypi: pypi_ok.clone(),
            coverage: vec![],
        };
        assert!(!pypi_only.required_generic_available());
        assert!(matches!(
            pypi_only.pypi,
            EcosystemIntelligence::Available(_)
        ));

        let neither = IntelligenceSnapshot {
            npm: npm_bad,
            pypi: pypi_bad,
            coverage: vec![],
        };
        assert!(!neither.required_generic_available());
        assert!(matches!(neither.npm, EcosystemIntelligence::Unavailable(_)));
        assert!(matches!(
            neither.pypi,
            EcosystemIntelligence::Unavailable(_)
        ));
    }

    struct Served {
        url: String,
        handle: thread::JoinHandle<()>,
    }

    fn serve_http(
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
        chunked: bool,
        stall: bool,
    ) -> Served {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let body = body.to_vec();
        let handle = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut tmp = [0u8; 1024];
            let mut req = Vec::new();
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&tmp[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if stall {
                thread::sleep(Duration::from_millis(800));
                return;
            }
            let reason = match status {
                200 => "OK",
                304 => "Not Modified",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Error",
            };
            let mut head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
            if chunked {
                head.push_str("Transfer-Encoding: chunked\r\n");
                for (k, v) in &headers {
                    if !k.eq_ignore_ascii_case("content-length") {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = write!(stream, "{:x}\r\n", body.len());
                let _ = stream.write_all(&body);
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            } else {
                let mut has_len = false;
                for (k, v) in &headers {
                    if k.eq_ignore_ascii_case("content-length") {
                        has_len = true;
                    }
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                if !has_len && status != 304 {
                    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                if status != 304 {
                    let _ = stream.write_all(&body);
                }
            }
            let _ = stream.flush();
        });
        Served {
            url: format!("http://{addr}/feed"),
            handle,
        }
    }

    fn join(served: Served) {
        let _ = served.handle.join();
    }

    #[test]
    fn load_attempts_both_feeds_when_npm_fails() {
        let pypi = serve_http(200, &[], VALID_PYPI.as_bytes(), false, false);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let npm_addr = listener.local_addr().unwrap();
        drop(listener);
        let npm_url = format!("http://{npm_addr}/feed");
        let snap = load_generic_intelligence_from(&npm_url, &pypi.url, tiny_limits(4096, 2_000));
        join(pypi);
        assert!(matches!(
            snap.npm,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        ));
        match &snap.pypi {
            EcosystemIntelligence::Available(feed) => {
                assert!(feed.accepted_records() > 0);
            }
            other => panic!("PyPI should still load, got {other:?}"),
        }
        assert!(!snap.required_generic_available());
    }

    #[test]
    fn load_attempts_both_feeds_when_pypi_fails() {
        let npm = serve_http(200, &[], VALID_NPM.as_bytes(), false, false);
        let pypi = serve_http(500, &[], b"nope", false, false);
        let snap = load_generic_intelligence_from(&npm.url, &pypi.url, tiny_limits(4096, 2_000));
        join(npm);
        join(pypi);
        assert!(matches!(snap.npm, EcosystemIntelligence::Available(_)));
        assert_eq!(
            snap.pypi,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        );
        assert!(!snap.required_generic_available());
    }

    #[test]
    fn load_retains_independent_failures() {
        let npm = serve_http(500, &[], b"npm-fail", false, false);
        let pypi = serve_http(200, &[], b"{", false, false);
        let snap = load_generic_intelligence_from(&npm.url, &pypi.url, tiny_limits(4096, 2_000));
        join(npm);
        join(pypi);
        assert_eq!(
            snap.npm,
            EcosystemIntelligence::Unavailable(FeedFailure::Network)
        );
        assert_eq!(
            snap.pypi,
            EcosystemIntelligence::Unavailable(FeedFailure::InvalidJson)
        );
    }

    #[test]
    fn load_both_available() {
        let npm = serve_http(200, &[], VALID_NPM.as_bytes(), false, false);
        let pypi = serve_http(200, &[], VALID_PYPI.as_bytes(), false, false);
        let snap = load_generic_intelligence_from(&npm.url, &pypi.url, tiny_limits(4096, 2_000));
        join(npm);
        join(pypi);
        assert!(snap.required_generic_available());
    }
}
