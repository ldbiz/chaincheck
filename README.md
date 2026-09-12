# ChainCheck

## What ChainCheck is

ChainCheck is a **Linux/WSL scanner** that retrospectively examines local package-manager, filesystem and related evidence for signs of known malicious software supply-chain activity. It applies [Aikido's open malware intelligence](https://github.com/AikidoSec/safe-chain) to npm and Python/PyPI artefacts and adds narrowly scoped checks for documented ChainDrop/Shai-Hulud campaign artefacts.

Aikido Security supplies the generic intelligence; ChainCheck independently applies it and is not affiliated with or endorsed by Aikido. ChainCheck is not a general antivirus, CVE scanner, SBOM generator, or remediation tool.

ChainCheck does not replace tools such as npm audit, OSV-Scanner or other dependency scanners. These tools primarily identify known problems in project dependencies. ChainCheck additionally examines evidence left on the developer system itself, to help determine whether a known malicious package may actually have been downloaded or installed.

## Install

ChainCheck is Linux/WSL only. None of these options edit `PATH` or shell profiles. If `~/.local/bin` is not already on your `PATH`, add it yourself or invoke the binary by path.

### Download a release

The current release is [0.1.2](https://github.com/ldbiz/chaincheck/releases/tag/v0.1.2).

Supported GNU Linux binaries:

| Architecture | Release asset |
|---|---|
| `x86_64` / `amd64` | `chaincheck-linux-x86_64` |
| `aarch64` / `arm64` | `chaincheck-linux-aarch64` |

Release binaries require **glibc 2.39 or newer** (Ubuntu 24.04 and equivalent). They are built on Ubuntu 24.04 runners; musl/static binaries are out of scope. On older distros (for example Ubuntu 22.04 or RHEL 9), use [build from source](#build-from-source-with-cargo) or the [install script](#install-script) on that machine instead.

If a downloaded release fails with `GLIBC_2.39 not found`, your host glibc is too old for the prebuilt binary — build from source on that host.

```bash
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) asset=chaincheck-linux-x86_64 ;;
  aarch64|arm64) asset=chaincheck-linux-aarch64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
curl -fsSL -O "https://github.com/ldbiz/chaincheck/releases/latest/download/${asset}"
curl -fsSL -O "https://github.com/ldbiz/chaincheck/releases/latest/download/${asset}.sha256"
sha256sum -c "${asset}.sha256"
chmod +x "$asset"
mkdir -p ~/.local/bin
mv "$asset" ~/.local/bin/chaincheck
```

### Build from source with Cargo

Requires Rust 1.98 (the repository pins this in `rust-toolchain.toml` for rustup).

```bash
git clone https://github.com/ldbiz/chaincheck.git
cd chaincheck
cargo build --locked --release
mkdir -p ~/.local/bin
cp target/release/chaincheck ~/.local/bin/chaincheck
chmod +x ~/.local/bin/chaincheck
```

After copying the binary, the source checkout is not required to run ChainCheck. The checkout contains deliberately malicious-looking synthetic fixtures for testing; a later system-wide scan can find those fixtures if you leave the checkout under a scanned root. Keep the checkout if you are developing ChainCheck; otherwise it may be removed after installation.

### Install script

The script runs the same Cargo build and copies the binary to `~/.local/bin/chaincheck`. It does not download a prebuilt release. Use this when the release binary does not match your host glibc. Requires `git` and `cargo`.

```bash
curl -fsSL https://raw.githubusercontent.com/ldbiz/chaincheck/main/scripts/install.sh | bash
```

From a clone, run `./scripts/install.sh` instead. When run from an existing checkout, the script reminds you that the checkout is not required by the installed binary and that its synthetic fixtures can appear in system-wide scans. The one-line `curl` form uses a temporary clone and removes it automatically when installation completes.

## Basic usage

```bash
chaincheck
chaincheck /path/to/project
chaincheck --help
```

With no path, the ordinary filesystem walk covers `$HOME` plus applicable configured/discovered npm prefix locations and existing common Linux global-module directories. Whole-user scans also perform targeted discovery of installed Python environments (system library prefixes, pipx, uv tool environments, Poetry virtualenvs, and other currently supported host roots). An explicit path limits **the filesystem walk** to that directory and does not add unrelated installed Python environments; host-level cache/log and credential-inventory checks still run, including the pip wheel cache. Each scan writes a new `$HOME/chaincheck-<UTC-timestamp>/` report unless `CHAINCHECK_REPORT_DIR` is set. Reports contain local filesystem paths; review them before sharing.

ChainCheck may make ordinary outbound HTTPS requests to its documented Aikido malware feeds and may write its own reports. It does not alter network, DNS, firewall, package-manager, Git, credential, or shell configuration.

## Self-test

```bash
chaincheck --self-test
```

`--self-test` tests ChainCheck itself against synthetic fixtures; it is **not a malware scan**. Expected fixture `HIGH`/`CONFIRMED` messages do not describe this host.

## Result interpretation

- **No known malware evidence found:** requested intelligence loaded and no MEDIUM/HIGH/CONFIRMED evidence was found; this is not proof of safety.
- **Review recommended:** MEDIUM evidence needs manual interpretation.
- **Action recommended:** HIGH/CONFIRMED is strong evidence requiring investigation, but evidence presence does not necessarily prove payload execution.
- **Incomplete scan:** required Aikido intelligence was unavailable or invalid, so an otherwise-clean scan cannot be reported as clean.

If a finding is under a recognized ChainCheck source tree's `tests/fixtures` directory, ChainCheck keeps the finding and its normal severity. When every evidence finding is a likely fixture, the report headline adds **`see ChainCheck fixture note below`**. If some evidence is not identified as a ChainCheck fixture, the headline instead says **`including N evidence finding(s) not identified as a ChainCheck fixture; see ChainCheck fixture note below`**, so fixture files cannot be read as explaining the whole result. Console evidence lines for recognized fixtures are tagged **`[likely ChainCheck fixture]`**. The note explains that the source repository deliberately contains synthetic malware evidence and separately counts likely fixture findings and evidence findings not identified as ChainCheck fixtures. This is annotation only: it does not suppress findings, weaken matching, or change the scan exit code. If the path is not one you recognize as ChainCheck test data, investigate it normally.

## Retrospective checking is not ongoing protection

ChainCheck looks retrospectively at local evidence that remains available. It does not intercept package installs and provides no real-time protection. For preventive protection during future package installations, see upstream [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain). ChainCheck does not replace Safe Chain or Aikido's broader products.

## Use with other security scanners

The ChainCheck source repository contains test fixtures that deliberately resemble malicious packages and campaign artefacts. ChainCheck and other security scanners may report these files when the repository is present on the system.

Normal ChainCheck releases contain only the compiled executable and do not install these fixture files.

`chaincheck --self-test` creates temporary synthetic fixtures and removes them when the test completes. A real-time endpoint security product may detect these temporary test files while the self-test is running.

Do not dismiss a finding only because ChainCheck is installed. Treat it as a test fixture only when its path clearly identifies the ChainCheck source tree or a ChainCheck self-test temporary directory.

## Technical coverage

### Generic npm and PyPI malware intelligence

At scan time ChainCheck downloads Aikido's JavaScript and PyPI malware feeds independently, subject to a defensive response-size limit, without persisting them. It loads only records whose `reason` is `MALWARE` (case-insensitive); `TELEMETRY`, `PROTESTWARE`, and other reasons are excluded. Exact `(package_name, version)` records and `version == "*"` wildcards use indexed lookups. There is no embedded feed, offline fallback, persistent cache, second intelligence source, or new-package/release-age feed.

npm intelligence is checked against:

- installed `node_modules` package metadata;
- exact identities/declarations in `package.json` (ranges do not become exact versions; wildcard intelligence still applies);
- `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, and text `bun.lock`;
- npm cacache index records and available npm debug/install/reification logs.

Binary `bun.lockb` is reported as unsupported rather than claiming content coverage.

PyPI intelligence is checked against:

- installed `.dist-info` metadata;
- `pyproject.toml`, requirements files, Pipfile, and `setup.cfg`;
- pylock, uv.lock, Poetry lock, Pipfile.lock, and PDM lock;
- pip wheel-cache filenames.

Relevant unreadable, oversized, or unparseable manifests/lockfiles and unreadable/oversized cache/log files make the corresponding detector coverage `partial`; reports show per-detector artefact totals where applicable and only bounded representative failure paths. They are not malware findings. Directory-walk errors likewise make filesystem coverage partial.

A cache hit proves download to this host, not lifecycle execution. A lockfile proves resolution, not installation. npm cache content blobs use tarball sha512/sha1 integrity, not the campaign payload-file SHA-256 values, so ChainCheck matches cache index registry URLs instead. Generic package Git-history searching is intentionally omitted.

### Fixed campaign-specific indicators

The additional ChainDrop/Shai-Hulud indicators are a **fixed bundled set derived from documented Aikido Safe Chain incident intelligence**, last reviewed **2026-08-29**. Unlike generic npm/PyPI intelligence, these constants are not remotely updated: changes to the known campaign indicator set require a ChainCheck update. Their absence does not prove the campaign never executed.

Checks include known payload filenames (`setup.mjs`, `Math_Symbol.js`, `math_init.js`) and exact published file hashes; narrow payload/config content, exfiltration-domain, contract/marker and contextual NodeReal indicators; `.vscode/tasks.json` and `.claude/settings.json`; hosts/DNS context; and the exact reported Git author/message propagation signature. This is not a filesystem-wide hash sweep, so renamed or deleted artefacts may be missed.

An exact reported Git author/message signature remains HIGH: it is strong campaign evidence requiring investigation, but does not by itself prove payload execution on the current host. Author-email-only context remains MEDIUM.

### Evidence and corroboration

Severity describes strength of local evidence, not malware severity:

| Severity | Meaning |
|---|---|
| `CONFIRMED` | Known campaign payload filename matches an exact published malicious hash. |
| `HIGH` | Strong local package evidence, genuine install context, independently corroborated evidence, or a strong narrow campaign artefact. |
| `MEDIUM` | Evidence needing review, such as a resolved lockfile, cache download, non-install-context log, or contextual campaign indicator. |
| `EXPOSURE` / `INFO` | Non-evidentiary inventory/context; does not affect exit status. |

Independent package evidence can corroborate a malware-listed version only when at least two source classes agree and one is host-local (`installed`, npm cache, or npm log). Multiple declarative references alone do not escalate. Existing direct HIGH evidence suppresses redundant corroborated HIGH output.

### Degraded intelligence and exit codes

If a live Aikido feed cannot be downloaded, exceeds the defensive size limit, is invalid JSON, or yields no valid MALWARE records, that ecosystem's generic coverage is unavailable. Campaign checks still run, the report is marked degraded, and an otherwise-clean result exits 4.

| Code | Meaning |
|---:|---|
| 0 | No MEDIUM/HIGH/CONFIRMED finding under available required intelligence. |
| 1 | MEDIUM finding requiring review. |
| 2 | HIGH or CONFIRMED finding. |
| 3 | Scan could not start. |
| 4 | Otherwise-clean scan with unavailable/invalid required intelligence. |
| 64 | Invalid command line. |

Finding codes 1/2 take precedence over 4 while the coverage warning remains in the report.

## Optional scheduled retrospective scans

A weekly cron job is one reasonable example for users who choose repeated retrospective checks. Use the absolute installed command path because cron commonly has a minimal PATH:

```cron
30 3 * * 0 /home/YOU/.local/bin/chaincheck >>/home/YOU/chaincheck-cron.log 2>&1
```

Do not set a fixed `CHAINCHECK_REPORT_DIR` in this example: the normal timestamped directories retain prior reports. This is periodic retrospective checking, not continuous or preventive protection.

## Credential inventory, privacy, and limitations

Credential files and credential-shaped environment variables are listed as `EXPOSURE` by existence only; contents are not inspected. Such files are normal and are not evidence of theft. They are an inventory for possible rotation only if stronger evidence establishes compromise.

ChainCheck cannot detect unknown malware merely because it is malicious, reconstruct deleted evidence, prove execution from package/cache/log evidence, provide durable process-attributed network history, or inspect remote CI/build machines. DNS inspection is limited to readable volatile systemd-resolved cache where available. Linux/WSL only is supported; scan each WSL distribution separately. Reports contain local paths and should be reviewed before sharing.

## Development / CI

```bash
cargo fmt --all -- --check
cargo test --locked
cargo build --locked --release
./target/release/chaincheck --self-test
```

`--self-test` also succeeds when invoked from outside the checkout. Branch CI artifacts are development snapshots, not the supported install path. Supported release binaries are published on version tags; see [Install](#install).

The frozen Python behavioural oracle (reference `8caa0f1934d8276cd7c56b546aa2579f5c96d1ce`) remains historical evidence in [`docs/python-oracle.md`](docs/python-oracle.md) and [`tests/cases.json`](tests/cases.json). Native tests consume that corpus; the Python implementation is not present.

The scanner does not install packages, run lifecycle scripts, modify scanned projects/npm/Git/credentials, intercept package managers, or remediate findings.
