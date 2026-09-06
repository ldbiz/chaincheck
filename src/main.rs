//! Native ChainCheck scanner.

use std::env;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use chaincheck::campaign::CampaignIntelligence;
use chaincheck::cli::{
    ParsedCli, ProcessConfig, ensure_report_dir, help_text, parse_args, resolve_invocation,
    resolve_report_dir,
};
use chaincheck::error::{ProcessExit, StartError};
use chaincheck::intelligence::load_generic_intelligence_with_progress;
use chaincheck::progress::{Progress, TerminalProgress};
use chaincheck::report::{console_brief, write_reports};
use chaincheck::scan::{ScanScope, ScanWorkPlan, scan_with_progress};
use chaincheck::self_test;

fn main() -> ExitCode {
    let code = run();
    ExitCode::from(u8::try_from(code).unwrap_or(3))
}

fn run() -> i32 {
    let argv: Vec<_> = env::args_os().skip(1).collect();
    match parse_args(&argv, ProcessConfig::from_env()) {
        Err(err) => {
            eprintln!("Error: {err}");
            eprint!("{}", help_text());
            ProcessExit::Usage(err).exit_code()
        }
        Ok(ParsedCli::Help) => {
            print!("{}", help_text());
            ProcessExit::Help.exit_code()
        }
        Ok(parsed) => {
            let home = env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from);
            match resolve_invocation(parsed, home.clone()) {
                Err(err) => {
                    eprintln!("Error: {err}");
                    ProcessExit::CouldNotStart(err).exit_code()
                }
                Ok(chaincheck::cli::Invocation::SelfTest) => {
                    let ok = self_test::run();
                    ProcessExit::SelfTest { ok }.exit_code()
                }
                Ok(chaincheck::cli::Invocation::Scan { scope, config }) => {
                    match run_scan(scope, config, home) {
                        Ok(code) => code,
                        Err(err) => {
                            eprintln!("Error: {err}");
                            ProcessExit::CouldNotStart(err).exit_code()
                        }
                    }
                }
            }
        }
    }
}

fn run_scan(
    scope: ScanScope,
    config: ProcessConfig,
    home: Option<PathBuf>,
) -> Result<i32, StartError> {
    let report_dir = resolve_report_dir(&config, home.as_deref(), SystemTime::now())?;
    ensure_report_dir(&report_dir)?;
    println!("Primary root: {}", primary_root(&scope));
    println!("Report:       {}", report_dir.display());
    println!();
    let progress = TerminalProgress::new(progress_enabled(&config));
    let plan = ScanWorkPlan::estimate_if_live(&scope, &config, home.as_deref(), &progress);
    progress.begin(plan.total);
    let intelligence = load_generic_intelligence_with_progress(&progress);
    let campaign = CampaignIntelligence::bundled();
    let result = scan_with_progress(
        scope,
        &config,
        home.as_deref(),
        intelligence,
        &campaign,
        &progress,
    );
    progress.stage("Writing reports");
    let written = write_reports(&result, &report_dir)?;
    progress.tick();
    progress.finish();
    print!("{}", console_brief(&result, &written));
    let code = ProcessExit::Scan(result.outcome).exit_code();
    println!("Scan exit code: {code}");
    println!("Report directory: {}", report_dir.display());
    Ok(code)
}

fn primary_root(scope: &ScanScope) -> String {
    match scope {
        ScanScope::WholeUser { home } => home.display().to_string(),
        ScanScope::ExplicitRoot { root } => root.display().to_string(),
    }
}

fn progress_enabled(config: &ProcessConfig) -> bool {
    !config.no_progress && io::stderr().is_terminal()
}
