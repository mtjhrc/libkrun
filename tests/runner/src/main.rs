use anyhow::Context;
use clap::Parser;
use nix::sys::resource::{getrlimit, setrlimit, Resource};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempdir::TempDir;
use test_cases::{test_cases, Test, TestCase, TestSetup};

#[derive(Clone, Copy, PartialEq)]
enum TestOutcome {
    Pass,
    Fail,
    Skip,
    XFail, // Expected failure (test failed as expected)
    XPass, // Unexpected pass (xfail test passed unexpectedly)
}

struct TestResult {
    name: String,
    outcome: TestOutcome,
    log_path: PathBuf,
}

fn get_test(name: &str) -> anyhow::Result<Box<dyn Test>> {
    let tests = test_cases();
    tests
        .into_iter()
        .find(|t| t.name() == name)
        .with_context(|| format!("No such test: {name}"))
        .map(|t| t.test)
}

fn start_vm(test_setup: TestSetup) -> anyhow::Result<()> {
    // Raise soft fd limit up to the hard limit
    let (_soft_limit, hard_limit) =
        getrlimit(Resource::RLIMIT_NOFILE).context("getrlimit RLIMIT_NOFILE")?;
    setrlimit(Resource::RLIMIT_NOFILE, hard_limit, hard_limit)
        .context("setrlimit RLIMIT_NOFILE")?;

    let test = get_test(&test_setup.test_case)?;
    test.start_vm(test_setup.clone())
        .with_context(|| format!("testcase: {test_setup:?}"))?;
    Ok(())
}

fn run_single_test(
    test_case: &TestCase,
    base_dir: &Path,
    keep_all: bool,
    max_name_len: usize,
) -> anyhow::Result<TestResult> {
    let executable = env::current_exe().context("Failed to detect current executable")?;
    let test_dir = base_dir.join(test_case.name);
    fs::create_dir(&test_dir).context("Failed to create test directory")?;

    let log_path = test_dir.join("log.txt");
    let log_file = File::create(&log_path).context("Failed to create log file")?;

    eprint!(
        "[{}] {:.<width$} ",
        test_case.name,
        "",
        width = max_name_len - test_case.name.len() + 3
    );

    let child = Command::new(&executable)
        .arg("start-vm")
        .arg("--test-case")
        .arg(test_case.name)
        .arg("--tmp-dir")
        .arg(&test_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log_file)
        .spawn()
        .context("Failed to start subprocess for test")?;

    let output = child.wait_with_output().context("Failed to wait for test")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let outcome = if stdout == "SKIP\n" {
        TestOutcome::Skip
    } else if stdout == "OK\n" {
        if test_case.expects_failure {
            TestOutcome::XPass // Unexpected pass
        } else {
            TestOutcome::Pass
        }
    } else {
        // Test failed
        if test_case.expects_failure {
            TestOutcome::XFail // Expected failure
        } else {
            TestOutcome::Fail
        }
    };

    match outcome {
        TestOutcome::Pass => {
            eprintln!("OK");
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
        }
        TestOutcome::Skip => {
            eprintln!("SKIP");
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
        }
        TestOutcome::XFail => {
            eprintln!("XFAIL (expected)");
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
        }
        TestOutcome::XPass => eprintln!("XPASS (unexpected pass!)"),
        TestOutcome::Fail => eprintln!("FAIL"),
    }

    Ok(TestResult {
        name: test_case.name.to_string(),
        outcome,
        log_path,
    })
}

fn write_github_summary(results: &[TestResult], num_ok: usize, num_fail: usize) -> anyhow::Result<()> {
    let summary_path = env::var("GITHUB_STEP_SUMMARY")
        .context("GITHUB_STEP_SUMMARY environment variable not set")?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&summary_path)
        .context("Failed to open GITHUB_STEP_SUMMARY")?;

    let all_passed = num_fail == 0;
    let status = if all_passed { "✅" } else { "❌" };

    writeln!(
        file,
        "## {status} Integration Tests ({num_ok} passed, {num_fail} failed)\n"
    )?;

    for result in results {
        let icon = match result.outcome {
            TestOutcome::Pass => "✅",
            TestOutcome::Skip => "⏭️",
            TestOutcome::XFail => "⚠️",
            TestOutcome::XPass => "🔴",
            TestOutcome::Fail => "❌",
        };
        let log_content = fs::read_to_string(&result.log_path).unwrap_or_default();

        writeln!(file, "<details>")?;
        writeln!(file, "<summary>{icon} {}</summary>\n", result.name)?;
        writeln!(file, "```")?;
        // Limit log size to avoid huge summaries (2 MiB limit)
        const MAX_LOG_SIZE: usize = 2 * 1024 * 1024;
        let truncated = if log_content.len() > MAX_LOG_SIZE {
            format!(
                "... (truncated, showing last 1 MiB) ...\n{}",
                &log_content[log_content.len() - MAX_LOG_SIZE..]
            )
        } else {
            log_content
        };
        writeln!(file, "{truncated}")?;
        writeln!(file, "```")?;
        writeln!(file, "</details>\n")?;
    }

    Ok(())
}

fn run_tests(
    test_case_name: &str,
    base_dir: Option<PathBuf>,
    keep_all: bool,
    github_summary: bool,
) -> anyhow::Result<()> {
    // Create the base directory - either use provided path or create a temp one
    let base_dir = match base_dir {
        Some(path) => {
            fs::create_dir_all(&path).context("Failed to create base directory")?;
            path
        }
        None => TempDir::new("libkrun-tests")
            .context("Failed to create temp base directory")?
            .into_path(),
    };

    let mut results: Vec<TestResult> = Vec::new();
    let all_tests = test_cases();

    let tests_to_run: Vec<_> = if test_case_name == "all" {
        all_tests
    } else {
        all_tests
            .into_iter()
            .filter(|t| t.name == test_case_name)
            .collect()
    };

    if tests_to_run.is_empty() {
        anyhow::bail!("No such test: {test_case_name}");
    }

    let max_name_len = tests_to_run.iter().map(|t| t.name.len()).max().unwrap_or(0);

    for test_case in &tests_to_run {
        results.push(
            run_single_test(test_case, &base_dir, keep_all, max_name_len)
                .context(test_case.name)?,
        );
    }

    // Count outcomes: Pass, XFail, Skip are OK; Fail, XPass are failures
    let num_ok = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Pass | TestOutcome::XFail))
        .count();
    let num_skip = results
        .iter()
        .filter(|r| r.outcome == TestOutcome::Skip)
        .count();
    let num_fail = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Fail | TestOutcome::XPass))
        .count();

    // Write GitHub Actions summary if requested
    if github_summary {
        write_github_summary(&results, num_ok, num_fail)?;
    }

    if num_fail > 0 {
        eprintln!("(See test artifacts at: {})", base_dir.display());
        let skip_msg = if num_skip > 0 {
            format!(", {num_skip} skipped")
        } else {
            String::new()
        };
        println!("\nFAIL ({num_ok} passed, {num_fail} failed{skip_msg})");
        anyhow::bail!("")
    } else {
        if keep_all {
            eprintln!("(See test artifacts at: {})", base_dir.display());
        }
        let skip_msg = if num_skip > 0 {
            format!(", {num_skip} skipped")
        } else {
            String::new()
        };
        eprintln!("\nOK ({num_ok} passed{skip_msg})");
    }

    Ok(())
}

#[derive(clap::Subcommand, Clone, Debug)]
enum CliCommand {
    Test {
        /// Specify which test to run or "all"
        #[arg(long, default_value = "all")]
        test_case: String,
        /// Base directory for test artifacts
        #[arg(long)]
        base_dir: Option<PathBuf>,
        /// Keep all test artifacts even on success
        #[arg(long)]
        keep_all: bool,
        /// Write test results to GitHub Actions job summary ($GITHUB_STEP_SUMMARY)
        #[arg(long)]
        github_summary: bool,
    },
    StartVm {
        #[arg(long)]
        test_case: String,
        #[arg(long)]
        tmp_dir: PathBuf,
    },
}

impl Default for CliCommand {
    fn default() -> Self {
        Self::Test {
            test_case: "all".to_string(),
            base_dir: None,
            keep_all: false,
            github_summary: false,
        }
    }
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or_default();

    match command {
        CliCommand::StartVm { test_case, tmp_dir } => start_vm(TestSetup { test_case, tmp_dir }),
        CliCommand::Test {
            test_case,
            base_dir,
            keep_all,
            github_summary,
        } => run_tests(&test_case, base_dir, keep_all, github_summary),
    }
}
