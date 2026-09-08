//! NVIDIA SkillSpector integration — an optional, external security
//! scanner for agent skills ([NVIDIA/SkillSpector], Apache-2.0). When
//! the `skillspector` CLI is on the machine, the app runs it in
//! static-only mode (`--no-llm`: no API keys, no model calls) to
//! detect prompt injection, data exfiltration, dangerous code, and
//! ~70 other vulnerability patterns before a skill is installed, and
//! to audit the skills already on disk.
//!
//! [NVIDIA/SkillSpector]: https://github.com/NVIDIA/SkillSpector

pub mod store;

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BINARY_NAME: &str = "skillspector";
/// Env var pointing at a specific `skillspector` binary — an escape
/// hatch for installs a PATH probe can't see (GUI apps on macOS get a
/// minimal PATH).
const BINARY_ENV: &str = "SKILL_MANAGER_SKILLSPECTOR";
/// NVIDIA's own triage gate: a risk score above this is unsafe.
pub const RISK_THRESHOLD: i64 = 50;
/// Static scans of normal skill folders finish in well under a second;
/// the cap only exists so a pathological archive can't wedge a command.
const SCAN_TIMEOUT: Duration = Duration::from_secs(120);
/// Worker count for batch scans — scanning is CPU/IO bound per process.
const SCAN_WORKERS: usize = 4;

// ---------------------------------------------------------------------------
// Report model
//
// Field names as SkillSpector emits them (snake_case) are deserialization
// aliases; the canonical serde names are camelCase, so the same structs
// serialize straight to the webview without a mapping layer.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FindingLocation {
    #[serde(alias = "file")]
    pub file: String,
    #[serde(alias = "start_line")]
    pub start_line: i64,
    #[serde(alias = "end_line")]
    pub end_line: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanFinding {
    /// Rule id, e.g. `PI-001`.
    #[serde(alias = "id")]
    pub id: String,
    pub severity: String,
    #[serde(alias = "category")]
    pub category: String,
    #[serde(alias = "explanation")]
    pub explanation: String,
    #[serde(alias = "remediation")]
    pub remediation: String,
    #[serde(alias = "code_snippet")]
    pub code_snippet: String,
    pub confidence: f64,
    pub location: FindingLocation,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanSkillInfo {
    pub name: String,
    #[serde(alias = "scanned_at")]
    pub scanned_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RiskAssessment {
    /// 0–100; above [`RISK_THRESHOLD`] NVIDIA treats the skill as unsafe.
    pub score: i64,
    pub severity: String,
    #[serde(alias = "recommendation")]
    pub recommendation: String,
    #[serde(alias = "max_issue_severity")]
    pub max_issue_severity: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanMetadata {
    #[serde(alias = "skillspector_version")]
    pub skillspector_version: Option<String>,
    #[serde(alias = "has_executable_scripts")]
    pub has_executable_scripts: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanReport {
    pub skill: ScanSkillInfo,
    /// Upstream key is `risk_assessment`; serialized as `riskAssessment`.
    #[serde(alias = "risk_assessment")]
    pub risk_assessment: RiskAssessment,
    #[serde(default)]
    pub issues: Vec<ScanFinding>,
    #[serde(alias = "execution_successful")]
    pub execution_successful: bool,
    pub metadata: ScanMetadata,
}

/// NVIDIA's triage table blocks critical/high findings regardless of the
/// aggregate score, so the gate follows both signals.
pub fn is_risky(report: &ScanReport) -> bool {
    report.risk_assessment.score > RISK_THRESHOLD
        || matches!(
            report
                .risk_assessment
                .max_issue_severity
                .to_ascii_uppercase()
                .as_str(),
            "HIGH" | "CRITICAL"
        )
}

/// Per-skill risk data, keyed by the skill's manifest path — the same
/// id the frontend's `Skill.id` uses, so chips are a plain join.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SkillScanSummary {
    pub id: String,
    pub score: i64,
    pub severity: String,
    pub recommendation: String,
    #[serde(alias = "max_issue_severity")]
    pub max_issue_severity: String,
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
    /// When this summary was recorded (epoch seconds, our clock).
    #[serde(alias = "scanned_at")]
    pub scanned_at: u64,
    #[serde(alias = "skillspector_version")]
    pub skillspector_version: Option<String>,
    #[serde(alias = "execution_successful")]
    pub execution_successful: bool,
    /// Set when the scan itself failed; the risk fields are then zeroes.
    pub error: Option<String>,
}

pub fn summary_for(id: &str, report: &ScanReport) -> SkillScanSummary {
    let mut counts = SkillScanSummary {
        id: id.to_string(),
        score: report.risk_assessment.score,
        severity: report.risk_assessment.severity.clone(),
        recommendation: report.risk_assessment.recommendation.clone(),
        max_issue_severity: report.risk_assessment.max_issue_severity.clone(),
        scanned_at: crate::collections::now_secs(),
        skillspector_version: report.metadata.skillspector_version.clone(),
        execution_successful: report.execution_successful,
        ..Default::default()
    };
    for issue in &report.issues {
        match issue.severity.to_ascii_uppercase().as_str() {
            "LOW" => counts.low += 1,
            "MEDIUM" => counts.medium += 1,
            "HIGH" => counts.high += 1,
            "CRITICAL" => counts.critical += 1,
            _ => {}
        }
    }
    counts
}

pub fn summary_error(id: &str, error: &str) -> SkillScanSummary {
    SkillScanSummary {
        id: id.to_string(),
        scanned_at: crate::collections::now_secs(),
        execution_successful: false,
        error: Some(error.to_string()),
        ..Default::default()
    }
}

/// Whether the CLI is usable on this machine, surfaced to the UI so a
/// missing scanner is visible instead of silently skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerStatus {
    pub available: bool,
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

/// Where the CLI may live besides PATH: `uv tool install` puts it in
/// `~/.local/bin`, Homebrew in `/opt/homebrew/bin` or `/usr/local/bin`.
/// GUI launches on macOS get a minimal PATH, so the explicit probes
/// matter. `SKILL_MANAGER_SKILLSPECTOR` overrides everything.
fn explicit_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(custom) = std::env::var(BINARY_ENV) {
        let custom = custom.trim();
        if !custom.is_empty() {
            candidates.push(PathBuf::from(custom));
        }
    }
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".local").join("bin").join(BINARY_NAME));
    }
    candidates.push(PathBuf::from("/opt/homebrew/bin").join(BINARY_NAME));
    candidates.push(PathBuf::from("/usr/local/bin").join(BINARY_NAME));
    candidates
}

pub fn find_binary() -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(BINARY_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    explicit_candidates().into_iter().find(|c| c.is_file())
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Indirection so tests can fake scans the way `collections::GithubHttp`
/// fakes the network.
pub trait ScanRunner: Send + Sync {
    /// Version string of an installed CLI, or None when unavailable.
    fn version(&self) -> Option<String>;
    /// Scan one skill directory in static-only mode.
    fn scan(&self, dir: &Path) -> Result<ScanReport, String>;
}

pub struct CliRunner;

impl ScanRunner for CliRunner {
    fn version(&self) -> Option<String> {
        let binary = find_binary()?;
        let output = Command::new(binary).arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        if text.trim().is_empty() {
            return None;
        }
        Some(parse_version_text(&text))
    }

    fn scan(&self, dir: &Path) -> Result<ScanReport, String> {
        let Some(binary) = find_binary() else {
            return Err("scanner not installed".into());
        };
        let mut child = Command::new(binary)
            .arg("scan")
            .arg(dir)
            .arg("--format")
            .arg("json")
            .arg("--no-llm")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run scanner: {e}"))?;

        // Drain both pipes on threads: a chatty stderr would otherwise
        // fill the OS pipe buffer and deadlock the wait below.
        let Some(mut stdout_pipe) = child.stdout.take() else {
            return Err("scanner stdout unavailable".into());
        };
        let stdout_reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout_pipe.read_to_string(&mut text);
            text
        });
        let Some(mut stderr_pipe) = child.stderr.take() else {
            return Err("scanner stderr unavailable".into());
        };
        let stderr_reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr_pipe.read_to_string(&mut text);
            text
        });

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if started.elapsed() > SCAN_TIMEOUT {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("scan timed out".into());
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Err(e) => return Err(format!("cannot run scanner: {e}")),
            }
        };
        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();

        // Exit 2 is the CLI's "execution failed"; exit 1 just means the
        // risk threshold tripped — that report is exactly what we want.
        if status.code() == Some(2) {
            let detail = first_line(&stderr);
            return Err(if detail.is_empty() {
                "scan failed".into()
            } else {
                detail
            });
        }
        parse_report(&stdout).ok_or_else(|| {
            let detail = first_line(&stderr);
            if detail.is_empty() {
                "scanner produced no readable report".to_string()
            } else {
                format!("scanner produced no readable report: {detail}")
            }
        })
    }
}

/// "SkillSpector v2.11.1\n" → "2.11.1"; falls back to the raw text.
fn parse_version_text(text: &str) -> String {
    text.split_whitespace()
        .find(|t| {
            t.len() > 1
                && t.starts_with('v')
                && t[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(|t| t[1..].to_string())
        .unwrap_or_else(|| text.trim().to_string())
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

/// The CLI writes the report to stdout, but warnings from the scanner's
/// own logger can precede it — parse from the first `{` onward.
fn parse_report(stdout: &str) -> Option<ScanReport> {
    let json = stdout[stdout.find('{')?..].trim();
    serde_json::from_str(json).ok()
}

/// Shared production runner.
pub const SCAN: CliRunner = CliRunner;

/// Scan every directory in `groups` (one scan per distinct on-disk
/// folder), fan the result out to every skill entry that shares the
/// folder, and report progress through `progress` as groups complete.
pub fn scan_groups(
    groups: Vec<(PathBuf, Vec<String>)>,
    runner: &dyn ScanRunner,
    progress: impl Fn(usize, usize) + Sync,
) -> Vec<SkillScanSummary> {
    use std::sync::Mutex;

    let total = groups.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results = Mutex::new(Vec::<SkillScanSummary>::new());
    std::thread::scope(|scope| {
        for _ in 0..SCAN_WORKERS.min(total.max(1)) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::SeqCst);
                if index >= total {
                    break;
                }
                let (dir, ids) = &groups[index];
                let scanned = runner.scan(Path::new(dir));
                let mut summaries = results.lock().unwrap();
                for id in ids {
                    summaries.push(match &scanned {
                        Ok(report) => summary_for(id, report),
                        Err(e) => summary_error(id, e),
                    });
                }
                drop(summaries);
                progress(done.fetch_add(1, Ordering::SeqCst) + 1, total);
            });
        }
    });
    let mut summaries = results.into_inner().unwrap_or_default();
    summaries.sort_by(|a, b| risk_rank(b).cmp(&risk_rank(a)).then(a.id.cmp(&b.id)));
    summaries
}

/// Worst-first ordering for scan-all results: failures first, then
/// critical/high/medium/low, then raw score.
fn risk_rank(summary: &SkillScanSummary) -> i64 {
    if summary.error.is_some() {
        return i64::MAX;
    }
    let severity = match summary.max_issue_severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };
    severity * 1000 + summary.score
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as SyncMutex;

    fn report_with(score: i64, max_severity: &str) -> ScanReport {
        ScanReport {
            skill: ScanSkillInfo {
                name: "demo".into(),
                scanned_at: "2026-09-08T00:00:00+00:00".into(),
            },
            risk_assessment: RiskAssessment {
                score,
                severity: "MEDIUM".into(),
                recommendation: "CAUTION".into(),
                max_issue_severity: max_severity.into(),
            },
            issues: vec![],
            execution_successful: true,
            metadata: ScanMetadata {
                skillspector_version: Some("2.11.1".into()),
                has_executable_scripts: false,
            },
        }
    }

    #[test]
    fn report_parses_real_skillspector_output() {
        // Captured from `skillspector scan --format json --no-llm` v2.11.1.
        let raw = r#"{
          "skill": {"name": "curious-skill", "source": "/tmp/x", "scanned_at": "2026-09-08T06:28:04.896518+00:00"},
          "risk_assessment": {"score": 48, "severity": "MEDIUM", "recommendation": "CAUTION", "max_issue_severity": "HIGH"},
          "components": [],
          "structured_summaries": [],
          "issues": [{
            "id": "DE-001", "finding_id": "finding-abc", "category": "Data Exfiltration",
            "pattern": "curl", "severity": "HIGH", "confidence": 0.9,
            "location": {"file": "SKILL.md", "start_line": 8, "end_line": 8},
            "finding": "curl", "explanation": "sends data out", "remediation": "remove it",
            "code_snippet": "curl -d @~/.ssh/id_rsa", "intent": null,
            "tags": [], "evidence": {}, "match_fingerprint": "fp", "occurrences": []
          }],
          "suppressed_count": 0, "suppressed": [],
          "metadata": {"has_executable_scripts": false, "skillspector_version": "2.11.1",
            "llm_requested": false, "llm_available": false, "meta_analysis_applied": false,
            "filtering_mode": "heuristic"},
          "execution_successful": true, "analysis_completeness": {}
        }"#;
        let report = parse_report(raw).expect("fixture must parse");
        assert_eq!(report.skill.name, "curious-skill");
        assert_eq!(report.risk_assessment.score, 48);
        assert_eq!(report.risk_assessment.max_issue_severity, "HIGH");
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].id, "DE-001");
        assert_eq!(report.issues[0].location.start_line, 8);
        assert_eq!(report.issues[0].code_snippet, "curl -d @~/.ssh/id_rsa");
        assert_eq!(
            report.metadata.skillspector_version.as_deref(),
            Some("2.11.1")
        );
        // serialization is camelCase for the webview
        let out = serde_json::to_value(&report).unwrap();
        assert!(out.get("riskAssessment").is_some());
        assert!(out.get("executionSuccessful").is_some());
        assert!(out["riskAssessment"].get("maxIssueSeverity").is_some());
    }

    #[test]
    fn report_with_missing_optional_fields_parses() {
        let report = parse_report("{}").expect("empty object parses");
        assert_eq!(report.risk_assessment.score, 0);
        assert!(report.issues.is_empty());
        assert!(!report.execution_successful);
    }

    #[test]
    fn risky_gate_follows_score_and_max_severity() {
        assert!(!is_risky(&report_with(0, "")));
        assert!(!is_risky(&report_with(50, "LOW")));
        assert!(
            is_risky(&report_with(51, "LOW")),
            "score over NVIDIA's threshold"
        );
        // NVIDIA's triage table: high/critical findings block regardless
        // of the aggregate score.
        assert!(is_risky(&report_with(10, "HIGH")));
        assert!(is_risky(&report_with(10, "CRITICAL")));
    }

    #[test]
    fn summary_counts_findings_by_severity() {
        let mut report = report_with(30, "HIGH");
        report.issues = vec![
            finding_with_severity("LOW"),
            finding_with_severity("HIGH"),
            finding_with_severity("HIGH"),
            finding_with_severity("CRITICAL"),
            finding_with_severity("weird"),
        ];
        let summary = summary_for("/skills/demo/SKILL.md", &report);
        assert_eq!(summary.id, "/skills/demo/SKILL.md");
        assert_eq!(summary.score, 30);
        assert_eq!(
            (summary.low, summary.medium, summary.high, summary.critical),
            (1, 0, 2, 1)
        );
        assert_eq!(summary.scanned_at, crate::collections::now_secs());
    }

    fn finding_with_severity(severity: &str) -> ScanFinding {
        ScanFinding {
            id: "X-001".into(),
            severity: severity.into(),
            category: "Test".into(),
            explanation: "e".into(),
            remediation: String::new(),
            code_snippet: String::new(),
            confidence: 0.5,
            location: FindingLocation {
                file: "SKILL.md".into(),
                start_line: 1,
                end_line: None,
            },
        }
    }

    #[test]
    fn summaries_sort_worst_first() {
        let a = summary_for("a", &report_with(5, "LOW"));
        let b = summary_for("b", &report_with(90, "MEDIUM"));
        let c = summary_for("c", &report_with(10, "CRITICAL"));
        let d = summary_error("d", "scan failed");
        let mut list = [a, b, c, d];
        list.sort_by(|x, y| risk_rank(y).cmp(&risk_rank(x)).then(x.id.cmp(&y.id)));
        assert_eq!(list[0].id, "d");
        assert_eq!(list[1].id, "c");
        assert_eq!(list[2].id, "b");
        assert_eq!(list[3].id, "a");
    }

    struct FakeRunner {
        result: Result<ScanReport, String>,
        seen_dirs: SyncMutex<Vec<PathBuf>>,
    }

    impl ScanRunner for FakeRunner {
        fn version(&self) -> Option<String> {
            Some("fake".into())
        }
        fn scan(&self, dir: &Path) -> Result<ScanReport, String> {
            self.seen_dirs.lock().unwrap().push(dir.to_path_buf());
            self.result.clone()
        }
    }

    fn skill_ids(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scan_groups_scan_each_dir_once_and_fan_out() {
        let runner = FakeRunner {
            result: Ok(report_with(20, "MEDIUM")),
            seen_dirs: SyncMutex::new(Vec::new()),
        };
        let groups = vec![
            (PathBuf::from("/s/a"), skill_ids(&["/s/a/SKILL.md"])),
            (
                PathBuf::from("/s/b"),
                skill_ids(&["/s/b/SKILL.md", "/s/link-b/SKILL.md"]),
            ),
        ];
        let progress_events = SyncMutex::new(Vec::new());
        let summaries = scan_groups(groups, &runner, |done, total| {
            progress_events.lock().unwrap().push((done, total));
        });
        assert_eq!(
            runner.seen_dirs.lock().unwrap().len(),
            2,
            "one scan per dir"
        );
        assert_eq!(summaries.len(), 3, "every skill entry gets a summary");
        let progress_events = progress_events.into_inner().unwrap();
        assert_eq!(progress_events.len(), 2);
        assert!(progress_events.contains(&(1, 2)));
        assert!(progress_events.contains(&(2, 2)));
        let b = summaries
            .iter()
            .find(|s| s.id == "/s/link-b/SKILL.md")
            .unwrap();
        assert_eq!(b.score, 20);
    }

    #[test]
    fn scan_groups_record_errors_per_skill() {
        let runner = FakeRunner {
            result: Err("scanner not installed".into()),
            seen_dirs: SyncMutex::new(Vec::new()),
        };
        let groups = vec![(PathBuf::from("/s/a"), skill_ids(&["/s/a/SKILL.md"]))];
        let summaries = scan_groups(groups, &runner, |_, _| {});
        let summary = &summaries[0];
        assert!(!summary.execution_successful);
        assert_eq!(summary.error.as_deref(), Some("scanner not installed"));
    }

    #[test]
    fn version_string_extracts_semver() {
        assert_eq!(parse_version_text("SkillSpector v2.11.1\n"), "2.11.1");
        assert_eq!(parse_version_text("SkillSpector v1.0.0rc1"), "1.0.0rc1");
        assert_eq!(parse_version_text("unknown-tool 9.9"), "unknown-tool 9.9");
        assert_eq!(parse_version_text("  v2.0 "), "2.0");
    }

    #[test]
    #[ignore = "runs the real skillspector CLI; requires `uv tool install git+https://github.com/NVIDIA/skillspector.git`"]
    fn real_scanner_reports_fixture_skill() {
        let Some(binary) = find_binary() else {
            panic!("skillspector not installed");
        };
        let _ = binary;
        let dir = std::path::Path::new("/tmp/ss-fixture/curious-skill");
        let report = SCAN.scan(dir).expect("scan should succeed");
        assert!(report.execution_successful);
        assert!(!report.issues.is_empty());
    }
}
