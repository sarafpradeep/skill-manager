use super::manifest_is_manageable;
use crate::collections::install::SkillFile;
use crate::skills::{self, Skill};
use crate::skillspector::{self, store, ScanReport, ScanRunner, ScannerStatus, SkillScanSummary};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

const RUNNER: skillspector::CliRunner = skillspector::SCAN;

fn config_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// Whether the SkillSpector CLI is usable — the UI shows an
/// install hint in the browse view when it is not.
#[tauri::command]
pub fn check_scanner() -> ScannerStatus {
    let version = RUNNER.version();
    ScannerStatus {
        available: version.is_some(),
        version,
    }
}

/// Scan one installed skill (the manifest path is the skill id, exactly
/// like read/write/delete) and record the result so the card chip
/// refreshes.
#[tauri::command]
pub fn scan_installed_skill(app: AppHandle, id: String) -> Result<ScanReport, String> {
    let path = Path::new(&id);
    if !manifest_is_manageable(&app, path) {
        return Err("not a managed skill path".into());
    }
    let Some(dir) = path.parent() else {
        return Err("not a managed skill path".into());
    };
    let report = RUNNER.scan(dir)?;
    if let Ok(cfg) = config_dir(&app) {
        store::upsert_result(&cfg, skillspector::summary_for(&id, &report));
    }
    Ok(report)
}

/// The persisted last-scan summaries, keyed by skill id — loaded at
/// startup so risk chips survive restarts.
#[tauri::command]
pub fn list_scan_results(app: AppHandle) -> Vec<SkillScanSummary> {
    config_dir(&app)
        .map(|cfg| store::results_by_id(&cfg).into_values().collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgress {
    done: u32,
    total: u32,
}

/// Scan every managed skill — user-level across all tools plus every
/// tracked project's skills. Distinct on-disk folders are scanned once
/// (a skill shared between tools via a symlink is one scan), workers
/// run in parallel, and the results replace the persisted set so chips
/// survive restarts.
#[tauri::command]
pub fn scan_all_skills(app: AppHandle) -> Result<Vec<SkillScanSummary>, String> {
    let cfg = config_dir(&app)?;
    let tracked = crate::projects::list(&app).unwrap_or_default();
    let mut all: Vec<Skill> = skills::all_adapters()
        .into_iter()
        .flat_map(|adapter| adapter.discover())
        .collect();
    for project in &tracked {
        all.extend(skills::discover_project_skills(Path::new(&project.path)));
    }

    let groups = group_by_skill_dir(all);
    let app_handle = app.clone();
    let results = skillspector::scan_groups(groups, &RUNNER, move |done, total| {
        let _ = app_handle.emit(
            "scan-progress",
            ScanProgress {
                done: done as u32,
                total: total as u32,
            },
        );
    });
    store::replace_results(&cfg, &results);
    Ok(results)
}

/// Group skill entries by their real on-disk folder so a skill linked
/// into several tools is scanned once and each tool's card gets a chip.
fn group_by_skill_dir(skills: Vec<Skill>) -> Vec<(PathBuf, Vec<String>)> {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut groups: std::collections::HashMap<PathBuf, Vec<String>> =
        std::collections::HashMap::new();
    for skill in skills {
        let key = fs::canonicalize(&skill.path).unwrap_or_else(|_| PathBuf::from(&skill.path));
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(skill.id);
    }
    order
        .into_iter()
        .map(|dir| {
            let ids = groups.remove(&dir).unwrap_or_default();
            (dir, ids)
        })
        .collect()
}

/// Forget one skill's persisted result — the skill is gone or about to
/// be replaced, so a stale chip must not survive.
pub(crate) fn forget_result(app: &AppHandle, id: &str) {
    if let Ok(cfg) = config_dir(app) {
        store::remove_result(&cfg, id);
    }
}

// ---------------------------------------------------------------------------
// Install-time gate
// ---------------------------------------------------------------------------

/// What the pre-install scan decided. `Block` stops the install before
/// anything is written; the frontend then shows the report and may
/// re-run with the user's explicit confirmation.
#[derive(Debug, Clone)]
pub(crate) enum InstallScan {
    Proceed {
        scan: Option<ScanReport>,
        note: Option<String>,
    },
    Block(ScanReport),
}

pub(crate) fn scan_for_install(
    runner: &dyn ScanRunner,
    files: &[SkillFile],
    confirm_risky: bool,
) -> InstallScan {
    if runner.version().is_none() {
        return InstallScan::Proceed {
            scan: None,
            note: Some("safety scanner not installed — see README to enable scans".into()),
        };
    }
    let tmp = match materialize_files(files) {
        Ok(dir) => dir,
        Err(e) => {
            return InstallScan::Proceed {
                scan: None,
                note: Some(format!("safety scan failed: {e}")),
            }
        }
    };
    let outcome = runner.scan(&tmp);
    let _ = fs::remove_dir_all(&tmp);
    match outcome {
        Ok(report) if skillspector::is_risky(&report) && !confirm_risky => {
            InstallScan::Block(report)
        }
        Ok(report) => InstallScan::Proceed {
            scan: Some(report),
            note: None,
        },
        Err(e) => InstallScan::Proceed {
            scan: None,
            note: Some(format!("safety scan failed: {e}")),
        },
    }
}

/// Materialize the in-memory tarball files into a scratch dir so the
/// CLI — which reads from disk — can scan exactly what would land in
/// the managed root. Paths were already validated by
/// `files_from_tarball`; re-checked here as defense in depth.
fn materialize_files(files: &[SkillFile]) -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("skill-manager-scan-{}-{nanos}", std::process::id()));
    let result = write_files_into(&dir, files);
    if result.is_err() {
        let _ = fs::remove_dir_all(&dir);
    }
    result.map(|()| dir)
}

fn write_files_into(dir: &Path, files: &[SkillFile]) -> Result<(), String> {
    // Validate every path before touching the disk, so a rejected file
    // list leaves no partial scratch dir behind.
    for file in files {
        if !crate::collections::install::safe_relative(&file.relative_path) {
            return Err(format!(
                "archive path '{}' is not safe to write",
                file.relative_path
            ));
        }
    }
    fs::create_dir_all(dir).map_err(|e| format!("cannot create scan dir: {e}"))?;
    for file in files {
        let dest = dir.join(&file.relative_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create scan folders: {e}"))?;
        }
        fs::write(&dest, &file.bytes).map_err(|e| format!("cannot write scan file: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skillspector::{RiskAssessment, ScanSkillInfo};
    use std::sync::Mutex as SyncMutex;

    fn file(rel: &str, body: &str) -> SkillFile {
        SkillFile {
            relative_path: rel.into(),
            bytes: body.as_bytes().to_vec(),
            mode: 0o644,
        }
    }

    fn report_with(score: i64, max_severity: &str) -> ScanReport {
        ScanReport {
            skill: ScanSkillInfo::default(),
            risk_assessment: RiskAssessment {
                score,
                severity: "MEDIUM".into(),
                recommendation: "CAUTION".into(),
                max_issue_severity: max_severity.into(),
            },
            issues: vec![],
            execution_successful: true,
            metadata: Default::default(),
        }
    }

    struct FakeRunner {
        result: Result<ScanReport, String>,
        installed: bool,
        seen_dirs: SyncMutex<Vec<PathBuf>>,
        /// Whether each scanned dir contained a SKILL.md, recorded at
        /// scan time — the scratch dir is deleted right after, so the
        /// evidence must be captured inside the scan.
        saw_manifest: SyncMutex<Vec<bool>>,
    }

    impl ScanRunner for FakeRunner {
        fn version(&self) -> Option<String> {
            self.installed.then(|| "fake".into())
        }
        fn scan(&self, dir: &Path) -> Result<ScanReport, String> {
            self.seen_dirs.lock().unwrap().push(dir.to_path_buf());
            self.saw_manifest
                .lock()
                .unwrap()
                .push(dir.join("SKILL.md").is_file());
            self.result.clone()
        }
    }

    fn fake(result: Result<ScanReport, String>) -> FakeRunner {
        FakeRunner {
            result,
            installed: true,
            seen_dirs: SyncMutex::new(Vec::new()),
            saw_manifest: SyncMutex::new(Vec::new()),
        }
    }

    #[test]
    fn clean_scan_proceeds_with_report() {
        let runner = fake(Ok(report_with(5, "LOW")));
        let outcome = scan_for_install(&runner, &[file("SKILL.md", "---\nname: a\n---\n")], false);
        match outcome {
            InstallScan::Proceed { scan, note } => {
                assert_eq!(scan.unwrap().risk_assessment.score, 5);
                assert!(note.is_none());
            }
            InstallScan::Block(_) => panic!("clean scan must not block"),
        }
        let seen = runner.seen_dirs.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].exists(), "scratch dir must be cleaned up");
        assert!(
            runner.saw_manifest.lock().unwrap()[0],
            "manifest was materialized"
        );
    }

    #[test]
    fn risky_scan_blocks_unless_user_confirms() {
        let runner = fake(Ok(report_with(80, "HIGH")));
        let blocked = scan_for_install(&runner, &[file("SKILL.md", "x")], false);
        assert!(matches!(blocked, InstallScan::Block(_)));
        assert!(
            runner.saw_manifest.lock().unwrap()[0],
            "the scanner saw the real materialized skill"
        );
        {
            let seen = runner.seen_dirs.lock().unwrap();
            assert!(
                !seen[0].exists(),
                "a blocked install leaves no scratch dir behind"
            );
        }

        let confirmed = scan_for_install(&runner, &[file("SKILL.md", "x")], true);
        match confirmed {
            InstallScan::Proceed { scan, note } => {
                assert!(scan.is_some());
                assert!(note.is_none());
            }
            InstallScan::Block(_) => panic!("explicit confirmation must override"),
        }
    }

    #[test]
    fn high_finding_blocks_even_with_low_score() {
        let runner = fake(Ok(report_with(10, "CRITICAL")));
        let outcome = scan_for_install(&runner, &[file("SKILL.md", "x")], false);
        assert!(matches!(outcome, InstallScan::Block(_)));
    }

    #[test]
    fn missing_scanner_skips_without_blocking() {
        let mut runner = fake(Ok(report_with(0, "")));
        runner.installed = false;
        let outcome = scan_for_install(&runner, &[file("SKILL.md", "x")], false);
        match outcome {
            InstallScan::Proceed { scan, note } => {
                assert!(scan.is_none());
                assert_eq!(
                    note.as_deref(),
                    Some("safety scanner not installed — see README to enable scans")
                );
            }
            InstallScan::Block(_) => panic!("missing scanner must never block"),
        }
        assert!(
            runner.seen_dirs.lock().unwrap().is_empty(),
            "no scan attempted"
        );
    }

    #[test]
    fn scan_error_proceeds_with_note() {
        let runner = fake(Err("scan failed".into()));
        let outcome = scan_for_install(&runner, &[file("SKILL.md", "x")], false);
        match outcome {
            InstallScan::Proceed { scan, note } => {
                assert!(scan.is_none());
                assert_eq!(note.as_deref(), Some("safety scan failed: scan failed"));
            }
            InstallScan::Block(_) => panic!("scan errors must not block installs"),
        }
    }

    #[test]
    fn materialize_writes_files_and_nested_dirs() {
        let files = vec![
            file("SKILL.md", "---\nname: a\n---\n"),
            file("scripts/run.py", "print('hi')\n"),
        ];
        let dir = materialize_files(&files).unwrap();
        assert!(dir.join("SKILL.md").is_file());
        assert!(dir.join("scripts").join("run.py").is_file());
        assert!(dir.starts_with(std::env::temp_dir()));
        assert!(dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("skill-manager-scan-")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn materialize_rejects_unsafe_paths() {
        let dir = std::env::temp_dir().join(format!("ss-mat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let err = write_files_into(&dir, &[file("../escape.txt", "x")]).unwrap_err();
        assert!(err.contains("not safe to write"), "unexpected error: {err}");
        assert!(
            !dir.exists(),
            "an empty dir is only created for valid input"
        );
        // and the wrapper cleans its scratch dir when writing fails
        let files = vec![file("../escape.txt", "x")];
        assert!(materialize_files(&files).is_err());
    }

    #[test]
    fn grouping_dedupes_by_real_directory() {
        let skill = |id: &str, path: &str| Skill {
            id: id.into(),
            tool: skills::AgentTool::Claude,
            name: "n".into(),
            description: String::new(),
            path: path.into(),
            scope: skills::SkillScope::User,
            enabled: true,
        };
        let dir =
            std::env::temp_dir().join(format!("skill-manager-scan-grp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let groups = group_by_skill_dir(vec![
            skill("/s/a/SKILL.md", "/s/a"),
            skill("/s/b/SKILL.md", "/s/b"),
            skill("/link/SKILL.md", dir.to_string_lossy().as_ref()),
            skill("/link2/SKILL.md", dir.to_string_lossy().as_ref()),
        ]);
        let non_canonical: Vec<_> = groups.iter().filter(|(_, ids)| ids.len() > 1).collect();
        assert_eq!(
            non_canonical.len(),
            1,
            "the two entries sharing the temp dir group together"
        );
        assert_eq!(non_canonical[0].1.len(), 2);
        assert_eq!(groups.len(), 3, "/s/a, /s/b, and the shared dir");
        fs::remove_dir_all(&dir).unwrap();
    }
}
