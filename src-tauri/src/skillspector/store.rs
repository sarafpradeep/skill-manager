use super::SkillScanSummary;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const RESULTS_FILE: &str = "scan-results.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ResultsFile {
    saved_at: u64,
    results: Vec<SkillScanSummary>,
}

/// The last recorded scan per skill id. A missing or malformed file
/// reads as empty — like the collections store, a hand-edited config
/// file must not break the app.
fn load(dir: &Path) -> ResultsFile {
    let Ok(raw) = fs::read_to_string(dir.join(RESULTS_FILE)) else {
        return ResultsFile::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save(dir: &Path, file: &ResultsFile) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    fs::write(dir.join(RESULTS_FILE), raw).map_err(|e| e.to_string())
}

/// Replace the whole file — a scan-all pass is authoritative, and this
/// drops entries for skills that no longer exist.
pub fn replace_results(dir: &Path, results: &[SkillScanSummary]) {
    let file = ResultsFile {
        saved_at: crate::collections::now_secs(),
        results: results.to_vec(),
    };
    let _ = save(dir, &file);
}

/// Record one fresh scan (single-skill scan, or the report attached to
/// an install) without disturbing the other entries.
pub fn upsert_result(dir: &Path, summary: SkillScanSummary) {
    let mut file = load(dir);
    if let Some(existing) = file.results.iter_mut().find(|r| r.id == summary.id) {
        *existing = summary;
    } else {
        file.results.push(summary);
    }
    file.saved_at = crate::collections::now_secs();
    let _ = save(dir, &file);
}

/// Drop a skill's entry — called when the skill is deleted or
/// reinstalled, so a stale result never outlives its skill.
pub fn remove_result(dir: &Path, id: &str) {
    let mut file = load(dir);
    let before = file.results.len();
    file.results.retain(|r| r.id != id);
    if file.results.len() == before {
        return;
    }
    file.saved_at = crate::collections::now_secs();
    let _ = save(dir, &file);
}

pub fn results_by_id(dir: &Path) -> HashMap<String, SkillScanSummary> {
    load(dir)
        .results
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "skill-manager-ss-store-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn summary(id: &str, score: i64) -> SkillScanSummary {
        SkillScanSummary {
            id: id.into(),
            score,
            ..Default::default()
        }
    }

    #[test]
    fn replace_upsert_remove_round_trip() {
        let dir = tmp_dir("roundtrip");
        assert!(results_by_id(&dir).is_empty());

        replace_results(&dir, &[summary("a", 5), summary("b", 50)]);
        upsert_result(&dir, summary("c", 90));
        upsert_result(&dir, summary("b", 55));
        let loaded = results_by_id(&dir);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded["b"].score, 55);

        remove_result(&dir, "b");
        remove_result(&dir, "ghost");
        assert_eq!(results_by_id(&dir).len(), 2);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_results_file_reads_as_empty() {
        let dir = tmp_dir("malformed");
        fs::write(dir.join(RESULTS_FILE), "{ not json").unwrap();
        assert!(results_by_id(&dir).is_empty());
        // and a write after repairs the file
        upsert_result(&dir, summary("a", 1));
        assert_eq!(results_by_id(&dir)["a"].score, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persisted_shape_is_camel_case_json() {
        let dir = tmp_dir("shape");
        let mut s = summary("a", 30);
        s.max_issue_severity = "HIGH".into();
        upsert_result(&dir, s);
        let raw = fs::read_to_string(dir.join(RESULTS_FILE)).unwrap();
        assert!(raw.contains("maxIssueSeverity"));
        assert!(raw.contains("executionSuccessful"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
