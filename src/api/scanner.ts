import { invoke } from "@tauri-apps/api/core";
import type { ScanReport, ScannerStatus, SkillScanSummary } from "../types";

/** Invoke wrappers over the scan commands in
 *  src-tauri/src/commands/scan.rs. */
export const scannerApi = {
  checkScanner(): Promise<ScannerStatus> {
    return invoke("check_scanner");
  },
  /** Scans one installed skill (id = SKILL.md manifest path) and
   *  records the result in the persisted scan results. */
  scanInstalledSkill(id: string): Promise<ScanReport> {
    return invoke("scan_installed_skill", { id });
  },
  /** Scans every managed skill; progress arrives via the
   *  "scan-progress" event. */
  scanAllSkills(): Promise<SkillScanSummary[]> {
    return invoke("scan_all_skills");
  },
  /** Persisted last-scan summaries — chips survive restarts. */
  listScanResults(): Promise<SkillScanSummary[]> {
    return invoke("list_scan_results");
  },
};
