/** Types for the SkillSpector safety-scan integration
 *  (mirrors src-tauri/src/skillspector/mod.rs). */
import type { Skill } from "./skill";

/** One vulnerability finding in a scan report. */
export interface ScanFinding {
  /** Rule id, e.g. "PI-001". */
  id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | (string & {});
  category: string;
  explanation: string;
  remediation: string;
  codeSnippet: string;
  confidence: number;
  location: {
    file: string;
    startLine: number;
    endLine: number | null;
  };
}

export interface ScanReport {
  skill: {
    name: string;
    scannedAt: string;
  };
  riskAssessment: {
    /** 0–100; NVIDIA treats > 50 as unsafe. */
    score: number;
    severity: string;
    recommendation: string;
    maxIssueSeverity: string;
  };
  issues: ScanFinding[];
  executionSuccessful: boolean;
  metadata: {
    skillspectorVersion: string | null;
    hasExecutableScripts: boolean;
  };
}

/** Whether the SkillSpector CLI is usable on this machine. */
export interface ScannerStatus {
  available: boolean;
  version: string | null;
}

/** Last recorded scan for one skill, keyed by the skill's manifest id. */
export interface SkillScanSummary {
  id: string;
  score: number;
  severity: string;
  recommendation: string;
  maxIssueSeverity: string;
  low: number;
  medium: number;
  high: number;
  critical: number;
  scannedAt: number;
  skillspectorVersion: string | null;
  executionSuccessful: boolean;
  error: string | null;
}

/** What an install attempt ended as. `blocked` means the safety scan
 *  flagged the skill and nothing was installed — the UI may re-invoke
 *  with confirmRisky to install anyway. */
export type InstallOutcome =
  | {
      status: "installed";
      skill: Skill;
      skippedLinks: number;
      scan: ScanReport | null;
      scanNote: string | null;
    }
  | { status: "blocked"; report: ScanReport };
