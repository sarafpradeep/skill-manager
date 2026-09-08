import type { ScanFinding, ScanReport, SkillScanSummary } from "../types";

/** Severity chips collapse to three visual bands, matching the app's
 *  monochrome-plus-danger palette: clean/low stay neutral, medium is
 *  emphasized, high/critical (and scan failures) go red. */
export type ScanBand = "clean" | "warn" | "danger" | "failed";

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/** The install gate, mirrored from the Rust side (NVIDIA's triage
 *  policy): a score over 50 or any high/critical finding is unsafe. */
export function isRiskyReport(report: ScanReport): boolean {
  return (
    report.riskAssessment.score > 50 ||
    SEVERITY_ORDER.slice(0, 2).includes(
      report.riskAssessment.maxIssueSeverity.toUpperCase() as "HIGH" | "CRITICAL",
    )
  );
}

export function bandForSummary(summary: SkillScanSummary): ScanBand {
  if (!summary.executionSuccessful) return "failed";
  if (summary.critical > 0 || summary.high > 0) return "danger";
  if (summary.score > 50 || summary.medium > 0) return "warn";
  return "clean";
}

export function bandForReport(report: ScanReport): ScanBand {
  if (!report.executionSuccessful) return "failed";
  return isRiskyReport(report) ? "danger" : bandFromScore(report.riskAssessment.score);
}

function bandFromScore(score: number): ScanBand {
  if (score > 50) return "danger";
  if (score >= 20) return "warn";
  return "clean";
}

/** Counts by severity for a full report — the single-scan counterpart
 *  of the summary's flat counters. */
export function countsFor(issues: ScanFinding[]): Record<string, number> {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const issue of issues) {
    const key = issue.severity.toUpperCase();
    if (key in counts) counts[key] += 1;
  }
  return counts;
}

/** Findings ordered worst-first, ties broken by rule id. */
export function sortFindings(issues: ScanFinding[]): ScanFinding[] {
  const rank = (severity: string) => {
    const index = SEVERITY_ORDER.indexOf(severity.toUpperCase() as (typeof SEVERITY_ORDER)[number]);
    return index === -1 ? SEVERITY_ORDER.length : index;
  };
  return [...issues].sort((a, b) => rank(a.severity) - rank(b.severity) || a.id.localeCompare(b.id));
}

/** Short human label for a report: "3 high · 1 medium" style counts. */
export function reportHeadline(report: ScanReport): string {
  const counts = countsFor(report.issues);
  const parts = SEVERITY_ORDER.map((severity) => {
    const n = counts[severity];
    return n > 0 ? `${n} ${severity.toLowerCase()}` : null;
  }).filter(Boolean);
  if (parts.length === 0) return "no findings";
  return parts.join(" · ");
}

/** Turn a fresh single-scan report into the persisted-summary shape so
 *  card chips join on the same data scan-all produces. */
export function summaryFromReport(id: string, report: ScanReport): SkillScanSummary {
  const counts = countsFor(report.issues);
  return {
    id,
    score: report.riskAssessment.score,
    severity: report.riskAssessment.severity,
    recommendation: report.riskAssessment.recommendation,
    maxIssueSeverity: report.riskAssessment.maxIssueSeverity,
    low: counts.LOW,
    medium: counts.MEDIUM,
    high: counts.HIGH,
    critical: counts.CRITICAL,
    scannedAt: Math.floor(Date.now() / 1000),
    skillspectorVersion: report.metadata.skillspectorVersion,
    executionSuccessful: report.executionSuccessful,
    error: null,
  };
}
