import { describe, expect, it } from "vitest";
import type { ScanFinding, ScanReport, SkillScanSummary } from "../../types";
import {
  bandForReport,
  bandForSummary,
  countsFor,
  isRiskyReport,
  reportHeadline,
  sortFindings,
} from "../scanReport";

function finding(severity: string, id = "X-001"): ScanFinding {
  return {
    id,
    severity,
    category: "Test",
    explanation: "e",
    remediation: "",
    codeSnippet: "",
    confidence: 0.5,
    location: { file: "SKILL.md", startLine: 1, endLine: null },
  };
}

function report(score: number, maxSeverity: string, issues: ScanFinding[] = []): ScanReport {
  return {
    skill: { name: "demo", scannedAt: "2026-09-08T00:00:00+00:00" },
    riskAssessment: {
      score,
      severity: "MEDIUM",
      recommendation: "CAUTION",
      maxIssueSeverity: maxSeverity,
    },
    issues,
    executionSuccessful: true,
    metadata: { skillspectorVersion: "2.11.1", hasExecutableScripts: false },
  };
}

function summary(overrides: Partial<SkillScanSummary> = {}): SkillScanSummary {
  return {
    id: "/skills/demo/SKILL.md",
    score: 0,
    severity: "LOW",
    recommendation: "OK",
    maxIssueSeverity: "",
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
    scannedAt: 0,
    skillspectorVersion: null,
    executionSuccessful: true,
    error: null,
    ...overrides,
  };
}

describe("isRiskyReport", () => {
  it("follows NVIDIA's threshold and severity table", () => {
    expect(isRiskyReport(report(0, ""))).toBe(false);
    expect(isRiskyReport(report(50, "LOW"))).toBe(false);
    expect(isRiskyReport(report(51, "LOW"))).toBe(true);
    // high/critical findings block regardless of the aggregate score
    expect(isRiskyReport(report(10, "HIGH"))).toBe(true);
    expect(isRiskyReport(report(10, "CRITICAL"))).toBe(true);
  });
});

describe("bandForSummary", () => {
  it("maps counts to the visual bands", () => {
    expect(bandForSummary(summary({ executionSuccessful: false }))).toBe("failed");
    expect(bandForSummary(summary({ high: 1 }))).toBe("danger");
    expect(bandForSummary(summary({ critical: 2 }))).toBe("danger");
    expect(bandForSummary(summary({ medium: 1 }))).toBe("warn");
    expect(bandForSummary(summary({ score: 60 }))).toBe("warn");
    expect(bandForSummary(summary({ score: 5, low: 3 }))).toBe("clean");
  });
});

describe("bandForReport", () => {
  it("flags risky reports as danger and scales by score otherwise", () => {
    expect(bandForReport(report(80, "LOW"))).toBe("danger");
    expect(bandForReport(report(10, "HIGH"))).toBe("danger");
    expect(bandForReport(report(30, "MEDIUM"))).toBe("warn");
    expect(bandForReport(report(0, ""))).toBe("clean");
    const failed = report(0, "");
    failed.executionSuccessful = false;
    expect(bandForReport(failed)).toBe("failed");
  });
});

describe("countsFor", () => {
  it("counts known severities and ignores unknown ones", () => {
    const counts = countsFor([
      finding("LOW"),
      finding("HIGH"),
      finding("HIGH", "X-002"),
      finding("weird", "X-003"),
    ]);
    expect(counts).toEqual({ CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 1 });
  });
});

describe("sortFindings", () => {
  it("orders worst-first with stable id tiebreak", () => {
    const sorted = sortFindings([
      finding("LOW", "A"),
      finding("CRITICAL", "B"),
      finding("HIGH", "Z"),
      finding("HIGH", "Y"),
    ]);
    expect(sorted.map((f) => f.id)).toEqual(["B", "Y", "Z", "A"]);
  });
});

describe("reportHeadline", () => {
  it("summarizes counts or says when the report is clean", () => {
    expect(reportHeadline(report(48, "HIGH", [finding("HIGH"), finding("MEDIUM")]))).toBe(
      "1 high · 1 medium",
    );
    expect(reportHeadline(report(0, ""))).toBe("no findings");
  });
});
