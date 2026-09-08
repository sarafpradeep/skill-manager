import { useMemo } from "react";
import { CloseIcon } from "../ui/icons";
import { ModalShell } from "../ui/ModalShell";
import { bandForReport, countsFor, reportHeadline, sortFindings } from "../../utils/scanReport";
import type { ScanReport } from "../../types";

interface SafetyReportModalProps {
  /** Null while the scan it was triggered from is still running. */
  report: ScanReport | null;
  /** Set when the scan itself failed — shown in place of the report. */
  error?: string | null;
  /** Read-only views close via this; the install gate passes the
   *  cancel button explicitly. */
  onClose: () => void;
  title?: string;
  /** The install-gate actions; absent for read-only report views. */
  onConfirmRisky?: () => void;
  busy?: boolean;
}

const RECOMMENDATION_LABELS: Record<string, string> = {
  INSTALL: "safe to install",
  CAUTION: "review before installing",
  DONT_INSTALL: "do not install",
};

/** The full scan report for one skill: risk score, per-severity counts,
 *  and every finding with its location and suggested fix. Opens over
 *  the install picker when a scan flagged a skill, or read-only from
 *  the editor / card chips. */
export function SafetyReportModal({
  report,
  error,
  onClose,
  title,
  onConfirmRisky,
  busy = false,
}: SafetyReportModalProps) {
  const band = report ? bandForReport(report) : null;
  const counts = useMemo(() => countsFor(report?.issues ?? []), [report]);
  const findings = useMemo(() => sortFindings(report?.issues ?? []), [report]);
  const heading =
    title ?? (report?.skill.name ? `safety report — ${report.skill.name}` : "safety report");

  return (
    <ModalShell className="safety-modal" onClose={onClose}>
      <div className="modal-header">
        <span className="title">{heading}</span>
        <button className="icon-btn square" onClick={onClose} title="close">
          <CloseIcon />
        </button>
      </div>

      {!report ? (
        error ? (
          <div className="empty-state">{error}</div>
        ) : (
          <div className="empty-state">scanning…</div>
        )
      ) : (
        <>
          <div className={`safety-score safety-score-${band}`}>
            <span className="safety-score-number">{report.riskAssessment.score}</span>
            <span className="safety-score-outof">/ 100</span>
            <span className="safety-score-meta">
              {RECOMMENDATION_LABELS[report.riskAssessment.recommendation] ??
                report.riskAssessment.recommendation.replace(/_/g, " ").toLowerCase()}
              {report.metadata.skillspectorVersion &&
                ` · SkillSpector v${report.metadata.skillspectorVersion}`}
              {" · static analysis"}
            </span>
          </div>

          <div className="safety-counts">
            {(["critical", "high", "medium", "low"] as const).map((severity) => (
              <span
                key={severity}
                className={`safety-count safety-count-${severity}`}
                title={`${severity} severity findings`}
              >
                {counts[severity.toUpperCase()]} {severity}
              </span>
            ))}
            {report.issues.length === 0 && <span className="safety-count">no findings</span>}
          </div>

          {report.issues.length > 0 && (
            <div className="safety-findings">
              {findings.map((finding, i) => (
                <details key={`${finding.id}-${i}`} className="safety-finding">
                  <summary>
                    <span className={`safety-sev safety-sev-${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    <span className="safety-finding-id">{finding.id}</span>
                    <span className="safety-finding-text">
                      {finding.explanation.length > 90
                        ? `${finding.explanation.slice(0, 90)}…`
                        : finding.explanation}
                    </span>
                  </summary>
                  <div className="safety-finding-body">
                    <div className="safety-finding-loc">
                      {finding.location.file}
                      {finding.location.startLine > 0 && `:${finding.location.startLine}`}
                    </div>
                    <p>{finding.explanation}</p>
                    {finding.codeSnippet && (
                      <pre className="safety-snippet">{finding.codeSnippet}</pre>
                    )}
                    {finding.remediation && (
                      <p className="safety-remediation">fix: {finding.remediation}</p>
                    )}
                  </div>
                </details>
              ))}
            </div>
          )}
        </>
      )}

      <div className="modal-footer">
        {onConfirmRisky && (
          <>
            <span className="safety-footer-note">
              {report ? reportHeadline(report) : "scanning…"}
            </span>
            <div className="footer-spacer" />
            <button className="btn danger" onClick={onConfirmRisky} disabled={busy || !report}>
              {busy ? "installing…" : "install anyway"}
            </button>
            <button className="btn" onClick={onClose} disabled={busy}>
              cancel
            </button>
          </>
        )}
      </div>
    </ModalShell>
  );
}
