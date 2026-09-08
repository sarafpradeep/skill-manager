import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api } from "../api";
import { summaryFromReport } from "../utils/scanReport";
import type { ScanReport, SkillScanSummary } from "../types";

export interface ScanProgressInfo {
  done: number;
  total: number;
}

/** Safety-scan state for the whole app: the persisted per-skill
 *  summaries behind the card chips, the scan-all progress counter, and
 *  single-skill rescans. */
export function useSkillScans() {
  const [results, setResults] = useState<Record<string, SkillScanSummary>>({});
  const [progress, setProgress] = useState<ScanProgressInfo>({ done: 0, total: 0 });
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    // last-known results survive restarts via scan-results.json
    api
      .listScanResults()
      .then((list) => setResults(Object.fromEntries(list.map((r) => [r.id, r]))))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!scanning) return;
    const unlisten = listen<ScanProgressInfo>("scan-progress", (event) =>
      setProgress(event.payload),
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [scanning]);

  const merge = useCallback((list: SkillScanSummary[]) => {
    setResults((prev) => {
      const next = { ...prev };
      for (const summary of list) next[summary.id] = summary;
      return next;
    });
  }, []);

  const scanAll = useCallback(async () => {
    setScanning(true);
    setProgress({ done: 0, total: 0 });
    try {
      merge(await api.scanAllSkills());
    } finally {
      setScanning(false);
    }
  }, [merge]);

  const scanOne = useCallback(
    async (id: string): Promise<ScanReport> => {
      const report = await api.scanInstalledSkill(id);
      merge([summaryFromReport(id, report)]);
      return report;
    },
    [merge],
  );

  /** Fold a report the backend produced on its own (e.g. attached to an
   *  install) into the chip state. */
  const recordReport = useCallback(
    (id: string, report: ScanReport | null) => {
      if (report) merge([summaryFromReport(id, report)]);
    },
    [merge],
  );

  return { results, progress, scanning, scanAll, scanOne, recordReport };
}

/** Whether the SkillSpector CLI is usable — checked once per mount so
 *  both the top bar and the browse view can admit when scans are off. */
export function useScannerStatus() {
  const [status, setStatus] = useState<{ available: boolean; version: string | null } | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .checkScanner()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        if (!cancelled) setStatus({ available: false, version: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return status;
}
