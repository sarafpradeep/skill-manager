import type { ScanProgressInfo } from "../../hooks/useSkillScans";
import type { ToolFolderInfo } from "../../types";

interface TopbarProps {
  title: string;
  subtitle: string;
  /** Folders the selected tool reads — shown as the page header. */
  folders?: ToolFolderInfo[];
  query: string;
  onQueryChange: (query: string) => void;
  onForgetProject?: () => void;
  /** Opens the collections browse flow. */
  onBrowse?: () => void;
  /** Opens the new-skill flow. */
  onNewSkill?: () => void;
  /** Runs the SkillSpector scan across every managed skill. */
  onScanAll?: () => void;
  /** Non-null while a scan-all is in flight. */
  scanProgress?: ScanProgressInfo | null;
  /** True when the scanner CLI isn't installed — scans are skipped. */
  scannerMissing?: boolean;
}

export function Topbar({
  title,
  subtitle,
  folders,
  query,
  onQueryChange,
  onForgetProject,
  onBrowse,
  onNewSkill,
  onScanAll,
  scanProgress,
  scannerMissing,
}: TopbarProps) {
  return (
    <div className="topbar">
      <div className="topbar-title">
        <h1>{title}</h1>
        <span className="subtitle">{subtitle}</span>
        {folders && folders.length > 0 && (
          <div className="folder-chips">
            {folders.map((f) => (
              <span
                key={f.tool}
                className={`folder-chip ${f.role === "compat" ? "compat" : ""} ${f.dirExists ? "" : "missing"}`}
                title={f.role === "compat" ? `${f.dir} — compatibility path` : f.dir}
              >
                {f.dir}
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="topbar-actions">
        {onScanAll && (
          <button
            className="btn"
            onClick={onScanAll}
            disabled={scanProgress !== null && scanProgress !== undefined}
            title="scan every installed skill for safety issues (NVIDIA SkillSpector, static analysis)"
          >
            {scanProgress
              ? `scanning ${scanProgress.done}/${scanProgress.total}…`
              : "safety scan"}
          </button>
        )}
        {scannerMissing && (
          <span
            className="source-pill"
            title="install it with: uv tool install git+https://github.com/NVIDIA/skillspector.git"
          >
            no safety scanner
          </span>
        )}
        {onBrowse && (
          <button className="btn" onClick={onBrowse} title="browse and install skills from GitHub collections">
            browse
          </button>
        )}
        {onNewSkill && (
          <button className="btn" onClick={onNewSkill} title="create a new skill from a minimal template">
            new skill
          </button>
        )}
        <input
          className="search"
          placeholder="search skills..."
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
        />
        {onForgetProject && (
          <button className="icon-btn danger" onClick={onForgetProject}>
            forget project
          </button>
        )}
      </div>
    </div>
  );
}
