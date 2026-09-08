import type { Skill, SkillScanSummary, ToolEntry } from "../../types";
import { SkillCard } from "./SkillCard";

interface SkillListProps {
  skills: Skill[];
  toolEntries: ToolEntry[];
  emptyHint: string;
  onToggle: (skill: Skill) => void;
  onOpen: (skill: Skill) => void;
  /** Safety-scan summaries keyed by skill id; cards show a chip when
   *  their id has one. */
  scans?: Record<string, SkillScanSummary>;
  /** Re-runs the safety scan for a skill and opens the report. */
  onScanClick?: (skill: Skill) => void;
}

export function SkillList({
  skills,
  toolEntries,
  emptyHint,
  onToggle,
  onOpen,
  scans,
  onScanClick,
}: SkillListProps) {
  if (skills.length === 0) {
    return (
      <div className="empty-state">
        {emptyHint} Drop a folder with a <code>SKILL.md</code> file into the
        directory and it will show up here.
      </div>
    );
  }

  return (
    <>
      {skills.map((skill) => (
        <SkillCard
          key={skill.id}
          skill={skill}
          toolEntries={toolEntries}
          onToggle={onToggle}
          onOpen={onOpen}
          scan={scans?.[skill.id]}
          onScanClick={onScanClick}
        />
      ))}
    </>
  );
}
