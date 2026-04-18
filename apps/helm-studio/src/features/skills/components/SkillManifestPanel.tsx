import type { InstalledSkill, SkillCandidate } from '../types';

/** Displays the skill manifest details — ID, version, self-mod class, and status. */
export function SkillManifestPanel({
  skill,
}: {
  skill: InstalledSkill | SkillCandidate;
}) {
  const selfModLabel: Record<string, string> = {
    C0: 'C0 — Read-only',
    C1: 'C1 — Config write',
    C2: 'C2 — Code write',
    C3: 'C3 — Full self-modification',
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        padding: '12px',
        borderRadius: '8px',
        border: '1px solid rgba(158, 178, 198, 0.12)',
        background: 'rgba(158, 178, 198, 0.04)',
      }}
    >
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-text-muted)',
        }}
      >
        Skill Manifest
      </span>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {[
          { label: 'Skill ID', value: skill.skillId },
          { label: 'Name', value: skill.name },
          { label: 'Version', value: skill.version },
          {
            label: 'Self-mod class',
            value: selfModLabel[skill.selfModClass] ?? skill.selfModClass,
          },
        ].map(({ label, value }) => (
          <div key={label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
            <span style={{ color: 'var(--operator-text-soft)' }}>{label}</span>
            <span style={{ color: 'var(--operator-text)', fontWeight: 600 }}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
