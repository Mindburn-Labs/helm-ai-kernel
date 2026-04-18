import type { InstalledSkill } from '../types';

/** Shows promotion history for installed skills in a compact table. */
export function PromotionHistory({ skills }: { skills: InstalledSkill[] }) {
  if (skills.length === 0) {
    return (
      <p style={{ fontSize: '12px', color: 'var(--operator-text-muted)' }}>
        No promoted skills yet.
      </p>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
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
        Promotion History
      </span>
      <div className="operator-table-shell">
        <table className="operator-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Class</th>
              <th>Status</th>
              <th>Installed</th>
            </tr>
          </thead>
          <tbody>
            {skills.map((skill) => (
              <tr key={skill.id}>
                <td>{skill.name}</td>
                <td>{skill.version}</td>
                <td>{skill.selfModClass}</td>
                <td>{skill.status}</td>
                <td>{new Date(skill.installedAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
