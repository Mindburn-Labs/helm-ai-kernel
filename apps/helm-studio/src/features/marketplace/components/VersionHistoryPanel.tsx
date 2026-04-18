import { useConnectorVersions } from '../hooks';

/** Shows version history for a marketplace connector, fetched live. */
export function VersionHistoryPanel({ connectorId }: { connectorId: string }) {
  const { data, isLoading } = useConnectorVersions(connectorId);
  const versions = data?.versions ?? [];

  if (isLoading) {
    return (
      <p style={{ fontSize: '12px', color: 'var(--operator-text-muted)' }}>
        Loading version history…
      </p>
    );
  }

  if (versions.length === 0) {
    return (
      <p style={{ fontSize: '12px', color: 'var(--operator-text-muted)' }}>
        No version history available.
      </p>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: 'var(--operator-text-muted)',
        }}
      >
        Version History
      </span>
      <div className="operator-table-shell">
        <table className="operator-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>State</th>
              <th>Released</th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.version}>
                <td>
                  <code style={{ fontSize: '11px' }}>{v.version}</code>
                </td>
                <td>
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      color:
                        v.state === 'certified'
                          ? 'rgba(80, 220, 120, 0.9)'
                          : v.state === 'revoked'
                            ? 'var(--operator-tone-danger)'
                            : 'var(--operator-text-muted)',
                    }}
                  >
                    {v.state}
                  </span>
                </td>
                <td style={{ fontSize: '11px', color: 'var(--operator-text-muted)' }}>
                  {new Date(v.releasedAt).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
