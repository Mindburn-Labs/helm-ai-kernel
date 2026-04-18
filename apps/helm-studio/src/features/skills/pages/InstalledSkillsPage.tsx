import { useOperatorShell } from '../../../operator/layout';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  SurfaceIntro,
  TopStatusPill,
} from '../../../operator/components';
import { useInstalledSkills } from '../hooks';
import { SkillManifestPanel } from '../components/SkillManifestPanel';
import { PromotionHistory } from '../components/PromotionHistory';

export function InstalledSkillsPage() {
  const shell = useOperatorShell();

  const { data, isLoading, isError, error, refetch } = useInstalledSkills(shell.workspaceId);

  const skills = data?.skills ?? [];

  if (isLoading) {
    return <LoadingState label="Loading installed skills..." />;
  }

  if (isError) {
    return (
      <ErrorState
        error={error}
        retry={() => void refetch()}
        title="Could not load installed skills"
      />
    );
  }

  const activeCount = skills.filter((s) => s.status === 'active').length;
  const deprecatedCount = skills.filter((s) => s.status === 'deprecated').length;

  return (
    <div className="operator-surface-page">
      <SurfaceIntro
        eyebrow="Skills / Installed"
        title="Installed Skills"
        description="Skills currently active in this workspace. Each skill has a self-modification class that governs what it is permitted to change."
        actions={
          <div className="operator-rail-status">
            <TopStatusPill label="Total" tone="neutral" value={String(skills.length)} />
            <TopStatusPill label="Active" tone="success" value={String(activeCount)} />
            <TopStatusPill label="Deprecated" tone="warning" value={String(deprecatedCount)} />
          </div>
        }
      />

      {skills.length === 0 ? (
        <EmptyState
          title="No installed skills"
          body="No skills have been promoted to this workspace yet. Visit the Candidate Queue to review and promote pending skills."
        />
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: '12px',
          }}
        >
          {skills.map((skill) => (
            <div
              key={skill.id}
              style={{
                padding: '14px',
                borderRadius: '10px',
                border: '1px solid rgba(158, 178, 198, 0.12)',
                background: 'rgba(158, 178, 198, 0.03)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--operator-text)' }}>
                  {skill.name}
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    background:
                      skill.status === 'active'
                        ? 'rgba(80, 220, 120, 0.1)'
                        : skill.status === 'deprecated'
                          ? 'rgba(255, 200, 50, 0.1)'
                          : 'rgba(158, 178, 198, 0.08)',
                    color:
                      skill.status === 'active'
                        ? 'rgba(80, 220, 120, 0.9)'
                        : skill.status === 'deprecated'
                          ? 'var(--operator-tone-warning)'
                          : 'var(--operator-text-muted)',
                  }}
                >
                  {skill.status}
                </span>
              </div>
              <SkillManifestPanel skill={skill} />
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: '24px' }}>
        <PromotionHistory skills={skills} />
      </div>
    </div>
  );
}
