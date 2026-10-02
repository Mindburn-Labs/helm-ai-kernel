-- Worker episodes on attempts (HELM-752 K7, HELM-751 N1; docs/architecture/
-- gateway-effect-api.md "Episode attempts").
--
-- An attempt proposed with an episode token records the token's helm_episode
-- claim: the episode, and the organization version it runs under. The work item
-- is the attempt's case_id, which an episode attempt always has. Both columns
-- are NULL for every other attempt, which is every attempt proposed before this
-- migration. A row never changes them: they are written with the row, from the
-- verified claim alone.
--
-- IS NOT NULL comes first in the second branch because a CHECK passes on NULL.
-- The id pattern is the one the token validator holds an episode claim to
-- (jwks claimID).
ALTER TABLE authority_effect_attempts ADD COLUMN IF NOT EXISTS episode_id TEXT;
ALTER TABLE authority_effect_attempts ADD COLUMN IF NOT EXISTS organization_version_id TEXT;
ALTER TABLE authority_effect_attempts DROP CONSTRAINT IF EXISTS authority_effect_attempts_episode;
ALTER TABLE authority_effect_attempts ADD CONSTRAINT authority_effect_attempts_episode CHECK (
    (episode_id IS NULL AND organization_version_id IS NULL)
    OR (episode_id IS NOT NULL AND episode_id ~ '^[A-Za-z0-9._:-]{1,128}$'
        AND case_id IS NOT NULL
        AND (organization_version_id IS NULL OR organization_version_id ~ '^[A-Za-z0-9._:-]{1,128}$')));

-- An episode's attempts in listing order: ListAttempts with an episode filter
-- (and every read a worker token makes) is served from it. Partial, so the
-- attempts of no episode cost nothing.
CREATE INDEX IF NOT EXISTS authority_effect_attempts_by_episode
    ON authority_effect_attempts (tenant_id, workspace_id, episode_id, updated_at, attempt_id)
    WHERE episode_id IS NOT NULL;
