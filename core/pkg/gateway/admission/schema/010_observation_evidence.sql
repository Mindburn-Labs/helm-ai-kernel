-- A retry of one provider fact must not create a second observation. Null
-- digests remain allowed for legacy adapter refusals with no provider bytes.
-- Existing duplicate non-null evidence blocks migration for review; this
-- migration never deletes or rewrites retained observations.
CREATE UNIQUE INDEX IF NOT EXISTS authority_observations_attempt_evidence_unique
    ON authority_observations (tenant_id, attempt_id, evidence_digest)
    WHERE evidence_digest IS NOT NULL;
