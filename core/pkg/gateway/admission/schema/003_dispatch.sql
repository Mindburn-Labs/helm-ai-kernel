-- Effect gateway dispatch and observation (HELM-751 s3; ADR-0001 §1
-- "Dispatch claim", target architecture §4.1 items 3-4 and §4.3).

-- The dispatch claim's fence. The claim consumes the permit (claim_id) and
-- sets DISPATCHING with this deadline, before any provider I/O. Until it
-- passes, the dispatch may still be in flight and Observe leaves the attempt
-- alone; after it, the attempt is UNKNOWN and Observe reconciles it. It is
-- never dispatched again (§4.3).
ALTER TABLE authority_effect_attempts ADD COLUMN IF NOT EXISTS dispatch_deadline TIMESTAMPTZ;

-- Who claimed the permit: the workload principal of the Dispatch token and
-- its act.sub, if any. Only the workload the attempt was proposed through may
-- dispatch it.
ALTER TABLE authority_permits ADD COLUMN IF NOT EXISTS claimed_by_principal_id TEXT;
ALTER TABLE authority_permits ADD COLUMN IF NOT EXISTS claimed_by_actor_id TEXT;
