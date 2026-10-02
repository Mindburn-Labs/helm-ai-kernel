-- Effect gateway step-up proof (HELM-751; target architecture §10.1).
--
-- An approval of an effect that needs step-up keeps the proof it used up,
-- exactly as received: the compact token, so that it can be verified again
-- against the issuer's keys, and its issuer and jti (the key of the
-- authority_token_replay row that used it up: tenant, issuer, jti) and the
-- method the issuer attests. The four are all NULL for an approval that needed
-- no step-up and for a rejection. IS NOT NULL comes first in the second branch
-- because a CHECK passes on NULL. 8192 bytes is admission.MaxStepUpProofBytes.
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS step_up_issuer TEXT;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS step_up_jti TEXT;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS step_up_method TEXT;
ALTER TABLE authority_approvals ADD COLUMN IF NOT EXISTS step_up_proof TEXT;
ALTER TABLE authority_approvals DROP CONSTRAINT IF EXISTS authority_approvals_step_up_proof;
ALTER TABLE authority_approvals ADD CONSTRAINT authority_approvals_step_up_proof CHECK (
    (step_up_issuer IS NULL AND step_up_jti IS NULL AND step_up_method IS NULL AND step_up_proof IS NULL)
    OR (decision = 'APPROVED'
        AND step_up_issuer IS NOT NULL AND step_up_jti IS NOT NULL AND step_up_method IS NOT NULL AND step_up_proof IS NOT NULL
        AND step_up_issuer <> '' AND step_up_jti <> '' AND step_up_method <> '' AND step_up_proof <> ''
        AND octet_length(step_up_proof) <= 8192));
