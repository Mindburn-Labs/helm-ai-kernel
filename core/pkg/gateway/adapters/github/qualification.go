package github

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"

// QualificationSuite is the §9.3 suite of this adapter version. Each case is
// implemented in qualification_test.go under the same ID, and
// TestQualificationSuiteIsImplemented fails if the two lists differ. Changing
// a case changes the suite digest the records carry.
var QualificationSuite = adapters.Suite{
	Adapter:        "github",
	AdapterVersion: AdapterVersion,
	SuiteVersion:   "1",
	Cases: []adapters.SuiteCase{
		qcase("branch/happy-path", EffectBranchCreateFromChanges, "baseline",
			"Prepare, Dispatch and Observe create the branch; the result's commit has parent base_sha and files_digest is the proposal's."),
		qcase("branch/duplicate-submission", EffectBranchCreateFromChanges, "duplicate submission",
			"A second dispatch of the same effect writes nothing and is SENT; Observe finds the same commit, SUCCEEDED."),
		qcase("branch/existing-ref-not-overwritten", EffectBranchCreateFromChanges, "duplicate submission",
			"A dispatch whose head exists with other content writes nothing and leaves the ref unchanged; Observe answers READBACK_MISMATCH."),
		qcase("branch/lost-response", EffectBranchCreateFromChanges, "lost response after success",
			"The ref is created but the answer is lost: Dispatch is INDEFINITE and Observe reconciles it to SUCCEEDED."),
		qcase("branch/revoked-credential", EffectBranchCreateFromChanges, "revoked credential",
			"A rejected token is NOT_SENT with PROVIDER_CREDENTIAL_REJECTED and no write; Observe with it is UNKNOWN, never SUCCEEDED."),
		qcase("branch/precondition-failed", EffectBranchCreateFromChanges, "precondition failure",
			"A head equal to the default branch, or a base_sha the repository lacks, is refused with PRECONDITION_FAILED and no write."),
		qcase("branch/readback-mismatch", EffectBranchCreateFromChanges, "read-back mismatch",
			"Observe answers READBACK_MISMATCH for a wrong parent, an extra file and a blob that differs from the proposal."),
		qcase("branch/oversized-response", EffectBranchCreateFromChanges, "response exceeding the size limit",
			"An oversized read before the write is NOT_SENT; an oversized answer to the write is INDEFINITE and Observe reconciles it; an oversized read-back is UNKNOWN."),
		qcase("branch/permit-mismatch", EffectBranchCreateFromChanges, "boundary",
			"A permit digest of other bytes is NOT_SENT with PERMIT_ARGUMENT_MISMATCH before any provider call (09-01)."),
		qcase("branch/retarget", EffectBranchCreateFromChanges, "boundary",
			"Arguments naming a repository, and targets with '#', '?' or an extra segment, are refused with SCHEMA_VIOLATION before any provider call (09-02)."),
		qcase("pull_request/happy-path", EffectPullRequestCreateDraft, "baseline",
			"Dispatch opens a draft pull request at head_sha and Observe records it SUCCEEDED."),
		qcase("pull_request/duplicate-submission", EffectPullRequestCreateDraft, "duplicate submission",
			"A second dispatch opens no second pull request and is SENT; Observe finds the same pull request, SUCCEEDED."),
		qcase("pull_request/lost-response", EffectPullRequestCreateDraft, "lost response after success",
			"The pull request is opened but the answer is lost: Dispatch is INDEFINITE and Observe reconciles it to SUCCEEDED."),
		qcase("pull_request/revoked-credential", EffectPullRequestCreateDraft, "revoked credential",
			"A rejected token is NOT_SENT with PROVIDER_CREDENTIAL_REJECTED; Observe with it is UNKNOWN, never SUCCEEDED."),
		qcase("pull_request/head-moved", EffectPullRequestCreateDraft, "precondition failure",
			"A head that is not at the approved head_sha is NOT_SENT with PRECONDITION_FAILED and no pull request is opened."),
		qcase("pull_request/readback-mismatch", EffectPullRequestCreateDraft, "read-back mismatch",
			"A pull request that is not a draft, or whose title differs, is READBACK_MISMATCH with its URL recorded."),
		qcase("pull_request/oversized-response", EffectPullRequestCreateDraft, "response exceeding the size limit",
			"An oversized answer to the write is INDEFINITE and Observe reconciles it; an oversized read-back is UNKNOWN."),
		qcase("pull_request/permit-mismatch", EffectPullRequestCreateDraft, "boundary",
			"A permit digest of other bytes is NOT_SENT with PERMIT_ARGUMENT_MISMATCH before any provider call (09-01)."),
		qcase("repository/happy-path", EffectRepositoryGet, "baseline",
			"Dispatch writes nothing, and Observe reads the default branch and its head, and a requested branch, present or absent."),
		qcase("repository/revoked-credential", EffectRepositoryGet, "revoked credential",
			"A rejected token is NOT_SENT with PROVIDER_CREDENTIAL_REJECTED; Observe with it is UNKNOWN, never SUCCEEDED."),
		qcase("repository/oversized-response", EffectRepositoryGet, "response exceeding the size limit",
			"An oversized answer is NOT_SENT at Dispatch and UNKNOWN at Observe."),
		qcase("repository/permit-mismatch", EffectRepositoryGet, "boundary",
			"A permit digest of other bytes is NOT_SENT with PERMIT_ARGUMENT_MISMATCH before any provider call (09-01)."),
	},
}

func qcase(id, operation, category, description string) adapters.SuiteCase {
	return adapters.SuiteCase{ID: id, Operation: operation, Category: category, Description: description}
}
