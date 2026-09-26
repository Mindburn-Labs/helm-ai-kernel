// Package adapters is the effect adapter contract of the HELM gateway (target
// architecture §9.1, HELM-753).
//
// An adapter turns one admitted effect into provider calls. It implements:
//
//   - Prepare: resolve the target and its preconditions, read-only;
//   - Dispatch: perform the effect with a credential injected for this call,
//     after comparing the permit's argument digest with the exact bytes it is
//     about to act on (audit 09-01);
//   - Observe: an independent read-back that establishes the outcome.
//
// Compensate is optional in §9.1; no adapter implements it yet, so the
// interface does not carry it.
//
// Adapters hold no long-lived secrets and read no environment. The gateway's
// connection custody (§9.6) supplies a TokenSource per call. Every provider
// response an adapter reads is bounded (09-04), and the target comes only from
// the effect's target, never from its arguments (09-02).
//
// This package and its subpackages must not import the legacy runtime
// (guardian, proxy, mcp, executor); the gateway is Zone C and must stay
// movable to its own repository.
package adapters

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Adapter performs the effect types it declares.
type Adapter interface {
	// Declarations lists one declaration per effect type the adapter
	// performs.
	Declarations() []Declaration
	// Prepare validates the effect and reads the provider state it depends
	// on. It changes nothing. A refusal is a *Refusal.
	Prepare(ctx context.Context, creds TokenSource, effect Effect) (*Preparation, error)
	// Dispatch performs the effect once. permitArgumentDigest is the permit's
	// argument_digest; the adapter refuses unless it is SHA-256 of
	// effect.Arguments. Dispatch never retries a write whose outcome it cannot
	// tell; it answers DispatchIndefinite and leaves the outcome to Observe.
	Dispatch(ctx context.Context, creds TokenSource, effect Effect, permitArgumentDigest []byte) DispatchResult
	// Observe reads the provider state back and compares it with the effect.
	// It changes nothing and may be called any number of times.
	Observe(ctx context.Context, creds TokenSource, effect Effect) ObserveResult
}

// TokenSource yields the credential for one provider call, for example a
// GitHub App installation token minted by the gateway's connection custody.
// The adapter asks for it on every operation and never stores it.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Effect is the admitted effect: EffectDescriptor's three fields. Arguments
// are the exact bytes the permit's argument_digest covers.
type Effect struct {
	EffectType string
	Target     string
	Arguments  []byte
}

// Idempotency is how a repeated dispatch behaves (§9.1).
type Idempotency string

const (
	IdempotentYes         Idempotency = "yes"
	IdempotentNo          Idempotency = "no"
	IdempotentConditional Idempotency = "conditional"
)

// Observability is how far Observe can establish the outcome (§9.1).
type Observability string

const (
	ObservableYes     Observability = "yes"
	ObservablePartial Observability = "partial"
	ObservableNo      Observability = "no"
)

// Mediation is whether the gateway is the only path to the effect (§9.1).
type Mediation string

const (
	MediationEnforced     Mediation = "enforced"
	MediationObservedOnly Mediation = "observed-only"
)

// Reversibility is whether the effect can be undone (§9.1). An operation
// that writes nothing has nothing to reverse.
type Reversibility string

const (
	ReversibleYes           Reversibility = "yes"
	ReversibleNo            Reversibility = "no"
	ReversibleNotApplicable Reversibility = "not applicable"
)

// RiskClass is the effect type's risk class, as the proto's RiskClass names
// it in lower case.
type RiskClass string

const (
	RiskLow          RiskClass = "low"
	RiskMedium       RiskClass = "medium"
	RiskHigh         RiskClass = "high"
	RiskIrreversible RiskClass = "irreversible"
)

// Declaration is one operation's §9.1 declaration.
type Declaration struct {
	EffectType string
	RiskClass  RiskClass
	Idempotent Idempotency
	Observable Observability
	Reversible Reversibility
	Mediation  Mediation
	// ActivityTrail is whether this adapter version reconciles the provider's
	// activity feed against the log (rev 3.4 §9.1, §5.4).
	ActivityTrail bool
	// Notes qualifies the declaration in one or two sentences.
	Notes string
}

// Amount is one quote entry, as the proto's ResourceAmount.
type Amount struct {
	Unit   string
	Amount int64
}

// Preparation is what Prepare resolved.
type Preparation struct {
	Declaration Declaration
	// Target is the validated target, unchanged.
	Target string
	// Quote is the adapter's quote for the effect.
	Quote []Amount
	// Resolved names provider facts the preconditions read, for example
	// "default_branch".
	Resolved map[string]string
}

// DispatchStatus is how far a dispatch got.
type DispatchStatus string

const (
	// DispatchSent: the provider accepted the effect's write, or already
	// holds the object the write would create (a ref, an open pull request),
	// which the adapter never overwrites. The attempt is DISPATCHED and
	// Observe establishes the outcome: SUCCEEDED if the object is this
	// effect, FAILED with READBACK_MISMATCH if it is not.
	DispatchSent DispatchStatus = "SENT"
	// DispatchNotSent: the adapter refused, or the provider refused, before
	// any write that could take effect. The effect certainly did not happen:
	// the gateway records OBSERVED(FAILED) with Reason and releases the
	// reservation. It is never UNKNOWN.
	DispatchNotSent DispatchStatus = "NOT_SENT"
	// DispatchIndefinite: the effect may have happened. The attempt is
	// UNKNOWN; Observe reconciles it, and it is never dispatched again.
	DispatchIndefinite DispatchStatus = "INDEFINITE"
)

// DispatchResult is Dispatch's answer.
type DispatchResult struct {
	Status DispatchStatus
	// Reason is empty for DispatchSent.
	Reason contracts.ReasonCode
	Detail string
}

// Outcome is what an observation shows, as the proto's EffectOutcome.
type Outcome string

const (
	OutcomeSucceeded Outcome = "SUCCEEDED"
	OutcomeFailed    Outcome = "FAILED"
	// OutcomeUnknown: the read-back was inconclusive (EFFECT_OUTCOME_UNSPECIFIED).
	OutcomeUnknown Outcome = "UNKNOWN"
)

// ObserveResult is Observe's answer. Observation is set when the outcome is
// established (SUCCEEDED or FAILED) and nil when it is UNKNOWN.
type ObserveResult struct {
	Outcome     Outcome
	Reason      contracts.ReasonCode
	Detail      string
	Observation *Observation
}

// Observation mirrors helm.gateway.v1.Observation without result_ref, which
// the gateway assigns when it stores the result. Exactly one typed result is
// set, the one the effect type defines.
type Observation struct {
	Source     string
	TrustClass string
	// EvidenceDigest is SHA-256 over the provider bytes the read-back used.
	EvidenceDigest    []byte
	ObservedAt        time.Time
	GitHubPullRequest *GitHubPullRequestResult
	GitHubBranch      *GitHubBranchResult
	GitHubRepository  *GitHubRepositoryResult
}

// GitHubPullRequestResult mirrors helm.gateway.v1.GitHubPullRequestResult;
// the JSON names are the proto field names, and TestResultTypesMirrorTheProto
// keeps them in step.
type GitHubPullRequestResult struct {
	URL     string `json:"url"`
	Number  int64  `json:"number"`
	NodeID  string `json:"node_id"`
	HeadRef string `json:"head_ref"`
	HeadSHA string `json:"head_sha"`
	BaseRef string `json:"base_ref"`
	Draft   bool   `json:"draft"`
	State   string `json:"state"`
}

// GitHubBranchResult mirrors helm.gateway.v1.GitHubBranchResult.
type GitHubBranchResult struct {
	Ref         string `json:"ref"`
	CommitSHA   string `json:"commit_sha"`
	BaseSHA     string `json:"base_sha"`
	FilesDigest []byte `json:"files_digest"`
}

// GitHubRepositoryResult mirrors helm.gateway.v1.GitHubRepositoryResult. The
// branch fields are set only when the effect asked for a branch.
type GitHubRepositoryResult struct {
	DefaultBranch    string `json:"default_branch"`
	DefaultBranchSHA string `json:"default_branch_sha"`
	Branch           string `json:"branch"`
	BranchSHA        string `json:"branch_sha"`
	BranchExists     bool   `json:"branch_exists"`
}

// Refusal is a definite refusal with its registry reason code.
type Refusal struct {
	Reason contracts.ReasonCode
	Detail string
}

func (r *Refusal) Error() string { return fmt.Sprintf("%s: %s", r.Reason, r.Detail) }

// Refuse builds a *Refusal.
func Refuse(reason contracts.ReasonCode, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// CheckPermitDigest is the last guard of audit 09-01: it refuses unless
// permitArgumentDigest is SHA-256 of exactly the argument bytes the adapter is
// about to act on. Every adapter calls it before any provider I/O.
func CheckPermitDigest(arguments, permitArgumentDigest []byte) *Refusal {
	if len(permitArgumentDigest) != sha256.Size {
		return Refuse(contracts.ReasonPermitArgumentMismatch, "the permit carries no 32-byte argument digest")
	}
	sum := sha256.Sum256(arguments)
	if !bytes.Equal(sum[:], permitArgumentDigest) {
		return Refuse(contracts.ReasonPermitArgumentMismatch, "the arguments are not the bytes the permit admitted")
	}
	return nil
}
