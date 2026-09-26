// Package github is the GitHub effect adapter v2 (HELM-753): the effects of
// the HELM-789 walking skeleton, github.branch.create_from_changes and
// github.pull_request.create_draft, and the read github.repository.get, over
// the GitHub REST API.
//
// The wire contract is docs/architecture/gateway-effect-api.md, section
// "Typed observation results and the GitHub effects", with the argument
// schemas in protocols/json-schemas/effects/github. It replaces nothing yet:
// core/pkg/connectors/github is the legacy connector, whose audit findings
// this adapter answers:
//
//   - 09-01: Dispatch compares the permit's argument digest with the exact
//     argument bytes before any provider call;
//   - 09-02: the repository comes only from the validated target, and the
//     arguments are a closed schema that cannot name one;
//   - 09-04: every GitHub answer is read through a size limit.
//
// The qualification suite (§9.3) is qualification_test.go, run against a
// fake GitHub and, when configured, a real sandbox repository.
package github

import (
	"context"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// AdapterVersion is the version qualification records name.
const AdapterVersion = "2.0.0"

// The effect types this adapter performs.
const (
	EffectBranchCreateFromChanges = "github.branch.create_from_changes"
	EffectPullRequestCreateDraft  = "github.pull_request.create_draft"
	EffectRepositoryGet           = "github.repository.get"
)

const (
	defaultBaseURL = "https://api.github.com"
	apiVersion     = "2022-11-28"
	// DefaultMaxResponseBytes bounds every answer except a comparison.
	DefaultMaxResponseBytes = 1 << 20
	// DefaultMaxCompareBytes bounds a comparison, which carries a patch for
	// each of up to 50 files of up to 48 KiB.
	DefaultMaxCompareBytes = 8 << 20
	// Observation.source and trust_class for this adapter's read-backs.
	observationSource = "github.rest.readback"
	trustClass        = "provider_readback"
)

// Adapter is the GitHub effect adapter. It holds no credential.
type Adapter struct {
	baseURL          string
	httpClient       *http.Client
	maxResponseBytes int64
	maxCompareBytes  int64
	now              func() time.Time
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithBaseURL points the adapter at another API root, such as a test server.
func WithBaseURL(u string) Option { return func(a *Adapter) { a.baseURL = u } }

// WithHTTPClient replaces the HTTP client. The adapter still refuses to
// follow redirects: a moved repository is a different target.
func WithHTTPClient(c *http.Client) Option { return func(a *Adapter) { a.httpClient = c } }

// WithMaxResponseBytes sets one limit for every answer, comparisons included.
func WithMaxResponseBytes(n int64) Option {
	return func(a *Adapter) { a.maxResponseBytes, a.maxCompareBytes = n, n }
}

// WithClock sets the clock for Observation.observed_at.
func WithClock(now func() time.Time) Option { return func(a *Adapter) { a.now = now } }

// New builds an adapter.
func New(opts ...Option) *Adapter {
	a := &Adapter{
		baseURL:          defaultBaseURL,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		maxResponseBytes: DefaultMaxResponseBytes,
		maxCompareBytes:  DefaultMaxCompareBytes,
		now:              time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	client := *a.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a.httpClient = &client
	return a
}

var _ adapters.Adapter = (*Adapter)(nil)

var declarations = []adapters.Declaration{
	{
		EffectType:    EffectBranchCreateFromChanges,
		RiskClass:     adapters.RiskMedium,
		Idempotent:    adapters.IdempotentConditional,
		Observable:    adapters.ObservableYes,
		Reversible:    adapters.ReversibleYes,
		Mediation:     adapters.MediationEnforced,
		ActivityTrail: false,
		Notes: "The ref is created only if it does not exist and is never overwritten. The read-back checks the ref, " +
			"the commit's parents, the compared paths and the blob SHA-1s. Deleting the branch reverses it; v1 has no compensation.",
	},
	{
		EffectType: EffectPullRequestCreateDraft,
		// Medium: mandate policy escalates it for approval; the effect type
		// itself is not high risk.
		RiskClass:     adapters.RiskMedium,
		Idempotent:    adapters.IdempotentConditional,
		Observable:    adapters.ObservableYes,
		Reversible:    adapters.ReversibleYes,
		Mediation:     adapters.MediationEnforced,
		ActivityTrail: false,
		Notes: "One open pull request per (head, base). The read-back finds it by head and base and checks draft, " +
			"head SHA, base and title. Closing it reverses it; v1 has no compensation.",
	},
	{
		EffectType:    EffectRepositoryGet,
		RiskClass:     adapters.RiskLow,
		Idempotent:    adapters.IdempotentYes,
		Observable:    adapters.ObservableYes,
		Reversible:    adapters.ReversibleNotApplicable,
		Mediation:     adapters.MediationEnforced,
		ActivityTrail: false,
		Notes:         "A read: it writes nothing. Observe reads the default branch and, when asked, one branch.",
	},
}

// Declarations implements adapters.Adapter.
func (a *Adapter) Declarations() []adapters.Declaration {
	return append([]adapters.Declaration(nil), declarations...)
}

func declaration(effectType string) (adapters.Declaration, bool) {
	for _, d := range declarations {
		if d.EffectType == effectType {
			return d, true
		}
	}
	return adapters.Declaration{}, false
}

// Prepare implements adapters.Adapter. It reads the default branch and, for
// a branch, refuses a head that is the default branch or already exists and a
// base_sha the repository does not have; for a pull request, a head that is
// not at head_sha.
func (a *Adapter) Prepare(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) (*adapters.Preparation, error) {
	decl, ok := declaration(effect.EffectType)
	if !ok {
		return nil, schemaViolation("effect type %q is not a GitHub adapter effect", effect.EffectType)
	}
	repo, err := parseTarget(effect.Target)
	if err != nil {
		return nil, err
	}
	var check func(context.Context, *client, repoInfo) error
	switch effect.EffectType {
	case EffectBranchCreateFromChanges:
		args, err := parseBranchArgs(effect.Arguments)
		if err != nil {
			return nil, err
		}
		check = func(ctx context.Context, c *client, info repoInfo) error { return c.prepareBranch(ctx, info, args) }
	case EffectPullRequestCreateDraft:
		args, err := parsePullRequestArgs(effect.Arguments)
		if err != nil {
			return nil, err
		}
		check = func(ctx context.Context, c *client, _ repoInfo) error {
			return c.checkHeadAt(ctx, args.Head, args.HeadSHA)
		}
	default:
		if _, err := parseRepositoryArgs(effect.Arguments); err != nil {
			return nil, err
		}
		check = func(context.Context, *client, repoInfo) error { return nil }
	}
	c, err := a.newClient(ctx, creds, repo)
	if err != nil {
		return nil, refusal(err)
	}
	info, err := c.getRepo(ctx)
	if err != nil {
		return nil, refusal(err)
	}
	if err := check(ctx, c, info); err != nil {
		return nil, refusal(err)
	}
	return &adapters.Preparation{
		Declaration: decl,
		Target:      effect.Target,
		Quote:       []adapters.Amount{{Unit: "count", Amount: 1}},
		Resolved:    map[string]string{"default_branch": info.DefaultBranch},
	}, nil
}

// Dispatch implements adapters.Adapter.
func (a *Adapter) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, permitArgumentDigest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, permitArgumentDigest); r != nil {
		return notSent(r)
	}
	repo, err := parseTarget(effect.Target)
	if err != nil {
		return notSent(err)
	}
	switch effect.EffectType {
	case EffectBranchCreateFromChanges:
		args, err := parseBranchArgs(effect.Arguments)
		if err != nil {
			return notSent(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return notSent(err)
		}
		return c.dispatchBranch(ctx, args)
	case EffectPullRequestCreateDraft:
		args, err := parsePullRequestArgs(effect.Arguments)
		if err != nil {
			return notSent(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return notSent(err)
		}
		return c.dispatchPullRequest(ctx, args)
	case EffectRepositoryGet:
		args, err := parseRepositoryArgs(effect.Arguments)
		if err != nil {
			return notSent(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return notSent(err)
		}
		return c.dispatchRepository(ctx, args)
	default:
		return notSent(schemaViolation("effect type %q is not a GitHub adapter effect", effect.EffectType))
	}
}

// Observe implements adapters.Adapter.
func (a *Adapter) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	repo, err := parseTarget(effect.Target)
	if err != nil {
		return unknown(err)
	}
	switch effect.EffectType {
	case EffectBranchCreateFromChanges:
		args, err := parseBranchArgs(effect.Arguments)
		if err != nil {
			return unknown(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return unknown(err)
		}
		return c.observeBranch(ctx, args)
	case EffectPullRequestCreateDraft:
		args, err := parsePullRequestArgs(effect.Arguments)
		if err != nil {
			return unknown(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return unknown(err)
		}
		return c.observePullRequest(ctx, args)
	case EffectRepositoryGet:
		args, err := parseRepositoryArgs(effect.Arguments)
		if err != nil {
			return unknown(err)
		}
		c, err := a.newClient(ctx, creds, repo)
		if err != nil {
			return unknown(err)
		}
		return c.observeRepository(ctx, args)
	default:
		return unknown(schemaViolation("effect type %q is not a GitHub adapter effect", effect.EffectType))
	}
}

// refusal turns any error into a *adapters.Refusal.
func refusal(err error) *adapters.Refusal {
	if r, ok := err.(*adapters.Refusal); ok {
		return r
	}
	pe := asProviderError(err)
	return &adapters.Refusal{Reason: pe.Reason, Detail: pe.Detail}
}

func notSent(err error) adapters.DispatchResult {
	r := refusal(err)
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
}

func indefinite(err error) adapters.DispatchResult {
	r := refusal(err)
	return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: r.Reason, Detail: r.Detail}
}

// writeResult classifies the answer to the effect's one write: a definite
// refusal means it did not happen, a 422 may mean it already had (Observe
// reconciles), and anything else is indefinite.
func writeResult(err error) adapters.DispatchResult {
	if err == nil {
		return adapters.DispatchResult{Status: adapters.DispatchSent}
	}
	pe := asProviderError(err)
	if pe.Refused && pe.Status != http.StatusUnprocessableEntity {
		return notSent(pe)
	}
	return indefinite(pe)
}

func unknown(err error) adapters.ObserveResult {
	r := refusal(err)
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: r.Reason, Detail: r.Detail}
}

func (c *client) observation() *adapters.Observation {
	return &adapters.Observation{
		Source:         observationSource,
		TrustClass:     trustClass,
		EvidenceDigest: evidenceDigest(c.evidence),
		ObservedAt:     c.a.now().UTC(),
	}
}

// settle turns a read-back into its result: SUCCEEDED when mismatch is empty,
// otherwise FAILED with READBACK_MISMATCH. Both carry the observation.
func settle(obs *adapters.Observation, mismatch string) adapters.ObserveResult {
	if mismatch == "" {
		return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: obs}
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch, Detail: mismatch, Observation: obs}
}
