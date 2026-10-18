package admission

// quantum_posture: consumes claims authenticated by the classical RS256 JWT
// validator; this file adds no post-quantum cryptographic primitive.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Continuation is copied only from a verified successor executor JWT. Each
// source names the original attempts that the Control Plane drained and
// committed before this successor was issued. It grants read and exact replay,
// never approval, dispatch, observation, or a second permit.
type Continuation struct {
	TenantID, WorkspaceID, OrganizationID, WorkItemID, OrganizationVersionID string
	SuccessorEpisodeID, SuccessorPrincipalID, SuccessorActorID               string
	Sources                                                                  []ContinuationSource
}

type ContinuationSource struct {
	EpisodeID, PrincipalID, ActorID string
	AttemptIDs                      []string
}

func validContinuationCaller(c Caller) bool {
	g := c.Continuation
	if g == nil {
		return true
	}
	if c.Episode == nil || g.TenantID != c.TenantID || g.WorkspaceID != c.WorkspaceID ||
		g.WorkItemID != c.Episode.WorkItemID || g.OrganizationVersionID != c.Episode.OrganizationVersionID ||
		g.SuccessorEpisodeID != c.Episode.EpisodeID || g.SuccessorPrincipalID != c.PrincipalID ||
		g.SuccessorActorID != c.ActorID || !strings.HasPrefix(c.PrincipalID, "agt:") || len(g.Sources) == 0 {
		return false
	}
	for _, source := range g.Sources {
		if source.EpisodeID == "" || source.EpisodeID == c.Episode.EpisodeID ||
			source.PrincipalID != c.PrincipalID || len(source.AttemptIDs) > 0 && source.ActorID == "" {
			return false
		}
	}
	return true
}

func workAttemptIsOwn(c Caller, a Attempt) bool {
	return c.Episode != nil && a.Episode != nil && a.Episode.EpisodeID == c.Episode.EpisodeID &&
		a.Episode.WorkItemID == c.Episode.WorkItemID && a.Episode.OrganizationVersionID == c.Episode.OrganizationVersionID &&
		a.RequesterPrincipalID == c.PrincipalID && a.RequesterActorID == c.ActorID && a.WorkspaceID == c.WorkspaceID
}

func continuationAllows(c Caller, a Attempt) bool {
	if !validContinuationCaller(c) || c.Continuation == nil || a.Episode == nil ||
		a.WorkspaceID != c.WorkspaceID || a.CaseID != c.Episode.WorkItemID ||
		a.Episode.OrganizationVersionID != c.Episode.OrganizationVersionID {
		return false
	}
	for _, source := range c.Continuation.Sources {
		if a.Episode.EpisodeID != source.EpisodeID || a.RequesterPrincipalID != source.PrincipalID ||
			a.RequesterActorID != source.ActorID {
			continue
		}
		for _, id := range source.AttemptIDs {
			if id == a.ID {
				return true
			}
		}
	}
	return false
}

// authorizeWorkReplay runs after the unique key collision, in the same tenant
// transaction. Its refusal does not identify an unlisted predecessor attempt.
func authorizeWorkReplay(ctx context.Context, tx *sql.Tx, caller Caller, in ProposeInput, attemptID string, argumentDigest []byte) error {
	a, err := loadAttemptScoped(ctx, tx, caller, attemptID, caller.Episode.WorkItemID, workEffectDigest(caller, in))
	if err != nil {
		return err
	}
	if !workAttemptIsOwn(caller, a) && !continuationAllows(caller, a) {
		return errNotFound
	}
	if a.IdempotencyKey != in.IdempotencyKey || a.EffectType != in.EffectType ||
		workEffectTarget(a.EffectType, a.Target) != workEffectTarget(in.EffectType, in.Target) ||
		!bytes.Equal(a.ArgumentDigest, argumentDigest) || !sameQuote(a.Quote, in.Quote) {
		return errNotFound
	}
	// Work-effect inputs are the closed MCP shape. A source with nonempty
	// distinct values cannot be replayed through that shape.
	var distinct []byte
	if err := tx.QueryRowContext(ctx, `SELECT distinct_values FROM authority_effect_attempts
		WHERE tenant_id = $1 AND attempt_id = $2`, caller.TenantID, attemptID).Scan(&distinct); err != nil {
		return err
	}
	var stored []storedDistinct
	if err := json.Unmarshal(distinct, &stored); err != nil || len(stored) != 0 {
		return errNotFound
	}
	return nil
}

func sameQuote(a, b []Amount) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]Amount(nil), a...), append([]Amount(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].Unit < x[j].Unit })
	sort.Slice(y, func(i, j int) bool { return y[i].Unit < y[j].Unit })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// GetContinuation is the explicit predecessor read path. Get and GetContent
// retain their original episode isolation and never consume this grant.
func (s *Service) GetContinuation(ctx context.Context, caller Caller, attemptID string) (Attempt, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, err
	}
	if caller.Continuation == nil {
		return Attempt{}, errNotFound
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, err
	}
	var a Attempt
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireActiveContinuationAgent(ctx, tx, caller); err != nil {
			return err
		}
		var err error
		a, err = loadAttemptScoped(ctx, tx, caller, attemptID, caller.Episode.WorkItemID, nil)
		if err != nil {
			return err
		}
		if !continuationAllows(caller, a) {
			return errNotFound
		}
		return nil
	})
	return a, err
}

// GetContentContinuation recovers only the original arguments of one listed
// predecessor. It does not alter or widen the ordinary GetContent route.
func (s *Service) GetContentContinuation(ctx context.Context, caller Caller, attemptID string) ([]byte, error) {
	if err := checkCaller(caller); err != nil {
		return nil, err
	}
	if caller.Continuation == nil {
		return nil, errNotFound
	}
	if err := checkAttemptID(attemptID); err != nil {
		return nil, err
	}
	var content []byte
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireActiveContinuationAgent(ctx, tx, caller); err != nil {
			return err
		}
		a, err := loadAttemptScoped(ctx, tx, caller, attemptID, caller.Episode.WorkItemID, nil)
		if err != nil {
			return err
		}
		if !continuationAllows(caller, a) {
			return errNotFound
		}
		err = tx.QueryRowContext(ctx, `SELECT arguments FROM authority_attempt_contents
			WHERE tenant_id = $1 AND attempt_id = $2`, caller.TenantID, attemptID).Scan(&content)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	return content, err
}

func requireActiveContinuationAgent(ctx context.Context, tx *sql.Tx, caller Caller) error {
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2 AND kind = 'agent' AND status = 'active')`,
		caller.TenantID, caller.PrincipalID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return refuse(CodePermissionDenied, contracts.ReasonPrincipalInactive, "a continuation requires an active agent principal")
	}
	return nil
}
