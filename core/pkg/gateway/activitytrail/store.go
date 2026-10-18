package activitytrail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

var ErrDeliveryConflict = errors.New("provider delivery ID was already used for different evidence")

// Service owns provider reads and tenant-scoped persistence. The caller must
// authenticate Scope and supply a repository-scoped provider credential. No
// public route is registered here.
type Service struct {
	db       *sql.DB
	provider *githubClient
	now      func() time.Time
}

func New(db *sql.DB, apiURL string, httpClient *http.Client) (*Service, error) {
	if db == nil {
		return nil, errors.New("activity trail requires PostgreSQL")
	}
	provider, err := newGitHubClient(apiURL, httpClient)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, provider: provider, now: time.Now}, nil
}

func (s *Service) inTenant(ctx context.Context, tenantID string, options *sql.TxOptions, fn func(*sql.Tx) error) error {
	if tenantID == "" {
		return errors.New("tenant is required")
	}
	tx, err := s.db.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func credential(ctx context.Context, source TokenSource) (string, error) {
	if source == nil {
		return "", errors.New("repository-scoped GitHub credential is required")
	}
	token, err := source.Token(ctx)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) == "" {
		return "", errors.New("empty GitHub credential")
	}
	return token, nil
}

// Enable establishes a provider-read baseline. Re-enabling an already active
// source keeps its old cursor, so a retry cannot erase an unseen transition.
func (s *Service) Enable(ctx context.Context, scope Scope, source TokenSource) (Coverage, error) {
	if err := scope.validate(); err != nil {
		return Coverage{}, err
	}
	token, err := credential(ctx, source)
	if err != nil {
		return Coverage{}, err
	}
	snap, err := s.provider.snapshot(ctx, scope.Repository, token)
	if err != nil {
		return Coverage{}, err
	}
	err = s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO gateway_activity_sources
			(tenant_id,workspace_id,repository,enabled,default_branch,head_sha)
			VALUES ($1,$2,$3,true,$4,$5)
			ON CONFLICT (tenant_id,workspace_id,repository) DO UPDATE SET
			 enabled = true,
			 enabled_at = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.enabled_at ELSE now() END,
			 default_branch = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.default_branch ELSE EXCLUDED.default_branch END,
			 head_sha = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.head_sha ELSE EXCLUDED.head_sha END,
			 last_poll_at = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.last_poll_at ELSE NULL END,
			 last_poll_error = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.last_poll_error ELSE '' END,
			 last_event_poll_at = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.last_event_poll_at ELSE NULL END,
			 next_event_poll_at = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.next_event_poll_at ELSE NULL END,
			 event_window_capped = CASE WHEN gateway_activity_sources.enabled THEN gateway_activity_sources.event_window_capped ELSE false END`,
			scope.TenantID, scope.WorkspaceID, scope.Repository, snap.branch, snap.head)
		return err
	})
	if err != nil {
		return Coverage{}, err
	}
	return s.CoverageMap(ctx, scope)
}

// Disable preserves observations and the cursor. A later Enable takes a fresh
// baseline and makes that reset explicit in the source configuration.
func (s *Service) Disable(ctx context.Context, scope Scope) error {
	if err := scope.validate(); err != nil {
		return err
	}
	return s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE gateway_activity_sources SET enabled=false
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

type sourceCursor struct {
	enabled       bool
	branch, head  string
	enabledAt     time.Time
	nextEventPoll sql.NullTime
}

func readSource(ctx context.Context, tx *sql.Tx, scope Scope, lock bool) (sourceCursor, error) {
	query := `SELECT enabled,default_branch,head_sha,enabled_at,next_event_poll_at FROM gateway_activity_sources
		WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	var c sourceCursor
	err := tx.QueryRowContext(ctx, query, scope.TenantID, scope.WorkspaceID, scope.Repository).
		Scan(&c.enabled, &c.branch, &c.head, &c.enabledAt, &c.nextEventPoll)
	if errors.Is(err, sql.ErrNoRows) {
		return sourceCursor{}, ErrNotEnabled
	}
	if err != nil {
		return sourceCursor{}, err
	}
	if !c.enabled {
		return sourceCursor{}, ErrNotEnabled
	}
	return c, nil
}

func (s *Service) currentSource(ctx context.Context, scope Scope) (sourceCursor, error) {
	var c sourceCursor
	err := s.inTenant(ctx, scope.TenantID, &sql.TxOptions{ReadOnly: true}, func(tx *sql.Tx) error {
		var err error
		c, err = readSource(ctx, tx, scope, false)
		return err
	})
	return c, err
}

type activityFact struct {
	Version    string `json:"version"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	BeforeSHA  string `json:"before_sha"`
	AfterSHA   string `json:"after_sha"`
}

func newFact(repository, ref, before, after string) (activityFact, [32]byte, error) {
	var zero [32]byte
	if !validSHA(before) || !validSHA(after) || strings.EqualFold(before, after) ||
		strings.EqualFold(before, strings.Repeat("0", 40)) || strings.EqualFold(after, strings.Repeat("0", 40)) || !strings.HasPrefix(ref, "refs/heads/") {
		return activityFact{}, zero, errors.New("invalid default-branch transition")
	}
	fact := activityFact{Version: "github.default_branch_transition.v1", Repository: strings.ToLower(repository), Ref: ref,
		BeforeSHA: strings.ToLower(before), AfterSHA: strings.ToLower(after)}
	raw, _ := json.Marshal(fact)
	return fact, sha256.Sum256(raw), nil
}

type activityEvidence struct {
	Version      string        `json:"version"`
	Kind         string        `json:"kind"`
	Fact         activityFact  `json:"fact"`
	BodyDigest   string        `json:"body_digest,omitempty"`
	Compare      *compareProof `json:"compare,omitempty"`
	DeliveryID   string        `json:"delivery_id,omitempty"`
	ActorLogin   string        `json:"actor_login,omitempty"`
	ProviderTime *time.Time    `json:"provider_time,omitempty"`
}

func (e activityEvidence) bytesAndDigest() ([]byte, [32]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return raw, sha256.Sum256(raw), nil
}

func (s *Service) persist(ctx context.Context, tx *sql.Tx, scope Scope, fact activityFact, factDigest [32]byte, evidence activityEvidence) (Observation, bool, error) {
	var observation Observation
	if evidence.Kind != "compare" && evidence.Kind != "push_webhook" && evidence.Kind != "repository_event" {
		return observation, false, errors.New("invalid activity evidence kind")
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO gateway_activity_observations
		(tenant_id,workspace_id,repository,fact_digest,ref,before_sha,after_sha,actor_login,provider_time)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9)
		ON CONFLICT (tenant_id,workspace_id,repository,fact_digest) DO NOTHING`,
		scope.TenantID, scope.WorkspaceID, scope.Repository, factDigest[:], fact.Ref, fact.BeforeSHA, fact.AfterSHA,
		evidence.ActorLogin, evidence.ProviderTime)
	if err != nil {
		return observation, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return observation, false, err
	}
	existing := n == 0
	if existing && (evidence.ActorLogin != "" || evidence.ProviderTime != nil) {
		res, err = tx.ExecContext(ctx, `UPDATE gateway_activity_observations SET
			actor_login=COALESCE(actor_login,NULLIF($5,'')), provider_time=COALESCE(provider_time,$6)
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3 AND fact_digest=$4
			AND (actor_login IS NULL OR $5='' OR actor_login=$5)
			AND (provider_time IS NULL OR $6::timestamptz IS NULL OR provider_time=$6)`,
			scope.TenantID, scope.WorkspaceID, scope.Repository, factDigest[:], evidence.ActorLogin, evidence.ProviderTime)
		if err != nil {
			return observation, false, err
		}
		n, err = res.RowsAffected()
		if err != nil {
			return observation, false, err
		}
		if n != 1 {
			return observation, false, ErrAttributionConflict
		}
	}
	raw, evidenceDigest, err := evidence.bytesAndDigest()
	if err != nil {
		return observation, false, err
	}
	res, err = tx.ExecContext(ctx, `INSERT INTO gateway_activity_evidence
		(tenant_id,workspace_id,repository,evidence_digest,fact_digest,delivery_id,kind,evidence)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8)
		ON CONFLICT DO NOTHING`, scope.TenantID, scope.WorkspaceID, scope.Repository,
		evidenceDigest[:], factDigest[:], evidence.DeliveryID, evidence.Kind, raw)
	if err != nil {
		return observation, false, err
	}
	if evidence.DeliveryID != "" {
		var stored []byte
		err = tx.QueryRowContext(ctx, `SELECT evidence_digest FROM gateway_activity_evidence
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3 AND delivery_id=$4`,
			scope.TenantID, scope.WorkspaceID, scope.Repository, evidence.DeliveryID).Scan(&stored)
		if err != nil {
			return observation, false, err
		}
		if !hmac.Equal(stored, evidenceDigest[:]) {
			return observation, false, ErrDeliveryConflict
		}
	}
	observation, err = readObservation(ctx, tx, scope, factDigest[:])
	return observation, existing, err
}

func readObservation(ctx context.Context, tx *sql.Tx, scope Scope, digest []byte) (Observation, error) {
	var o Observation
	var rawDigest []byte
	var actor sql.NullString
	var at sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT repository,ref,before_sha,after_sha,fact_digest,actor_login,provider_time,observed_at,source,coverage,governed
		FROM gateway_activity_observations WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3 AND fact_digest=$4`,
		scope.TenantID, scope.WorkspaceID, scope.Repository, digest).
		Scan(&o.Repository, &o.Ref, &o.BeforeSHA, &o.AfterSHA, &rawDigest, &actor, &at, &o.ObservedAt, &o.Source, &o.Coverage, &o.Governed)
	if err != nil {
		return Observation{}, err
	}
	o.FactDigest = hex.EncodeToString(rawDigest)
	if actor.Valid {
		o.ActorLogin = actor.String
	}
	if at.Valid {
		o.ProviderTime = &at.Time
	}
	return o, nil
}

func (s *Service) recordPollError(ctx context.Context, scope Scope, message string) {
	if len(message) > 400 {
		message = message[:400]
	}
	_ = s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE gateway_activity_sources SET last_poll_error=$4
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository, message)
		return err
	})
}

// PollDefaultBranch compares the stored baseline with GitHub's current ref.
// The provider read is outside the transaction; a row lock and cursor check
// prevent concurrent polls from skipping an intervening transition.
func (s *Service) PollDefaultBranch(ctx context.Context, scope Scope, source TokenSource) (PollResult, error) {
	if err := scope.validate(); err != nil {
		return PollResult{}, err
	}
	token, err := credential(ctx, source)
	if err != nil {
		return PollResult{}, err
	}
	for tries := 0; tries < 3; tries++ {
		cursor, err := s.currentSource(ctx, scope)
		if err != nil {
			return PollResult{}, err
		}
		snap, err := s.provider.snapshot(ctx, scope.Repository, token)
		if err != nil {
			s.recordPollError(ctx, scope, err.Error())
			return PollResult{}, err
		}
		if snap.branch != cursor.branch {
			s.recordPollError(ctx, scope, ErrBranchChanged.Error())
			return PollResult{}, ErrBranchChanged
		}
		var proof compareProof
		if snap.head != cursor.head {
			proof, err = s.provider.compare(ctx, scope.Repository, cursor.head, snap.head, token, snap)
			if err != nil {
				s.recordPollError(ctx, scope, err.Error())
				return PollResult{}, err
			}
		}
		var result PollResult
		stale := false
		err = s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
			locked, err := readSource(ctx, tx, scope, true)
			if err != nil {
				return err
			}
			if locked.branch != cursor.branch || locked.head != cursor.head {
				stale = true
				return nil
			}
			if snap.head == cursor.head {
				_, err = tx.ExecContext(ctx, `UPDATE gateway_activity_sources SET last_poll_at=now(),last_poll_error=''
					WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository)
				return err
			}
			fact, digest, err := newFact(scope.Repository, "refs/heads/"+snap.branch, cursor.head, snap.head)
			if err != nil {
				return err
			}
			evidence := activityEvidence{Version: "github.activity.evidence.v1", Kind: "compare", Fact: fact, Compare: &proof}
			observation, existing, err := s.persist(ctx, tx, scope, fact, digest, evidence)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE gateway_activity_sources SET head_sha=$4,last_poll_at=now(),last_poll_error=''
				WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository, snap.head)
			if err != nil {
				return err
			}
			result = PollResult{Changed: true, Existing: existing, BeforeSHA: cursor.head, AfterSHA: snap.head, Observation: &observation}
			return nil
		})
		if err != nil {
			return PollResult{}, err
		}
		if stale {
			continue
		}
		return result, nil
	}
	return PollResult{}, errors.New("activity trail cursor changed during every poll attempt")
}

type pushPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// IngestSignedPush accepts only a GitHub HMAC-SHA256 verified push payload.
// A push webhook has no provider action timestamp, so ProviderTime remains
// absent until a matching authenticated repository event is read.
func (s *Service) IngestSignedPush(ctx context.Context, scope Scope, eventType, deliveryID, signature string, payload, secret []byte) (Observation, bool, error) {
	if err := scope.validate(); err != nil {
		return Observation{}, false, err
	}
	if eventType != "push" || deliveryID == "" || len(deliveryID) > 255 || len(payload) == 0 || len(payload) > maxProviderBody || len(secret) < 16 {
		return Observation{}, false, errors.New("invalid signed push delivery")
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || !strings.HasPrefix(signature, "sha256=") || len(got) != sha256.Size {
		return Observation{}, false, errors.New("invalid GitHub push signature")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return Observation{}, false, errors.New("GitHub push signature mismatch")
	}
	var push pushPayload
	if err := json.Unmarshal(payload, &push); err != nil {
		return Observation{}, false, err
	}
	if push.Deleted || !strings.EqualFold(push.Repository.FullName, strings.TrimPrefix(scope.Repository, "github.com/")) || push.Sender.Login == "" || len(push.Sender.Login) > 255 {
		return Observation{}, false, errors.New("push payload identity is invalid")
	}
	fact, digest, err := newFact(scope.Repository, push.Ref, push.Before, push.After)
	if err != nil {
		return Observation{}, false, err
	}
	bodyDigest := sha256.Sum256(payload)
	evidence := activityEvidence{Version: "github.activity.evidence.v1", Kind: "push_webhook", Fact: fact,
		BodyDigest: digestString(bodyDigest[:]), DeliveryID: deliveryID, ActorLogin: push.Sender.Login}
	var observation Observation
	var existing bool
	err = s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
		cursor, err := readSource(ctx, tx, scope, true)
		if err != nil {
			return err
		}
		if push.Ref != "refs/heads/"+cursor.branch {
			return errors.New("push is not for the configured default branch")
		}
		observation, existing, err = s.persist(ctx, tx, scope, fact, digest, evidence)
		return err
	})
	return observation, existing, err
}

// PollRepositoryEvents enriches default-branch observations with GitHub's
// actor and created_at, when the delayed Events API makes those facts
// available. It respects the provider's X-Poll-Interval and reads all three
// pages of GitHub's 300-event window.
func (s *Service) PollRepositoryEvents(ctx context.Context, scope Scope, source TokenSource) (int, error) {
	if err := scope.validate(); err != nil {
		return 0, err
	}
	cursor, err := s.currentSource(ctx, scope)
	if err != nil {
		return 0, err
	}
	if cursor.nextEventPoll.Valid && s.now().Before(cursor.nextEventPoll.Time) {
		return 0, nil
	}
	token, err := credential(ctx, source)
	if err != nil {
		return 0, err
	}
	events, interval, capped, err := s.provider.events(ctx, scope.Repository, token)
	if err != nil {
		return 0, err
	}
	matched := 0
	err = s.inTenant(ctx, scope.TenantID, nil, func(tx *sql.Tx) error {
		locked, err := readSource(ctx, tx, scope, true)
		if err != nil {
			return err
		}
		for _, event := range events {
			if event.Type != "PushEvent" || event.CreatedAt.Before(locked.enabledAt.Add(-2*time.Second)) ||
				!strings.EqualFold(event.Repo.Name, strings.TrimPrefix(scope.Repository, "github.com/")) ||
				event.Payload.Ref != "refs/heads/"+locked.branch || event.ID == "" || len(event.ID) > 255 || event.Actor.Login == "" || event.CreatedAt.IsZero() {
				continue
			}
			fact, digest, err := newFact(scope.Repository, event.Payload.Ref, event.Payload.Before, event.Payload.Head)
			if err != nil {
				continue
			}
			eventRaw, err := json.Marshal(event)
			if err != nil {
				return err
			}
			proofDigest := sha256.Sum256(eventRaw)
			evidence := activityEvidence{Version: "github.activity.evidence.v1", Kind: "repository_event", Fact: fact,
				BodyDigest: digestString(proofDigest[:]), DeliveryID: "event:" + event.ID, ActorLogin: event.Actor.Login, ProviderTime: &event.CreatedAt}
			if _, _, err := s.persist(ctx, tx, scope, fact, digest, evidence); err != nil {
				return err
			}
			matched++
		}
		next := s.now().Add(time.Duration(interval) * time.Second)
		_, err = tx.ExecContext(ctx, `UPDATE gateway_activity_sources SET last_event_poll_at=now(),next_event_poll_at=$4,
			event_window_capped=event_window_capped OR $5
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository, next, capped)
		return err
	})
	return matched, err
}
