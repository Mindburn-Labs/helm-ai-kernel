// Package activitytrail records GitHub default-branch changes seen outside the
// governed effect path. Its records are observations and owner exceptions;
// they never grant authority or create an effect attempt, approval, or permit.
package activitytrail

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SourceGitHubActivity = "github activity"
	CoverageObservedOnly = "observed-only"
	CoverageUnmanaged    = "unmanaged"
	OutsideHELMReason    = "change made outside HELM"
)

var (
	ErrNotEnabled          = errors.New("activity trail is not enabled for this repository")
	ErrBranchChanged       = errors.New("repository default branch changed; re-enable activity trail with a new baseline")
	ErrIncompleteCompare   = errors.New("GitHub comparison is incomplete")
	ErrAttributionConflict = errors.New("provider facts conflict on actor or timestamp for one branch transition")
	shaPattern             = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	namePattern            = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

// Scope is supplied only by an authenticated internal caller. In particular,
// TenantID is never read from provider content or an untrusted request body.
type Scope struct {
	TenantID    string
	WorkspaceID string
	Repository  string // github.com/{owner}/{repo}
}

func (s Scope) validate() error {
	if s.TenantID == "" || s.WorkspaceID == "" || len(s.TenantID) > 255 || len(s.WorkspaceID) > 255 {
		return errors.New("tenant and workspace are required")
	}
	_, _, err := repositoryParts(s.Repository)
	return err
}

// Validate rejects malformed internal scope before a provider or database read.
func (s Scope) Validate() error { return s.validate() }

func repositoryParts(repository string) (string, string, error) {
	if !strings.HasPrefix(repository, "github.com/") {
		return "", "", fmt.Errorf("repository %q is not github.com/{owner}/{repo}", repository)
	}
	parts := strings.Split(strings.TrimPrefix(repository, "github.com/"), "/")
	if len(parts) != 2 || !namePattern.MatchString(parts[0]) || !namePattern.MatchString(parts[1]) || parts[0] == "." || parts[1] == "." || parts[0] == ".." || parts[1] == ".." {
		return "", "", fmt.Errorf("repository %q is not github.com/{owner}/{repo}", repository)
	}
	return parts[0], parts[1], nil
}

func validSHA(sha string) bool { return shaPattern.MatchString(sha) }

func digestString(b []byte) string { return hex.EncodeToString(b) }

// TokenSource supplies a short-lived, repository-scoped read credential for a
// single provider request. The package never stores the credential.
type TokenSource interface {
	Token(context.Context) (string, error)
}

// Observation is one default-branch transition. ActorLogin and ProviderTime
// remain absent until an authenticated provider event names them. Commit
// author and committer metadata are deliberately not substituted for actor.
type Observation struct {
	Repository   string     `json:"repository"`
	Ref          string     `json:"ref"`
	BeforeSHA    string     `json:"before_sha"`
	AfterSHA     string     `json:"after_sha"`
	FactDigest   string     `json:"fact_digest"`
	ActorLogin   string     `json:"actor_login,omitempty"`
	ProviderTime *time.Time `json:"provider_time,omitempty"`
	ObservedAt   time.Time  `json:"observed_at"`
	Source       string     `json:"source"`
	Coverage     string     `json:"coverage"`
	Governed     bool       `json:"governed"`
}

// OwnerException is a read projection of an observed-only transition. There
// is no independent writable exception state to drift from the observation.
type OwnerException struct {
	Observation Observation `json:"observation"`
	Reason      string      `json:"reason"`
}

// Coverage is the source-owned classification and freshness of one repository.
// An enabled source is observed-only even if its last poll failed: failure is
// surfaced rather than silently promoted to governed coverage.
type Coverage struct {
	Repository          string     `json:"repository"`
	Class               string     `json:"class"`
	Enabled             bool       `json:"enabled"`
	DefaultBranch       string     `json:"default_branch,omitempty"`
	HeadSHA             string     `json:"head_sha,omitempty"`
	LastPollAt          *time.Time `json:"last_poll_at,omitempty"`
	LastPollError       string     `json:"last_poll_error,omitempty"`
	LastEventPollAt     *time.Time `json:"last_event_poll_at,omitempty"`
	NextEventPollAt     *time.Time `json:"next_event_poll_at,omitempty"`
	EventWindowCapped   bool       `json:"event_window_capped"`
	AttributionComplete bool       `json:"attribution_complete"`
	UnattributedCount   int64      `json:"unattributed_count"`
}

// Page uses a bounded keyset cursor, bound to the requested scope.
type Page struct {
	Limit int
	After string
}

// PollResult reports exactly what one compare proved.
type PollResult struct {
	Changed     bool
	Existing    bool
	BeforeSHA   string
	AfterSHA    string
	Observation *Observation
}
