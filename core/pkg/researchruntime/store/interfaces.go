package store

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// MissionFilter specifies optional filters for listing missions.
type MissionFilter struct {
	State *string
	Class *string
	Limit int
}

// MissionStore persists and retrieves MissionSpec records.
type MissionStore interface {
	Create(ctx context.Context, m researchruntime.MissionSpec) error
	Get(ctx context.Context, id string) (*researchruntime.MissionSpec, error)
	UpdateState(ctx context.Context, id string, state string) error
	List(ctx context.Context, f MissionFilter) ([]researchruntime.MissionSpec, error)
}

// TaskStore manages TaskLease records including distributed lease acquisition.
type TaskStore interface {
	Create(ctx context.Context, t researchruntime.TaskLease) error
	Get(ctx context.Context, id string) (*researchruntime.TaskLease, error)
	UpdateState(ctx context.Context, id, state string) error
	ListByMission(ctx context.Context, missionID string) ([]researchruntime.TaskLease, error)
	AcquireLease(ctx context.Context, id, workerID string, until time.Time) error
	ReleaseLease(ctx context.Context, id string) error
}

// SourceStore persists SourceSnapshot records captured during research.
type SourceStore interface {
	Save(ctx context.Context, s researchruntime.SourceSnapshot) error
	Get(ctx context.Context, id string) (*researchruntime.SourceSnapshot, error)
	ListByMission(ctx context.Context, missionID string) ([]researchruntime.SourceSnapshot, error)
	UpdateState(ctx context.Context, id string, state string) error
}

// DraftStore persists DraftManifest records produced by synthesis workers.
type DraftStore interface {
	Save(ctx context.Context, d researchruntime.DraftManifest) error
	Get(ctx context.Context, id string) (*researchruntime.DraftManifest, error)
	ListByMission(ctx context.Context, missionID string) ([]researchruntime.DraftManifest, error)
	UpdateState(ctx context.Context, id string, state string) error
}

// PublicationStore persists PublicationRecord entries and supports versioning.
type PublicationStore interface {
	Save(ctx context.Context, p researchruntime.PublicationRecord) error
	Get(ctx context.Context, id string) (*researchruntime.PublicationRecord, error)
	GetBySlug(ctx context.Context, slug string) (*researchruntime.PublicationRecord, error)
	List(ctx context.Context) ([]researchruntime.PublicationRecord, error)
	UpdateState(ctx context.Context, id string, state string) error
	SetSupersededBy(ctx context.Context, oldID, newID string) error
}

// FeedStore appends and queries feed events for mission activity.
type FeedStore interface {
	Append(ctx context.Context, missionID, actor, action, detail string) error
	Latest(ctx context.Context, limit int) ([]FeedEvent, error)
	ByMission(ctx context.Context, missionID string) ([]FeedEvent, error)
}

// FeedEvent is a single entry in the mission activity feed.
type FeedEvent struct {
	ID        string
	MissionID string
	Actor     string
	Action    string
	Detail    string
	CreatedAt time.Time
}

// OverrideStore manages human-operator override requests and their resolutions.
type OverrideStore interface {
	Save(ctx context.Context, o Override) error
	Get(ctx context.Context, id string) (*Override, error)
	ListPending(ctx context.Context) ([]Override, error)
	Resolve(ctx context.Context, id, decision, operatorID, notes string) error
}

// Override represents a human-operator override request on a mission or artifact.
type Override struct {
	ID          string
	MissionID   string
	ArtifactID  string
	ReasonCodes []string
	OperatorID  string
	Decision    string
	Notes       string
	CreatedAt   time.Time
}

// BlobStore provides raw byte storage for content blobs (snapshots, PDFs, drafts).
type BlobStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	Exists(ctx context.Context, key string) (bool, error)
}
