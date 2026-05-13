package authz

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// RelationshipSnapshotHash returns a deterministic hash of the relationship
// tuples currently visible to the engine. It intentionally excludes transient
// graph indexes so offline evidence binds only the public relationship state.
func (e *Engine) RelationshipSnapshotHash() (string, error) {
	e.mu.RLock()
	tuples := append([]RelationTuple(nil), e.tuples...)
	e.mu.RUnlock()

	sort.Slice(tuples, func(i, j int) bool {
		if tuples[i].Object != tuples[j].Object {
			return tuples[i].Object < tuples[j].Object
		}
		if tuples[i].Relation != tuples[j].Relation {
			return tuples[i].Relation < tuples[j].Relation
		}
		return tuples[i].Subject < tuples[j].Subject
	})
	hash, err := canonicalize.CanonicalHash(tuples)
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}

// SnapshotCheck evaluates a relationship authorization check and seals a HELM
// AuthzSnapshot for receipt or EvidencePack binding.
func (e *Engine) SnapshotCheck(
	ctx context.Context,
	resolver string,
	modelID string,
	object string,
	relation string,
	subject string,
	checkedAt time.Time,
	stale bool,
	modelMismatch bool,
) (contracts.AuthzSnapshot, error) {
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	decision, err := e.Check(ctx, object, relation, subject)
	if err != nil {
		return contracts.AuthzSnapshot{}, err
	}
	relationshipHash, err := e.RelationshipSnapshotHash()
	if err != nil {
		return contracts.AuthzSnapshot{}, err
	}

	snapshotIDSeed := struct {
		Resolver         string `json:"resolver"`
		ModelID          string `json:"model_id"`
		RelationshipHash string `json:"relationship_hash"`
		Object           string `json:"object"`
		Relation         string `json:"relation"`
		Subject          string `json:"subject"`
		CheckedAt        string `json:"checked_at"`
	}{
		Resolver:         resolver,
		ModelID:          modelID,
		RelationshipHash: relationshipHash,
		Object:           object,
		Relation:         relation,
		Subject:          subject,
		CheckedAt:        checkedAt.UTC().Format(time.RFC3339Nano),
	}
	snapshotIDHash, err := canonicalize.CanonicalHash(snapshotIDSeed)
	if err != nil {
		return contracts.AuthzSnapshot{}, err
	}

	snapshot := contracts.AuthzSnapshot{
		SnapshotID:       fmt.Sprintf("authz-%s", snapshotIDHash[:16]),
		Resolver:         resolver,
		ModelID:          modelID,
		RelationshipHash: relationshipHash,
		SnapshotToken:    relationshipHash,
		Subject:          subject,
		Object:           object,
		Relation:         relation,
		Decision:         decision,
		Stale:            stale,
		ModelMismatch:    modelMismatch,
		CheckedAt:        checkedAt.UTC(),
	}
	return snapshot.Seal()
}
