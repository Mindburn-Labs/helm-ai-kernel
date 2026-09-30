package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// failingArtifactStore refuses every operation.
type failingArtifactStore struct{}

var errDiskFull = errors.New("disk full")

func (failingArtifactStore) Store(context.Context, []byte) (string, error) { return "", errDiskFull }
func (failingArtifactStore) Get(context.Context, string) ([]byte, error)   { return nil, errDiskFull }
func (failingArtifactStore) Exists(context.Context, string) (bool, error)  { return false, errDiskFull }
func (failingArtifactStore) Delete(context.Context, string) error          { return errDiskFull }

// verifySnapshot fails closed: a snapshot whose content hash differs from the
// decision's phenotype hash, a decision minted under another phenotype, or an
// unstorable snapshot all block execution.
func TestVerifySnapshotFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const snapshot = `{"policy":"v1"}`
	snapshotHash, err := store.Store(ctx, []byte(snapshot))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		store    artifacts.Store
		current  string
		decision contracts.DecisionRecord
		wantHash string
		wantErr  string
	}{
		{
			name:     "matching snapshot is stored and returned",
			store:    store,
			current:  snapshotHash,
			decision: contracts.DecisionRecord{Snapshot: snapshot, PhenotypeHash: snapshotHash},
			wantHash: snapshotHash,
		},
		{
			name:     "snapshot hash differs from decision phenotype",
			store:    store,
			decision: contracts.DecisionRecord{Snapshot: snapshot, PhenotypeHash: "sha256:other"},
			wantErr:  "phenotype mismatch: snapshot hash",
		},
		{
			name:     "decision minted under another phenotype",
			current:  "sha256:current",
			decision: contracts.DecisionRecord{PhenotypeHash: "sha256:stale"},
			wantErr:  "execution blocked: phenotype mismatch",
		},
		{
			name:     "snapshot cannot be stored",
			store:    failingArtifactStore{},
			decision: contracts.DecisionRecord{Snapshot: snapshot, PhenotypeHash: snapshotHash},
			wantErr:  "failed to store snapshot artifact",
		},
		{
			name:     "no snapshot and no phenotype pin",
			store:    store,
			decision: contracts.DecisionRecord{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &SafeExecutor{artifactStore: tc.store, currentPhenotypeHash: tc.current}
			got, err := e.verifySnapshot(ctx, &tc.decision)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantHash {
				t.Fatalf("hash = %q, want %q", got, tc.wantHash)
			}
		})
	}
}
