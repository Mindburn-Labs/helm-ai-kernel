package pack

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCoverageCompatibilityMatrixEdges(t *testing.T) {
	matrix := &CompatibilityMatrix{
		Entries: []CompatibilityEntry{
			{
				ComponentA: "kernel",
				VersionA:   ">=1.0.0 <2.0.0",
				ComponentB: "sdk-go",
				VersionB:   "^1.4.0",
				Status:     CompatFull,
				TestedAt:   time.Now().UTC(),
			},
		},
	}

	assert.Equal(t, CompatFull, matrix.IsCompatible("kernel", "1.5.0", "sdk-go", "1.4.2"))
	assert.Equal(t, CompatFull, matrix.IsCompatible("sdk-go", "1.4.2", "kernel", "1.5.0"))
	assert.Equal(t, CompatUntested, matrix.IsCompatible("kernel", "2.0.0", "sdk-go", "1.4.2"))
	assert.False(t, matchesConstraint("not a constraint", "1.0.0"))
	assert.False(t, matchesConstraint(">=1.0.0", "not-semver"))
}

type behaviorCoverageErrorPackRegistry struct {
	err error
}

func (r behaviorCoverageErrorPackRegistry) GetPack(context.Context, string) (*Pack, error) {
	return nil, r.err
}

func (r behaviorCoverageErrorPackRegistry) FindByCapability(context.Context, string) ([]Pack, error) {
	return nil, r.err
}

func (r behaviorCoverageErrorPackRegistry) ListVersions(context.Context, string) ([]PackVersion, error) {
	return nil, r.err
}
