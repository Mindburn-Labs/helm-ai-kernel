package executor

import (
	"context"
	"errors"
)

// failingArtifactStore refuses every operation.
type failingArtifactStore struct{}

var errDiskFull = errors.New("disk full")

func (failingArtifactStore) Store(context.Context, []byte) (string, error) { return "", errDiskFull }
func (failingArtifactStore) Get(context.Context, string) ([]byte, error)   { return nil, errDiskFull }
func (failingArtifactStore) Exists(context.Context, string) (bool, error)  { return false, errDiskFull }
func (failingArtifactStore) Delete(context.Context, string) error          { return errDiskFull }
