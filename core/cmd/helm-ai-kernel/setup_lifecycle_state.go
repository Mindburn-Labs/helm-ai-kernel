package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// setupLifecycleStateTracker only removes state files that did not exist when
// the setup attempt began and whose exact bytes still match the file created
// during that attempt. That prevents a failed setup from deleting a concurrent
// user change while cleaning up a newly generated signer or SQLite store.
type setupLifecycleStateTracker struct {
	before  map[string]setupFileState
	created map[string]setupFileState
}

func beginSetupLifecycleStateTracker(dataDir string) (*setupLifecycleStateTracker, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	tracker := &setupLifecycleStateTracker{
		before:  make(map[string]setupFileState),
		created: make(map[string]setupFileState),
	}
	for _, path := range []string{
		filepath.Join(absDataDir, "root.key"),
		filepath.Join(absDataDir, "root.pub"),
		filepath.Join(absDataDir, "root.mldsa65.key"),
		filepath.Join(absDataDir, "helm.db"),
		filepath.Join(absDataDir, "helm.db-wal"),
		filepath.Join(absDataDir, "helm.db-shm"),
		filepath.Join(absDataDir, "helm.db-journal"),
	} {
		state, err := readSetupFileState(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot lifecycle state %s: %w", path, err)
		}
		tracker.before[path] = state
	}
	return tracker, nil
}

func (tracker *setupLifecycleStateTracker) captureCreated() error {
	if tracker == nil {
		return nil
	}
	for path, before := range tracker.before {
		if before.Exists {
			continue
		}
		state, err := readSetupFileState(path)
		if err != nil {
			return fmt.Errorf("snapshot newly-created lifecycle state %s: %w", path, err)
		}
		if state.Exists {
			tracker.created[path] = state
		}
	}
	return nil
}

func (tracker *setupLifecycleStateTracker) cleanupCreated() error {
	if tracker == nil {
		return nil
	}
	var cleanupErrors []error
	for path, created := range tracker.created {
		current, err := readSetupFileState(path)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("read lifecycle state %s before cleanup: %w", path, err))
			continue
		}
		if !current.Exists {
			continue
		}
		if !sameSetupFileState(current, created) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("lifecycle state %s changed concurrently; refusing to delete it", path))
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove newly-created lifecycle state %s: %w", path, err))
		}
	}
	return errors.Join(cleanupErrors...)
}
