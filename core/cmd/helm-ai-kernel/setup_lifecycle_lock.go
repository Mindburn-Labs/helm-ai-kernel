package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const setupCodexProjectLifecycleLockFile = ".helm-setup-codex-project.lock"

// setupCodexProjectLifecycleLock serializes mutating Codex project lifecycle
// commands for one secure data directory. Recovery journals make an interrupted
// transaction resumable; this lock prevents two live same-user processes from
// replacing each other's project namespace between preflight and publication.
type setupCodexProjectLifecycleLock struct {
	file *os.File
}

func acquireSetupCodexProjectLifecycleLock(dataDir string) (*setupCodexProjectLifecycleLock, error) {
	securedDataDir, err := ensureSetupAuthorityDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(securedDataDir, setupCodexProjectLifecycleLockFile)
	state, err := readSetupExistingPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		created, err := writeSetupPrivateFileIfAbsent(path, nil)
		if err != nil {
			return nil, err
		}
		if !created {
			state, err = readSetupExistingPrivateFile(path)
			if err != nil {
				return nil, err
			}
			if !state.Exists {
				return nil, fmt.Errorf("Codex project lifecycle lock disappeared during creation")
			}
		}
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := lockSetupCodexProjectLifecycleFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &setupCodexProjectLifecycleLock{file: file}, nil
}

func (lock *setupCodexProjectLifecycleLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockSetupCodexProjectLifecycleFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
