package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// setupAutoconfigureTransaction preserves only the three artifacts generated
// by `setup`. It keeps private snapshots in memory and restores them only when
// the exact bytes written by HELM still exist, so a failed setup cannot leave
// generated workspace inventory behind or overwrite a concurrent user edit.
type setupAutoconfigureTransaction struct {
	files []setupTransactionFile
	dirs  []setupDirectoryState
}

type setupDirectoryState struct {
	path   string
	exists bool
}

func beginSetupAutoconfigureTransaction(dataDir string) (*setupAutoconfigureTransaction, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	paths := []string{
		filepath.Join(absDataDir, "autoconfigure", "inventory.json"),
		filepath.Join(absDataDir, "autoconfigure", "policy.draft.json"),
		filepath.Join(absDataDir, "autoconfigure", "mcp_quarantine_plan.json"),
	}
	tx := &setupAutoconfigureTransaction{}
	for _, path := range paths {
		before, err := readSetupFileState(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot autoconfigure artifact %s: %w", path, err)
		}
		tx.files = append(tx.files, setupTransactionFile{before: before, after: before})
	}
	for _, dir := range []string{absDataDir, filepath.Join(absDataDir, "autoconfigure")} {
		state, err := snapshotSetupDirectory(dir)
		if err != nil {
			return nil, err
		}
		tx.dirs = append(tx.dirs, state)
	}
	return tx, nil
}

func snapshotSetupDirectory(path string) (setupDirectoryState, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return setupDirectoryState{path: path}, nil
	}
	if err != nil {
		return setupDirectoryState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return setupDirectoryState{}, fmt.Errorf("refusing to write setup artifacts through symlinked directory %s", path)
	}
	if !info.IsDir() {
		return setupDirectoryState{}, fmt.Errorf("setup artifact directory is not a directory: %s", path)
	}
	return setupDirectoryState{path: path, exists: true}, nil
}

func (tx *setupAutoconfigureTransaction) ensureDataDir() error {
	if tx == nil || len(tx.dirs) == 0 {
		return fmt.Errorf("autoconfigure transaction is not initialized")
	}
	if err := os.MkdirAll(tx.dirs[0].path, 0o750); err != nil {
		return err
	}
	return nil
}

func (tx *setupAutoconfigureTransaction) writeJSON(path string, value any) error {
	data, err := marshalSetupJSONArtifact(value)
	if err != nil {
		return err
	}
	return tx.replace(path, data)
}

func (tx *setupAutoconfigureTransaction) replace(path string, data []byte) error {
	if tx == nil {
		return fmt.Errorf("autoconfigure transaction is not initialized")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for index := range tx.files {
		file := &tx.files[index]
		if file.before.Path != absPath {
			continue
		}
		current, err := readSetupFileState(absPath)
		if err != nil {
			return err
		}
		if !sameSetupFileState(current, file.before) {
			return fmt.Errorf("autoconfigure artifact changed concurrently before HELM could modify it: %s", absPath)
		}
		if err := writeSetupPrivateFile(absPath, data); err != nil {
			return err
		}
		file.after = setupFileState{Path: absPath, Exists: true, Data: append([]byte(nil), data...)}
		file.mutated = true
		return nil
	}
	return fmt.Errorf("untracked autoconfigure artifact path %s", absPath)
}

func (tx *setupAutoconfigureTransaction) rollback() error {
	if tx == nil {
		return nil
	}
	var rollbackErrors []error
	for index := len(tx.files) - 1; index >= 0; index-- {
		if err := rollbackSetupTransactionFile(tx.files[index], "autoconfigure artifact"); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	// Empty directories created by this attempt are safe to remove. A nonempty
	// directory is retained and reported rather than risking a concurrent file.
	for index := len(tx.dirs) - 1; index >= 0; index-- {
		dir := tx.dirs[index]
		if dir.exists {
			continue
		}
		if err := os.Remove(dir.path); err != nil && !os.IsNotExist(err) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove empty setup directory %s: %w", dir.path, err))
		}
	}
	return errors.Join(rollbackErrors...)
}

func rollbackSetupAutoconfigure(tx *setupAutoconfigureTransaction, cause error) error {
	if rollbackErr := tx.rollback(); rollbackErr != nil {
		return fmt.Errorf("%w; autoconfigure rollback failed: %v", cause, rollbackErr)
	}
	return cause
}
