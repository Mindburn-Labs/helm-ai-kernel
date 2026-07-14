package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// setupFileState is an in-memory, private backup used only to compensate a
// failed local configuration transaction. It is never written into Kernel
// state because client configuration may contain user-owned sensitive data.
type setupFileState struct {
	Path   string
	Exists bool
	Data   []byte
}

// setupRegularFileState is a metadata-only view of a setup-owned file. It is
// intentionally separate from setupFileState: callers which only need to
// establish that a SQLite database exists must not read the full database into
// memory before opening it read-only.
type setupRegularFileState struct {
	Path   string
	Exists bool
	Info   os.FileInfo
}

type codexProjectConfigTransaction struct {
	client setupTransactionFile
	hook   setupTransactionFile
}

// setupTransactionFile carries an exact before/after pair for one file. The
// mutator verifies that the bytes it is about to replace are still the bytes
// captured at transaction start. It must never infer that a user change was
// made by HELM merely because before and after differ.
type setupTransactionFile struct {
	before  setupFileState
	after   setupFileState
	mutated bool
}

func beginCodexProjectConfigTransaction(summary setupSummary) (*codexProjectConfigTransaction, error) {
	clientBefore, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot Codex project config: %w", err)
	}
	hookBefore, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot Codex project hook config: %w", err)
	}
	return &codexProjectConfigTransaction{
		client: setupTransactionFile{before: clientBefore, after: clientBefore},
		hook:   setupTransactionFile{before: hookBefore, after: hookBefore},
	}, nil
}

func (tx *codexProjectConfigTransaction) clientBefore() setupFileState {
	return tx.client.before
}

func (tx *codexProjectConfigTransaction) hookBefore() setupFileState {
	return tx.hook.before
}

func (tx *codexProjectConfigTransaction) replaceClient(data []byte) error {
	return tx.replaceClientState(setupFileState{
		Path:   tx.client.before.Path,
		Exists: true,
		Data:   append([]byte(nil), data...),
	})
}

func (tx *codexProjectConfigTransaction) removeClient() error {
	return tx.replaceClientState(setupFileState{Path: tx.client.before.Path})
}

func (tx *codexProjectConfigTransaction) replaceClientState(next setupFileState) error {
	next.Path = tx.client.before.Path
	next.Data = append([]byte(nil), next.Data...)
	return tx.replace(&tx.client, next)
}

func (tx *codexProjectConfigTransaction) replaceHook(data []byte) error {
	return tx.replaceHookState(setupFileState{
		Path:   tx.hook.before.Path,
		Exists: true,
		Data:   append([]byte(nil), data...),
	})
}

func (tx *codexProjectConfigTransaction) removeHook() error {
	return tx.replaceHookState(setupFileState{Path: tx.hook.before.Path})
}

func (tx *codexProjectConfigTransaction) replaceHookState(next setupFileState) error {
	next.Path = tx.hook.before.Path
	next.Data = append([]byte(nil), next.Data...)
	return tx.replace(&tx.hook, next)
}

func (tx *codexProjectConfigTransaction) replace(file *setupTransactionFile, next setupFileState) error {
	current, err := readSetupFileState(file.before.Path)
	if err != nil {
		return err
	}
	if !sameSetupFileState(current, file.before) {
		return fmt.Errorf("setup config changed concurrently before HELM could modify it")
	}
	if sameSetupFileState(file.before, next) {
		file.after = file.before
		return nil
	}
	if err := restoreSetupFileState(next); err != nil {
		return err
	}
	file.after = next
	file.mutated = true
	return nil
}

func (tx *codexProjectConfigTransaction) hasOwnedConfig(expectedDataDir, expectedHookCommand string) (bool, error) {
	if err := requireCodexProjectHookSourceForRemoval(tx.client.before.Data); err != nil {
		return false, err
	}
	mcp, err := readCodexMCPServerFromBytes(tx.client.before.Data)
	if err != nil {
		return false, err
	}
	if mcp != nil {
		if err := requireSafeCodexMCPRemoval(mcp, expectedDataDir); err != nil {
			return false, err
		}
	}
	hasHook, err := hasOwnedSetupHookInBytes(tx.hook.before.Data, "codex", expectedHookCommand)
	if err != nil {
		return false, err
	}
	return (mcp != nil && isOwnedCodexMCPServerForDataDir(*mcp, expectedDataDir)) || hasHook, nil
}

func (tx *codexProjectConfigTransaction) rollback() error {
	if tx == nil {
		return nil
	}
	var rollbackErrors []error
	if err := rollbackSetupTransactionFile(tx.hook, "hook config"); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := rollbackSetupTransactionFile(tx.client, "Codex project config"); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	return errors.Join(rollbackErrors...)
}

func rollbackSetupTransactionFile(file setupTransactionFile, label string) error {
	if !file.mutated {
		return nil
	}
	current, err := readSetupFileState(file.before.Path)
	if err != nil {
		return fmt.Errorf("read %s before rollback: %w", label, err)
	}
	if !sameSetupFileState(current, file.after) {
		return fmt.Errorf("%s changed concurrently; refusing to overwrite user state", label)
	}
	if err := restoreSetupFileState(file.before); err != nil {
		return fmt.Errorf("restore %s: %w", label, err)
	}
	return nil
}

func readSetupFileState(path string) (setupFileState, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return setupFileState{}, err
	}
	if err := rejectSetupConfigParentSymlink(absPath); err != nil {
		return setupFileState{}, err
	}
	state := setupFileState{Path: absPath}
	info, err := os.Lstat(absPath)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return setupFileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return setupFileState{}, fmt.Errorf("refusing to modify symlinked setup config %s", absPath)
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return setupFileState{}, err
	}
	state.Exists = true
	state.Data = append([]byte(nil), data...)
	return state, nil
}

// inspectSetupRegularFile performs the same static path/symlink checks as a
// setup file read, but deliberately returns metadata only. It is appropriate
// for large durable state such as helm.db, where os.ReadFile would turn a
// provenance check into an avoidable local-memory denial of service.
func inspectSetupRegularFile(path string) (setupRegularFileState, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return setupRegularFileState{}, err
	}
	if err := rejectSetupConfigParentSymlink(absPath); err != nil {
		return setupRegularFileState{}, err
	}
	state := setupRegularFileState{Path: absPath}
	info, err := os.Lstat(absPath)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return setupRegularFileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return setupRegularFileState{}, fmt.Errorf("refusing to inspect symlinked setup file %s", absPath)
	}
	if !info.Mode().IsRegular() {
		return setupRegularFileState{}, fmt.Errorf("setup file is not a regular file: %s", absPath)
	}
	state.Exists = true
	state.Info = info
	return state, nil
}

// readSetupExistingPrivateFile accepts only an existing, regular, private
// local-authority file. Root signing keys are an authority boundary: loading a
// group/world-readable key would allow another local principal to forge the
// lifecycle receipts that recovery treats as proof.
func readSetupExistingPrivateFile(path string) (setupFileState, error) {
	metadata, err := inspectSetupRegularFile(path)
	if err != nil {
		return setupFileState{}, err
	}
	state := setupFileState{Path: metadata.Path}
	if !metadata.Exists {
		return state, nil
	}
	mode := metadata.Info.Mode()
	if mode.Perm() != 0o600 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return setupFileState{}, fmt.Errorf("setup private file must have exact mode 0600: %s", metadata.Path)
	}
	if err := requireSetupPrivateFileOwner(metadata.Path, metadata.Info); err != nil {
		return setupFileState{}, err
	}
	data, err := os.ReadFile(metadata.Path)
	if err != nil {
		return setupFileState{}, err
	}
	state.Exists = true
	state.Data = append([]byte(nil), data...)
	return state, nil
}

func sameSetupFileState(left, right setupFileState) bool {
	return left.Path == right.Path && left.Exists == right.Exists && bytes.Equal(left.Data, right.Data)
}

func restoreSetupFileState(state setupFileState) error {
	if state.Exists {
		return writeSetupPrivateFile(state.Path, state.Data)
	}
	if err := os.Remove(state.Path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return syncSetupParentDirectory(state.Path)
}

func writeSetupPrivateFile(path string, data []byte) (err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = absPath
	if err := rejectSetupConfigParentSymlink(path); err != nil {
		return err
	}
	if err := rejectSetupFileSymlink(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := rejectSetupConfigParentSymlink(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".helm-setup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rejectSetupFileSymlink(path); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncSetupParentDirectory(path)
}

// writeSetupPrivateFileIfAbsent publishes a new private authority file without
// ever replacing one produced by another local process. The temporary file is
// fully written and synced before Link gives it a durable final name, so a
// concurrent first-use process either wins with a complete key or reloads the
// complete key chosen by the winner.
func writeSetupPrivateFileIfAbsent(path string, data []byte) (bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	path = absPath
	if err := rejectSetupConfigParentSymlink(path); err != nil {
		return false, err
	}
	if err := rejectSetupFileSymlink(path); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	if err := rejectSetupConfigParentSymlink(path); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".helm-setup-*")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := rejectSetupFileSymlink(path); err != nil {
		return false, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			if symlinkErr := rejectSetupFileSymlink(path); symlinkErr != nil {
				return false, symlinkErr
			}
			return false, nil
		}
		return false, err
	}
	if err := syncSetupParentDirectory(path); err != nil {
		return false, err
	}
	return true, nil
}

// syncSetupParentDirectory makes the rename/removal boundary durable on the
// Unix platforms that run the local Kernel. Windows does not expose durable
// directory fsync through os.File, so it keeps the atomic replacement but does
// not claim the stronger crash-durability boundary there.
func syncSetupParentDirectory(path string) error {
	return syncSetupDirectory(filepath.Dir(path))
}

func syncSetupDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func rejectSetupFileSymlink(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlinked setup config %s", path)
	}
	return nil
}

func rejectSetupConfigParentSymlink(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to modify setup config through symlinked parent %s", parent)
	}
	return nil
}
