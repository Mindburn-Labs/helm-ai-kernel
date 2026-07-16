package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	setupRecoverySchema               = "helm.codex-project-recovery/v1"
	setupRecoveryMarkerSchema         = "helm.codex-project-recovery-marker/v1"
	setupRecoveryDirectory            = ".helm-setup-recovery"
	setupRecoveryJournalFile          = "journal.json"
	setupRecoveryStagingDir           = "staged"
	setupRecoveryPreparingFile        = "PREPARING"
	setupRecoveryCommittedFile        = "COMMITTED"
	setupRecoveryPhasePrepared        = "prepared"
	setupRecoveryMarkerStatePreparing = "preparing"
	setupRecoveryMarkerStateCommitted = "committed"
	setupRecoveryTemporaryPrefix      = ".helm-setup-"
)

// setupRecoveryFingerprint intentionally records only existence plus a
// content hash. It never persists user-owned TOML or JSON bytes in Kernel
// state. A resumed transaction can only move a file from its exact recorded
// before state to a reproducible after state; any third state is a conflict.
type setupRecoveryFingerprint struct {
	Exists      bool   `json:"exists"`
	ContentHash string `json:"content_hash,omitempty"`
}

type setupRecoveryFilePlan struct {
	ID        string                   `json:"id"`
	Before    setupRecoveryFingerprint `json:"before"`
	After     setupRecoveryFingerprint `json:"after"`
	StageFile string                   `json:"stage_file,omitempty"`
}

type setupRecoveryJournal struct {
	SchemaVersion      string                  `json:"schema_version"`
	TransactionID      string                  `json:"transaction_id"`
	Operation          string                  `json:"operation"`
	Target             string                  `json:"target"`
	Scope              string                  `json:"scope"`
	WorkspacePathHash  string                  `json:"workspace_path_hash"`
	DataDirPathHash    string                  `json:"data_dir_path_hash"`
	BinaryPath         string                  `json:"binary_path"`
	BinaryContentHash  string                  `json:"binary_content_hash"`
	LifecycleReceiptID string                  `json:"lifecycle_receipt_id"`
	ScanGrade          string                  `json:"scan_grade,omitempty"`
	Phase              string                  `json:"phase"`
	Files              []setupRecoveryFilePlan `json:"files"`
}

// setupRecoveryMarker is deliberately much smaller than the journal. It
// makes the two otherwise-unobservable crash windows explicit: preparation
// before a journal is durable, and completion before its directory cleanup is
// durable. Markers contain no user-owned configuration bytes.
type setupRecoveryMarker struct {
	SchemaVersion      string `json:"schema_version"`
	State              string `json:"state"`
	TransactionID      string `json:"transaction_id,omitempty"`
	LifecycleReceiptID string `json:"lifecycle_receipt_id,omitempty"`
	JournalHash        string `json:"journal_hash,omitempty"`
	Operation          string `json:"operation,omitempty"`
	Target             string `json:"target,omitempty"`
	Scope              string `json:"scope,omitempty"`
	WorkspacePathHash  string `json:"workspace_path_hash,omitempty"`
	DataDirPathHash    string `json:"data_dir_path_hash,omitempty"`
	BinaryPath         string `json:"binary_path,omitempty"`
	BinaryContentHash  string `json:"binary_content_hash,omitempty"`
	Signature          string `json:"signature,omitempty"`
}

type setupRecoveryState uint8

const (
	setupRecoveryStateAbsent setupRecoveryState = iota
	setupRecoveryStatePrepared
	setupRecoveryStatePending
	setupRecoveryStateCommitted
)

type setupRecoveryInspection struct {
	State   setupRecoveryState
	Journal *setupRecoveryJournal
}

type setupRecoveryPlanSpec struct {
	ID        string
	StageFile string
}

func setupRecoveryRoot(dataDir string) string {
	return currentCodexProjectPaths(dataDir).RecoveryRoot
}

func setupRecoveryJournalPath(dataDir string) string {
	return filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryJournalFile)
}

func setupRecoveryMarkerPath(dataDir, filename string) string {
	return filepath.Join(setupRecoveryRoot(dataDir), filename)
}

func setupRecoveryStagePath(dataDir, stageFile string) string {
	return filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir, stageFile)
}

func setupRecoveryFingerprintForState(state setupFileState) setupRecoveryFingerprint {
	fingerprint := setupRecoveryFingerprint{Exists: state.Exists}
	if state.Exists {
		fingerprint.ContentHash = canonicalize.HashBytes(state.Data)
	}
	return fingerprint
}

func sameSetupRecoveryFingerprint(left, right setupRecoveryFingerprint) bool {
	return left.Exists == right.Exists && left.ContentHash == right.ContentHash
}

func setupRecoveryFingerprintMatchesState(fingerprint setupRecoveryFingerprint, state setupFileState) bool {
	return sameSetupRecoveryFingerprint(fingerprint, setupRecoveryFingerprintForState(state))
}

func newSetupRecoveryTransactionID() (string, error) {
	var random [16]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate recovery transaction id: %w", err)
	}
	return "txn_native_client_" + hex.EncodeToString(random[:]), nil
}

func isSetupRecoveryTransactionID(value string) bool {
	return isSetupOpaqueID(value, "txn_native_client_")
}

func isSetupLifecycleReceiptID(value string) bool {
	return isSetupOpaqueID(value, "rcpt_native_client_")
}

func isSetupOpaqueID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func isSetupSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func expectedSetupRecoveryPlans(operation string) ([]setupRecoveryPlanSpec, error) {
	switch operation {
	case "install":
		return []setupRecoveryPlanSpec{
			{ID: setupRecoveryFileInventory, StageFile: "inventory.json"},
			{ID: setupRecoveryFilePolicyDraft, StageFile: "policy.draft.json"},
			{ID: setupRecoveryFileMCPQuarantinePlan, StageFile: "mcp_quarantine_plan.json"},
			{ID: setupRecoveryFileHook},
			{ID: setupRecoveryFileMCP},
			{ID: setupRecoveryFileBinding, StageFile: "codex-project-binding.json"},
		}, nil
	case "remove":
		return []setupRecoveryPlanSpec{
			{ID: setupRecoveryFileMCP},
			{ID: setupRecoveryFileHook},
			{ID: setupRecoveryFileBinding},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported setup recovery operation %q", operation)
	}
}

func validateSetupRecoveryFingerprint(fingerprint setupRecoveryFingerprint) error {
	if !fingerprint.Exists && fingerprint.ContentHash != "" {
		return fmt.Errorf("absent recovery file fingerprint must not include a content hash")
	}
	if fingerprint.Exists && !isSetupSHA256(fingerprint.ContentHash) {
		return fmt.Errorf("present recovery file fingerprint requires a SHA-256 content hash")
	}
	return nil
}

func validateSetupRecoveryJournal(journal *setupRecoveryJournal) error {
	if journal == nil {
		return fmt.Errorf("setup recovery journal is required")
	}
	if journal.SchemaVersion != setupRecoverySchema || journal.Phase != setupRecoveryPhasePrepared {
		return fmt.Errorf("unsupported or incomplete setup recovery journal")
	}
	if !isSetupRecoveryTransactionID(journal.TransactionID) || !isSetupLifecycleReceiptID(journal.LifecycleReceiptID) {
		return fmt.Errorf("setup recovery journal has invalid transaction or lifecycle receipt id")
	}
	if journal.Target != "codex" || journal.Scope != "project" {
		return fmt.Errorf("setup recovery journal has unsupported target or scope")
	}
	if !isSetupSHA256(journal.WorkspacePathHash) || !isSetupSHA256(journal.DataDirPathHash) || !isSetupSHA256(journal.BinaryContentHash) {
		return fmt.Errorf("setup recovery journal has invalid path or binary hash")
	}
	if !filepath.IsAbs(journal.BinaryPath) || filepath.Clean(journal.BinaryPath) != journal.BinaryPath || strings.ContainsRune(journal.BinaryPath, '\x00') {
		return fmt.Errorf("setup recovery journal has invalid Kernel binary path")
	}
	expected, err := expectedSetupRecoveryPlans(journal.Operation)
	if err != nil {
		return err
	}
	if len(journal.Files) != len(expected) {
		return fmt.Errorf("setup recovery journal has an unexpected recovery plan count")
	}
	for index, spec := range expected {
		plan := journal.Files[index]
		if plan.ID != spec.ID || plan.StageFile != spec.StageFile {
			return fmt.Errorf("setup recovery journal plan %d is not the expected %s plan", index, spec.ID)
		}
		if err := validateSetupRecoveryFingerprint(plan.Before); err != nil {
			return fmt.Errorf("setup recovery %s plan before fingerprint: %w", spec.ID, err)
		}
		if err := validateSetupRecoveryFingerprint(plan.After); err != nil {
			return fmt.Errorf("setup recovery %s plan after fingerprint: %w", spec.ID, err)
		}
	}
	return nil
}

func readSetupRecoveryJournal(dataDir string) (*setupRecoveryJournal, error) {
	return readSetupRecoveryJournalAtPath(setupRecoveryJournalPath(dataDir))
}

// readSetupRecoveryJournalAtPath keeps the canonical parser reusable for the
// explicit v0-to-v1 migration path. It parses only a caller-validated private
// file; it is never a fallback for normal recovery.
func readSetupRecoveryJournalAtPath(path string) (*setupRecoveryJournal, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return nil, nil
	}
	var journal setupRecoveryJournal
	if err := json.Unmarshal(state.Data, &journal); err != nil {
		return nil, fmt.Errorf("decode setup recovery journal: %w", err)
	}
	canonical, err := canonicalize.JCS(journal)
	if err != nil {
		return nil, fmt.Errorf("canonicalize setup recovery journal: %w", err)
	}
	if !bytes.Equal(state.Data, canonical) {
		return nil, fmt.Errorf("setup recovery journal is not canonical")
	}
	if err := validateSetupRecoveryJournal(&journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func writeSetupRecoveryJournal(dataDir string, journal setupRecoveryJournal) error {
	if err := validateSetupRecoveryJournal(&journal); err != nil {
		return err
	}
	data, err := canonicalize.JCS(journal)
	if err != nil {
		return err
	}
	if err := writeSetupPrivateFile(setupRecoveryJournalPath(dataDir), data); err != nil {
		return err
	}
	// writeSetupPrivateFile fsyncs the recovery directory. The recovery-root
	// entry itself is synced when it is created below, so this journal is
	// durable before any shared configuration mutation can begin.
	return nil
}

func validateSetupRecoveryMarker(marker *setupRecoveryMarker) error {
	if marker == nil || marker.SchemaVersion != setupRecoveryMarkerSchema {
		return fmt.Errorf("unsupported setup recovery marker")
	}
	switch marker.State {
	case setupRecoveryMarkerStatePreparing:
		if marker.TransactionID != "" || marker.LifecycleReceiptID != "" || marker.JournalHash != "" || marker.Operation != "" || marker.Target != "" || marker.Scope != "" || marker.WorkspacePathHash != "" || marker.DataDirPathHash != "" || marker.BinaryPath != "" || marker.BinaryContentHash != "" || marker.Signature != "" {
			return fmt.Errorf("preparing setup recovery marker must not contain transaction state")
		}
	case setupRecoveryMarkerStateCommitted:
		if !isSetupRecoveryTransactionID(marker.TransactionID) || !isSetupLifecycleReceiptID(marker.LifecycleReceiptID) {
			return fmt.Errorf("committed setup recovery marker has invalid transaction state")
		}
		if !setupRecoveryMarkerHasTerminalProof(marker) {
			// Older/incomplete markers are deliberately readable so a live
			// journal remains resumable. They are never terminal authority.
			if marker.JournalHash != "" || marker.Operation != "" || marker.Target != "" || marker.Scope != "" || marker.WorkspacePathHash != "" || marker.DataDirPathHash != "" || marker.BinaryPath != "" || marker.BinaryContentHash != "" || marker.Signature != "" {
				return fmt.Errorf("committed setup recovery marker has incomplete terminal proof")
			}
			return nil
		}
		if !isSetupSHA256(marker.JournalHash) || !isSetupSHA256(marker.WorkspacePathHash) || !isSetupSHA256(marker.DataDirPathHash) || !isSetupSHA256(marker.BinaryContentHash) || marker.Target != "codex" || marker.Scope != "project" || strings.ContainsRune(marker.BinaryPath, '\x00') || !filepath.IsAbs(marker.BinaryPath) {
			return fmt.Errorf("committed setup recovery marker has invalid terminal proof")
		}
		if _, err := expectedSetupRecoveryPlans(marker.Operation); err != nil {
			return fmt.Errorf("committed setup recovery marker has invalid operation: %w", err)
		}
	default:
		return fmt.Errorf("unknown setup recovery marker state %q", marker.State)
	}
	return nil
}

func setupRecoveryMarkerHasTerminalProof(marker *setupRecoveryMarker) bool {
	return setupRecoveryMarkerHasTerminalPayload(marker) && marker.Signature != ""
}

func setupRecoveryMarkerHasTerminalPayload(marker *setupRecoveryMarker) bool {
	if marker == nil {
		return false
	}
	return marker.JournalHash != "" && marker.Operation != "" && marker.Target != "" && marker.Scope != "" && marker.WorkspacePathHash != "" && marker.DataDirPathHash != "" && marker.BinaryPath != "" && marker.BinaryContentHash != ""
}

func readSetupRecoveryMarker(dataDir, filename string) (*setupRecoveryMarker, error) {
	return readSetupRecoveryMarkerAtPath(setupRecoveryMarkerPath(dataDir, filename), filename)
}

// readSetupRecoveryMarkerAtPath keeps canonical marker parsing independent of
// the active v1 recovery root so explicit legacy migration can reject malformed
// source state during dry-run before it moves a directory.
func readSetupRecoveryMarkerAtPath(path, filename string) (*setupRecoveryMarker, error) {
	state, err := readSetupExistingPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return nil, nil
	}
	var marker setupRecoveryMarker
	if err := json.Unmarshal(state.Data, &marker); err != nil {
		return nil, fmt.Errorf("decode setup recovery marker %s: %w", filename, err)
	}
	canonical, err := canonicalize.JCS(marker)
	if err != nil {
		return nil, fmt.Errorf("canonicalize setup recovery marker %s: %w", filename, err)
	}
	if !bytes.Equal(state.Data, canonical) {
		return nil, fmt.Errorf("setup recovery marker %s is not canonical", filename)
	}
	if err := validateSetupRecoveryMarker(&marker); err != nil {
		return nil, err
	}
	return &marker, nil
}

func writeSetupRecoveryMarker(dataDir, filename string, marker setupRecoveryMarker) error {
	if err := validateSetupRecoveryMarker(&marker); err != nil {
		return err
	}
	data, err := canonicalize.JCS(marker)
	if err != nil {
		return err
	}
	return writeSetupPrivateFile(setupRecoveryMarkerPath(dataDir, filename), data)
}

func removeSetupRecoveryMarker(dataDir, filename string) error {
	path := setupRecoveryMarkerPath(dataDir, filename)
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	if !state.Exists {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncSetupParentDirectory(path)
}

func setupRecoveryAllowedStageFile(name string) bool {
	switch name {
	case "inventory.json", "policy.draft.json", "mcp_quarantine_plan.json", "codex-project-binding.json":
		return true
	default:
		return false
	}
}

// isSetupRecoveryTemporaryName accepts only the exact shape emitted by
// os.CreateTemp(dir, ".helm-setup-*") in writeSetupPrivateFile. Crash residue
// is deliberately allowlisted only in the private recovery root and its
// direct staged child; this must never become a generic cleanup rule.
func isSetupRecoveryTemporaryName(name string) bool {
	if !strings.HasPrefix(name, setupRecoveryTemporaryPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, setupRecoveryTemporaryPrefix)
	if suffix == "" {
		return false
	}
	for _, char := range suffix {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validateSetupRecoveryTemporaryEntry(path string, info os.FileInfo) error {
	if !isSetupRecoveryTemporaryName(filepath.Base(path)) {
		return fmt.Errorf("invalid setup recovery temporary entry %q", filepath.Base(path))
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() || mode.Perm() != 0o600 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("invalid setup recovery temporary entry %q", filepath.Base(path))
	}
	if err := requireSetupPrivateFileOwner(path, info); err != nil {
		return fmt.Errorf("invalid setup recovery temporary entry %q: %w", filepath.Base(path), err)
	}
	return nil
}

func setupRecoverySafeStagePath(dataDir, stageFile string) (string, error) {
	if !setupRecoveryAllowedStageFile(stageFile) || filepath.Base(stageFile) != stageFile {
		return "", fmt.Errorf("invalid setup recovery staged file %q", stageFile)
	}
	return setupRecoveryStagePath(dataDir, stageFile), nil
}

func inspectSetupRecoveryStageDirectory(dataDir string) (bool, error) {
	stageDir := filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir)
	info, err := os.Lstat(stageDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("invalid setup recovery staging directory %s", stageDir)
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return false, err
		}
		entryPath := filepath.Join(stageDir, entry.Name())
		if isSetupRecoveryTemporaryName(entry.Name()) {
			if err := validateSetupRecoveryTemporaryEntry(entryPath, entryInfo); err != nil {
				return false, err
			}
			continue
		}
		if !setupRecoveryAllowedStageFile(entry.Name()) {
			return false, fmt.Errorf("unexpected setup recovery staged entry %q", entry.Name())
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
			return false, fmt.Errorf("invalid setup recovery staged entry %q", entry.Name())
		}
	}
	return true, nil
}

func inspectSetupRecovery(dataDir string) (setupRecoveryInspection, error) {
	projectStateExists, authorityErr := inspectCodexProjectStateAuthority(dataDir)
	if authorityErr != nil {
		return setupRecoveryInspection{}, fmt.Errorf("inspect Codex project authority state: %w", authorityErr)
	}
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	legacyInfo, legacyErr := os.Lstat(legacyRoot)
	if legacyErr == nil {
		if legacyInfo.Mode()&os.ModeSymlink != 0 || !legacyInfo.IsDir() {
			return setupRecoveryInspection{}, fmt.Errorf("legacy unscoped Codex recovery state is invalid and must be inspected before native setup can continue")
		}
		return setupRecoveryInspection{}, fmt.Errorf("legacy unscoped Codex recovery state is present; migrate or resolve it before native setup can continue")
	}
	if !os.IsNotExist(legacyErr) {
		return setupRecoveryInspection{}, legacyErr
	}
	if !projectStateExists {
		return setupRecoveryInspection{State: setupRecoveryStateAbsent}, nil
	}
	root := setupRecoveryRoot(dataDir)
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return setupRecoveryInspection{State: setupRecoveryStateAbsent}, nil
	}
	if err != nil {
		return setupRecoveryInspection{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return setupRecoveryInspection{}, fmt.Errorf("invalid setup recovery directory %s", root)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return setupRecoveryInspection{}, err
	}
	known := map[string]bool{
		setupRecoveryJournalFile:   true,
		setupRecoveryStagingDir:    true,
		setupRecoveryPreparingFile: true,
		setupRecoveryCommittedFile: true,
	}
	nonTemporaryEntries := 0
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return setupRecoveryInspection{}, err
		}
		entryPath := filepath.Join(root, entry.Name())
		if isSetupRecoveryTemporaryName(entry.Name()) {
			if err := validateSetupRecoveryTemporaryEntry(entryPath, entryInfo); err != nil {
				return setupRecoveryInspection{}, err
			}
			continue
		}
		if !known[entry.Name()] {
			return setupRecoveryInspection{}, fmt.Errorf("unexpected setup recovery entry %q", entry.Name())
		}
		nonTemporaryEntries++
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return setupRecoveryInspection{}, fmt.Errorf("refusing setup recovery through symlinked entry %q", entry.Name())
		}
		if entry.Name() == setupRecoveryStagingDir {
			if !entryInfo.IsDir() {
				return setupRecoveryInspection{}, fmt.Errorf("setup recovery staging entry is not a directory")
			}
		} else if !entryInfo.Mode().IsRegular() {
			return setupRecoveryInspection{}, fmt.Errorf("setup recovery entry %q is not a regular file", entry.Name())
		}
	}

	stageExists, err := inspectSetupRecoveryStageDirectory(dataDir)
	if err != nil {
		return setupRecoveryInspection{}, err
	}
	journal, err := readSetupRecoveryJournal(dataDir)
	if err != nil {
		return setupRecoveryInspection{}, err
	}
	preparing, err := readSetupRecoveryMarker(dataDir, setupRecoveryPreparingFile)
	if err != nil {
		return setupRecoveryInspection{}, err
	}
	committed, err := readSetupRecoveryMarker(dataDir, setupRecoveryCommittedFile)
	if err != nil {
		return setupRecoveryInspection{}, err
	}

	if committed != nil {
		terminal, terminalErr := verifyCommittedSetupRecoveryTerminal(dataDir, committed, journal)
		if terminalErr != nil {
			if journal == nil {
				return setupRecoveryInspection{}, fmt.Errorf("committed setup recovery marker cannot be verified: %w", terminalErr)
			}
			// A journal is still present, so an unsigned or damaged marker must
			// never discard the resumable transaction or open the runtime gate.
			// Treat it as pending and let a real resume write a new signed marker.
		} else if terminal {
			return setupRecoveryInspection{State: setupRecoveryStateCommitted, Journal: journal}, nil
		} else if journal == nil {
			return setupRecoveryInspection{}, fmt.Errorf("committed setup recovery marker has no terminal proof")
		}
	}
	if journal != nil {
		if !stageExists {
			return setupRecoveryInspection{}, fmt.Errorf("prepared setup recovery journal has no staging directory")
		}
		return setupRecoveryInspection{State: setupRecoveryStatePending, Journal: journal}, nil
	}
	if preparing != nil || stageExists || nonTemporaryEntries == 0 {
		// Before a journal is durable, no shared client configuration has been
		// touched. This is still surfaced as recovery-required so a caller must
		// use `setup recover --yes` to remove only this known private residue.
		return setupRecoveryInspection{State: setupRecoveryStatePrepared}, nil
	}
	return setupRecoveryInspection{}, fmt.Errorf("unclassifiable setup recovery state")
}

func setupRecoveryRequired(dataDir string) (bool, error) {
	inspection, err := inspectSetupRecovery(dataDir)
	if err != nil {
		return false, err
	}
	return inspection.State == setupRecoveryStatePrepared || inspection.State == setupRecoveryStatePending, nil
}

func ensureSetupDirectory(path string, mode os.FileMode) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var missing []string
	for current := absPath; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("refusing to create setup state beneath invalid directory %s", current)
			}
			break
		}
		if !os.IsNotExist(statErr) {
			return statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("cannot find an existing parent for setup directory %s", absPath)
		}
		missing = append(missing, current)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		dir := missing[index]
		if err := os.Mkdir(dir, mode); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("setup directory is not a real directory: %s", dir)
		}
		if err := syncSetupDirectory(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	return nil
}

func createSetupRecoveryDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	return syncSetupDirectory(filepath.Dir(path))
}

func prepareSetupRecoveryDirectory(dataDir string) error {
	if err := ensureCodexProjectStateAuthority(dataDir); err != nil {
		return err
	}
	inspection, err := inspectSetupRecovery(dataDir)
	if err != nil {
		return err
	}
	switch inspection.State {
	case setupRecoveryStateCommitted:
		if err := cleanupCommittedSetupRecoveryDirectory(dataDir); err != nil {
			return fmt.Errorf("clean completed setup recovery residue: %w", err)
		}
	case setupRecoveryStatePrepared, setupRecoveryStatePending:
		return fmt.Errorf("setup recovery is pending; run `helm-ai-kernel setup recover codex --scope project --yes` before starting a new transaction")
	}

	root := setupRecoveryRoot(dataDir)
	if err := createSetupRecoveryDirectory(root, 0o700); err != nil {
		return err
	}
	if err := createSetupRecoveryDirectory(filepath.Join(root, setupRecoveryStagingDir), 0o700); err != nil {
		return err
	}
	// Persist this marker immediately. A crash before it appears leaves only
	// an empty owned root/staging shape, which inspectSetupRecovery classifies
	// as prepared and recovery can clean without touching shared config.
	return writeSetupRecoveryMarker(dataDir, setupRecoveryPreparingFile, setupRecoveryMarker{
		SchemaVersion: setupRecoveryMarkerSchema,
		State:         setupRecoveryMarkerStatePreparing,
	})
}

func removeSetupRecoveryKnownFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove invalid setup recovery file %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncSetupParentDirectory(path)
}

func removeSetupRecoveryKnownDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing to remove invalid setup recovery directory %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncSetupParentDirectory(path)
}

// removeSetupRecoveryTemporaryEntries removes only exact writer-shaped crash
// residue from a direct child directory. It intentionally does not recurse:
// any nested or malformed entry remains an invalid recovery state for a human
// to inspect instead of being silently deleted.
func removeSetupRecoveryTemporaryEntries(directory string) error {
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("invalid setup recovery temporary directory %s", directory)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !isSetupRecoveryTemporaryName(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		entryInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := validateSetupRecoveryTemporaryEntry(path, entryInfo); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := syncSetupParentDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func cleanupSetupRecoveryDirectory(dataDir string, terminal bool) error {
	inspection, err := inspectSetupRecovery(dataDir)
	if err != nil {
		return err
	}
	if terminal {
		if inspection.State == setupRecoveryStateAbsent {
			return nil
		}
		if inspection.State != setupRecoveryStateCommitted {
			return fmt.Errorf("setup recovery transaction is not committed")
		}
	} else {
		if inspection.State == setupRecoveryStateAbsent {
			return nil
		}
		if inspection.State != setupRecoveryStatePrepared {
			return fmt.Errorf("setup recovery journal is durable; resume it instead of discarding it")
		}
	}
	stageDir := filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir)
	if err := removeSetupRecoveryTemporaryEntries(stageDir); err != nil {
		return err
	}
	if err := removeSetupRecoveryTemporaryEntries(setupRecoveryRoot(dataDir)); err != nil {
		return err
	}

	for _, stageFile := range []string{"inventory.json", "policy.draft.json", "mcp_quarantine_plan.json", "codex-project-binding.json"} {
		stagePath, err := setupRecoverySafeStagePath(dataDir, stageFile)
		if err != nil {
			return err
		}
		if err := removeSetupRecoveryKnownFile(stagePath); err != nil {
			return err
		}
	}
	if err := removeSetupRecoveryKnownDirectory(stageDir); err != nil {
		return err
	}
	if terminal {
		if err := removeSetupRecoveryMarker(dataDir, setupRecoveryPreparingFile); err != nil {
			return err
		}
		if err := removeSetupRecoveryKnownFile(setupRecoveryJournalPath(dataDir)); err != nil {
			return err
		}
	}
	if err := removeSetupRecoveryMarker(dataDir, setupRecoveryPreparingFile); err != nil {
		return err
	}
	if terminal {
		if err := removeSetupRecoveryMarker(dataDir, setupRecoveryCommittedFile); err != nil {
			return err
		}
	}
	return removeSetupRecoveryKnownDirectory(setupRecoveryRoot(dataDir))
}

func cleanupIncompleteSetupRecoveryDirectory(dataDir string) error {
	return cleanupSetupRecoveryDirectory(dataDir, false)
}

func cleanupCommittedSetupRecoveryDirectory(dataDir string) error {
	return cleanupSetupRecoveryDirectory(dataDir, true)
}

func removeSetupRecoveryJournal(dataDir string, journal *setupRecoveryJournal) error {
	if journal == nil {
		return nil
	}
	if err := validateSetupRecoveryJournal(journal); err != nil {
		return err
	}
	inspection, err := inspectSetupRecovery(dataDir)
	if err != nil {
		return err
	}
	if inspection.State == setupRecoveryStateAbsent {
		return nil
	}
	if inspection.State != setupRecoveryStateCommitted {
		if inspection.Journal == nil || inspection.Journal.TransactionID != journal.TransactionID || inspection.Journal.LifecycleReceiptID != journal.LifecycleReceiptID {
			return fmt.Errorf("setup recovery journal changed before finalization")
		}
		marker, err := newSignedSetupRecoveryCommittedMarker(dataDir, journal)
		if err != nil {
			return err
		}
		if err := writeSetupRecoveryMarker(dataDir, setupRecoveryCommittedFile, marker); err != nil {
			return err
		}
	}
	// Once COMMITTED is durable, config and lifecycle evidence have completed.
	// A process death in cleanup is terminal, not a new rollback/replay state;
	// the next setup/recover safely retries only this allowlisted cleanup.
	return cleanupCommittedSetupRecoveryDirectory(dataDir)
}

func lookupSetupRecoveryFilePlan(journal *setupRecoveryJournal, id string) (setupRecoveryFilePlan, error) {
	if err := validateSetupRecoveryJournal(journal); err != nil {
		return setupRecoveryFilePlan{}, err
	}
	for _, plan := range journal.Files {
		if plan.ID == id {
			return plan, nil
		}
	}
	return setupRecoveryFilePlan{}, fmt.Errorf("setup recovery journal has no %s plan", id)
}
