package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func writeSetupSecurityPendingJournal(t *testing.T, dataDir, operation string, plans []setupRecoveryFilePlan) *setupRecoveryJournal {
	t.Helper()
	if err := prepareSetupRecoveryDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	if plans == nil {
		specs, err := expectedSetupRecoveryPlans(operation)
		if err != nil {
			t.Fatal(err)
		}
		plans = make([]setupRecoveryFilePlan, 0, len(specs))
		for _, spec := range specs {
			plans = append(plans, setupRecoveryFilePlan{ID: spec.ID, StageFile: spec.StageFile})
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := inspectSetupKernelBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		t.Fatal(err)
	}
	txnID, err := newSetupRecoveryTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	receiptID, err := newSetupLifecycleReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	journal := &setupRecoveryJournal{
		SchemaVersion:      setupRecoverySchema,
		TransactionID:      txnID,
		Operation:          operation,
		Target:             "codex",
		Scope:              "project",
		WorkspacePathHash:  workspacePathHash,
		DataDirPathHash:    canonicalize.HashBytes([]byte(dataDir)),
		BinaryPath:         identity.Path,
		BinaryContentHash:  identity.ContentHash,
		LifecycleReceiptID: receiptID,
		Phase:              setupRecoveryPhasePrepared,
		Files:              plans,
	}
	if err := writeSetupRecoveryJournal(dataDir, *journal); err != nil {
		t.Fatal(err)
	}
	if err := removeSetupRecoveryMarker(dataDir, setupRecoveryPreparingFile); err != nil {
		t.Fatal(err)
	}
	return journal
}

func writeSetupRecoveryCrashTemp(t *testing.T, directory, suffix string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, setupRecoveryTemporaryPrefix+suffix)
	if err := os.WriteFile(path, []byte("incomplete private write"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetupRecoveryPreparedResidueFailsClosedThenRecovers(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	if err := os.MkdirAll(filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeSetupRecoveryCrashTemp(t, setupRecoveryRoot(dataDir), "101")
	writeSetupRecoveryCrashTemp(t, filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir), "102")

	pending, err := setupRecoveryRequired(dataDir)
	if err != nil || !pending {
		t.Fatalf("pre-journal residue pending=%v err=%v", pending, err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("status exit=%d stderr=%s", code, stderr.String())
	}
	var status setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil || !status.RecoveryRequired {
		t.Fatalf("prepared residue status=%#v err=%v", status, err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "recovery") {
		t.Fatalf("pending hook did not deny safely: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{filepath.Join(dataDir, "root.key"), filepath.Join(dataDir, "receipts", "hooks")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("pending hook created state %s: %v", path, err)
		}
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("prepared residue did not block MCP: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("recover prepared residue exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(setupRecoveryRoot(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("recover retained pre-journal residue: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("fresh setup stayed blocked after residue cleanup: code=%d stderr=%s", code, stderr.String())
	}
}

func TestSetupRecoveryUnexpectedResidueIsPreservedAndFailsClosed(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	root := setupRecoveryRoot(dataDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "not-owned")
	if err := os.WriteFile(unknown, []byte("user-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unexpected") {
		t.Fatalf("status did not fail closed: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unexpected") {
		t.Fatalf("recover accepted unknown residue: code=%d stderr=%s", code, stderr.String())
	}
	if raw, err := os.ReadFile(unknown); err != nil || string(raw) != "user-data" {
		t.Fatalf("recover modified unknown residue: raw=%q err=%v", raw, err)
	}
}

func TestSetupRecoveryPendingJournalToleratesOnlyWriterShapedCrashTemps(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	stubSetupSideEffects(t)
	previousRecord := recordCodexProjectSetupLifecycleFn
	recordCodexProjectSetupLifecycleFn = func(setupOptions, setupSummary, string) (setupLifecycleResult, error) {
		return setupLifecycleResult{}, errors.New("injected lifecycle failure")
	}
	t.Cleanup(func() { recordCodexProjectSetupLifecycleFn = previousRecord })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("setup with injected lifecycle failure exit=%d stderr=%s", code, stderr.String())
	}
	if inspection, err := inspectSetupRecovery(dataDir); err != nil || inspection.State != setupRecoveryStatePending {
		t.Fatalf("initial pending recovery inspection=%#v err=%v", inspection, err)
	}
	writeSetupRecoveryCrashTemp(t, setupRecoveryRoot(dataDir), "201")
	writeSetupRecoveryCrashTemp(t, filepath.Join(setupRecoveryRoot(dataDir), setupRecoveryStagingDir), "202")
	if inspection, err := inspectSetupRecovery(dataDir); err != nil || inspection.State != setupRecoveryStatePending {
		t.Fatalf("pending recovery rejected writer-shaped temps: inspection=%#v err=%v", inspection, err)
	}

	recordCodexProjectSetupLifecycleFn = previousRecord
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("pending recovery with crash temps exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(setupRecoveryRoot(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("pending recovery left temporary residue: %v", err)
	}

	db, _, receiptStore, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM receipts WHERE status = 'DENY'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("recovered install wrote %d lifecycle receipts, want one", count)
	}
	if _, err := receiptStore.GetByReceiptID(context.Background(), func() string {
		var id string
		if err := db.QueryRow("SELECT receipt_id FROM receipts WHERE status = 'DENY' LIMIT 1").Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}()); err != nil {
		t.Fatalf("recovered lifecycle receipt unreadable: %v", err)
	}
}

func TestSetupRecoveryRejectsMalformedTemporaryResidueWithoutDeletingIt(t *testing.T) {
	cases := []struct {
		name   string
		stage  bool
		create func(t *testing.T, path string, external string)
	}{
		{
			name: "unknown root file",
			create: func(t *testing.T, path string, _ string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("user-data"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "temporary-shaped staged symlink",
			stage: true,
			create: func(t *testing.T, path string, external string) {
				t.Helper()
				if err := os.Symlink(external, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "temporary-shaped root directory",
			create: func(t *testing.T, path string, _ string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "temporary-shaped staged wrong mode",
			stage: true,
			create: func(t *testing.T, path string, _ string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("must-remain"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := chdirTempDir(t)
			dataDir := filepath.Join(dir, "helm")
			root := setupRecoveryRoot(dataDir)
			stageDir := filepath.Join(root, setupRecoveryStagingDir)
			if err := os.MkdirAll(stageDir, 0o700); err != nil {
				t.Fatal(err)
			}
			directory := root
			name := "not-owned"
			if tc.stage {
				directory = stageDir
				name = setupRecoveryTemporaryPrefix + "303"
			} else if strings.Contains(tc.name, "temporary-shaped") {
				name = setupRecoveryTemporaryPrefix + "304"
			}
			path := filepath.Join(directory, name)
			external := filepath.Join(dir, "external")
			if err := os.WriteFile(external, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.create(t, path, external)

			var stdout, stderr bytes.Buffer
			if code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--data-dir", dataDir}, &stdout, &stderr); code != 2 {
				t.Fatalf("status accepted malformed temporary residue: code=%d stderr=%s", code, stderr.String())
			}
			stdout.Reset()
			stderr.Reset()
			if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
				t.Fatalf("recover accepted malformed temporary residue: code=%d stderr=%s", code, stderr.String())
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("recover removed malformed temporary residue: %v", err)
			}
			if got, err := os.ReadFile(external); err != nil || string(got) != "outside" {
				t.Fatalf("recover touched symlink target: got=%q err=%v", got, err)
			}
		})
	}
}

func TestForgedCodexRemovalJournalCannotAlterUnprovenConfig(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertCodexProjectMCP(summary.ClientConfigPath, summary.BinaryPath, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := upsertOwnedSetupHookConfig(summary.HookConfigPath, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target); err != nil {
		t.Fatal(err)
	}
	clientBefore, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hookBefore, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	clientAfter, err := buildRemoveCodexProjectMCPStateForBinary(clientBefore, dataDir, summary.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	hookAfter, err := buildRemoveOwnedSetupHookState(hookBefore, opts.Target, setupHookCommand(opts, summary.BinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	writeSetupSecurityPendingJournal(t, dataDir, "remove", []setupRecoveryFilePlan{
		setupRecoveryPlanForStates(setupRecoveryFileMCP, clientBefore, clientAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileHook, hookBefore, hookAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileBinding, setupFileState{Path: setupCodexProjectBindingPath(dataDir)}, setupFileState{Path: setupCodexProjectBindingPath(dataDir)}, ""),
	})

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "provenance") {
		t.Fatalf("forged removal journal was not rejected: code=%d stderr=%s", code, stderr.String())
	}
	clientAfterAttempt, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil || !bytes.Equal(clientAfterAttempt, clientBefore.Data) {
		t.Fatalf("forged removal journal changed MCP config: %q err=%v", clientAfterAttempt, err)
	}
	hookAfterAttempt, err := os.ReadFile(summary.HookConfigPath)
	if err != nil || !bytes.Equal(hookAfterAttempt, hookBefore.Data) {
		t.Fatalf("forged removal journal changed hook config: %q err=%v", hookAfterAttempt, err)
	}
	for _, path := range []string{filepath.Join(dataDir, "root.key"), filepath.Join(dataDir, "helm.db")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("forged removal journal created lifecycle state %s: %v", path, err)
		}
	}
}

func TestCodexRemovalRecoveryCompletesAfterBindingDeletedBeforeTerminalMarker(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	stubSetupSideEffects(t)
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit=%d stderr=%s", code, stderr.String())
	}

	previousFinalize := finalizeCodexProjectRecoveryJournal
	finalizeCodexProjectRecoveryJournal = func(_ string, _ *setupRecoveryJournal) error {
		return errors.New("injected pre-marker finalization failure")
	}
	t.Cleanup(func() { finalizeCodexProjectRecoveryJournal = previousFinalize })
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("remove with injected finalization failure exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(setupCodexProjectBindingPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("binding survived the intended post-revocation crash boundary: %v", err)
	}
	if inspection, err := inspectSetupRecovery(dataDir); err != nil || inspection.State != setupRecoveryStatePending {
		t.Fatalf("post-binding-delete recovery inspection=%#v err=%v", inspection, err)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("pending post-binding-delete recovery did not block MCP: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "recovery") {
		t.Fatalf("pending post-binding-delete recovery did not deny hook: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var revokedBefore int
	if err := db.QueryRow("SELECT COUNT(1) FROM receipts WHERE status = 'REVOKED'").Scan(&revokedBefore); err != nil {
		t.Fatal(err)
	}
	if revokedBefore != 1 {
		t.Fatalf("post-binding-delete state has %d revoked receipts, want one", revokedBefore)
	}

	finalizeCodexProjectRecoveryJournal = previousFinalize
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("recover after binding delete exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(setupRecoveryRoot(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("completed removal recovery left recovery root: %v", err)
	}
	var revokedAfter int
	if err := db.QueryRow("SELECT COUNT(1) FROM receipts WHERE status = 'REVOKED'").Scan(&revokedAfter); err != nil {
		t.Fatal(err)
	}
	if revokedAfter != 1 {
		t.Fatalf("completed removal recovery duplicated revoked receipt: before=%d after=%d", revokedBefore, revokedAfter)
	}
	refreshSetupConfiguration(opts, &summary)
	if summary.MCPConfigured || summary.HookConfigured {
		t.Fatalf("completed removal recovery restored owned config: %#v", summary)
	}
}

func TestCodexRemovalRecoveryAfterBindingDeleteRefusesChangedConfig(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	stubSetupSideEffects(t)
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit=%d stderr=%s", code, stderr.String())
	}
	previousFinalize := finalizeCodexProjectRecoveryJournal
	finalizeCodexProjectRecoveryJournal = func(_ string, _ *setupRecoveryJournal) error {
		return errors.New("injected pre-marker finalization failure")
	}
	t.Cleanup(func() { finalizeCodexProjectRecoveryJournal = previousFinalize })
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("remove with injected finalization failure exit=%d stderr=%s", code, stderr.String())
	}
	const userChange = "# user changed this after HELM removed its MCP\n"
	if err := os.WriteFile(summary.ClientConfigPath, []byte(userChange), 0o600); err != nil {
		t.Fatal(err)
	}
	finalizeCodexProjectRecoveryJournal = previousFinalize
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "post-removal") {
		t.Fatalf("recovery accepted a post-revocation config edit: code=%d stderr=%s", code, stderr.String())
	}
	if got, err := os.ReadFile(summary.ClientConfigPath); err != nil || string(got) != userChange {
		t.Fatalf("recovery overwrote user config after binding deletion: got=%q err=%v", got, err)
	}
	if _, err := os.Stat(setupRecoveryJournalPath(dataDir)); err != nil {
		t.Fatalf("recovery discarded journal after a concurrent edit: %v", err)
	}
}

func TestBindingAbsentRemovalJournalWithoutSignedRevocationCannotMutateConfig(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	stubSetupSideEffects(t)
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit=%d stderr=%s", code, stderr.String())
	}
	clientBefore, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hookBefore, err := os.ReadFile(summary.HookConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := prepareCodexProjectRecoveryRemove(opts, summary)
	if err != nil || preparation.journal == nil {
		t.Fatalf("prepare removal journal err=%v preparation=%#v", err, preparation)
	}
	if err := os.Remove(setupCodexProjectBindingPath(dataDir)); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("binding-absent journal without signed revocation recovered: code=%d stderr=%s", code, stderr.String())
	}
	if got, err := os.ReadFile(summary.ClientConfigPath); err != nil || !bytes.Equal(got, clientBefore) {
		t.Fatalf("unsigned binding-absent journal changed MCP config: got=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(summary.HookConfigPath); err != nil || !bytes.Equal(got, hookBefore) {
		t.Fatalf("unsigned binding-absent journal changed hook config: got=%q err=%v", got, err)
	}
	if _, err := os.Stat(setupRecoveryJournalPath(dataDir)); err != nil {
		t.Fatalf("unsigned binding-absent journal was discarded: %v", err)
	}
}

func TestCodexProjectsShareAuthorityStateWithoutSharingBindingsRecoveryOrArtifacts(t *testing.T) {
	root := t.TempDir()
	projectA := filepath.Join(root, "project-a")
	projectB := filepath.Join(root, "project-b")
	for _, project := range []string{projectA, projectB} {
		if err := os.MkdirAll(project, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	enterProject := func(project string) {
		t.Helper()
		if err := os.Chdir(project); err != nil {
			t.Fatal(err)
		}
	}
	stubSetupSideEffects(t)
	dataDir := filepath.Join(root, "shared-kernel-state")
	setup := func(project string) setupCodexProjectPaths {
		t.Helper()
		enterProject(project)
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
			t.Fatalf("setup %s exit=%d stderr=%s stdout=%s", project, code, stderr.String(), stdout.String())
		}
		paths, err := newSetupCodexProjectPaths(setupOptions{Target: "codex", Scope: "project", DataDir: dataDir})
		if err != nil {
			t.Fatal(err)
		}
		return paths
	}
	pathsA := setup(projectA)
	pathsB := setup(projectB)
	if pathsA.StateRoot == pathsB.StateRoot || pathsA.BindingPath == pathsB.BindingPath || pathsA.RecoveryRoot == pathsB.RecoveryRoot || pathsA.ArtifactsDir == pathsB.ArtifactsDir {
		t.Fatalf("project state namespaces collided: A=%#v B=%#v", pathsA, pathsB)
	}
	for _, path := range []string{pathsA.BindingPath, filepath.Join(pathsA.ArtifactsDir, "policy.draft.json"), pathsB.BindingPath, filepath.Join(pathsB.ArtifactsDir, "policy.draft.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing project-scoped native state %s: %v", path, err)
		}
	}

	enterProject(projectA)
	if _, configured, err := admitCodexProjectRuntime(dataDir); err != nil || !configured {
		t.Fatalf("project A lost runtime admission after project B setup: configured=%v err=%v", configured, err)
	}
	if err := prepareSetupRecoveryDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("project A prepared recovery was not project-local pending state: pending=%v err=%v", pending, err)
	}

	enterProject(projectB)
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("project A recovery incorrectly blocked project B: pending=%v err=%v", pending, err)
	}
	if _, configured, err := admitCodexProjectRuntime(dataDir); err != nil || !configured {
		t.Fatalf("project B runtime admission failed while A recovery was pending: configured=%v err=%v", configured, err)
	}

	enterProject(projectA)
	if err := cleanupIncompleteSetupRecoveryDirectory(dataDir); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("remove project A exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(pathsA.BindingPath); !os.IsNotExist(err) {
		t.Fatalf("removing project A retained its binding: %v", err)
	}

	enterProject(projectB)
	if _, err := os.Stat(pathsB.BindingPath); err != nil {
		t.Fatalf("removing project A altered project B binding: %v", err)
	}
	if _, configured, err := admitCodexProjectRuntime(dataDir); err != nil || !configured {
		t.Fatalf("project B lost runtime admission after A removal: configured=%v err=%v", configured, err)
	}
}

func TestLegacyUnscopedRecoveryStateBlocksNamespacedCodexEntrypoints(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	if err := os.MkdirAll(filepath.Join(legacyRoot, setupRecoveryStagingDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyRoot, setupRecoveryJournalFile), []byte(`{"schema_version":"helm.codex-project-recovery/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--data-dir", dataDir}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "legacy unscoped") {
		t.Fatalf("status ignored legacy recovery state: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "legacy unscoped") {
		t.Fatalf("setup ignored legacy recovery state: code=%d stderr=%s", code, stderr.String())
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "legacy unscoped") {
		t.Fatalf("MCP ignored legacy recovery state: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "recovery") {
		t.Fatalf("hook ignored legacy recovery state: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "root.key")); !os.IsNotExist(err) {
		t.Fatalf("legacy-blocked entrypoint created new lifecycle authority: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacyRoot, setupRecoveryJournalFile)); err != nil {
		t.Fatalf("legacy-blocked entrypoint altered recovery journal: %v", err)
	}
}

func TestForgedCommittedMarkerKeepsLiveJournalPending(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	journal := writeSetupSecurityPendingJournal(t, dataDir, "install", nil)
	if err := writeSetupRecoveryMarker(dataDir, setupRecoveryCommittedFile, setupRecoveryMarker{
		SchemaVersion:      setupRecoveryMarkerSchema,
		State:              setupRecoveryMarkerStateCommitted,
		TransactionID:      journal.TransactionID,
		LifecycleReceiptID: journal.LifecycleReceiptID,
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := setupRecoveryRequired(dataDir)
	if err != nil || !pending {
		t.Fatalf("forged committed marker unblocked recovery: pending=%v err=%v", pending, err)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("forged committed marker unblocked MCP: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "recovery") {
		t.Fatalf("forged committed marker unblocked hook: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(setupRecoveryJournalPath(dataDir)); err != nil {
		t.Fatalf("forged marker discarded live journal: %v", err)
	}
}

func TestStagedCodexBindingCannotBeReplayedBeforeConfigMutation(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := prepareCodexProjectRecoveryInstall(opts, summary)
	if err != nil {
		t.Fatal(err)
	}
	bindingPath, err := setupRecoverySafeStagePath(dataDir, setupCodexProjectBindingFile)
	if err != nil {
		t.Fatal(err)
	}
	state, err := readSetupFileState(bindingPath)
	if err != nil {
		t.Fatal(err)
	}
	var binding setupCodexProjectBinding
	if err := decodeCanonicalSetupJSON(state.Data, &binding); err != nil {
		t.Fatal(err)
	}
	binding.InstallReceiptID, err = newSetupLifecycleReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := canonicalize.JCS(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSetupPrivateFile(bindingPath, tampered); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resumeCodexProjectRecovery(opts, preparation.summary, preparation.journal); err == nil || !strings.Contains(err.Error(), "staged") {
		t.Fatalf("replayed staged binding was accepted: %v", err)
	}
	for _, path := range []string{summary.ClientConfigPath, summary.HookConfigPath, setupCodexProjectBindingPath(dataDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid staged binding changed durable config %s: %v", path, err)
		}
	}
}

func TestLifecycleReceiptReadBackRejectsAfterInsertMutation(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	previousPrepared := setupLifecycleStorePrepared
	setupLifecycleStorePrepared = func(db *sql.DB) error {
		_, err := db.Exec(`CREATE TRIGGER helm_setup_tamper AFTER INSERT ON receipts BEGIN UPDATE receipts SET signature = '00' WHERE receipt_id = NEW.receipt_id; END;`)
		return err
	}
	t.Cleanup(func() { setupLifecycleStorePrepared = previousPrepared })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || (!strings.Contains(stderr.String(), "failed verification") && !strings.Contains(stderr.String(), "receipt envelope does not match")) {
		t.Fatalf("tampered appended receipt was accepted: code=%d stderr=%s", code, stderr.String())
	}
	pending, err := setupRecoveryRequired(dataDir)
	if err != nil || !pending {
		t.Fatalf("tampered receipt did not retain recovery: pending=%v err=%v", pending, err)
	}
	if _, err := os.Stat(setupCodexProjectBindingPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("tampered receipt published install binding: %v", err)
	}
}

func TestRemovalProvenanceFailureDoesNotMutateReceiptStore(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit=%d stderr=%s", code, stderr.String())
	}
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	clientBefore, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	clientTampered := append(append([]byte(nil), clientBefore...), []byte("# user-owned change\n")...)
	if err := writeSetupPrivateFile(summary.ClientConfigPath, clientTampered); err != nil {
		t.Fatal(err)
	}
	dbBefore, err := os.ReadFile(filepath.Join(dataDir, "helm.db"))
	if err != nil {
		t.Fatal(err)
	}
	walPath := filepath.Join(dataDir, "helm.db-wal")
	walBefore, walBeforeErr := os.ReadFile(walPath)

	stdout.Reset()
	stderr.Reset()
	code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "differs from its proven install binding") {
		t.Fatalf("tampered config removal did not fail provenance: code=%d stderr=%s", code, stderr.String())
	}
	dbAfter, err := os.ReadFile(filepath.Join(dataDir, "helm.db"))
	if err != nil || !bytes.Equal(dbAfter, dbBefore) {
		t.Fatalf("failed provenance check changed lifecycle DB: equal=%v err=%v", bytes.Equal(dbAfter, dbBefore), err)
	}
	walAfter, walAfterErr := os.ReadFile(walPath)
	if (walBeforeErr == nil) != (walAfterErr == nil) || walBeforeErr == nil && !bytes.Equal(walAfter, walBefore) {
		t.Fatalf("failed provenance check changed lifecycle WAL: beforeErr=%v afterErr=%v", walBeforeErr, walAfterErr)
	}
	clientAfter, err := os.ReadFile(summary.ClientConfigPath)
	if err != nil || !bytes.Equal(clientAfter, clientTampered) {
		t.Fatalf("failed provenance check changed user config: %q err=%v", clientAfter, err)
	}
}

func TestLifecycleEvidenceRejectsSymlinkAndDuplicateJSON(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("initial setup exit=%d stderr=%s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	receipt, err := readSetupLifecycleReceiptReadOnly(context.Background(), dataDir, summary.LifecycleReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Type != "native_client_setup_lifecycle" || receipt.Action != "install" || receipt.Verdict != "DENY" || receipt.ToolName != "file_write" || receipt.ReasonCode != "ERR_SYNTHETIC_FILE_WRITE_DENIED" || receipt.SignatureProfile == "" || receipt.SignatureAlgorithm == "" || receipt.KeyID == "" {
		t.Fatalf("read-only lifecycle proof lost canonical receipt fields: %#v", receipt)
	}
	original, err := os.ReadFile(summary.LifecycleEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(dir, "external-evidence.json")
	if err := os.WriteFile(external, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(summary.LifecycleEvidencePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, summary.LifecycleEvidencePath); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySetupLifecycleEvidence(dataDir, receipt); err == nil {
		t.Fatal("symlinked lifecycle evidence unexpectedly verified")
	}
	if err := os.Remove(summary.LifecycleEvidencePath); err != nil {
		t.Fatal(err)
	}
	needle := `"receipt_id":"` + summary.LifecycleReceiptID + `"`
	duplicate := strings.Replace(string(original), needle, `"receipt_id":"tampered","receipt_id":"`+summary.LifecycleReceiptID+`"`, 1)
	if duplicate == string(original) {
		t.Fatal("fixture did not locate receipt_id in canonical evidence")
	}
	if err := writeSetupPrivateFile(summary.LifecycleEvidencePath, []byte(duplicate)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySetupLifecycleEvidence(dataDir, receipt); err == nil {
		t.Fatal("duplicate-key lifecycle evidence unexpectedly verified")
	}
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`UPDATE receipts SET receipt_envelope = '' WHERE receipt_id = ?`, summary.LifecycleReceiptID); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetupLifecycleReceiptReadOnly(context.Background(), dataDir, summary.LifecycleReceiptID); err == nil || !strings.Contains(err.Error(), "predates canonical durable receipt envelopes") {
		t.Fatalf("legacy receipt projection was accepted as native lifecycle authority: %v", err)
	}
}

func TestLifecycleSignerRejectsMalformedAndSymlinkedRootKey(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dataDir, "root.key")
	if err := writeSetupPrivateFile(rootPath, []byte("00")); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("malformed root.key panicked: %v", recovered)
			}
		}()
		if _, err := loadOrGenerateSignerWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "seed size") {
			t.Fatalf("malformed root.key error=%v", err)
		}
	}()
	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(dir, "external-root.key")
	if err := os.WriteFile(external, []byte("00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, rootPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked root.key error=%v", err)
	}
}

func TestLifecycleSignerRejectsInsecureExistingPrivateKeyModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX 0600 boundary")
	}
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dataDir, "root.key")
	if err := os.Chmod(rootPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExistingEd25519Root(dataDir); err == nil || !strings.Contains(err.Error(), "exact mode 0600") {
		t.Fatalf("insecure root.key mode accepted: %v", err)
	}
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "exact mode 0600") {
		t.Fatalf("load-or-generate accepted insecure root.key mode: %v", err)
	}
	if err := os.Chmod(rootPath, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_RECEIPT_PROFILE", "hybrid")
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err != nil {
		t.Fatal(err)
	}
	mlDSAPath := filepath.Join(dataDir, "root.mldsa65.key")
	if err := os.Chmod(mlDSAPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExistingMLDSARoot(dataDir); err == nil || !strings.Contains(err.Error(), "exact mode 0600") {
		t.Fatalf("insecure ML-DSA root mode accepted: %v", err)
	}
}

func TestLifecycleSignerRejectsInvalidProfileBeforeAuthorityStateCreation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "fresh-authority")
	t.Setenv("HELM_RECEIPT_PROFILE", "invalid-profile")
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "unknown HELM_RECEIPT_PROFILE") {
		t.Fatalf("invalid receipt profile was accepted: %v", err)
	}
	for _, path := range []string{
		dataDir,
		filepath.Join(dataDir, "root.key"),
		filepath.Join(dataDir, "root.mldsa65.key"),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("invalid receipt profile created authority state %s: %v", path, err)
		}
	}
}

func TestCodexProjectSetupRejectsWorldWritableAuthorityDataDirBeforeConfigMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "shared-authority")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unsafe Codex project authority state") || !strings.Contains(stderr.String(), "group/world-writable") {
		t.Fatalf("unsafe authority setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, path := range []string{
		filepath.Join(dir, ".codex", "config.toml"),
		filepath.Join(dir, ".codex", "hooks.json"),
		filepath.Join(dataDir, "root.key"),
		setupRecoveryRoot(dataDir),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("unsafe authority setup mutated %s: %v", path, err)
		}
	}
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("signer accepted world-writable authority data dir: %v", err)
	}
}

func TestAuthoritySubdirectoryRejectsExistingWorldWritableStateComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dataDir := filepath.Join(t.TempDir(), "authority")
	if _, err := ensureSetupAuthorityDataDir(dataDir); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(dataDir, "native-client")
	if err := os.MkdirAll(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unsafe, 0o700) })
	if err := ensureSetupAuthoritySubdirectory(dataDir, filepath.Join("native-client", "codex-projects")); err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("unsafe authority subdirectory accepted: %v", err)
	}
}

func TestCodexProjectSetupRejectsUnsafeProjectStateAncestorBeforeConfigMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "shared-authority")
	if _, err := ensureSetupAuthorityDataDir(dataDir); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(dataDir, "native-client")
	if err := os.MkdirAll(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unsafe, 0o700) })
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "inspect Codex project recovery state") || !strings.Contains(stderr.String(), "group/world-writable") {
		t.Fatalf("unsafe project state ancestor setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, path := range []string{
		filepath.Join(dir, ".codex", "config.toml"),
		filepath.Join(dir, ".codex", "hooks.json"),
		filepath.Join(dataDir, "root.key"),
		setupRecoveryRoot(dataDir),
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("unsafe project state ancestor setup mutated %s: %v", path, err)
		}
	}
}

func TestConfiguredCodexRuntimeRejectsUnsafeProjectStateAuthority(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dataDir, _ := setupProvenNativeCodexProjectForRuntime(t)
	unsafe := filepath.Join(dataDir, "native-client")
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unsafe, 0o700) })

	if _, _, err := newLocalMCPRuntimeWithDataDir(dataDir); err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("configured runtime admitted unsafe project authority: %v", err)
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("stdio runtime admitted unsafe project authority: %v", err)
	}
}

func moveCurrentCodexProjectBindingToLegacyForTest(t *testing.T, dataDir string) setupCodexProjectPaths {
	t.Helper()
	paths := currentCodexProjectPaths(dataDir)
	bindingData, err := os.ReadFile(paths.BindingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSetupPrivateFile(legacyCodexProjectBindingPath(dataDir), bindingData); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.BindingPath); err != nil {
		t.Fatal(err)
	}
	if err := ensureSetupAuthoritySubdirectory(dataDir, "autoconfigure"); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"inventory.json", "policy.draft.json", "mcp_quarantine_plan.json"} {
		source := filepath.Join(paths.ArtifactsDir, filename)
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeSetupPrivateFile(filepath.Join(legacyCodexProjectArtifactsDir(dataDir), filename), data); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(paths.ArtifactsDir); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Remove(paths.StateRoot); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return paths
}

func TestSetupMigrateCodexProjectBindingMovesOnlyValidatedLegacyState(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	if _, err := os.Stat(legacyBinding); err != nil {
		t.Fatalf("legacy fixture binding is missing: %v", err)
	}
	if _, err := os.Stat(paths.BindingPath); !os.IsNotExist(err) {
		t.Fatalf("current binding survived fixture migration: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("migration dry-run exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyBinding); err != nil {
		t.Fatalf("migration dry-run changed legacy binding: %v", err)
	}
	if _, err := os.Stat(paths.BindingPath); !os.IsNotExist(err) {
		t.Fatalf("migration dry-run created current binding: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyBinding); !os.IsNotExist(err) {
		t.Fatalf("migration retained legacy binding: %v", err)
	}
	if _, err := os.Stat(paths.BindingPath); err != nil {
		t.Fatalf("migration did not publish current binding: %v", err)
	}
	for _, filename := range []string{"inventory.json", "policy.draft.json", "mcp_quarantine_plan.json"} {
		if _, err := os.Stat(filepath.Join(paths.ArtifactsDir, filename)); err != nil {
			t.Fatalf("migration did not publish %s: %v", filename, err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "remove", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("removal after binding migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestSetupMigrateCodexProjectBindingRefusesWrongWorkspaceWithoutMutation(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	binding, err := readSetupCodexProjectBindingAtPath(legacyBinding)
	if err != nil || binding == nil {
		t.Fatalf("read legacy fixture binding: binding=%#v err=%v", binding, err)
	}
	binding.WorkspacePathHash = strings.Repeat("0", 64)
	data, err := marshalSetupCodexProjectBinding(*binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSetupPrivateFile(legacyBinding, data); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "different workspace") {
		t.Fatalf("wrong-workspace migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyBinding); err != nil {
		t.Fatalf("wrong-workspace migration removed legacy binding: %v", err)
	}
	if _, err := os.Stat(paths.BindingPath); !os.IsNotExist(err) {
		t.Fatalf("wrong-workspace migration wrote current binding: %v", err)
	}
}

func TestSetupMigrateCodexProjectRecoveryMovesValidatedJournalThenRecovers(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := prepareCodexProjectRecoveryInstall(opts, summary)
	if err != nil || preparation == nil || preparation.journal == nil {
		t.Fatalf("prepare current recovery fixture: preparation=%#v err=%v", preparation, err)
	}
	paths := currentCodexProjectPaths(dataDir)
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
		t.Fatal(err)
	}
	if err := syncSetupParentDirectory(legacyRoot); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("recovery migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyRoot); !os.IsNotExist(err) {
		t.Fatalf("recovery migration retained legacy root: %v", err)
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || !pending {
		t.Fatalf("migrated recovery was not pending: pending=%v err=%v", pending, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("recovery after migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("migrated recovery remained pending: pending=%v err=%v", pending, err)
	}
}

func TestSetupMigrateCodexProjectBindingRejectsUnsafeLegacyArtifactsBeforeDryRunOrApply(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	legacyArtifacts := legacyCodexProjectArtifactsDir(dataDir)
	beforeBinding, err := os.ReadFile(legacyBinding)
	if err != nil {
		t.Fatal(err)
	}
	beforeArtifact, err := os.ReadFile(filepath.Join(legacyArtifacts, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(legacyArtifacts, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(legacyArtifacts, 0o700) })

	for _, args := range [][]string{
		{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--dry-run", "--data-dir", dataDir},
		{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "autoconfigure authority") {
			t.Fatalf("unsafe artifact migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
		}
		if got, err := os.ReadFile(legacyBinding); err != nil || !bytes.Equal(got, beforeBinding) {
			t.Fatalf("unsafe artifact migration changed legacy binding: equal=%v err=%v", bytes.Equal(got, beforeBinding), err)
		}
		if got, err := os.ReadFile(filepath.Join(legacyArtifacts, "inventory.json")); err != nil || !bytes.Equal(got, beforeArtifact) {
			t.Fatalf("unsafe artifact migration changed legacy artifact: equal=%v err=%v", bytes.Equal(got, beforeArtifact), err)
		}
		if _, err := os.Stat(paths.BindingPath); !os.IsNotExist(err) {
			t.Fatalf("unsafe artifact migration created current binding: %v", err)
		}
	}
}

func TestSetupMigrateCodexProjectBindingRollsBackSecondArtifactStageFailure(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	legacyArtifacts := legacyCodexProjectArtifactsDir(dataDir)
	beforeBinding, err := os.ReadFile(legacyBinding)
	if err != nil {
		t.Fatal(err)
	}
	beforeArtifacts := make(map[string][]byte)
	for _, filename := range []string{"inventory.json", "policy.draft.json", "mcp_quarantine_plan.json"} {
		data, err := os.ReadFile(filepath.Join(legacyArtifacts, filename))
		if err != nil {
			t.Fatal(err)
		}
		beforeArtifacts[filename] = data
	}
	previousWrite := writeLegacyCodexProjectMigrationFile
	writeLegacyCodexProjectMigrationFile = func(path string, data []byte) error {
		if filepath.Base(path) == "policy.draft.json" && strings.Contains(path, setupLegacyMigrationTemporaryPrefix) {
			return errors.New("injected second artifact stage failure")
		}
		return previousWrite(path, data)
	}
	t.Cleanup(func() { writeLegacyCodexProjectMigrationFile = previousWrite })

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "injected second artifact") {
		t.Fatalf("injected migration failure exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if got, err := os.ReadFile(legacyBinding); err != nil || !bytes.Equal(got, beforeBinding) {
		t.Fatalf("second artifact failure changed legacy binding: equal=%v err=%v", bytes.Equal(got, beforeBinding), err)
	}
	for filename, before := range beforeArtifacts {
		if got, err := os.ReadFile(filepath.Join(legacyArtifacts, filename)); err != nil || !bytes.Equal(got, before) {
			t.Fatalf("second artifact failure changed %s: equal=%v err=%v", filename, bytes.Equal(got, before), err)
		}
	}
	if _, err := os.Stat(paths.StateRoot); !os.IsNotExist(err) {
		t.Fatalf("second artifact failure retained current project state: %v", err)
	}
}

func TestSetupMigrateCodexProjectBindingRejectsDestinationArtifactConflictWithoutMutation(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	legacyArtifact := filepath.Join(legacyCodexProjectArtifactsDir(dataDir), "inventory.json")
	legacyBindingData, err := os.ReadFile(legacyBinding)
	if err != nil {
		t.Fatal(err)
	}
	legacyArtifactData, err := os.ReadFile(legacyArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCodexProjectStateAuthority(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := writeSetupPrivateFile(paths.BindingPath, legacyBindingData); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.ArtifactsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSetupPrivateFile(filepath.Join(paths.ArtifactsDir, "inventory.json"), []byte("different-current-artifact")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--dry-run", "--data-dir", dataDir},
		{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "differs from the validated legacy artifact") {
			t.Fatalf("artifact-conflict migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
		}
		if got, err := os.ReadFile(legacyBinding); err != nil || !bytes.Equal(got, legacyBindingData) {
			t.Fatalf("artifact-conflict migration changed legacy binding: equal=%v err=%v", bytes.Equal(got, legacyBindingData), err)
		}
		if got, err := os.ReadFile(legacyArtifact); err != nil || !bytes.Equal(got, legacyArtifactData) {
			t.Fatalf("artifact-conflict migration changed legacy artifact: equal=%v err=%v", bytes.Equal(got, legacyArtifactData), err)
		}
		if got, err := os.ReadFile(filepath.Join(paths.ArtifactsDir, "inventory.json")); err != nil || string(got) != "different-current-artifact" {
			t.Fatalf("artifact-conflict migration changed current artifact: got=%q err=%v", got, err)
		}
	}
}

func TestSetupMigrateCodexProjectRecoveryRejectsUnsafeDestinationAndMalformedSourceDuringDryRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	t.Run("unsafe destination ancestor", func(t *testing.T) {
		dir := chdirTempDir(t)
		dataDir := filepath.Join(dir, "kernel-state")
		opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
		summary, err := buildSetupSummary(opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err != nil {
			t.Fatal(err)
		}
		paths := currentCodexProjectPaths(dataDir)
		legacyRoot := legacySetupRecoveryRoot(dataDir)
		if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
			t.Fatal(err)
		}
		unsafe := filepath.Join(dataDir, "native-client", "codex-projects")
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unsafe, 0o700) })
		for _, args := range [][]string{
			{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--dry-run", "--data-dir", dataDir},
			{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir},
		} {
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "group/world-writable") {
				t.Fatalf("unsafe destination migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			if _, err := os.Stat(legacyRoot); err != nil {
				t.Fatalf("unsafe destination migration moved legacy recovery: %v", err)
			}
			if _, err := os.Stat(paths.RecoveryRoot); !os.IsNotExist(err) {
				t.Fatalf("unsafe destination migration created current recovery: %v", err)
			}
		}
	})
	t.Run("malformed source staging", func(t *testing.T) {
		dir := chdirTempDir(t)
		dataDir := filepath.Join(dir, "kernel-state")
		opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
		summary, err := buildSetupSummary(opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err != nil {
			t.Fatal(err)
		}
		paths := currentCodexProjectPaths(dataDir)
		legacyRoot := legacySetupRecoveryRoot(dataDir)
		if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacyRoot, setupRecoveryStagingDir, "unexpected"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--dry-run", "--data-dir", dataDir},
			{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir},
		} {
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "unexpected setup recovery staged entry") {
				t.Fatalf("malformed source migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			if _, err := os.Stat(legacyRoot); err != nil {
				t.Fatalf("malformed source migration moved legacy recovery: %v", err)
			}
			if _, err := os.Stat(paths.RecoveryRoot); !os.IsNotExist(err) {
				t.Fatalf("malformed source migration created current recovery: %v", err)
			}
		}
	})
}

func TestSetupMigrateCodexProjectRecoverySyncFailureRestoresLegacySource(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err != nil {
		t.Fatal(err)
	}
	paths := currentCodexProjectPaths(dataDir)
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
		t.Fatal(err)
	}
	previousSync := syncLegacyCodexProjectMigrationParent
	syncLegacyCodexProjectMigrationParent = func(path string) error {
		if path == paths.RecoveryRoot {
			return errors.New("injected migrated recovery sync failure")
		}
		return previousSync(path)
	}
	t.Cleanup(func() { syncLegacyCodexProjectMigrationParent = previousSync })
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "injected migrated recovery sync failure") {
		t.Fatalf("sync-failure migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyRoot); err != nil {
		t.Fatalf("sync-failure migration did not restore legacy recovery: %v", err)
	}
	if _, err := os.Stat(paths.RecoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("sync-failure migration retained current recovery: %v", err)
	}
}

func TestSetupMigrateCodexProjectRecoveryReportsRollbackFailure(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err != nil {
		t.Fatal(err)
	}
	paths := currentCodexProjectPaths(dataDir)
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
		t.Fatal(err)
	}
	previousSync := syncLegacyCodexProjectMigrationParent
	previousRename := renameLegacyCodexProjectMigration
	syncLegacyCodexProjectMigrationParent = func(path string) error {
		if path == paths.RecoveryRoot {
			return errors.New("injected migrated recovery sync failure")
		}
		return previousSync(path)
	}
	renameLegacyCodexProjectMigration = func(oldPath, newPath string) error {
		if oldPath == paths.RecoveryRoot && newPath == legacyRoot {
			return errors.New("injected recovery rollback rename failure")
		}
		return previousRename(oldPath, newPath)
	}
	t.Cleanup(func() {
		syncLegacyCodexProjectMigrationParent = previousSync
		renameLegacyCodexProjectMigration = previousRename
	})
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "rollback migrated recovery state") || !strings.Contains(stderr.String(), "injected recovery rollback rename failure") {
		t.Fatalf("rollback-failure migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyRoot); !os.IsNotExist(err) {
		t.Fatalf("rollback-failure migration unexpectedly restored legacy recovery: %v", err)
	}
	if _, err := os.Stat(paths.RecoveryRoot); err != nil {
		t.Fatalf("rollback-failure migration hid current recovery state: %v", err)
	}
}

func TestSetupMigrateCodexProjectRecoveryRejectsJournalPresenceChangeUnderLock(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCodexProjectRecoveryInstall(opts, summary); err != nil {
		t.Fatal(err)
	}
	paths := currentCodexProjectPaths(dataDir)
	legacyRoot := legacySetupRecoveryRoot(dataDir)
	if err := os.Rename(paths.RecoveryRoot, legacyRoot); err != nil {
		t.Fatal(err)
	}
	previousAfterPreflight := afterLegacyRecoveryMigrationPreflight
	afterLegacyRecoveryMigrationPreflight = func() {
		if err := os.Remove(filepath.Join(legacyRoot, setupRecoveryJournalFile)); err != nil {
			t.Fatalf("remove legacy journal during interleaving test: %v", err)
		}
	}
	t.Cleanup(func() { afterLegacyRecoveryMigrationPreflight = previousAfterPreflight })
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "journal presence changed") {
		t.Fatalf("journal-presence migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(legacyRoot); err != nil {
		t.Fatalf("journal-presence migration moved legacy recovery: %v", err)
	}
	if _, err := os.Stat(paths.RecoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("journal-presence migration created current recovery: %v", err)
	}
}

func TestSetupMigrateCodexProjectBindingRevalidatesLegacyAuthorityBeforePublish(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file mode semantics do not provide the POSIX directory boundary")
	}
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyArtifacts := legacyCodexProjectArtifactsDir(dataDir)
	previousAfterPreflight := afterLegacyBindingMigrationPreflight
	afterLegacyBindingMigrationPreflight = func() {
		if err := os.Chmod(legacyArtifacts, 0o777); err != nil {
			t.Fatalf("make legacy authority unsafe during interleaving test: %v", err)
		}
	}
	t.Cleanup(func() {
		afterLegacyBindingMigrationPreflight = previousAfterPreflight
		_ = os.Chmod(legacyArtifacts, 0o700)
	})
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "revalidate legacy autoconfigure authority") {
		t.Fatalf("legacy-authority interleaving migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(paths.BindingPath); !os.IsNotExist(err) {
		t.Fatalf("legacy-authority interleaving migration published target binding: %v", err)
	}
	if _, err := os.Stat(legacyCodexProjectBindingPath(dataDir)); err != nil {
		t.Fatalf("legacy-authority interleaving migration moved source binding: %v", err)
	}
}

func TestSetupMigrateCodexProjectBindingKeepsPublishedStateWhenRetiredSourceCleanupFails(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	previousRemoveTree := removeLegacyCodexProjectMigrationTree
	removeLegacyCodexProjectMigrationTree = func(path string) error {
		if strings.HasPrefix(filepath.Base(path), setupLegacyMigrationTemporaryPrefix) && filepath.Dir(path) == dataDir {
			return errors.New("injected retired-source cleanup failure")
		}
		return previousRemoveTree(path)
	}
	t.Cleanup(func() { removeLegacyCodexProjectMigrationTree = previousRemoveTree })
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 || !strings.Contains(stderr.String(), "migration completed") || !strings.Contains(stderr.String(), "retired-source cleanup remains") {
		t.Fatalf("cleanup-failure migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(paths.BindingPath); err != nil {
		t.Fatalf("cleanup-failure migration rolled back published target binding: %v", err)
	}
	if _, err := os.Stat(legacyCodexProjectBindingPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("cleanup-failure migration retained active legacy binding: %v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	foundRetiredSource := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), setupLegacyMigrationTemporaryPrefix) {
			foundRetiredSource = true
			break
		}
	}
	if !foundRetiredSource {
		t.Fatal("cleanup-failure migration lost retired source instead of retaining it safely")
	}
}

func TestSetupMigrateCodexProjectBindingKeepsPublishedStateWhenSourceRollbackFails(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "kernel-state")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	paths := moveCurrentCodexProjectBindingToLegacyForTest(t, dataDir)
	legacyBinding := legacyCodexProjectBindingPath(dataDir)
	legacyInventory := filepath.Join(legacyCodexProjectArtifactsDir(dataDir), "inventory.json")
	beforeBinding, err := os.ReadFile(legacyBinding)
	if err != nil {
		t.Fatal(err)
	}
	previousRename := renameLegacyCodexProjectMigration
	renameLegacyCodexProjectMigration = func(oldPath, newPath string) error {
		if oldPath == legacyInventory && strings.HasPrefix(filepath.Base(filepath.Dir(newPath)), setupLegacyMigrationTemporaryPrefix) {
			return errors.New("injected second source move failure")
		}
		if newPath == legacyBinding && strings.HasPrefix(filepath.Base(filepath.Dir(oldPath)), setupLegacyMigrationTemporaryPrefix) {
			return errors.New("injected source rollback rename failure")
		}
		return previousRename(oldPath, newPath)
	}
	t.Cleanup(func() { renameLegacyCodexProjectMigration = previousRename })

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "setup", "migrate", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 0 || !strings.Contains(stderr.String(), "could not be completed or fully rolled back") || !strings.Contains(stderr.String(), "injected source rollback rename failure") {
		t.Fatalf("rollback-failure migration exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if got, err := os.ReadFile(paths.BindingPath); err != nil || !bytes.Equal(got, beforeBinding) {
		t.Fatalf("rollback-failure migration lost published target binding: equal=%v err=%v", bytes.Equal(got, beforeBinding), err)
	}
	if _, err := os.Stat(legacyBinding); !os.IsNotExist(err) {
		t.Fatalf("rollback-failure migration restored an ambiguous active legacy binding: %v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	foundSealedBackup := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), setupLegacyMigrationTemporaryPrefix) {
			continue
		}
		backup := filepath.Join(dataDir, entry.Name(), "00-"+setupCodexProjectBindingFile)
		if got, err := os.ReadFile(backup); err == nil && bytes.Equal(got, beforeBinding) {
			foundSealedBackup = true
			break
		}
	}
	if !foundSealedBackup {
		t.Fatal("rollback-failure migration did not retain the sealed source backup")
	}
}

func TestSetupCodexProjectLifecycleLockRejectsConcurrentMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("safe cross-process lifecycle lock intentionally fails closed on Windows")
	}
	dataDir := filepath.Join(t.TempDir(), "kernel-state")
	first, err := acquireSetupCodexProjectLifecycleLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := acquireSetupCodexProjectLifecycleLock(dataDir)
	if second != nil {
		_ = second.Close()
		t.Fatal("second lifecycle lock unexpectedly succeeded")
	}
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("second lifecycle lock error=%v", err)
	}
}

func TestConcurrentFirstUseChoosesOneDurableLifecycleRoot(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "shared-kernel-state")
	const workers = 16
	start := make(chan struct{})
	results := make(chan []byte, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			signer, err := loadOrGenerateSignerWithDataDir(dataDir)
			if err != nil {
				errors <- err
				return
			}
			results <- append([]byte(nil), signer.PublicKeyBytes()...)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent first-use signer initialization failed: %v", err)
	}
	var winner []byte
	for publicKey := range results {
		if winner == nil {
			winner = publicKey
			continue
		}
		if !bytes.Equal(winner, publicKey) {
			t.Fatalf("concurrent first-use signers disagreed: %x != %x", winner, publicKey)
		}
	}
	if winner == nil {
		t.Fatal("no concurrent signer was initialized")
	}
	if _, err := loadExistingEd25519Root(dataDir); err != nil {
		t.Fatalf("concurrent first-use root is not reloadable: %v", err)
	}
}

func TestConcurrentLiteModeInitializationSharesAuthorityDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "shared-kernel-state")
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
			if err == nil {
				err = db.Close()
			}
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent shared data-dir initialization failed: %v", err)
		}
	}
}

func TestRuntimeEntrypointsRejectSymlinkedDataDir(t *testing.T) {
	dir := chdirTempDir(t)
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "data-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", link}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr); code != 2 {
		t.Fatalf("hook accepted symlinked data dir: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMCPServe([]string{"--transport", "stdio", "--data-dir", link}, &stdout, &stderr); code != 2 {
		t.Fatalf("mcp serve accepted symlinked data dir: code=%d stderr=%s", code, stderr.String())
	}
	if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("direct stdio accepted symlinked data dir: %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("runtime wrote through data-dir symlink: %#v", entries)
	}
}

type setupRecoveryInjectingReader struct {
	chunks   [][]byte
	index    int
	injected bool
	inject   func() error
}

func (r *setupRecoveryInjectingReader) Read(p []byte) (int, error) {
	if r.index == 1 && !r.injected {
		r.injected = true
		if err := r.inject(); err != nil {
			return 0, err
		}
	}
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	n := copy(p, chunk)
	if n == len(chunk) {
		r.index++
	} else {
		r.chunks[r.index] = chunk[n:]
	}
	return n, nil
}

func TestMCPRechecksRecoveryBeforeEveryToolCall(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	reader := &setupRecoveryInjectingReader{
		chunks: [][]byte{
			[]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n"),
			[]byte("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"file_write\",\"arguments\":{\"path\":\"ignored\",\"content\":\"x\"}}}\n"),
		},
		inject: func() error {
			writeSetupSecurityPendingJournal(t, dataDir, "install", nil)
			return nil
		},
	}
	var stdout bytes.Buffer
	err := serveLocalMCPStdioWithDataDir(reader, &stdout, dataDir)
	if err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("mid-session recovery did not stop MCP: %v", err)
	}
	if !strings.Contains(stdout.String(), `"id":1`) || strings.Contains(stdout.String(), `"id":2`) {
		t.Fatalf("MCP answered after recovery became pending: %s", stdout.String())
	}
}

func TestRecoveryJournalTamperingFailsClosedWithoutCleanup(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*setupRecoveryJournal, string)
	}{
		{
			name: "stage traversal",
			mutate: func(journal *setupRecoveryJournal, _ string) {
				journal.Files[0].StageFile = "../outside"
			},
		},
		{
			name: "receipt traversal",
			mutate: func(journal *setupRecoveryJournal, _ string) {
				journal.LifecycleReceiptID = "../outside"
			},
		},
		{
			name: "duplicate plan",
			mutate: func(journal *setupRecoveryJournal, _ string) {
				journal.Files[1].ID = journal.Files[0].ID
			},
		},
		{
			name:   "noncanonical bytes",
			mutate: func(_ *setupRecoveryJournal, _ string) {},
		},
		{
			name: "unclean binary path",
			mutate: func(journal *setupRecoveryJournal, dir string) {
				journal.BinaryPath = dir + "/bin/../" + filepath.Base(journal.BinaryPath)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := chdirTempDir(t)
			dataDir := filepath.Join(dir, "helm")
			journal := writeSetupSecurityPendingJournal(t, dataDir, "install", nil)
			tampered := *journal
			tampered.Files = append([]setupRecoveryFilePlan(nil), journal.Files...)
			tc.mutate(&tampered, dir)
			var raw []byte
			var err error
			if tc.name == "noncanonical bytes" {
				raw, err = os.ReadFile(setupRecoveryJournalPath(dataDir))
				if err == nil {
					raw = append(raw, '\n')
				}
			} else {
				raw, err = canonicalize.JCS(tampered)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSetupPrivateFile(setupRecoveryJournalPath(dataDir), raw); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(dir, "outside")
			if err := os.WriteFile(sentinel, []byte("do-not-touch"), 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			if code := Run([]string{"helm-ai-kernel", "setup", "status", "codex", "--scope", "project", "--data-dir", dataDir}, &stdout, &stderr); code != 2 {
				t.Fatalf("tampered journal status exit=%d stderr=%s", code, stderr.String())
			}
			stdout.Reset()
			stderr.Reset()
			if code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr); code != 1 {
				t.Fatalf("tampered journal recover exit=%d stderr=%s", code, stderr.String())
			}
			if err := serveLocalMCPStdioWithDataDir(strings.NewReader(""), io.Discard, dataDir); err == nil {
				t.Fatal("tampered journal unexpectedly opened MCP")
			}
			stdout.Reset()
			stderr.Reset()
			if code := runHookPreToolCmd([]string{"--client", "codex", "--data-dir", dataDir}, strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":".env"}}`), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "recovery") {
				t.Fatalf("tampered journal did not deny hook: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			persisted, err := os.ReadFile(setupRecoveryJournalPath(dataDir))
			if err != nil || !bytes.Equal(persisted, raw) {
				t.Fatalf("tampered journal changed during failure handling: equal=%v err=%v", bytes.Equal(persisted, raw), err)
			}
			if got, err := os.ReadFile(sentinel); err != nil || string(got) != "do-not-touch" {
				t.Fatalf("tampered journal touched external sentinel: got=%q err=%v", got, err)
			}
		})
	}
}

func TestRecoveryJournalPinsExecutablePathAndAvailability(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, journal *setupRecoveryJournal, dir string)
		want   string
	}{
		{
			name: "same bytes different path",
			mutate: func(t *testing.T, journal *setupRecoveryJournal, dir string) {
				t.Helper()
				raw, err := os.ReadFile(journal.BinaryPath)
				if err != nil {
					t.Fatal(err)
				}
				copyPath := filepath.Join(dir, "alternate", "helm-ai-kernel")
				if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(copyPath, raw, 0o700); err != nil {
					t.Fatal(err)
				}
				journal.BinaryPath = copyPath
			},
			want: "path does not match",
		},
		{
			name: "symlink alternate path",
			mutate: func(t *testing.T, journal *setupRecoveryJournal, dir string) {
				t.Helper()
				linkPath := filepath.Join(dir, "alternate", "helm-ai-kernel")
				if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(journal.BinaryPath, linkPath); err != nil {
					t.Fatal(err)
				}
				journal.BinaryPath = linkPath
			},
			want: "path does not match",
		},
		{
			name: "deleted binary",
			mutate: func(_ *testing.T, journal *setupRecoveryJournal, dir string) {
				journal.BinaryPath = filepath.Join(dir, "missing", "helm-ai-kernel")
			},
			want: "unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := chdirTempDir(t)
			dataDir := filepath.Join(dir, "helm")
			journal := writeSetupSecurityPendingJournal(t, dataDir, "install", nil)
			tampered := *journal
			tampered.Files = append([]setupRecoveryFilePlan(nil), journal.Files...)
			tc.mutate(t, &tampered, dir)
			raw, err := canonicalize.JCS(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSetupPrivateFile(setupRecoveryJournalPath(dataDir), raw); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("binary-pinned recovery did not fail closed: code=%d stderr=%s", code, stderr.String())
			}
			if _, err := os.Stat(filepath.Join(dataDir, "root.key")); !os.IsNotExist(err) {
				t.Fatalf("failed binary recovery initialized signer state: %v", err)
			}
		})
	}
}

func TestSignedCommittedMarkerSurvivesPostMarkerCrashAndCleans(t *testing.T) {
	dir := chdirTempDir(t)
	dataDir := filepath.Join(dir, "helm")
	previousFinalize := finalizeCodexProjectRecoveryJournal
	finalizeCodexProjectRecoveryJournal = func(dataDir string, journal *setupRecoveryJournal) error {
		marker, err := newSignedSetupRecoveryCommittedMarker(dataDir, journal)
		if err != nil {
			return err
		}
		if err := writeSetupRecoveryMarker(dataDir, setupRecoveryCommittedFile, marker); err != nil {
			return err
		}
		return errors.New("injected post-marker cleanup failure")
	}
	t.Cleanup(func() { finalizeCodexProjectRecoveryJournal = previousFinalize })

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("signed post-marker setup exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || !summary.RecoveryCleanupPending {
		t.Fatalf("signed terminal marker was not surfaced: summary=%#v err=%v", summary, err)
	}
	if pending, err := setupRecoveryRequired(dataDir); err != nil || pending {
		t.Fatalf("verified signed marker remained runtime-blocking: pending=%v err=%v", pending, err)
	}
	if err := os.Remove(setupRecoveryJournalPath(dataDir)); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectSetupRecovery(dataDir)
	if err != nil || inspection.State != setupRecoveryStateCommitted {
		t.Fatalf("signed marker-only crash residue was not terminal: inspection=%#v err=%v", inspection, err)
	}

	finalizeCodexProjectRecoveryJournal = previousFinalize
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "recover", "codex", "--scope", "project", "--yes", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("signed terminal residue cleanup exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(setupRecoveryRoot(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("signed terminal residue remained after cleanup: %v", err)
	}
}
