package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	setupRecoveryFileMCP               = "mcp"
	setupRecoveryFileHook              = "hook"
	setupRecoveryFileInventory         = "artifact.inventory"
	setupRecoveryFilePolicyDraft       = "artifact.policy_draft"
	setupRecoveryFileMCPQuarantinePlan = "artifact.mcp_quarantine_plan"
	setupRecoveryFileBinding           = "binding"
)

type codexProjectRecoveryPreparation struct {
	journal *setupRecoveryJournal
	summary setupSummary
}

var finalizeCodexProjectRecoveryJournal = removeSetupRecoveryJournal

func prepareCodexProjectRecoveryInstall(opts setupOptions, summary setupSummary) (*codexProjectRecoveryPreparation, error) {
	if err := validateSetupLifecycleReceiptProfile(); err != nil {
		return nil, err
	}
	if err := preflightCodexProjectSetup(opts, summary); err != nil {
		return nil, err
	}
	clientBefore, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return nil, err
	}
	hookBefore, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return nil, err
	}
	clientAfter, err := buildUpsertCodexProjectMCPState(clientBefore, summary.BinaryPath, opts.DataDir)
	if err != nil {
		return nil, err
	}
	hookAfter, err := buildUpsertOwnedSetupHookState(hookBefore, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target)
	if err != nil {
		return nil, err
	}
	if err := prepareSetupRecoveryDirectory(opts.DataDir); err != nil {
		return nil, err
	}
	artifactsDir := setupCodexProjectArtifactsDir(opts.DataDir)
	grade, policyPath, err := stageSetupAutoconfigure(opts.DataDir)
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	inventoryBefore, err := readSetupFileState(filepath.Join(artifactsDir, "inventory.json"))
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	policyBefore, err := readSetupFileState(filepath.Join(artifactsDir, "policy.draft.json"))
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	quarantineBefore, err := readSetupFileState(filepath.Join(artifactsDir, "mcp_quarantine_plan.json"))
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	bindingBefore, err := readSetupFileState(setupCodexProjectBindingPath(opts.DataDir))
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	inventoryAfter, err := readSetupFileState(setupRecoveryStagePath(opts.DataDir, "inventory.json"))
	if err != nil || !inventoryAfter.Exists {
		if err == nil {
			err = fmt.Errorf("staged inventory is missing")
		}
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	policyAfter, err := readSetupFileState(setupRecoveryStagePath(opts.DataDir, "policy.draft.json"))
	if err != nil || !policyAfter.Exists {
		if err == nil {
			err = fmt.Errorf("staged policy draft is missing")
		}
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	quarantineAfter, err := readSetupFileState(setupRecoveryStagePath(opts.DataDir, "mcp_quarantine_plan.json"))
	if err != nil || !quarantineAfter.Exists {
		if err == nil {
			err = fmt.Errorf("staged MCP quarantine plan is missing")
		}
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	txnID, err := newSetupRecoveryTransactionID()
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	receiptID, err := newSetupLifecycleReceiptID()
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	binding, err := buildSetupCodexProjectBinding(opts, summary, receiptID, clientAfter, hookAfter)
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	bindingData, err := marshalSetupCodexProjectBinding(binding)
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	bindingStagePath, err := setupRecoverySafeStagePath(opts.DataDir, setupCodexProjectBindingFile)
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	if err := writeSetupPrivateFile(bindingStagePath, bindingData); err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	bindingAfter, err := readSetupFileState(bindingStagePath)
	if err != nil || !bindingAfter.Exists {
		if err == nil {
			err = fmt.Errorf("staged Codex project install binding is missing")
		}
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	summary.ScanGrade = grade
	summary.DraftPolicyPath = policyPath

	journal, err := newCodexProjectRecoveryJournal(opts, summary, "install", txnID, receiptID, []setupRecoveryFilePlan{
		setupRecoveryPlanForStates(setupRecoveryFileInventory, inventoryBefore, inventoryAfter, "inventory.json"),
		setupRecoveryPlanForStates(setupRecoveryFilePolicyDraft, policyBefore, policyAfter, "policy.draft.json"),
		setupRecoveryPlanForStates(setupRecoveryFileMCPQuarantinePlan, quarantineBefore, quarantineAfter, "mcp_quarantine_plan.json"),
		setupRecoveryPlanForStates(setupRecoveryFileHook, hookBefore, hookAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileMCP, clientBefore, clientAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileBinding, bindingBefore, bindingAfter, setupCodexProjectBindingFile),
	})
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	if err := writeSetupRecoveryJournal(opts.DataDir, *journal); err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	if err := removeSetupRecoveryMarker(opts.DataDir, setupRecoveryPreparingFile); err != nil {
		return nil, fmt.Errorf("publish prepared Codex project recovery journal: %w", err)
	}
	return &codexProjectRecoveryPreparation{journal: journal, summary: summary}, nil
}

func prepareCodexProjectRecoveryRemove(opts setupOptions, summary setupSummary) (*codexProjectRecoveryPreparation, error) {
	if err := validateSetupLifecycleReceiptProfile(); err != nil {
		return nil, err
	}
	clientBefore, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return nil, err
	}
	hookBefore, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return nil, err
	}
	if err := requireCodexProjectHookSourceForRemoval(clientBefore.Data); err != nil {
		return nil, err
	}
	mcp, err := readCodexMCPServerFromBytes(clientBefore.Data)
	if err != nil {
		return nil, err
	}
	if mcp == nil {
		if strings.Contains(string(hookBefore.Data), setupHookOwnershipStatus) {
			return nil, fmt.Errorf("Codex hook looks HELM-managed but no MCP install binding can prove automatic removal")
		}
		refreshSetupConfiguration(opts, &summary)
		return &codexProjectRecoveryPreparation{summary: summary}, nil
	}
	if !isHELMCodexMCPServerCore(*mcp) {
		if strings.Contains(string(hookBefore.Data), setupHookOwnershipStatus) {
			return nil, fmt.Errorf("Codex hook looks HELM-managed but its MCP server is not a proven HELM installation")
		}
		refreshSetupConfiguration(opts, &summary)
		return &codexProjectRecoveryPreparation{summary: summary}, nil
	}
	if err := requireSafeCodexMCPRemoval(mcp, opts.DataDir); err != nil {
		return nil, err
	}
	provenBinary, err := validateCodexProjectRemovalProvenance(opts, summary, clientBefore, hookBefore)
	if err != nil {
		return nil, err
	}
	summary.BinaryPath = provenBinary
	hookAfter, err := buildRemoveOwnedSetupHookState(hookBefore, opts.Target, setupHookCommand(opts, summary.BinaryPath))
	if err != nil {
		return nil, err
	}
	clientAfter, err := buildRemoveCodexProjectMCPStateForBinary(clientBefore, opts.DataDir, summary.BinaryPath)
	if err != nil {
		return nil, err
	}
	bindingBefore, err := readSetupFileState(setupCodexProjectBindingPath(opts.DataDir))
	if err != nil {
		return nil, err
	}
	if err := prepareSetupRecoveryDirectory(opts.DataDir); err != nil {
		return nil, err
	}
	txnID, err := newSetupRecoveryTransactionID()
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	receiptID, err := newSetupLifecycleReceiptID()
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	journal, err := newCodexProjectRecoveryJournal(opts, summary, "remove", txnID, receiptID, []setupRecoveryFilePlan{
		setupRecoveryPlanForStates(setupRecoveryFileMCP, clientBefore, clientAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileHook, hookBefore, hookAfter, ""),
		setupRecoveryPlanForStates(setupRecoveryFileBinding, bindingBefore, setupFileState{Path: bindingBefore.Path}, ""),
	})
	if err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	if err := writeSetupRecoveryJournal(opts.DataDir, *journal); err != nil {
		return nil, discardUncommittedSetupRecoveryDirectory(opts.DataDir, err)
	}
	if err := removeSetupRecoveryMarker(opts.DataDir, setupRecoveryPreparingFile); err != nil {
		return nil, fmt.Errorf("publish prepared Codex project removal journal: %w", err)
	}
	return &codexProjectRecoveryPreparation{journal: journal, summary: summary}, nil
}

func newCodexProjectRecoveryJournal(opts setupOptions, summary setupSummary, operation, transactionID, receiptID string, files []setupRecoveryFilePlan) (*setupRecoveryJournal, error) {
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return nil, err
	}
	identity, err := inspectSetupKernelBinary(summary.BinaryPath)
	if err != nil {
		return nil, err
	}
	return &setupRecoveryJournal{
		SchemaVersion:      setupRecoverySchema,
		TransactionID:      transactionID,
		Operation:          operation,
		Target:             opts.Target,
		Scope:              opts.Scope,
		WorkspacePathHash:  workspacePathHash,
		DataDirPathHash:    canonicalize.HashBytes([]byte(opts.DataDir)),
		BinaryPath:         identity.Path,
		BinaryContentHash:  identity.ContentHash,
		LifecycleReceiptID: receiptID,
		ScanGrade:          summary.ScanGrade,
		Phase:              setupRecoveryPhasePrepared,
		Files:              files,
	}, nil
}

func setupRecoveryWorkspacePathHash() (string, error) {
	workspacePath, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(workspacePath); resolveErr == nil {
		workspacePath = resolved
	}
	return canonicalize.HashBytes([]byte(workspacePath)), nil
}

func setupRecoveryPlanForStates(id string, before, after setupFileState, stageFile string) setupRecoveryFilePlan {
	return setupRecoveryFilePlan{
		ID:        id,
		Before:    setupRecoveryFingerprintForState(before),
		After:     setupRecoveryFingerprintForState(after),
		StageFile: stageFile,
	}
}

func stageSetupAutoconfigure(dataDir string) (string, string, error) {
	artifactsDir := setupCodexProjectArtifactsDir(dataDir)
	writer := func(finalPath string, value any) error {
		data, err := marshalSetupJSONArtifact(value)
		if err != nil {
			return err
		}
		return writeSetupPrivateFile(setupRecoveryStagePath(dataDir, filepath.Base(finalPath)), data)
	}
	return runSetupAutoconfigureTo(artifactsDir, writer)
}

func discardUncommittedSetupRecoveryDirectory(dataDir string, cause error) error {
	if cleanupErr := cleanupIncompleteSetupRecoveryDirectory(dataDir); cleanupErr != nil {
		return fmt.Errorf("%w; preserve incomplete setup recovery state: %v", cause, cleanupErr)
	}
	return cause
}

func validateCodexProjectRecoveryJournal(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal) (setupKernelBinaryIdentity, error) {
	if err := validateSetupRecoveryJournal(journal); err != nil {
		return setupKernelBinaryIdentity{}, err
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return setupKernelBinaryIdentity{}, err
	}
	if journal.Target != "codex" || journal.Scope != "project" || opts.Target != journal.Target || opts.Scope != journal.Scope {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery journal does not match the requested Codex project scope")
	}
	if journal.WorkspacePathHash != workspacePathHash || journal.DataDirPathHash != canonicalize.HashBytes([]byte(opts.DataDir)) {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery journal is bound to a different workspace or data-dir")
	}
	journalBinary, err := inspectSetupKernelBinary(journal.BinaryPath)
	if err != nil {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery journal Kernel binary is unavailable: %w", err)
	}
	// A recovery journal is itself untrusted crash residue. It must name the
	// canonical executable path that was pinned at prepare time, rather than a
	// symlink which happens to resolve to it today. Otherwise a journal could
	// redirect a resumed transaction through a mutable alternate pathname.
	if journalBinary.Path != journal.BinaryPath {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery journal Kernel executable path does not match its resolved pinned path")
	}
	if journalBinary.ContentHash != journal.BinaryContentHash {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery journal Kernel binary no longer matches its pinned content hash")
	}
	currentBinary, err := inspectSetupKernelBinary(summary.BinaryPath)
	if err != nil {
		return setupKernelBinaryIdentity{}, err
	}
	if currentBinary.ContentHash != journal.BinaryContentHash {
		return setupKernelBinaryIdentity{}, fmt.Errorf("current Kernel binary does not match the prepared recovery transaction")
	}
	if currentBinary.Path != journalBinary.Path {
		return setupKernelBinaryIdentity{}, fmt.Errorf("current Kernel executable path does not match the prepared recovery transaction")
	}
	if summary.ClientConfigPath == "" || summary.HookConfigPath == "" {
		return setupKernelBinaryIdentity{}, fmt.Errorf("setup recovery paths are incomplete")
	}
	return journalBinary, nil
}

func resumeCodexProjectRecovery(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal) (setupLifecycleResult, setupSummary, error) {
	journalBinary, err := validateCodexProjectRecoveryJournal(opts, summary, journal)
	if err != nil {
		return setupLifecycleResult{}, summary, err
	}
	_, persistedReceipt, receiptErr := inspectSetupLifecycleReceiptReadOnly(context.Background(), opts.DataDir, journal.LifecycleReceiptID)
	if receiptErr != nil {
		return setupLifecycleResult{}, summary, fmt.Errorf("inspect recovered lifecycle receipt before config mutation: %w", receiptErr)
	}
	if !persistedReceipt {
		if err := validateSetupLifecycleReceiptProfile(); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("validate receipt profile before resumable config mutation: %w", err)
		}
	}
	summary.BinaryPath = journalBinary.Path
	if journal.Operation == "remove" {
		if err := validateCodexProjectRemoveRecoveryProvenance(opts, summary, journal, journalBinary); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("verify recovered Codex project removal provenance: %w", err)
		}
	}
	if journal.Operation == "install" {
		if _, err := validateStagedCodexProjectInstallBinding(opts, journal); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("verify staged Codex project install binding: %w", err)
		}
		artifactsDir := setupCodexProjectArtifactsDir(opts.DataDir)
		for _, id := range []string{setupRecoveryFileInventory, setupRecoveryFilePolicyDraft, setupRecoveryFileMCPQuarantinePlan} {
			if err := applyStagedSetupRecoveryFile(opts.DataDir, journal, id, filepath.Join(artifactsDir, stageFileForRecoveryID(id))); err != nil {
				return setupLifecycleResult{}, summary, err
			}
		}
		if err := applyCodexRecoveryHook(opts, summary, journal, true); err != nil {
			return setupLifecycleResult{}, summary, err
		}
		if err := applyCodexRecoveryMCP(opts, summary, journal, true); err != nil {
			return setupLifecycleResult{}, summary, err
		}
		summary.ScanGrade = journal.ScanGrade
		summary.DraftPolicyPath = filepath.Join(artifactsDir, "policy.draft.json")
	} else {
		if err := applyCodexRecoveryMCP(opts, summary, journal, false); err != nil {
			return setupLifecycleResult{}, summary, err
		}
		if err := applyCodexRecoveryHook(opts, summary, journal, false); err != nil {
			return setupLifecycleResult{}, summary, err
		}
	}

	refreshSetupConfiguration(opts, &summary)
	if journal.Operation == "install" && !summary.LocalConfigVerified {
		return setupLifecycleResult{}, summary, fmt.Errorf("recovered Codex project config is not exact")
	}
	if journal.Operation == "remove" && (summary.MCPConfigured || summary.HookConfigured) {
		return setupLifecycleResult{}, summary, fmt.Errorf("recovered Codex project removal left owned config")
	}
	recordOpts := opts
	recordOpts.lifecycleReceiptID = journal.LifecycleReceiptID
	recordOpts.lifecycleRecoveryManaged = true
	lifecycle, err := recordCodexProjectSetupLifecycleFn(recordOpts, summary, journal.Operation)
	if err != nil {
		return setupLifecycleResult{}, summary, fmt.Errorf("record recovered lifecycle: %w", err)
	}
	if journal.Operation == "install" {
		if _, err := validateStagedCodexProjectInstallBindingForCurrentConfig(opts, journal); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("verify signed Codex project install binding before publication: %w", err)
		}
		if err := applyStagedSetupRecoveryFile(opts.DataDir, journal, setupRecoveryFileBinding, setupCodexProjectBindingPath(opts.DataDir)); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("publish proven Codex project install binding: %w", err)
		}
	} else {
		if err := applySetupRecoveryFilePlan(opts.DataDir, journal, setupRecoveryFileBinding, setupCodexProjectBindingPath(opts.DataDir)); err != nil {
			return setupLifecycleResult{}, summary, fmt.Errorf("remove Codex project install binding: %w", err)
		}
	}
	if err := finalizeCodexProjectRecoveryJournal(opts.DataDir, journal); err != nil {
		inspection, inspectErr := inspectSetupRecovery(opts.DataDir)
		if inspectErr == nil && inspection.State == setupRecoveryStateCommitted {
			summary.RecoveryCleanupPending = true
			return lifecycle, summary, nil
		}
		return setupLifecycleResult{}, summary, fmt.Errorf("finalize recovered setup journal: %w", err)
	}
	return lifecycle, summary, nil
}

// validateCodexProjectRemoveRecoveryProvenance replays only a removal that is
// causally anchored to a signed install binding. A recovery journal is an
// integrity record, not authority by itself: it may be damaged or forged while
// a process is down. The binding proves the pre-removal configs; the journal
// must then describe exactly the deterministic removal of those configs.
func validateCodexProjectRemoveRecoveryProvenance(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal, journalBinary setupKernelBinaryIdentity) error {
	bindingState, err := readSetupFileState(setupCodexProjectBindingPath(opts.DataDir))
	if err != nil {
		return err
	}
	if !bindingState.Exists {
		return validateCodexProjectCompletedRemoveRecovery(opts, summary, journal, journalBinary, bindingState)
	}
	proof, err := loadCodexProjectInstallProof(opts)
	if err != nil {
		return err
	}
	if proof.Binary.Path != journalBinary.Path || proof.Binary.ContentHash != journalBinary.ContentHash || summary.BinaryPath != proof.Binary.Path {
		return fmt.Errorf("recovery journal Kernel binary does not match the proven install binding")
	}

	mcpPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileMCP)
	if err != nil {
		return err
	}
	hookPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileHook)
	if err != nil {
		return err
	}
	bindingPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileBinding)
	if err != nil {
		return err
	}
	if !mcpPlan.Before.Exists || mcpPlan.Before.ContentHash != proof.Binding.ClientConfigContentHash ||
		!hookPlan.Before.Exists || hookPlan.Before.ContentHash != proof.Binding.HookConfigContentHash ||
		bindingPlan.After.Exists {
		return fmt.Errorf("recovery journal does not preserve the proven Codex install binding state")
	}
	bindingData, err := marshalSetupCodexProjectBinding(*proof.Binding)
	if err != nil {
		return err
	}
	if !bindingPlan.Before.Exists || bindingPlan.Before.ContentHash != canonicalize.HashBytes(bindingData) {
		return fmt.Errorf("recovery journal binding plan does not match the proven install binding")
	}

	clientState, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return err
	}
	hookState, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return err
	}
	if err := validateRemoveRecoveryConfigPlan(mcpPlan, clientState, func(before setupFileState) (setupFileState, error) {
		return buildRemoveCodexProjectMCPStateForBinary(before, opts.DataDir, proof.Binary.Path)
	}); err != nil {
		return fmt.Errorf("Codex MCP recovery plan: %w", err)
	}
	if err := validateRemoveRecoveryConfigPlan(hookPlan, hookState, func(before setupFileState) (setupFileState, error) {
		return buildRemoveOwnedSetupHookState(before, opts.Target, setupHookCommand(opts, proof.Binary.Path))
	}); err != nil {
		return fmt.Errorf("Codex hook recovery plan: %w", err)
	}
	if setupRecoveryFingerprintMatchesState(bindingPlan.After, bindingState) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(bindingPlan.Before, bindingState) {
		return fmt.Errorf("Codex project binding changed outside the recorded removal")
	}
	return nil
}

// validateCodexProjectCompletedRemoveRecovery handles the narrow crash window
// after an already-signed REVOKED lifecycle receipt has been persisted and the
// install binding has been deleted, but before the terminal marker is durable.
// The missing binding is never accepted on the strength of a journal alone:
// this branch is cleanup-only and requires the signed post-removal receipt,
// evidence, and exact post-removal file snapshots before resume may continue.
func validateCodexProjectCompletedRemoveRecovery(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal, journalBinary setupKernelBinaryIdentity, bindingState setupFileState) error {
	if bindingState.Exists {
		return fmt.Errorf("completed Codex removal recovery requires an absent install binding")
	}
	mcpPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileMCP)
	if err != nil {
		return err
	}
	hookPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileHook)
	if err != nil {
		return err
	}
	bindingPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileBinding)
	if err != nil {
		return err
	}
	if !bindingPlan.Before.Exists || bindingPlan.After.Exists {
		return fmt.Errorf("missing install binding is not an exact recorded removal state")
	}
	clientState, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return err
	}
	hookState, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return err
	}
	if !setupRecoveryFingerprintMatchesState(mcpPlan.After, clientState) || !setupRecoveryFingerprintMatchesState(hookPlan.After, hookState) || !setupRecoveryFingerprintMatchesState(bindingPlan.After, bindingState) {
		return fmt.Errorf("post-removal Codex project state differs from the recorded recovery plan")
	}

	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return err
	}
	receipt, err := readSetupLifecycleReceiptReadOnly(context.Background(), opts.DataDir, journal.LifecycleReceiptID)
	if err != nil {
		return fmt.Errorf("read signed completed Codex removal receipt: %w", err)
	}
	signer, err := loadExistingSetupLifecycleSignerForSignature(opts.DataDir, receipt.Signature)
	if err != nil {
		return err
	}
	evidence, err := verifySetupLifecycleEvidence(opts.DataDir, receipt)
	if err != nil {
		return fmt.Errorf("verify completed Codex removal evidence: %w", err)
	}
	descriptorHash, err := canonicalize.CanonicalHash(evidence.Descriptor)
	if err != nil {
		return err
	}
	observationHash, err := canonicalize.CanonicalHash(evidence.Observation)
	if err != nil {
		return err
	}
	if err := validatePersistedSetupLifecycleReceipt(signer, receipt, journal.LifecycleReceiptID, descriptorHash, observationHash, workspacePathHash, "remove"); err != nil {
		return fmt.Errorf("completed Codex removal receipt is not an exact signed lifecycle record: %w", err)
	}
	if evidence.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Descriptor.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Observation.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Descriptor.Client != "codex" || evidence.Descriptor.Scope != "project" || evidence.Descriptor.Operation != "remove" ||
		evidence.Descriptor.WorkspacePathHash != workspacePathHash || evidence.Descriptor.DataDirPathHash != canonicalize.HashBytes([]byte(opts.DataDir)) ||
		evidence.Descriptor.KernelBinaryPath != journalBinary.Path || evidence.Descriptor.KernelBinaryContentHash != journalBinary.ContentHash ||
		evidence.Descriptor.ExpectedMCP || evidence.Descriptor.ExpectedHook ||
		evidence.Observation.Operation != "remove" || evidence.Observation.MCPConfigured || evidence.Observation.HookConfigured ||
		evidence.Observation.ClientLoadObserved || evidence.Observation.KernelDispatchObserved || evidence.Observation.SyntheticDenial != nil ||
		evidence.Observation.WorkspacePathHash != workspacePathHash || evidence.Observation.DataDirPathHash != canonicalize.HashBytes([]byte(opts.DataDir)) {
		return fmt.Errorf("completed Codex removal evidence is incomplete or does not match the recorded transaction")
	}
	if ok, err := setupLifecycleSnapshotMatchesCurrent(evidence.Observation.ClientConfig, summary.ClientConfigPath); err != nil || !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("completed Codex removal client config snapshot changed after revocation")
	}
	if ok, err := setupLifecycleSnapshotMatchesCurrent(evidence.Observation.HookConfig, summary.HookConfigPath); err != nil || !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("completed Codex removal hook config snapshot changed after revocation")
	}
	refreshSetupConfiguration(opts, &summary)
	if summary.MCPConfigured || summary.HookConfigured {
		return fmt.Errorf("completed Codex removal still exposes owned configuration")
	}
	return nil
}

func validateRemoveRecoveryConfigPlan(plan setupRecoveryFilePlan, current setupFileState, transform func(setupFileState) (setupFileState, error)) error {
	if setupRecoveryFingerprintMatchesState(plan.After, current) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(plan.Before, current) {
		return fmt.Errorf("config differs from both the proven pre-removal and recorded post-removal state")
	}
	next, err := transform(current)
	if err != nil {
		return err
	}
	if !setupRecoveryFingerprintMatchesState(plan.After, next) {
		return fmt.Errorf("deterministic removal transformation differs from the recorded post-removal state")
	}
	return nil
}

func applyStagedSetupRecoveryFile(dataDir string, journal *setupRecoveryJournal, id, finalPath string) error {
	plan, err := lookupSetupRecoveryFilePlan(journal, id)
	if err != nil {
		return err
	}
	current, err := readSetupFileState(finalPath)
	if err != nil {
		return err
	}
	if setupRecoveryFingerprintMatchesState(plan.After, current) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(plan.Before, current) {
		return fmt.Errorf("setup recovery conflict: %s changed outside HELM", id)
	}
	stagePath, err := setupRecoverySafeStagePath(dataDir, plan.StageFile)
	if err != nil {
		return err
	}
	staged, err := readSetupFileState(stagePath)
	if err != nil {
		return err
	}
	if !setupRecoveryFingerprintMatchesState(plan.After, staged) {
		return fmt.Errorf("setup recovery staged artifact does not match its journal: %s", id)
	}
	staged.Path = finalPath
	return restoreSetupFileState(staged)
}

func applySetupRecoveryFilePlan(dataDir string, journal *setupRecoveryJournal, id, finalPath string) error {
	plan, err := lookupSetupRecoveryFilePlan(journal, id)
	if err != nil {
		return err
	}
	current, err := readSetupFileState(finalPath)
	if err != nil {
		return err
	}
	if setupRecoveryFingerprintMatchesState(plan.After, current) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(plan.Before, current) {
		return fmt.Errorf("setup recovery conflict: %s changed outside HELM", id)
	}
	if plan.After.Exists {
		return fmt.Errorf("setup recovery non-staged plan %s unexpectedly creates a file", id)
	}
	return restoreSetupFileState(setupFileState{Path: finalPath, Exists: plan.After.Exists})
}

func applyCodexRecoveryHook(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal, install bool) error {
	plan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileHook)
	if err != nil {
		return err
	}
	current, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return err
	}
	if setupRecoveryFingerprintMatchesState(plan.After, current) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(plan.Before, current) {
		return fmt.Errorf("setup recovery conflict: hook config changed outside HELM")
	}
	var next setupFileState
	if install {
		next, err = buildUpsertOwnedSetupHookState(current, setupHookMatcher(opts.Target), setupHookCommand(opts, summary.BinaryPath), opts.Target)
	} else {
		next, err = buildRemoveOwnedSetupHookState(current, opts.Target, setupHookCommand(opts, summary.BinaryPath))
	}
	if err != nil {
		return err
	}
	if !setupRecoveryFingerprintMatchesState(plan.After, next) {
		return fmt.Errorf("setup recovery hook transformation differs from its prepared journal")
	}
	return restoreSetupFileState(next)
}

func applyCodexRecoveryMCP(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal, install bool) error {
	plan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileMCP)
	if err != nil {
		return err
	}
	current, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return err
	}
	if setupRecoveryFingerprintMatchesState(plan.After, current) {
		return nil
	}
	if !setupRecoveryFingerprintMatchesState(plan.Before, current) {
		return fmt.Errorf("setup recovery conflict: Codex MCP config changed outside HELM")
	}
	var next setupFileState
	if install {
		next, err = buildUpsertCodexProjectMCPState(current, summary.BinaryPath, opts.DataDir)
	} else {
		next, err = buildRemoveCodexProjectMCPStateForBinary(current, opts.DataDir, summary.BinaryPath)
	}
	if err != nil {
		return err
	}
	if !setupRecoveryFingerprintMatchesState(plan.After, next) {
		return fmt.Errorf("setup recovery MCP transformation differs from its prepared journal")
	}
	return restoreSetupFileState(next)
}

func stageFileForRecoveryID(id string) string {
	switch id {
	case setupRecoveryFileInventory:
		return "inventory.json"
	case setupRecoveryFilePolicyDraft:
		return "policy.draft.json"
	case setupRecoveryFileMCPQuarantinePlan:
		return "mcp_quarantine_plan.json"
	case setupRecoveryFileBinding:
		return setupCodexProjectBindingFile
	default:
		return ""
	}
}
