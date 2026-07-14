package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const setupCodexProjectLifecycleSchema = "helm.native-client.setup/v1"

var recordCodexProjectSetupLifecycleFn = recordCodexProjectSetupLifecycle

// setupLifecycleStorePrepared is a narrow deterministic test seam. Production
// uses the no-op default; tests can install a SQLite trigger after the store is
// initialized to prove cleanup behavior for an actual append failure.
var setupLifecycleStorePrepared = func(_ *sql.DB) error { return nil }

func validateSetupLifecycleReceiptProfile() error {
	switch profile := os.Getenv("HELM_RECEIPT_PROFILE"); profile {
	case "", helmcrypto.ReceiptProfileClassical, helmcrypto.ReceiptProfileHybrid:
		return nil
	default:
		return fmt.Errorf("unknown HELM_RECEIPT_PROFILE %q (expected %q or %q)", profile, helmcrypto.ReceiptProfileClassical, helmcrypto.ReceiptProfileHybrid)
	}
}

type setupLifecycleResult struct {
	ReceiptID               string
	EvidencePath            string
	SyntheticDenialVerified bool
}

type setupFileSnapshot struct {
	PathHash    string `json:"path_hash"`
	Exists      bool   `json:"exists"`
	ContentHash string `json:"content_hash,omitempty"`
}

type setupSyntheticDenial struct {
	Verified            bool   `json:"verified"`
	Dispatched          bool   `json:"dispatched"`
	SentinelAbsent      bool   `json:"sentinel_absent"`
	ResponseContentHash string `json:"response_content_hash"`
}

type setupLifecycleDescriptor struct {
	SchemaVersion           string `json:"schema_version"`
	Client                  string `json:"client"`
	Scope                   string `json:"scope"`
	Operation               string `json:"operation"`
	WorkspacePathHash       string `json:"workspace_path_hash"`
	DataDirPathHash         string `json:"data_dir_path_hash"`
	KernelBinaryPath        string `json:"kernel_binary_path"`
	KernelBinaryContentHash string `json:"kernel_binary_content_hash"`
	ExpectedMCP             bool   `json:"expected_mcp_configured"`
	ExpectedHook            bool   `json:"expected_hook_configured"`
}

type setupLifecycleObservation struct {
	SchemaVersion          string                `json:"schema_version"`
	Operation              string                `json:"operation"`
	MCPConfigured          bool                  `json:"mcp_configured"`
	HookConfigured         bool                  `json:"hook_configured"`
	ClientLoadObserved     bool                  `json:"client_load_observed"`
	ClientConfig           setupFileSnapshot     `json:"client_config"`
	HookConfig             setupFileSnapshot     `json:"hook_config"`
	SyntheticDenial        *setupSyntheticDenial `json:"synthetic_denial,omitempty"`
	KernelDispatchObserved bool                  `json:"kernel_dispatch_observed"`
	WorkspacePathHash      string                `json:"workspace_path_hash"`
	DataDirPathHash        string                `json:"data_dir_path_hash"`
}

type setupLifecycleEvidence struct {
	SchemaVersion string                    `json:"schema_version"`
	ReceiptID     string                    `json:"receipt_id"`
	Descriptor    setupLifecycleDescriptor  `json:"descriptor"`
	Observation   setupLifecycleObservation `json:"observation"`
}

// preflightCodexProjectSetup validates only local ownership and syntax before
// setup creates Kernel state or scans the workspace. The mutating helpers
// repeat these checks inside the transaction because the files can change
// between this preflight and the write.
func preflightCodexProjectSetup(opts setupOptions, summary setupSummary) error {
	clientState, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return fmt.Errorf("inspect Codex project config: %w", err)
	}
	if err := requireCodexProjectHookSourceForInstall(clientState.Data); err != nil {
		return err
	}
	mcp, hasMCP, err := readCodexMCPServer(summary.ClientConfigPath)
	if err != nil {
		return fmt.Errorf("inspect Codex MCP config: %w", err)
	}
	if hasMCP {
		if err := requireMutableCodexMCPServer(&mcp, opts.DataDir); err != nil {
			return err
		}
	}
	_, pre, err := readSetupHookConfig(summary.HookConfigPath)
	if err != nil {
		return fmt.Errorf("inspect Codex hook config: %w", err)
	}
	if err := requireMutableSetupHookEntries(pre, opts.Target, setupHookCommand(opts, summary.BinaryPath)); err != nil {
		return err
	}
	if hasMCP && isOwnedCodexMCPServerForDataDir(mcp, opts.DataDir) {
		hookState, err := readSetupFileState(summary.HookConfigPath)
		if err != nil {
			return fmt.Errorf("inspect Codex hook binding: %w", err)
		}
		if _, err := validateCodexProjectRemovalProvenance(opts, summary, clientState, hookState); err != nil {
			return fmt.Errorf("verify existing Codex project install provenance before replacement: %w", err)
		}
	}
	return nil
}

func refreshSetupConfiguration(opts setupOptions, summary *setupSummary) {
	summary.MCPConfigured = setupMCPConfigured(opts, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookConfigured = setupHookConfigured(opts, summary.HookConfigPath, summary.BinaryPath)
	summary.LocalConfigVerified = summary.MCPConfigured && summary.HookConfigured
	// A project file is only a candidate client configuration. Codex can skip
	// it until the project and hooks are trusted, so integration remains false
	// until a sterile client session observes the configured server loaded.
	summary.Configured = summary.LocalConfigVerified && summary.ClientLoadObserved
}

// reconcilePersistedSetupLifecycleReceipt completes the post-append recovery
// boundary without issuing a new receipt or using HELM_RECEIPT_PROFILE. A
// recovery journal may outlive a profile rollout, rollback, or an invalid
// environment override; the persisted receipt envelope is the only valid
// source for selecting its verification authority.
func reconcilePersistedSetupLifecycleReceipt(dataDir, receiptID, workspacePathHash, operation string, summary setupSummary, descriptor setupLifecycleDescriptor, clientConfig, hookConfig setupFileSnapshot, receipt *contracts.Receipt) (setupLifecycleResult, error) {
	if receipt == nil {
		return setupLifecycleResult{}, fmt.Errorf("persisted lifecycle receipt is required")
	}
	signer, err := loadExistingSetupLifecycleSignerForSignature(dataDir, receipt.Signature)
	if err != nil {
		return setupLifecycleResult{}, fmt.Errorf("load persisted lifecycle verification authority: %w", err)
	}
	evidence, err := verifySetupLifecycleEvidence(dataDir, receipt)
	if err != nil {
		return setupLifecycleResult{}, fmt.Errorf("verify persisted lifecycle evidence: %w", err)
	}
	if evidence.Descriptor != descriptor {
		return setupLifecycleResult{}, fmt.Errorf("persisted lifecycle descriptor does not match the recovered setup")
	}
	observation := evidence.Observation
	if observation.Operation != operation ||
		observation.MCPConfigured != summary.MCPConfigured ||
		observation.HookConfigured != summary.HookConfigured ||
		observation.ClientLoadObserved ||
		observation.ClientConfig != clientConfig ||
		observation.HookConfig != hookConfig ||
		observation.WorkspacePathHash != descriptor.WorkspacePathHash ||
		observation.DataDirPathHash != descriptor.DataDirPathHash {
		return setupLifecycleResult{}, fmt.Errorf("persisted lifecycle observation does not match the recovered setup")
	}
	if operation == "install" {
		if observation.SyntheticDenial == nil || !observation.SyntheticDenial.Verified || !observation.SyntheticDenial.SentinelAbsent || observation.SyntheticDenial.Dispatched || observation.KernelDispatchObserved {
			return setupLifecycleResult{}, fmt.Errorf("persisted install lifecycle evidence has no valid synthetic denial")
		}
	} else if observation.SyntheticDenial != nil || observation.KernelDispatchObserved {
		return setupLifecycleResult{}, fmt.Errorf("persisted removal lifecycle evidence has unexpected synthetic denial state")
	}
	descriptorHash, err := canonicalize.CanonicalHash(descriptor)
	if err != nil {
		return setupLifecycleResult{}, fmt.Errorf("hash recovered lifecycle descriptor: %w", err)
	}
	outputHash, err := canonicalize.CanonicalHash(observation)
	if err != nil {
		return setupLifecycleResult{}, fmt.Errorf("hash persisted lifecycle observation: %w", err)
	}
	if err := validatePersistedSetupLifecycleReceipt(signer, receipt, receiptID, descriptorHash, outputHash, workspacePathHash, operation); err != nil {
		return setupLifecycleResult{}, err
	}
	return setupLifecycleResult{
		ReceiptID:               receiptID,
		EvidencePath:            setupLifecycleEvidencePath(dataDir, receiptID),
		SyntheticDenialVerified: observation.SyntheticDenial != nil && observation.SyntheticDenial.Verified,
	}, nil
}

// recordCodexProjectSetupLifecycle records only a local Kernel observation.
// It intentionally does not claim that Codex trusted, loaded, or invoked the
// configured MCP server; that must be certified from a sterile client session.
func recordCodexProjectSetupLifecycle(opts setupOptions, summary setupSummary, operation string) (result setupLifecycleResult, returnErr error) {
	if opts.Target != "codex" || opts.Scope != "project" {
		return result, fmt.Errorf("Codex project lifecycle requires target codex with project scope")
	}
	if operation != "install" && operation != "remove" {
		return result, fmt.Errorf("unsupported Codex project lifecycle operation %q", operation)
	}
	if operation == "install" && !summary.LocalConfigVerified {
		return result, fmt.Errorf("Codex project config is incomplete after install")
	}
	if operation == "remove" && (summary.MCPConfigured || summary.HookConfigured) {
		return result, fmt.Errorf("owned Codex project config remains after remove")
	}
	stateTracker, err := beginSetupLifecycleStateTracker(opts.DataDir)
	if err != nil {
		return result, fmt.Errorf("snapshot lifecycle state: %w", err)
	}
	var evidencePath string
	cleanupLifecycleState := true
	defer func() {
		if returnErr == nil {
			return
		}
		if opts.lifecycleRecoveryManaged {
			// A prepared recovery journal owns this lifecycle attempt. Retain
			// signer, SQLite, and evidence state so a resumed transaction can
			// prove or finish the same receipt without tearing down an uncertain
			// post-append boundary.
			return
		}
		if evidencePath != "" {
			if err := os.Remove(evidencePath); err != nil && !os.IsNotExist(err) {
				returnErr = fmt.Errorf("%w; remove lifecycle evidence: %v", returnErr, err)
			}
			if err := os.Remove(filepath.Dir(evidencePath)); err != nil && !os.IsNotExist(err) {
				returnErr = fmt.Errorf("%w; remove empty lifecycle evidence dir: %v", returnErr, err)
			}
		}
		if !cleanupLifecycleState {
			return
		}
		if err := stateTracker.cleanupCreated(); err != nil {
			returnErr = fmt.Errorf("%w; cleanup newly-created lifecycle state: %v", returnErr, err)
		}
	}()

	workspacePath, err := filepath.Abs(".")
	if err != nil {
		return result, fmt.Errorf("resolve workspace: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(workspacePath); resolveErr == nil {
		workspacePath = resolved
	}
	workspacePathHash := canonicalize.HashBytes([]byte(workspacePath))
	dataDirPathHash := canonicalize.HashBytes([]byte(opts.DataDir))
	binaryIdentity, err := inspectSetupKernelBinary(summary.BinaryPath)
	if err != nil {
		return result, fmt.Errorf("inspect lifecycle Kernel binary: %w", err)
	}

	clientConfig, err := snapshotSetupFile(summary.ClientConfigPath)
	if err != nil {
		return result, fmt.Errorf("snapshot client config: %w", err)
	}
	hookConfig, err := snapshotSetupFile(summary.HookConfigPath)
	if err != nil {
		return result, fmt.Errorf("snapshot hook config: %w", err)
	}

	descriptor := setupLifecycleDescriptor{
		SchemaVersion:           setupCodexProjectLifecycleSchema,
		Client:                  "codex",
		Scope:                   "project",
		Operation:               operation,
		WorkspacePathHash:       workspacePathHash,
		DataDirPathHash:         dataDirPathHash,
		KernelBinaryPath:        binaryIdentity.Path,
		KernelBinaryContentHash: binaryIdentity.ContentHash,
		ExpectedMCP:             operation == "install",
		ExpectedHook:            operation == "install",
	}
	descriptorHash, err := canonicalize.CanonicalHash(descriptor)
	if err != nil {
		return result, fmt.Errorf("hash lifecycle descriptor: %w", err)
	}

	receiptID := opts.lifecycleReceiptID
	if receiptID == "" {
		var receiptErr error
		receiptID, receiptErr = newSetupLifecycleReceiptID()
		if receiptErr != nil {
			return result, receiptErr
		}
	}
	if opts.lifecycleReceiptID != "" {
		stored, persisted, inspectErr := inspectSetupLifecycleReceiptReadOnly(context.Background(), opts.DataDir, receiptID)
		if inspectErr != nil {
			return result, fmt.Errorf("inspect recovered lifecycle receipt: %w", inspectErr)
		}
		if persisted {
			return reconcilePersistedSetupLifecycleReceipt(opts.DataDir, receiptID, workspacePathHash, operation, summary, descriptor, clientConfig, hookConfig, stored)
		}
	}

	signer, signerErr := loadOrGenerateSignerWithDataDir(opts.DataDir)
	if captureErr := stateTracker.captureCreated(); captureErr != nil {
		return result, captureErr
	}
	if signerErr != nil {
		return result, fmt.Errorf("load lifecycle signer: %w", signerErr)
	}

	var synthetic *setupSyntheticDenial
	if operation == "install" {
		denial, err := verifyCodexProjectSyntheticDenial(opts.DataDir, signer)
		if err != nil {
			return result, err
		}
		synthetic = &denial
	}

	observation := setupLifecycleObservation{
		SchemaVersion:          setupCodexProjectLifecycleSchema,
		Operation:              operation,
		MCPConfigured:          summary.MCPConfigured,
		HookConfigured:         summary.HookConfigured,
		ClientLoadObserved:     false,
		ClientConfig:           clientConfig,
		HookConfig:             hookConfig,
		SyntheticDenial:        synthetic,
		KernelDispatchObserved: synthetic != nil && synthetic.Dispatched,
		WorkspacePathHash:      workspacePathHash,
		DataDirPathHash:        dataDirPathHash,
	}
	outputHash, err := canonicalize.CanonicalHash(observation)
	if err != nil {
		return result, fmt.Errorf("hash lifecycle observation: %w", err)
	}

	evidencePath, err = writeSetupLifecycleEvidence(opts.DataDir, setupLifecycleEvidence{
		SchemaVersion: setupCodexProjectLifecycleSchema,
		ReceiptID:     receiptID,
		Descriptor:    descriptor,
		Observation:   observation,
	})
	if err != nil {
		return result, fmt.Errorf("write lifecycle evidence: %w", err)
	}

	ctx := context.Background()
	db, _, receiptStore, storeErr := setupLiteModeWithDataDir(ctx, opts.DataDir)
	if captureErr := stateTracker.captureCreated(); captureErr != nil {
		return result, captureErr
	}
	if storeErr != nil {
		return result, fmt.Errorf("open lifecycle receipt store: %w", storeErr)
	}
	defer func() { _ = db.Close() }()
	if err := setupLifecycleStorePrepared(db); err != nil {
		return result, fmt.Errorf("prepare lifecycle receipt store: %w", err)
	}
	if opts.lifecycleReceiptID != "" {
		persisted, inspectErr := setupLifecycleReceiptPersisted(ctx, db, receiptID)
		if inspectErr != nil {
			return result, fmt.Errorf("inspect recovered lifecycle receipt: %w", inspectErr)
		}
		if persisted {
			stored, lookupErr := receiptStore.GetByReceiptID(ctx, receiptID)
			if lookupErr != nil {
				return result, fmt.Errorf("read recovered lifecycle receipt: %w", lookupErr)
			}
			return reconcilePersistedSetupLifecycleReceipt(opts.DataDir, receiptID, workspacePathHash, operation, summary, descriptor, clientConfig, hookConfig, stored)
		}
	}

	sessionID := "codex-project:" + workspacePathHash
	status := "DENY"
	effectID := "mcp.tools.call/file_write"
	reasonCode := "ERR_SYNTHETIC_FILE_WRITE_DENIED"
	toolName := "file_write"
	if operation == "remove" {
		status = "REVOKED"
		effectID = "native_client.setup/codex-project/remove"
		reasonCode = "CONFIG_REMOVED"
		toolName = ""
	}

	appendErr := receiptStore.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:           receiptID,
			DecisionID:          "decision/native-client/" + operation + "/" + receiptID,
			EffectID:            effectID,
			ExternalReferenceID: sessionID,
			Status:              status,
			OutputHash:          outputHash,
			Timestamp:           time.Now().UTC(),
			ExecutorID:          sessionID,
			PrevHash:            prevHash,
			LamportClock:        lamport,
			ArgsHash:            descriptorHash,
			Type:                "native_client_setup_lifecycle",
			Action:              operation,
			Verdict:             status,
			ToolName:            toolName,
			ReasonCode:          reasonCode,
			Metadata: map[string]any{
				"evidence_schema":     setupCodexProjectLifecycleSchema,
				"lifecycle_operation": operation,
			},
		}
		if err := signer.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("sign lifecycle receipt: %w", err)
		}
		return receipt, nil
	})
	if appendErr != nil {
		persisted, inspectErr := setupLifecycleReceiptPersisted(ctx, db, receiptID)
		if inspectErr != nil {
			cleanupLifecycleState = false
			return result, fmt.Errorf("append lifecycle receipt: %w; receipt outcome is unknown and local recovery is required: %v", appendErr, inspectErr)
		}
		if !persisted {
			if captureErr := stateTracker.captureCreated(); captureErr != nil {
				return result, fmt.Errorf("append lifecycle receipt: %w; snapshot rollback state: %v", appendErr, captureErr)
			}
			return result, fmt.Errorf("append lifecycle receipt: %w", appendErr)
		}
		stored, lookupErr := receiptStore.GetByReceiptID(ctx, receiptID)
		verificationSigner, verifierErr := loadExistingSetupLifecycleSignerForSignature(opts.DataDir, func() string {
			if stored == nil {
				return ""
			}
			return stored.Signature
		}())
		if lookupErr != nil || verifierErr != nil || validatePersistedSetupLifecycleReceipt(verificationSigner, stored, receiptID, descriptorHash, outputHash, workspacePathHash, operation) != nil {
			cleanupLifecycleState = false
			return result, fmt.Errorf("append lifecycle receipt returned an error but receipt state needs recovery review")
		}
	}

	stored, lookupErr := receiptStore.GetByReceiptID(ctx, receiptID)
	if lookupErr != nil {
		cleanupLifecycleState = false
		return result, fmt.Errorf("read appended lifecycle receipt: %w", lookupErr)
	}
	verificationSigner, verifierErr := loadExistingSetupLifecycleSignerForSignature(opts.DataDir, stored.Signature)
	if verifierErr != nil {
		cleanupLifecycleState = false
		return result, fmt.Errorf("load appended lifecycle verification authority: %w", verifierErr)
	}
	if err := validatePersistedSetupLifecycleReceipt(verificationSigner, stored, receiptID, descriptorHash, outputHash, workspacePathHash, operation); err != nil {
		cleanupLifecycleState = false
		return result, fmt.Errorf("appended lifecycle receipt failed verification: %w", err)
	}

	return setupLifecycleResult{
		ReceiptID:               receiptID,
		EvidencePath:            evidencePath,
		SyntheticDenialVerified: synthetic != nil && synthetic.Verified,
	}, nil
}

func validatePersistedSetupLifecycleReceipt(signer helmcrypto.Signer, receipt *contracts.Receipt, receiptID, descriptorHash, outputHash, workspacePathHash, operation string) error {
	if receipt == nil || receipt.ReceiptID != receiptID || receipt.ArgsHash != descriptorHash || receipt.OutputHash != outputHash {
		return fmt.Errorf("receipt identity or signed hashes differ from the prepared lifecycle observation")
	}
	sessionID := "codex-project:" + workspacePathHash
	if receipt.DecisionID != "decision/native-client/"+operation+"/"+receiptID || receipt.ExternalReferenceID != sessionID || receipt.ExecutorID != sessionID {
		return fmt.Errorf("receipt lifecycle identity does not match the prepared operation")
	}
	if receipt.Metadata["evidence_schema"] != setupCodexProjectLifecycleSchema || receipt.Metadata["lifecycle_operation"] != operation {
		return fmt.Errorf("receipt lifecycle metadata is incomplete")
	}
	switch operation {
	case "install":
		if receipt.Status != "DENY" || receipt.EffectID != "mcp.tools.call/file_write" {
			return fmt.Errorf("install lifecycle receipt has unexpected status or effect")
		}
	case "remove":
		if receipt.Status != "REVOKED" || receipt.EffectID != "native_client.setup/codex-project/remove" {
			return fmt.Errorf("remove lifecycle receipt has unexpected status or effect")
		}
	default:
		return fmt.Errorf("unsupported lifecycle operation %q", operation)
	}
	verified, err := verifySetupLifecycleReceiptWithSigner(signer, receipt)
	if err != nil {
		return err
	}
	if !verified {
		return fmt.Errorf("receipt signature does not verify under the local lifecycle authority")
	}
	return nil
}

func verifySetupLifecycleReceiptWithSigner(signer helmcrypto.Signer, receipt *contracts.Receipt) (bool, error) {
	if signer == nil || receipt == nil {
		return false, fmt.Errorf("lifecycle signer and receipt are required")
	}
	payload := []byte(helmcrypto.CanonicalizeReceipt(receipt.ReceiptID, receipt.DecisionID, receipt.EffectID, receipt.Status, receipt.OutputHash, receipt.PrevHash, receipt.LamportClock, receipt.ArgsHash))
	switch typed := signer.(type) {
	case *helmcrypto.HybridSigner:
		return typed.Verify(payload, receipt.Signature)
	default:
		verifier, err := helmcrypto.NewEd25519Verifier(signer.PublicKeyBytes())
		if err != nil {
			return false, err
		}
		return verifier.VerifyReceipt(receipt)
	}
}

func setupLifecycleReceiptPersisted(ctx context.Context, db *sql.DB, receiptID string) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(1) FROM receipts WHERE receipt_id = ?", receiptID).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func writeSetupLifecycleEvidence(dataDir string, evidence setupLifecycleEvidence) (string, error) {
	if !isSetupLifecycleReceiptID(evidence.ReceiptID) {
		return "", fmt.Errorf("lifecycle evidence receipt id is invalid")
	}
	securedDataDir, err := ensureSetupAuthorityDataDir(dataDir)
	if err != nil {
		return "", err
	}
	dataDir = securedDataDir
	if err := ensureSetupAuthoritySubdirectory(dataDir, "lifecycle-evidence"); err != nil {
		return "", fmt.Errorf("prepare lifecycle evidence directory: %w", err)
	}
	data, err := canonicalize.JCS(evidence)
	if err != nil {
		return "", err
	}
	path := setupLifecycleEvidencePath(dataDir, evidence.ReceiptID)
	state, err := readSetupFileState(path)
	if err != nil {
		return "", err
	}
	if state.Exists {
		if bytes.Equal(state.Data, data) {
			return path, nil
		}
		return "", fmt.Errorf("existing lifecycle evidence does not match the prepared receipt")
	}
	if err := writeSetupPrivateFile(path, data); err != nil {
		return "", err
	}
	return path, nil
}

func setupLifecycleEvidencePath(dataDir, receiptID string) string {
	return filepath.Join(dataDir, "lifecycle-evidence", receiptID+".json")
}

func verifySetupLifecycleEvidence(dataDir string, receipt *contracts.Receipt) (setupLifecycleEvidence, error) {
	if receipt == nil || !isSetupLifecycleReceiptID(receipt.ReceiptID) {
		return setupLifecycleEvidence{}, fmt.Errorf("receipt id is required")
	}
	securedDataDir, err := requireSetupAuthorityDataDir(dataDir)
	if err != nil {
		return setupLifecycleEvidence{}, err
	}
	dataDir = securedDataDir
	if _, err := requireSetupAuthoritySubdirectory(dataDir, "lifecycle-evidence"); err != nil {
		return setupLifecycleEvidence{}, fmt.Errorf("inspect lifecycle evidence directory: %w", err)
	}
	state, err := readSetupFileState(setupLifecycleEvidencePath(dataDir, receipt.ReceiptID))
	if err != nil {
		return setupLifecycleEvidence{}, err
	}
	if !state.Exists {
		return setupLifecycleEvidence{}, fmt.Errorf("lifecycle evidence does not exist")
	}
	var evidence setupLifecycleEvidence
	if err := decodeCanonicalSetupJSON(state.Data, &evidence); err != nil {
		return setupLifecycleEvidence{}, fmt.Errorf("decode lifecycle evidence: %w", err)
	}
	if evidence.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Descriptor.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Observation.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.ReceiptID != receipt.ReceiptID {
		return setupLifecycleEvidence{}, fmt.Errorf("evidence receipt id does not match signed receipt")
	}
	argsHash, err := canonicalize.CanonicalHash(evidence.Descriptor)
	if err != nil {
		return setupLifecycleEvidence{}, fmt.Errorf("hash lifecycle evidence descriptor: %w", err)
	}
	if argsHash != receipt.ArgsHash {
		return setupLifecycleEvidence{}, fmt.Errorf("lifecycle evidence descriptor hash does not match signed receipt")
	}
	outputHash, err := canonicalize.CanonicalHash(evidence.Observation)
	if err != nil {
		return setupLifecycleEvidence{}, fmt.Errorf("hash lifecycle evidence observation: %w", err)
	}
	if outputHash != receipt.OutputHash {
		return setupLifecycleEvidence{}, fmt.Errorf("lifecycle evidence observation hash does not match signed receipt")
	}
	return evidence, nil
}

func snapshotSetupFile(path string) (setupFileSnapshot, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return setupFileSnapshot{}, err
	}
	snapshot := setupFileSnapshot{PathHash: canonicalize.HashBytes([]byte(state.Path))}
	if !state.Exists {
		return snapshot, nil
	}
	snapshot.Exists = true
	snapshot.ContentHash = canonicalize.HashBytes(state.Data)
	return snapshot, nil
}

func verifyCodexProjectSyntheticDenial(dataDir string, signer helmcrypto.Signer) (setupSyntheticDenial, error) {
	probeID, err := newSetupLifecycleReceiptID()
	if err != nil {
		return setupSyntheticDenial{}, err
	}
	probeDir := filepath.Join(dataDir, "synthetic-denial")
	if err := ensureSetupAuthoritySubdirectory(dataDir, "synthetic-denial"); err != nil {
		return setupSyntheticDenial{}, fmt.Errorf("create synthetic denial probe dir: %w", err)
	}
	defer func() { _ = os.Remove(probeDir) }()
	sentinel := filepath.Join(probeDir, probeID+".sentinel")
	if _, err := os.Lstat(sentinel); err == nil {
		return setupSyntheticDenial{}, fmt.Errorf("synthetic denial sentinel already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return setupSyntheticDenial{}, fmt.Errorf("inspect synthetic denial sentinel: %w", err)
	}

	dispatched := false
	_, executor, err := newLocalMCPRuntimeWithSignerAndHandler(signer, func(ctx context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		dispatched = true
		return runLocalMCPTool(ctx, req)
	})
	if err != nil {
		return setupSyntheticDenial{}, fmt.Errorf("start local MCP runtime for synthetic denial: %w", err)
	}
	response, err := executor(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "file_write",
		SessionID: "setup-codex-project-synthetic-denial",
		Arguments: map[string]any{
			"path":    sentinel,
			"content": "must-not-exist",
		},
	})
	if err != nil {
		return setupSyntheticDenial{}, fmt.Errorf("run synthetic file_write: %w", err)
	}
	if _, err := os.Lstat(sentinel); err == nil {
		_ = os.Remove(sentinel)
		return setupSyntheticDenial{}, fmt.Errorf("synthetic file_write reached the executor; sentinel removed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return setupSyntheticDenial{}, fmt.Errorf("inspect synthetic denial sentinel after execution: %w", err)
	}
	if !response.Evaluated || !response.IsError || !strings.HasPrefix(response.Content, "Access Denied:") {
		return setupSyntheticDenial{}, fmt.Errorf("synthetic file_write did not produce an evaluated firewall denial")
	}
	if dispatched {
		return setupSyntheticDenial{}, fmt.Errorf("synthetic file_write reached the executor")
	}

	return setupSyntheticDenial{
		Verified:            true,
		Dispatched:          dispatched,
		SentinelAbsent:      true,
		ResponseContentHash: canonicalize.HashBytes([]byte(response.Content)),
	}, nil
}

func newSetupLifecycleReceiptID() (string, error) {
	var random [16]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate lifecycle receipt id: %w", err)
	}
	return "rcpt_native_client_" + hex.EncodeToString(random[:]), nil
}
