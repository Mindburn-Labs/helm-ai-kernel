package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	setupCodexProjectBindingSchema = "helm.native-client.install-binding/v1"
	setupCodexProjectBindingFile   = "codex-project-binding.json"
)

// setupCodexProjectBinding is a local pointer to a signed install receipt and
// its exact configuration snapshots. It contains hashes, not user-owned
// configuration bytes. Automatic removal only acts when this binding and its
// signed evidence prove that the exact currently-installed configuration was
// installed by this Kernel state.
type setupCodexProjectBinding struct {
	SchemaVersion           string `json:"schema_version"`
	WorkspacePathHash       string `json:"workspace_path_hash"`
	DataDirPathHash         string `json:"data_dir_path_hash"`
	ConfiguredBinaryPath    string `json:"configured_binary_path"`
	BinaryContentHash       string `json:"binary_content_hash"`
	InstallReceiptID        string `json:"install_receipt_id"`
	ClientConfigContentHash string `json:"client_config_content_hash"`
	HookConfigContentHash   string `json:"hook_config_content_hash"`
}

type setupLifecycleStatePresence uint8

const (
	setupLifecycleStateAbsent setupLifecycleStatePresence = iota
	setupLifecycleStateComplete
)

func setupCodexProjectBindingPath(dataDir string) string {
	return currentCodexProjectPaths(dataDir).BindingPath
}

func inspectSetupLifecycleStatePresence(dataDir string) (setupLifecycleStatePresence, error) {
	securedDataDir, err := requireSetupAuthorityDataDir(dataDir)
	if err != nil {
		return setupLifecycleStateAbsent, err
	}
	dataDir = securedDataDir
	rootKey, err := readSetupExistingPrivateFile(filepath.Join(dataDir, "root.key"))
	if err != nil {
		return setupLifecycleStateAbsent, err
	}
	database, err := inspectSetupRegularFile(filepath.Join(dataDir, "helm.db"))
	if err != nil {
		return setupLifecycleStateAbsent, err
	}
	if !rootKey.Exists && !database.Exists {
		return setupLifecycleStateAbsent, nil
	}
	if !rootKey.Exists || !database.Exists {
		return setupLifecycleStateAbsent, fmt.Errorf("incomplete local lifecycle state; root.key and helm.db must either both exist or both be absent")
	}
	return setupLifecycleStateComplete, nil
}

// loadExistingSetupLifecycleSignerForSignature chooses verification authority
// from the persisted signature envelope, never from HELM_RECEIPT_PROFILE.
// The environment controls new receipt issuance only; using it to verify an
// existing installation makes a valid hybrid proof unverifiable after a
// profile rollout or rollback.
func loadExistingSetupLifecycleSignerForSignature(dataDir, signature string) (helmcrypto.Signer, error) {
	presence, err := inspectSetupLifecycleStatePresence(dataDir)
	if err != nil {
		return nil, err
	}
	if presence != setupLifecycleStateComplete {
		return nil, fmt.Errorf("no existing local lifecycle signer and receipt store")
	}
	edSigner, err := loadExistingEd25519Root(dataDir)
	if err != nil {
		return nil, err
	}
	if helmcrypto.ReceiptSignatureProfile(signature) != helmcrypto.ReceiptProfileHybrid {
		return edSigner, nil
	}
	mldsaSigner, err := loadExistingMLDSARoot(dataDir)
	if err != nil {
		return nil, err
	}
	return helmcrypto.NewHybridSignerFromSigners(edSigner, mldsaSigner, "root")
}

func validateSetupCodexProjectBinding(binding *setupCodexProjectBinding) error {
	if binding == nil || binding.SchemaVersion != setupCodexProjectBindingSchema {
		return fmt.Errorf("unsupported Codex project install binding")
	}
	if !isSetupSHA256(binding.WorkspacePathHash) || !isSetupSHA256(binding.DataDirPathHash) || !isSetupSHA256(binding.BinaryContentHash) || !isSetupSHA256(binding.ClientConfigContentHash) || !isSetupSHA256(binding.HookConfigContentHash) {
		return fmt.Errorf("Codex project install binding has invalid hashes")
	}
	if !isSetupLifecycleReceiptID(binding.InstallReceiptID) || !filepath.IsAbs(binding.ConfiguredBinaryPath) || strings.ContainsRune(binding.ConfiguredBinaryPath, '\x00') {
		return fmt.Errorf("Codex project install binding has invalid receipt or Kernel binary path")
	}
	return nil
}

func readSetupCodexProjectBinding(dataDir string) (*setupCodexProjectBinding, error) {
	stateExists, err := inspectCodexProjectStateAuthority(dataDir)
	if err != nil {
		return nil, fmt.Errorf("inspect Codex project binding authority state: %w", err)
	}
	if !stateExists {
		return nil, nil
	}
	return readSetupCodexProjectBindingAtPath(setupCodexProjectBindingPath(dataDir))
}

// readSetupCodexProjectBindingAtPath keeps the parser independent from the
// current v1 namespace so the explicit legacy migration path can validate an
// old binding before it is copied into active state. Callers must never use it
// as a runtime fallback: an unscoped path is not project authority.
func readSetupCodexProjectBindingAtPath(path string) (*setupCodexProjectBinding, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return nil, nil
	}
	var binding setupCodexProjectBinding
	if err := decodeCanonicalSetupJSON(state.Data, &binding); err != nil {
		return nil, fmt.Errorf("decode Codex project install binding: %w", err)
	}
	if err := validateSetupCodexProjectBinding(&binding); err != nil {
		return nil, err
	}
	return &binding, nil
}

func decodeCanonicalSetupJSON(data []byte, value any) error {
	if err := jsonUnmarshalSetup(data, value); err != nil {
		return err
	}
	canonical, err := canonicalize.JCS(value)
	if err != nil {
		return err
	}
	if string(canonical) != string(data) {
		return fmt.Errorf("JSON is not canonical")
	}
	return nil
}

// jsonUnmarshalSetup is a narrow seam for canonical local-state parsing. It
// keeps the binding's strict JCS check self-contained without accepting a
// duplicate-key or whitespace-normalized representation.
var jsonUnmarshalSetup = func(data []byte, value any) error {
	return json.Unmarshal(data, value)
}

func buildSetupCodexProjectBinding(opts setupOptions, summary setupSummary, receiptID string, clientState, hookState setupFileState) (setupCodexProjectBinding, error) {
	if !clientState.Exists || !hookState.Exists {
		return setupCodexProjectBinding{}, fmt.Errorf("Codex project install binding requires both local configuration files")
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return setupCodexProjectBinding{}, err
	}
	identity, err := inspectSetupKernelBinary(summary.BinaryPath)
	if err != nil {
		return setupCodexProjectBinding{}, err
	}
	if !isSetupLifecycleReceiptID(receiptID) {
		return setupCodexProjectBinding{}, fmt.Errorf("invalid Codex project install receipt id")
	}
	return setupCodexProjectBinding{
		SchemaVersion:           setupCodexProjectBindingSchema,
		WorkspacePathHash:       workspacePathHash,
		DataDirPathHash:         canonicalize.HashBytes([]byte(opts.DataDir)),
		ConfiguredBinaryPath:    identity.Path,
		BinaryContentHash:       identity.ContentHash,
		InstallReceiptID:        receiptID,
		ClientConfigContentHash: canonicalize.HashBytes(clientState.Data),
		HookConfigContentHash:   canonicalize.HashBytes(hookState.Data),
	}, nil
}

func marshalSetupCodexProjectBinding(binding setupCodexProjectBinding) ([]byte, error) {
	if err := validateSetupCodexProjectBinding(&binding); err != nil {
		return nil, err
	}
	return canonicalize.JCS(binding)
}

type setupCodexProjectInstallProof struct {
	Binding  *setupCodexProjectBinding
	Binary   setupKernelBinaryIdentity
	Receipt  *contracts.Receipt
	Evidence setupLifecycleEvidence
	Signer   helmcrypto.Signer
}

// loadCodexProjectInstallProof verifies the signed install record without
// looking at a mutable live config. Recovery needs this distinction: after a
// crash, one config file may already be in its journaled removal state while
// the binding correctly describes the pre-removal install state.
func loadCodexProjectInstallProof(opts setupOptions) (setupCodexProjectInstallProof, error) {
	binding, err := readSetupCodexProjectBinding(opts.DataDir)
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if binding == nil {
		return setupCodexProjectInstallProof{}, fmt.Errorf("no prior HELM install binding proves this Codex project configuration; refusing automatic removal")
	}
	return validateCodexProjectInstallProof(opts, binding)
}

func validateCodexProjectInstallProof(opts setupOptions, binding *setupCodexProjectBinding) (setupCodexProjectInstallProof, error) {
	if err := validateSetupCodexProjectBinding(binding); err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	presence, err := inspectSetupLifecycleStatePresence(opts.DataDir)
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if presence != setupLifecycleStateComplete {
		return setupCodexProjectInstallProof{}, fmt.Errorf("no prior HELM lifecycle state proves this Codex project configuration; refusing automatic removal")
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if binding.WorkspacePathHash != workspacePathHash || binding.DataDirPathHash != canonicalize.HashBytes([]byte(opts.DataDir)) {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex project install binding is for a different workspace or data-dir")
	}
	identity, err := inspectSetupKernelBinary(binding.ConfiguredBinaryPath)
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if identity.ContentHash != binding.BinaryContentHash {
		return setupCodexProjectInstallProof{}, fmt.Errorf("configured Kernel binary no longer matches its proven install binding")
	}

	receipt, err := readSetupLifecycleReceiptReadOnly(context.Background(), opts.DataDir, binding.InstallReceiptID)
	if err != nil {
		return setupCodexProjectInstallProof{}, fmt.Errorf("read proven Codex install receipt: %w", err)
	}
	signer, err := loadExistingSetupLifecycleSignerForSignature(opts.DataDir, receipt.Signature)
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if receipt.ReceiptID != binding.InstallReceiptID ||
		receipt.DecisionID != "decision/native-client/install/"+binding.InstallReceiptID ||
		receipt.EffectID != "mcp.tools.call/file_write" ||
		receipt.Status != "DENY" ||
		receipt.ExternalReferenceID != "codex-project:"+workspacePathHash ||
		receipt.ExecutorID != "codex-project:"+workspacePathHash ||
		receipt.Metadata["evidence_schema"] != setupCodexProjectLifecycleSchema ||
		receipt.Metadata["lifecycle_operation"] != "install" {
		return setupCodexProjectInstallProof{}, fmt.Errorf("install binding receipt is not an exact Codex install lifecycle receipt")
	}
	verified, err := verifySetupLifecycleReceiptWithSigner(signer, receipt)
	if err != nil || !verified {
		return setupCodexProjectInstallProof{}, fmt.Errorf("install binding receipt signature does not verify under local lifecycle authority")
	}
	evidence, err := verifySetupLifecycleEvidence(opts.DataDir, receipt)
	if err != nil {
		return setupCodexProjectInstallProof{}, fmt.Errorf("verify Codex install binding evidence: %w", err)
	}
	clientPath, err := filepath.Abs(setupClientConfigPath(opts))
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	hookPath, err := filepath.Abs(setupHookConfigPath(opts))
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if evidence.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Descriptor.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Observation.SchemaVersion != setupCodexProjectLifecycleSchema ||
		evidence.Descriptor.Client != "codex" ||
		evidence.Descriptor.Scope != "project" ||
		evidence.Descriptor.Operation != "install" ||
		evidence.Observation.Operation != "install" ||
		evidence.Descriptor.WorkspacePathHash != binding.WorkspacePathHash ||
		evidence.Descriptor.DataDirPathHash != binding.DataDirPathHash ||
		evidence.Descriptor.KernelBinaryPath != binding.ConfiguredBinaryPath ||
		evidence.Descriptor.KernelBinaryContentHash != binding.BinaryContentHash ||
		!evidence.Descriptor.ExpectedMCP || !evidence.Descriptor.ExpectedHook ||
		!evidence.Observation.MCPConfigured || !evidence.Observation.HookConfigured ||
		!evidence.Observation.ClientConfig.Exists || !evidence.Observation.HookConfig.Exists ||
		evidence.Observation.ClientConfig.PathHash != canonicalize.HashBytes([]byte(clientPath)) ||
		evidence.Observation.HookConfig.PathHash != canonicalize.HashBytes([]byte(hookPath)) ||
		evidence.Observation.ClientConfig.ContentHash != binding.ClientConfigContentHash ||
		evidence.Observation.HookConfig.ContentHash != binding.HookConfigContentHash ||
		evidence.Observation.SyntheticDenial == nil || !evidence.Observation.SyntheticDenial.Verified || evidence.Observation.SyntheticDenial.Dispatched || !evidence.Observation.SyntheticDenial.SentinelAbsent {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex install binding evidence is incomplete")
	}
	return setupCodexProjectInstallProof{Binding: binding, Binary: identity, Receipt: receipt, Evidence: evidence, Signer: signer}, nil
}

func validateCodexProjectInstallBindingForCurrentConfig(opts setupOptions, clientState, hookState setupFileState) (setupCodexProjectInstallProof, error) {
	proof, err := loadCodexProjectInstallProof(opts)
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	return validateCodexProjectInstallProofForCurrentConfig(opts, proof, clientState, hookState)
}

// validateCodexProjectInstallProofForCurrentConfig is shared by ordinary
// provenance checks and the explicit legacy-binding migration. It accepts an
// already-verified proof so migration can prove the source binding before it
// publishes any v1 state.
func validateCodexProjectInstallProofForCurrentConfig(opts setupOptions, proof setupCodexProjectInstallProof, clientState, hookState setupFileState) (setupCodexProjectInstallProof, error) {
	if proof.Binding == nil {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex project install proof has no binding")
	}
	if !clientState.Exists || !hookState.Exists ||
		canonicalize.HashBytes(clientState.Data) != proof.Binding.ClientConfigContentHash ||
		canonicalize.HashBytes(hookState.Data) != proof.Binding.HookConfigContentHash {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex project config differs from its proven install binding; refusing automatic removal")
	}
	server, err := readCodexMCPServerFromBytes(clientState.Data)
	if err != nil || server == nil {
		if err != nil {
			return setupCodexProjectInstallProof{}, err
		}
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex project install binding has no configured MCP server")
	}
	if server.Command != proof.Binding.ConfiguredBinaryPath || !isOwnedCodexMCPServerForDataDir(*server, opts.DataDir) {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex MCP server does not match its proven install binding")
	}
	hasHook, err := hasOwnedSetupHookInBytes(hookState.Data, opts.Target, setupHookCommand(opts, proof.Binary.Path))
	if err != nil {
		return setupCodexProjectInstallProof{}, err
	}
	if !hasHook {
		return setupCodexProjectInstallProof{}, fmt.Errorf("Codex hook does not match its proven install binding")
	}
	return proof, nil
}

func validateCodexProjectRemovalProvenance(opts setupOptions, summary setupSummary, clientState, hookState setupFileState) (string, error) {
	proof, err := validateCodexProjectInstallBindingForCurrentConfig(opts, clientState, hookState)
	if err != nil {
		return "", err
	}
	if summary.BinaryPath != proof.Binary.Path {
		return "", fmt.Errorf("current Kernel executable path does not match the proven Codex install binding")
	}
	return proof.Binary.Path, nil
}

// validateStagedCodexProjectInstallBinding makes the staged artifact part of
// the transaction contract before any shared config is touched. A staged file
// is not authority merely because its hash appears in a mutable journal.
func validateStagedCodexProjectInstallBinding(opts setupOptions, journal *setupRecoveryJournal) (*setupCodexProjectBinding, error) {
	if err := validateSetupRecoveryJournal(journal); err != nil {
		return nil, err
	}
	if journal.Operation != "install" {
		return nil, fmt.Errorf("staged install binding requires an install recovery journal")
	}
	bindingPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileBinding)
	if err != nil {
		return nil, err
	}
	stagePath, err := setupRecoverySafeStagePath(opts.DataDir, bindingPlan.StageFile)
	if err != nil {
		return nil, err
	}
	state, err := readSetupFileState(stagePath)
	if err != nil {
		return nil, err
	}
	if !state.Exists || !setupRecoveryFingerprintMatchesState(bindingPlan.After, state) {
		return nil, fmt.Errorf("staged Codex project binding does not match its recovery fingerprint")
	}
	var binding setupCodexProjectBinding
	if err := decodeCanonicalSetupJSON(state.Data, &binding); err != nil {
		return nil, fmt.Errorf("decode staged Codex project binding: %w", err)
	}
	if err := validateSetupCodexProjectBindingAgainstJournal(opts, journal, &binding); err != nil {
		return nil, err
	}
	return &binding, nil
}

func validateSetupCodexProjectBindingAgainstJournal(opts setupOptions, journal *setupRecoveryJournal, binding *setupCodexProjectBinding) error {
	if err := validateSetupCodexProjectBinding(binding); err != nil {
		return err
	}
	if binding.InstallReceiptID != journal.LifecycleReceiptID ||
		binding.WorkspacePathHash != journal.WorkspacePathHash ||
		binding.DataDirPathHash != journal.DataDirPathHash ||
		binding.ConfiguredBinaryPath != journal.BinaryPath ||
		binding.BinaryContentHash != journal.BinaryContentHash ||
		binding.DataDirPathHash != canonicalize.HashBytes([]byte(opts.DataDir)) {
		return fmt.Errorf("staged Codex project binding does not match its recovery identity")
	}
	mcpPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileMCP)
	if err != nil {
		return err
	}
	hookPlan, err := lookupSetupRecoveryFilePlan(journal, setupRecoveryFileHook)
	if err != nil {
		return err
	}
	if !mcpPlan.After.Exists || !hookPlan.After.Exists ||
		mcpPlan.After.ContentHash != binding.ClientConfigContentHash ||
		hookPlan.After.ContentHash != binding.HookConfigContentHash {
		return fmt.Errorf("staged Codex project binding does not match the deterministic post-install config plans")
	}
	return nil
}

// validateStagedCodexProjectInstallBindingForCurrentConfig is called only
// after the lifecycle receipt has been recorded. It proves the same staged
// binding against that signed receipt/evidence and the exact post-install
// config before the binding is published to its durable final path.
func validateStagedCodexProjectInstallBindingForCurrentConfig(opts setupOptions, journal *setupRecoveryJournal) (*setupCodexProjectBinding, error) {
	binding, err := validateStagedCodexProjectInstallBinding(opts, journal)
	if err != nil {
		return nil, err
	}
	clientState, err := readSetupFileState(setupClientConfigPath(opts))
	if err != nil {
		return nil, err
	}
	hookState, err := readSetupFileState(setupHookConfigPath(opts))
	if err != nil {
		return nil, err
	}
	if !clientState.Exists || !hookState.Exists ||
		canonicalize.HashBytes(clientState.Data) != binding.ClientConfigContentHash ||
		canonicalize.HashBytes(hookState.Data) != binding.HookConfigContentHash {
		return nil, fmt.Errorf("post-install Codex config does not match the staged binding")
	}
	proof, err := validateCodexProjectInstallProof(opts, binding)
	if err != nil {
		return nil, err
	}
	if proof.Binary.Path != binding.ConfiguredBinaryPath || proof.Receipt.ReceiptID != journal.LifecycleReceiptID {
		return nil, fmt.Errorf("staged Codex project binding proof does not match the recovered lifecycle receipt")
	}
	return binding, nil
}
