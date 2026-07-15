package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// setupRecoveryCommittedMarkerPayload is the signed terminal assertion. It
// deliberately binds only identifiers and hashes; no user-owned config bytes
// enter recovery state.
type setupRecoveryCommittedMarkerPayload struct {
	SchemaVersion      string `json:"schema_version"`
	State              string `json:"state"`
	TransactionID      string `json:"transaction_id"`
	LifecycleReceiptID string `json:"lifecycle_receipt_id"`
	JournalHash        string `json:"journal_hash"`
	Operation          string `json:"operation"`
	Target             string `json:"target"`
	Scope              string `json:"scope"`
	WorkspacePathHash  string `json:"workspace_path_hash"`
	DataDirPathHash    string `json:"data_dir_path_hash"`
	BinaryPath         string `json:"binary_path"`
	BinaryContentHash  string `json:"binary_content_hash"`
}

func setupRecoveryJournalHash(journal *setupRecoveryJournal) (string, error) {
	if err := validateSetupRecoveryJournal(journal); err != nil {
		return "", err
	}
	data, err := canonicalize.JCS(journal)
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(data), nil
}

func setupRecoveryCommittedMarkerPayloadBytes(marker *setupRecoveryMarker) ([]byte, error) {
	if marker == nil || !setupRecoveryMarkerHasTerminalPayload(marker) {
		return nil, fmt.Errorf("committed setup recovery marker has no complete terminal proof")
	}
	return canonicalize.JCS(setupRecoveryCommittedMarkerPayload{
		SchemaVersion:      marker.SchemaVersion,
		State:              marker.State,
		TransactionID:      marker.TransactionID,
		LifecycleReceiptID: marker.LifecycleReceiptID,
		JournalHash:        marker.JournalHash,
		Operation:          marker.Operation,
		Target:             marker.Target,
		Scope:              marker.Scope,
		WorkspacePathHash:  marker.WorkspacePathHash,
		DataDirPathHash:    marker.DataDirPathHash,
		BinaryPath:         marker.BinaryPath,
		BinaryContentHash:  marker.BinaryContentHash,
	})
}

func newSignedSetupRecoveryCommittedMarker(dataDir string, journal *setupRecoveryJournal) (setupRecoveryMarker, error) {
	journalHash, err := setupRecoveryJournalHash(journal)
	if err != nil {
		return setupRecoveryMarker{}, err
	}
	marker := setupRecoveryMarker{
		SchemaVersion:      setupRecoveryMarkerSchema,
		State:              setupRecoveryMarkerStateCommitted,
		TransactionID:      journal.TransactionID,
		LifecycleReceiptID: journal.LifecycleReceiptID,
		JournalHash:        journalHash,
		Operation:          journal.Operation,
		Target:             journal.Target,
		Scope:              journal.Scope,
		WorkspacePathHash:  journal.WorkspacePathHash,
		DataDirPathHash:    journal.DataDirPathHash,
		BinaryPath:         journal.BinaryPath,
		BinaryContentHash:  journal.BinaryContentHash,
	}
	payload, err := setupRecoveryCommittedMarkerPayloadBytes(&marker)
	if err != nil {
		return setupRecoveryMarker{}, err
	}
	receipt, err := readSetupLifecycleReceiptReadOnly(context.Background(), dataDir, journal.LifecycleReceiptID)
	if err != nil {
		return setupRecoveryMarker{}, fmt.Errorf("read lifecycle receipt for committed recovery marker: %w", err)
	}
	signer, err := loadExistingSetupLifecycleSignerForSignature(dataDir, receipt.Signature)
	if err != nil {
		return setupRecoveryMarker{}, fmt.Errorf("load existing lifecycle signer for committed recovery marker: %w", err)
	}
	marker.Signature, err = signer.Sign(payload)
	if err != nil {
		return setupRecoveryMarker{}, fmt.Errorf("sign committed recovery marker: %w", err)
	}
	if err := validateSetupRecoveryMarker(&marker); err != nil {
		return setupRecoveryMarker{}, err
	}
	return marker, nil
}

func verifySetupRecoveryMarkerSignature(signer helmcrypto.Signer, marker *setupRecoveryMarker) (bool, error) {
	payload, err := setupRecoveryCommittedMarkerPayloadBytes(marker)
	if err != nil {
		return false, err
	}
	switch typed := signer.(type) {
	case *helmcrypto.HybridSigner:
		return typed.Verify(payload, marker.Signature)
	default:
		signature, err := hex.DecodeString(marker.Signature)
		if err != nil {
			return false, err
		}
		verifier, err := helmcrypto.NewEd25519Verifier(signer.PublicKeyBytes())
		if err != nil {
			return false, err
		}
		return verifier.Verify(payload, signature), nil
	}
}

// verifyCommittedSetupRecoveryTerminal prevents a filename-shaped COMMITTED
// marker from opening the runtime gate. With a journal present, a failed
// verification simply leaves the transaction pending and resumable. A
// marker-only crash residue must independently prove the receipt, evidence,
// config snapshots, and (for install) final binding before it is cleaned.
func verifyCommittedSetupRecoveryTerminal(dataDir string, marker *setupRecoveryMarker, journal *setupRecoveryJournal) (bool, error) {
	if marker == nil || marker.State != setupRecoveryMarkerStateCommitted || !setupRecoveryMarkerHasTerminalProof(marker) {
		return false, nil
	}
	if journal != nil {
		journalHash, err := setupRecoveryJournalHash(journal)
		if err != nil {
			return false, err
		}
		if marker.TransactionID != journal.TransactionID ||
			marker.LifecycleReceiptID != journal.LifecycleReceiptID ||
			marker.JournalHash != journalHash ||
			marker.Operation != journal.Operation ||
			marker.Target != journal.Target ||
			marker.Scope != journal.Scope ||
			marker.WorkspacePathHash != journal.WorkspacePathHash ||
			marker.DataDirPathHash != journal.DataDirPathHash ||
			marker.BinaryPath != journal.BinaryPath ||
			marker.BinaryContentHash != journal.BinaryContentHash {
			return false, nil
		}
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return false, err
	}
	if marker.WorkspacePathHash != workspacePathHash || marker.DataDirPathHash != canonicalize.HashBytes([]byte(dataDir)) {
		return false, nil
	}
	identity, err := inspectSetupKernelBinary(marker.BinaryPath)
	if err != nil || identity.Path != marker.BinaryPath || identity.ContentHash != marker.BinaryContentHash {
		return false, nil
	}
	opts := setupOptions{Target: marker.Target, Scope: marker.Scope, DataDir: dataDir}
	summary, err := buildSetupSummary(opts)
	if err != nil || summary.BinaryPath != marker.BinaryPath {
		return false, nil
	}
	markerSigner, err := loadExistingSetupLifecycleSignerForSignature(dataDir, marker.Signature)
	if err != nil {
		return false, err
	}
	verifiedMarker, err := verifySetupRecoveryMarkerSignature(markerSigner, marker)
	if err != nil || !verifiedMarker {
		return false, nil
	}
	receipt, err := readSetupLifecycleReceiptReadOnly(context.Background(), dataDir, marker.LifecycleReceiptID)
	if err != nil {
		return false, err
	}
	receiptSigner, err := loadExistingSetupLifecycleSignerForSignature(dataDir, receipt.Signature)
	if err != nil {
		return false, err
	}
	evidence, err := verifySetupLifecycleEvidence(dataDir, receipt)
	if err != nil {
		return false, err
	}
	descriptorHash, err := canonicalize.CanonicalHash(evidence.Descriptor)
	if err != nil {
		return false, err
	}
	observationHash, err := canonicalize.CanonicalHash(evidence.Observation)
	if err != nil {
		return false, err
	}
	if err := validatePersistedSetupLifecycleReceipt(receiptSigner, receipt, marker.LifecycleReceiptID, descriptorHash, observationHash, workspacePathHash, marker.Operation); err != nil {
		return false, nil
	}
	if evidence.Descriptor.Client != marker.Target || evidence.Descriptor.Scope != marker.Scope || evidence.Descriptor.Operation != marker.Operation ||
		evidence.Descriptor.WorkspacePathHash != marker.WorkspacePathHash || evidence.Descriptor.DataDirPathHash != marker.DataDirPathHash ||
		evidence.Descriptor.KernelBinaryPath != marker.BinaryPath || evidence.Descriptor.KernelBinaryContentHash != marker.BinaryContentHash ||
		evidence.Observation.Operation != marker.Operation || evidence.Observation.WorkspacePathHash != marker.WorkspacePathHash || evidence.Observation.DataDirPathHash != marker.DataDirPathHash {
		return false, nil
	}
	if ok, err := setupLifecycleSnapshotMatchesCurrent(evidence.Observation.ClientConfig, summary.ClientConfigPath); err != nil || !ok {
		return false, err
	}
	if ok, err := setupLifecycleSnapshotMatchesCurrent(evidence.Observation.HookConfig, summary.HookConfigPath); err != nil || !ok {
		return false, err
	}

	switch marker.Operation {
	case "install":
		if !evidence.Descriptor.ExpectedMCP || !evidence.Descriptor.ExpectedHook || !evidence.Observation.MCPConfigured || !evidence.Observation.HookConfigured {
			return false, nil
		}
		clientState, err := readSetupFileState(summary.ClientConfigPath)
		if err != nil {
			return false, err
		}
		hookState, err := readSetupFileState(summary.HookConfigPath)
		if err != nil {
			return false, err
		}
		proof, err := validateCodexProjectInstallBindingForCurrentConfig(opts, clientState, hookState)
		if err != nil || proof.Binding.InstallReceiptID != marker.LifecycleReceiptID {
			return false, nil
		}
	case "remove":
		if evidence.Descriptor.ExpectedMCP || evidence.Descriptor.ExpectedHook || evidence.Observation.MCPConfigured || evidence.Observation.HookConfigured {
			return false, nil
		}
		binding, err := readSetupCodexProjectBinding(dataDir)
		if err != nil {
			return false, err
		}
		if binding != nil {
			return false, nil
		}
		refreshSetupConfiguration(opts, &summary)
		if summary.MCPConfigured || summary.HookConfigured {
			return false, nil
		}
	default:
		return false, nil
	}
	return true, nil
}

func setupLifecycleSnapshotMatchesCurrent(expected setupFileSnapshot, path string) (bool, error) {
	actual, err := snapshotSetupFile(path)
	if err != nil {
		return false, err
	}
	return expected.PathHash == actual.PathHash && expected.Exists == actual.Exists && expected.ContentHash == actual.ContentHash, nil
}
