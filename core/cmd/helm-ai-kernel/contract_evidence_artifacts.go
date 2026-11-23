package main

import (
	"encoding/json"
	"fmt"
	"strings"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func addReferencedSurfaceArtifacts(files map[string][]byte, surfaces *boundarypkg.SurfaceRegistry, receipts []*contracts.Receipt) error {
	for _, scope := range surfaces.ListVerificationScopes() {
		if err := addSurfaceArtifactIfReferenced(files, "verification_scopes/", scope.VerificationScopeID, scope, receipts); err != nil {
			return err
		}
	}
	for _, trace := range surfaces.ListHarnessTraces() {
		if err := addSurfaceArtifactIfReferenced(files, "harness_traces/", trace.TraceID, trace, receipts); err != nil {
			return err
		}
	}
	for _, tx := range surfaces.ListPlanTransactions() {
		if err := addSurfaceArtifactIfReferenced(files, "plan_transactions/", tx.PlanTransactionID, tx, receipts); err != nil {
			return err
		}
	}
	for _, change := range surfaces.ListHarnessChanges() {
		if err := addSurfaceArtifactIfReferenced(files, "harness_change_contracts/", change.ChangeContractID, change, receipts); err != nil {
			return err
		}
	}
	for _, action := range surfaces.ListGroundedActions() {
		if err := addSurfaceArtifactIfReferenced(files, "grounded_action_refs/", action.GroundedActionID, action, receipts); err != nil {
			return err
		}
	}
	for _, receipt := range surfaces.ListGUIReceipts() {
		if err := addSurfaceArtifactIfReferenced(files, "gui_action_receipts/", receipt.ReceiptID, receipt, receipts); err != nil {
			return err
		}
	}
	return nil
}

func addSurfaceArtifactIfReferenced(files map[string][]byte, prefix, id string, artifact any, receipts []*contracts.Receipt) error {
	data, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal %s artifact %s: %w", strings.TrimSuffix(prefix, "/"), id, err)
	}
	for _, receipt := range receipts {
		if evidenceArtifactReferencesReceipt(prefix, data, receipt) {
			files[prefix+id+".json"] = data
			return nil
		}
	}
	return nil
}

// evidenceArtifactRequirements is the one list of artifacts a receipt can
// require in its bundle; the check and the decision to run it both read it.
var evidenceArtifactRequirements = []struct {
	prefix   string
	label    string
	requires func(*contracts.Receipt) bool
}{
	{"verification_scopes/", "verification scope", receiptRequiresVerificationScope},
	{"harness_traces/", "harness trace", receiptRequiresHarnessTrace},
	{"plan_transactions/", "plan transaction", receiptRequiresPlanTransaction},
	{"harness_change_contracts/", "harness change contract", receiptRequiresHarnessChange},
	{"grounded_action_refs/", "grounded action ref", receiptRequiresGroundedAction},
}

func verifyHarnessEvidenceRequirements(bundle *evidenceBundle, receipts []*contracts.Receipt) []string {
	var errs []string
	for _, receipt := range receipts {
		for _, requirement := range evidenceArtifactRequirements {
			if requirement.requires(receipt) && !bundleHasReferencedSurfaceArtifact(bundle, requirement.prefix, receipt) {
				errs = append(errs, fmt.Sprintf("%s missing %s", receipt.ReceiptID, requirement.label))
			}
		}
	}
	return errs
}

func bundleHasReferencedSurfaceArtifact(bundle *evidenceBundle, prefix string, receipt *contracts.Receipt) bool {
	for name, data := range bundle.Files {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") && evidenceArtifactReferencesReceipt(prefix, data, receipt) {
			return true
		}
	}
	return false
}

func evidenceArtifactReferencesReceipt(prefix string, data []byte, receipt *contracts.Receipt) bool {
	switch prefix {
	case "verification_scopes/":
		var scope contracts.VerificationScope
		return json.Unmarshal(data, &scope) == nil && receiptRequiresVerificationScope(receipt) && (receiptReferencesArtifact(receipt, scope.VerificationScopeID, scope.ScopeHash) || receiptMetadataReferencesArtifact(receipt, "verification_scope_ref", scope.VerificationScopeID, scope.ScopeHash) || artifactReferencesReceipt(receipt, scope.ReceiptRefs...))
	case "harness_traces/":
		var trace contracts.HarnessTrace
		if json.Unmarshal(data, &trace) != nil || !receiptRequiresHarnessTrace(receipt) {
			return false
		}
		return receiptReferencesArtifact(receipt, trace.TraceID, trace.TraceHash) || receiptMetadataReferencesArtifact(receipt, "harness_trace_ref", trace.TraceID, trace.TraceHash) || artifactReferencesReceipt(receipt, trace.ReceiptRefs...)
	case "plan_transactions/":
		var tx contracts.PlanTransaction
		return json.Unmarshal(data, &tx) == nil && receiptRequiresPlanTransaction(receipt) && (receiptReferencesArtifact(receipt, tx.PlanTransactionID, tx.PlanHash, tx.TransactionHash) || receiptMetadataReferencesArtifact(receipt, "plan_transaction_ref", tx.PlanTransactionID, tx.PlanHash, tx.TransactionHash) || artifactReferencesReceipt(receipt, tx.ReceiptRefs...))
	case "harness_change_contracts/":
		var change contracts.HarnessChangeContract
		return json.Unmarshal(data, &change) == nil && receiptRequiresHarnessChange(receipt) && (receiptReferencesArtifact(receipt, change.ChangeContractID, change.ContractHash) || receiptMetadataReferencesArtifact(receipt, "harness_change_contract_ref", change.ChangeContractID, change.ContractHash) || artifactReferencesReceipt(receipt, change.ActivationReceiptRef))
	case "grounded_action_refs/":
		var action contracts.GroundedActionRef
		return json.Unmarshal(data, &action) == nil && receiptRequiresGroundedAction(receipt) && (receiptReferencesArtifact(receipt, action.GroundedActionID, action.GroundingHash, action.ProofGraphNodeRef, action.VerificationScopeRef) || receiptMetadataReferencesArtifact(receipt, "grounded_action_ref", action.GroundedActionID, action.GroundingHash, action.ProofGraphNodeRef, action.VerificationScopeRef) || artifactReferencesReceipt(receipt, action.ReceiptRefs...))
	case "gui_action_receipts/":
		var actionReceipt contracts.GUIActionReceipt
		return json.Unmarshal(data, &actionReceipt) == nil && receiptRequiresGroundedAction(receipt) && (receiptReferencesArtifact(receipt, actionReceipt.GroundedActionRef, actionReceipt.ReceiptHash) || receiptMetadataReferencesArtifact(receipt, "gui_action_receipt_ref", actionReceipt.GroundedActionRef, actionReceipt.ReceiptHash) || artifactReferencesReceipt(receipt, actionReceipt.ReceiptID))
	default:
		return false
	}
}

func receiptReferencesArtifact(receipt *contracts.Receipt, artifactRefs ...string) bool {
	if receipt == nil || len(receipt.Evidence) == 0 {
		return false
	}
	for _, value := range receipt.Evidence {
		for _, ref := range artifactRefs {
			if strings.TrimSpace(value) != "" && strings.TrimSpace(value) == strings.TrimSpace(ref) {
				return true
			}
		}
	}
	return false
}

func receiptMetadataReferencesArtifact(receipt *contracts.Receipt, key string, artifactRefs ...string) bool {
	return artifactReferenceMatches(receiptMetadataString(receipt, key), artifactRefs...)
}

func artifactReferencesReceipt(receipt *contracts.Receipt, artifactRefs ...string) bool {
	if receipt == nil {
		return false
	}
	for _, ref := range artifactRefs {
		if strings.TrimSpace(receipt.ReceiptID) != "" && strings.TrimSpace(receipt.ReceiptID) == strings.TrimSpace(ref) {
			return true
		}
	}
	return false
}

func artifactReferenceMatches(value string, artifactRefs ...string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, ref := range artifactRefs {
		if value == strings.TrimSpace(ref) {
			return true
		}
	}
	return false
}

func receiptRequiresVerificationScope(receipt *contracts.Receipt) bool {
	risk := strings.ToUpper(receiptMetadataString(receipt, "risk_class"))
	effect := strings.ToUpper(receiptMetadataString(receipt, "effect_class"))
	return risk == "T2" || risk == "T3" || effect == "E2" || effect == "E3" || effect == "E4"
}

func receiptRequiresHarnessTrace(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "side_effectful") || receiptMetadataBool(receipt, "requires_harness_trace")
}

func receiptRequiresPlanTransaction(receipt *contracts.Receipt) bool {
	if receipt == nil || receipt.Metadata == nil {
		return false
	}
	return receiptMetadataBool(receipt, "requires_plan_transaction") || receipt.Metadata["write_set"] != nil
}

func receiptRequiresHarnessChange(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "requires_harness_change_contract") || receiptMetadataString(receipt, "harness_mutation_component") != ""
}

func receiptRequiresGroundedAction(receipt *contracts.Receipt) bool {
	return receiptMetadataBool(receipt, "requires_grounded_action_ref") || strings.EqualFold(receiptMetadataString(receipt, "action_type"), "gui")
}

func receiptMetadataString(receipt *contracts.Receipt, key string) string {
	if receipt == nil || receipt.Metadata == nil {
		return ""
	}
	value, _ := receipt.Metadata[key].(string)
	return strings.TrimSpace(value)
}

func receiptMetadataBool(receipt *contracts.Receipt, key string) bool {
	if receipt == nil || receipt.Metadata == nil {
		return false
	}
	value, _ := receipt.Metadata[key].(bool)
	return value
}
