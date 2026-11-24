package boundary

// quantum_posture: Evidence registry lookups compare canonical content hashes.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func (r *SurfaceRegistry) PutEnvelope(manifest contracts.EvidenceEnvelopeManifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopes[manifest.ManifestID] = manifest
	if err := r.appendEventLocked("evidence_envelope", manifest.ManifestID, manifest); err != nil {
		return err
	}
	return r.persistLocked()
}

func (r *SurfaceRegistry) PutEnvelopePayload(payload contracts.EvidenceEnvelopePayload) error {
	if strings.TrimSpace(payload.ManifestID) == "" {
		return fmt.Errorf("envelope payload manifest id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopePayloads[payload.ManifestID] = payload
	if err := r.appendEventLocked("evidence_envelope_payload", payload.ManifestID, payload); err != nil {
		return err
	}
	return r.persistLocked()
}

func (r *SurfaceRegistry) ListEnvelopes() []contracts.EvidenceEnvelopeManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.EvidenceEnvelopeManifest, 0, len(r.envelopes))
	for _, manifest := range r.envelopes {
		out = append(out, manifest)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ManifestID < out[j].ManifestID })
	return out
}

func (r *SurfaceRegistry) GetEnvelope(id string) (contracts.EvidenceEnvelopeManifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	manifest, ok := r.envelopes[id]
	return manifest, ok
}

func (r *SurfaceRegistry) GetEnvelopePayload(id string) (contracts.EvidenceEnvelopePayload, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	payload, ok := r.envelopePayloads[id]
	return payload, ok
}

func (r *SurfaceRegistry) PutVerificationScope(scope contracts.VerificationScope) (contracts.VerificationScope, error) {
	if scope.CreatedAt.IsZero() {
		scope.CreatedAt = r.now().UTC()
	}
	sealed, err := scope.Seal()
	if err != nil {
		return contracts.VerificationScope{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verificationScopes[sealed.VerificationScopeID] = sealed
	if err := r.appendEventLocked("verification_scope", sealed.VerificationScopeID, sealed); err != nil {
		return contracts.VerificationScope{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.VerificationScope{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListVerificationScopes() []contracts.VerificationScope {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.VerificationScope, 0, len(r.verificationScopes))
	for _, scope := range r.verificationScopes {
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VerificationScopeID < out[j].VerificationScopeID })
	return out
}

func (r *SurfaceRegistry) GetVerificationScope(id string) (contracts.VerificationScope, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	scope, ok := r.verificationScopes[id]
	return scope, ok
}

func (r *SurfaceRegistry) VerifyVerificationScope(id string) map[string]any {
	scope, ok := r.GetVerificationScope(id)
	if !ok {
		return harnessVerificationFailure("verification_scope_id", id, "verification scope not found", r.now)
	}
	expected := scope.ScopeHash
	scope.ScopeHash = ""
	hash, err := canonicalize.CanonicalHash(scope)
	return hashVerificationResult("verification_scope_id", id, "scope_hash", expected, hash, err, r.now)
}

func (r *SurfaceRegistry) PutHarnessTrace(trace contracts.HarnessTrace) (contracts.HarnessTrace, error) {
	if trace.CreatedAt.IsZero() {
		trace.CreatedAt = r.now().UTC()
	}
	sealed, err := trace.Seal()
	if err != nil {
		return contracts.HarnessTrace{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.harnessTraces[sealed.TraceID] = sealed
	if err := r.appendEventLocked("harness_trace", sealed.TraceID, sealed); err != nil {
		return contracts.HarnessTrace{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.HarnessTrace{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListHarnessTraces() []contracts.HarnessTrace {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.HarnessTrace, 0, len(r.harnessTraces))
	for _, trace := range r.harnessTraces {
		out = append(out, trace)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TraceID < out[j].TraceID })
	return out
}

func (r *SurfaceRegistry) GetHarnessTrace(id string) (contracts.HarnessTrace, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	trace, ok := r.harnessTraces[id]
	return trace, ok
}

func (r *SurfaceRegistry) VerifyHarnessTrace(id string) map[string]any {
	trace, ok := r.GetHarnessTrace(id)
	if !ok {
		return harnessVerificationFailure("trace_id", id, "harness trace not found", r.now)
	}
	expected := trace.TraceHash
	trace.TraceHash = ""
	hash, err := canonicalize.CanonicalHash(trace)
	return hashVerificationResult("trace_id", id, "trace_hash", expected, hash, err, r.now)
}

func (r *SurfaceRegistry) PutPlanTransaction(tx contracts.PlanTransaction) (contracts.PlanTransaction, error) {
	sealed, err := tx.Seal()
	if err != nil {
		return contracts.PlanTransaction{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.planTransactions[sealed.PlanTransactionID] = sealed
	if err := r.appendEventLocked("plan_transaction", sealed.PlanTransactionID, sealed); err != nil {
		return contracts.PlanTransaction{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.PlanTransaction{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListPlanTransactions() []contracts.PlanTransaction {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.PlanTransaction, 0, len(r.planTransactions))
	for _, tx := range r.planTransactions {
		out = append(out, tx)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlanTransactionID < out[j].PlanTransactionID })
	return out
}

func (r *SurfaceRegistry) GetPlanTransaction(id string) (contracts.PlanTransaction, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tx, ok := r.planTransactions[id]
	return tx, ok
}

func (r *SurfaceRegistry) VerifyPlanTransaction(id string) map[string]any {
	tx, ok := r.GetPlanTransaction(id)
	if !ok {
		return harnessVerificationFailure("plan_transaction_id", id, "plan transaction not found", r.now)
	}
	expected := tx.TransactionHash
	tx.TransactionHash = ""
	hash, err := canonicalize.CanonicalHash(tx)
	return hashVerificationResult("plan_transaction_id", id, "transaction_hash", expected, hash, err, r.now)
}

func (r *SurfaceRegistry) PutHarnessChange(contract contracts.HarnessChangeContract) (contracts.HarnessChangeContract, error) {
	if contract.CreatedAt.IsZero() {
		contract.CreatedAt = r.now().UTC()
	}
	sealed, err := contract.Seal()
	if err != nil {
		return contracts.HarnessChangeContract{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.harnessChanges[sealed.ChangeContractID] = sealed
	if err := r.appendEventLocked("harness_change_contract", sealed.ChangeContractID, sealed); err != nil {
		return contracts.HarnessChangeContract{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.HarnessChangeContract{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListHarnessChanges() []contracts.HarnessChangeContract {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.HarnessChangeContract, 0, len(r.harnessChanges))
	for _, contract := range r.harnessChanges {
		out = append(out, contract)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChangeContractID < out[j].ChangeContractID })
	return out
}

func (r *SurfaceRegistry) GetHarnessChange(id string) (contracts.HarnessChangeContract, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	contract, ok := r.harnessChanges[id]
	return contract, ok
}

func (r *SurfaceRegistry) VerifyHarnessChange(id string) map[string]any {
	contract, ok := r.GetHarnessChange(id)
	if !ok {
		return harnessVerificationFailure("change_contract_id", id, "harness change contract not found", r.now)
	}
	expected := contract.ContractHash
	contract.ContractHash = ""
	hash, err := canonicalize.CanonicalHash(contract)
	return hashVerificationResult("change_contract_id", id, "contract_hash", expected, hash, err, r.now)
}

func (r *SurfaceRegistry) ApproveHarnessChange(id, receiptRef string) (contracts.HarnessChangeContract, error) {
	contract, ok := r.GetHarnessChange(id)
	if !ok {
		return contracts.HarnessChangeContract{}, fmt.Errorf("harness change contract %q not found", id)
	}
	contract.ApprovalRequired = false
	contract.ActivationReceiptRef = strings.TrimSpace(receiptRef)
	return r.PutHarnessChange(contract)
}

func (r *SurfaceRegistry) PutGroundedAction(ref contracts.GroundedActionRef) (contracts.GroundedActionRef, error) {
	if ref.CreatedAt.IsZero() {
		ref.CreatedAt = r.now().UTC()
	}
	sealed, err := ref.Seal()
	if err != nil {
		return contracts.GroundedActionRef{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groundedActions[sealed.GroundedActionID] = sealed
	if err := r.appendEventLocked("grounded_action_ref", sealed.GroundedActionID, sealed); err != nil {
		return contracts.GroundedActionRef{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.GroundedActionRef{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListGroundedActions() []contracts.GroundedActionRef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.GroundedActionRef, 0, len(r.groundedActions))
	for _, ref := range r.groundedActions {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GroundedActionID < out[j].GroundedActionID })
	return out
}

func (r *SurfaceRegistry) GetGroundedAction(id string) (contracts.GroundedActionRef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ref, ok := r.groundedActions[id]
	return ref, ok
}

func (r *SurfaceRegistry) PutGUIReceipt(receipt contracts.GUIActionReceipt) (contracts.GUIActionReceipt, error) {
	if receipt.CreatedAt.IsZero() {
		receipt.CreatedAt = r.now().UTC()
	}
	sealed, err := receipt.Seal()
	if err != nil {
		return contracts.GUIActionReceipt{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guiReceipts[sealed.ReceiptID] = sealed
	if err := r.appendEventLocked("gui_action_receipt", sealed.ReceiptID, sealed); err != nil {
		return contracts.GUIActionReceipt{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.GUIActionReceipt{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListGUIReceipts() []contracts.GUIActionReceipt {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.GUIActionReceipt, 0, len(r.guiReceipts))
	for _, receipt := range r.guiReceipts {
		out = append(out, receipt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceiptID < out[j].ReceiptID })
	return out
}

func (r *SurfaceRegistry) GetGUIReceipt(id string) (contracts.GUIActionReceipt, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	receipt, ok := r.guiReceipts[id]
	return receipt, ok
}

func (r *SurfaceRegistry) VerifyGUIReceipt(id string) map[string]any {
	receipt, ok := r.GetGUIReceipt(id)
	if !ok {
		return harnessVerificationFailure("receipt_id", id, "gui action receipt not found", r.now)
	}
	expected := receipt.ReceiptHash
	receipt.ReceiptHash = ""
	hash, err := canonicalize.CanonicalHash(receipt)
	return hashVerificationResult("receipt_id", id, "receipt_hash", expected, hash, err, r.now)
}

func harnessVerificationFailure(idField, id, errText string, now func() time.Time) map[string]any {
	return map[string]any{
		idField:       id,
		"verdict":     "FAIL",
		"verified":    false,
		"offline":     true,
		"checks":      map[string]string{"object": "FAIL"},
		"errors":      []string{errText},
		"verified_at": now().UTC(),
	}
}

func hashVerificationResult(idField, id, hashField, expected, actual string, hashErr error, now func() time.Time) map[string]any {
	checks := map[string]string{"jcs": "PASS", hashField: "PASS"}
	var errs []string
	if hashErr != nil || expected == "" || "sha256:"+actual != expected {
		checks[hashField] = "FAIL"
		errs = append(errs, fmt.Sprintf("%s mismatch", hashField))
	}
	return map[string]any{
		idField:       id,
		hashField:     expected,
		"verdict":     passFail(len(errs) == 0),
		"verified":    len(errs) == 0,
		"offline":     true,
		"checks":      checks,
		"errors":      errs,
		"verified_at": now().UTC(),
	}
}
