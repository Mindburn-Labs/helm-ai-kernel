// quantum_posture: the operator read model checks classical Ed25519 receipt
// signatures; it adds no post-quantum or hybrid cryptographic control.
package workstation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type OperatorView struct {
	Runs              []OperatorRunSummary `json:"runs"`
	DeniedTimeline    []DeniedTimelineItem `json:"denied_timeline"`
	MemoryReviewQueue []MemoryReviewItem   `json:"memory_review_queue"`
	RecurringLoops    []RecurringLoopItem  `json:"recurring_loops"`
	// Verification says which signature checks the receipts behind this view
	// went through. It is nil for a view assembled from a receipt in hand.
	Verification *ReceiptVerification `json:"verification,omitempty"`
}

// TrustAnchor is the workstation public key the caller trusts and where it
// came from. The zero value means no anchor: signatures are still checked
// against the key each receipt names, and signer trust is reported as not
// checked.
type TrustAnchor struct {
	PublicKey ed25519.PublicKey
	Source    string
}

// Signature statuses of an input receipt. The first two mean the content
// cannot be tied to any key, so the receipt is not counted. The rest are
// counted and differ in how far the signer is known.
const (
	SignatureUnsigned         = "unsigned"
	SignatureInvalid          = "invalid_signature"
	SignatureRetiredKey       = "signed_by_retired_key"
	SignatureUntrustedKey     = "signed_by_untrusted_key"
	SignatureSignerNotChecked = "signer_not_checked"
	SignatureTrustedKey       = "signed_by_trusted_key"
)

// ReceiptVerification records, for a set of input receipts, what was checked
// and what each check found.
type ReceiptVerification struct {
	// TrustAnchor names the trusted key source, or is empty when signer trust
	// was not checked.
	TrustAnchor string           `json:"trust_anchor,omitempty"`
	Statuses    map[string]int   `json:"signature_statuses"`
	NotCounted  []UncountedInput `json:"not_counted"`
}

// UncountedInput is an input file left out because its signature is missing
// or does not match its content.
type UncountedInput struct {
	SourcePath      string `json:"source_path"`
	SignatureStatus string `json:"signature_status"`
}

func newReceiptVerification(trust TrustAnchor) *ReceiptVerification {
	verification := &ReceiptVerification{Statuses: map[string]int{}, NotCounted: []UncountedInput{}}
	if len(trust.PublicKey) == ed25519.PublicKeySize {
		verification.TrustAnchor = trust.Source
	}
	return verification
}

// note records one input and reports whether its content may be counted.
func (v *ReceiptVerification) note(sourcePath, status string) bool {
	v.Statuses[status]++
	if status == SignatureUnsigned || status == SignatureInvalid {
		v.NotCounted = append(v.NotCounted, UncountedInput{SourcePath: sourcePath, SignatureStatus: status})
		return false
	}
	return true
}

// Counted is the number of inputs whose signature matches their content.
func (v *ReceiptVerification) Counted() int {
	total := 0
	for status, count := range v.Statuses {
		if status != SignatureUnsigned && status != SignatureInvalid {
			total += count
		}
	}
	return total
}

// Statements describes the checks in sentences fit for a report: what was
// compared, which inputs were left out, and how far the signers are known.
func (v *ReceiptVerification) Statements() []string {
	inputs := v.Counted() + len(v.NotCounted)
	signature := fmt.Sprintf("Receipt signatures were checked against the key each receipt names: %d of %d input files match.", v.Counted(), inputs)
	if len(v.NotCounted) > 0 {
		excluded := make([]string, 0, len(v.NotCounted))
		for _, input := range v.NotCounted {
			excluded = append(excluded, fmt.Sprintf("%s (%s)", input.SourcePath, input.SignatureStatus))
		}
		signature += " The others are not counted in this report: " + strings.Join(excluded, ", ") + "."
	}
	statements := []string{signature}
	if v.TrustAnchor == "" {
		return append(statements, "Signer trust was not checked: no trusted workstation public key was available. A receipt signed with any key matches its own signature, so the counted receipts show what their signers claim, not who signed them.")
	}
	trust := fmt.Sprintf("Signer trust was checked against %s: %d counted receipts are signed by that key, %d by another key.",
		v.TrustAnchor, v.Statuses[SignatureTrustedKey], v.Statuses[SignatureUntrustedKey])
	if retired := v.Statuses[SignatureRetiredKey]; retired > 0 {
		trust += fmt.Sprintf(" %d are signed by the retired built-in key, which anyone can reproduce.", retired)
	}
	return append(statements, trust+" Only a receipt signed by the trusted key is evidence of what this workstation decided.")
}

// signatureStatus classifies one receipt from its own signature fields and
// the caller's trust anchor.
func signatureStatus(signature, signerKeyID string, matches bool, err error, trust TrustAnchor) string {
	switch {
	case strings.TrimSpace(signature) == "":
		return SignatureUnsigned
	case err != nil || !matches:
		return SignatureInvalid
	case signerKeyID == retiredObserveOnlySignerKeyID:
		return SignatureRetiredKey
	case len(trust.PublicKey) != ed25519.PublicKeySize:
		return SignatureSignerNotChecked
	case signerKeyID == ed25519SignerKeyID(trust.PublicKey):
		return SignatureTrustedKey
	}
	return SignatureUntrustedKey
}

type OperatorRunSummary struct {
	RunID             string    `json:"run_id"`
	ReceiptID         string    `json:"receipt_id,omitempty"`
	DecisionID        string    `json:"decision_id,omitempty"`
	Goal              string    `json:"goal,omitempty"`
	AgentSurface      string    `json:"agent_surface,omitempty"`
	PolicyProfile     string    `json:"policy_profile"`
	Verdict           string    `json:"verdict,omitempty"`
	ToolActions       int       `json:"tool_actions,omitempty"`
	ChangedFiles      int       `json:"changed_files,omitempty"`
	ValidationResults int       `json:"validation_results,omitempty"`
	MemoryEffects     int       `json:"memory_effects,omitempty"`
	RecurringLoops    int       `json:"recurring_loops,omitempty"`
	DeniedEffects     int       `json:"denied_effects,omitempty"`
	ReceiptHash       string    `json:"receipt_hash"`
	CreatedAt         time.Time `json:"created_at"`
	// SignatureStatus is one of the Signature* values when the receipt was
	// read from a file and checked; a row whose status is unsigned or
	// invalid_signature shows what the file says and nothing more.
	SignatureStatus string `json:"signature_status,omitempty"`
}

type DeniedTimelineItem struct {
	RunID    string    `json:"run_id,omitempty"`
	EffectID string    `json:"effect_id,omitempty"`
	Effect   string    `json:"effect"`
	ToolID   string    `json:"tool_id,omitempty"`
	Action   string    `json:"action,omitempty"`
	Target   string    `json:"target,omitempty"`
	Reason   string    `json:"reason_code"`
	Receipt  string    `json:"receipt"`
	Occurred time.Time `json:"occurred_at"`
	Source   string    `json:"source"`
}

type MemoryReviewItem struct {
	RunID       string    `json:"run_id"`
	EffectID    string    `json:"effect_id"`
	MemoryClass string    `json:"memory_class"`
	DataClass   string    `json:"data_class"`
	Sensitivity string    `json:"sensitivity"`
	TTLDays     uint32    `json:"ttl_days"`
	ReviewState string    `json:"review_state,omitempty"`
	Verdict     string    `json:"verdict"`
	Receipt     string    `json:"receipt"`
	ObservedAt  time.Time `json:"observed_at"`
}

type RecurringLoopItem struct {
	RunID      string    `json:"run_id"`
	EffectID   string    `json:"effect_id"`
	Schedule   string    `json:"schedule"`
	MaxRuntime string    `json:"max_runtime"`
	ToolScope  []string  `json:"tool_scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	Verdict    string    `json:"verdict"`
	Receipt    string    `json:"receipt"`
}

// BuildOperatorView reads receipts and checks each signature before using
// the receipt. Every input gets a row in Runs with its signature status; the
// denied timeline, memory queue and loop registry are built only from inputs
// whose signature matches their content.
func BuildOperatorView(trust TrustAnchor, paths ...string) (OperatorView, error) {
	files, err := expandJSONInputs(paths)
	if err != nil {
		return OperatorView{}, err
	}
	view := OperatorView{Verification: newReceiptVerification(trust)}
	for _, file := range files {
		input, err := loadCheckedReceipt(file, trust)
		if err != nil {
			return OperatorView{}, err
		}
		counted := view.Verification.note(file, input.status)
		before := len(view.Runs)
		detail := &view
		if !counted {
			// The row is kept so the operator sees the file; what it claims
			// about denials, memory and loops is not carried into the queues.
			detail = &OperatorView{}
		}
		if input.receipt != nil {
			appendAgentRunReceipt(detail, input.receipt)
		}
		if input.decision != nil {
			appendDecisionReceipt(detail, input.decision)
		}
		if !counted {
			view.Runs = append(view.Runs, detail.Runs...)
		}
		for i := before; i < len(view.Runs); i++ {
			view.Runs[i].SignatureStatus = input.status
		}
	}
	sortOperatorView(&view)
	return view, nil
}

// checkedReceipt is one input file with the result of its signature check.
type checkedReceipt struct {
	receipt  *contracts.AgentRunReceipt
	decision *contracts.WorkstationPolicyDecisionReceipt
	status   string
}

func loadCheckedReceipt(path string, trust TrustAnchor) (checkedReceipt, error) {
	receipt, decision, err := loadWorkstationReceipt(path)
	if err != nil {
		return checkedReceipt{}, err
	}
	input := checkedReceipt{receipt: receipt, decision: decision}
	if receipt != nil {
		matches, err := VerifyReceiptSignature(receipt)
		input.status = signatureStatus(receipt.Signature, receipt.SignerKeyID, matches, err, trust)
	} else {
		matches, err := VerifyDecisionReceiptSignature(decision)
		input.status = signatureStatus(decision.Signature, decision.SignerKeyID, matches, err, trust)
	}
	return input, nil
}

func appendAgentRunReceipt(view *OperatorView, receipt *contracts.AgentRunReceipt) {
	view.Runs = append(view.Runs, OperatorRunSummary{
		RunID:             receipt.RunID,
		ReceiptID:         receipt.ReceiptID,
		Goal:              receipt.Goal,
		AgentSurface:      receipt.AgentSurface,
		PolicyProfile:     receipt.PolicyProfile,
		ToolActions:       len(receipt.ToolActions),
		ChangedFiles:      len(receipt.ChangedFiles),
		ValidationResults: len(receipt.ValidationResults),
		MemoryEffects:     len(receipt.MemoryEffects),
		RecurringLoops:    len(receipt.RecurringLoopEffects),
		DeniedEffects:     len(receipt.DeniedEffects),
		ReceiptHash:       receipt.ReceiptHash,
		CreatedAt:         receipt.CreatedAt,
	})
	for _, denied := range receipt.DeniedEffects {
		view.DeniedTimeline = append(view.DeniedTimeline, DeniedTimelineItem{
			RunID:    receipt.RunID,
			EffectID: denied.EffectID,
			Effect:   denied.EffectType,
			ToolID:   denied.ToolID,
			Action:   denied.Action,
			Reason:   denied.ReasonCode,
			Receipt:  receipt.ReceiptID,
			Occurred: denied.OccurredAt,
			Source:   "agent_run_receipt",
		})
	}
	for _, memory := range receipt.MemoryEffects {
		view.MemoryReviewQueue = append(view.MemoryReviewQueue, MemoryReviewItem{
			RunID:       receipt.RunID,
			EffectID:    memory.EffectID,
			MemoryClass: memory.MemoryClass,
			DataClass:   memory.DataClass,
			Sensitivity: memory.Sensitivity,
			TTLDays:     memory.TTLDays,
			ReviewState: memory.ReviewState,
			Verdict:     memory.Verdict,
			Receipt:     receipt.ReceiptID,
			ObservedAt:  receipt.CreatedAt,
		})
	}
	for _, loop := range receipt.RecurringLoopEffects {
		view.RecurringLoops = append(view.RecurringLoops, RecurringLoopItem{
			RunID:      receipt.RunID,
			EffectID:   loop.EffectID,
			Schedule:   loop.Schedule,
			MaxRuntime: loop.MaxRuntime,
			ToolScope:  loop.ToolScope,
			ExpiresAt:  loop.ExpiresAt,
			Verdict:    loop.Verdict,
			Receipt:    receipt.ReceiptID,
		})
	}
}

func appendDecisionReceipt(view *OperatorView, receipt *contracts.WorkstationPolicyDecisionReceipt) {
	view.Runs = append(view.Runs, OperatorRunSummary{
		RunID:         receipt.Request.RunID,
		DecisionID:    receipt.DecisionID,
		AgentSurface:  receipt.Request.AgentSurface,
		PolicyProfile: receipt.PolicyProfile,
		Verdict:       receipt.Verdict,
		DeniedEffects: boolCount(receipt.Verdict == contracts.WorkstationVerdictDeny),
		ReceiptHash:   receipt.ReceiptHash,
		CreatedAt:     receipt.CreatedAt,
	})
	if receipt.Verdict == contracts.WorkstationVerdictDeny {
		view.DeniedTimeline = append(view.DeniedTimeline, DeniedTimelineItem{
			RunID:    receipt.Request.RunID,
			EffectID: receipt.Request.RequestID,
			Effect:   receipt.Request.EffectType,
			ToolID:   receipt.Request.ToolID,
			Action:   receipt.Request.Action,
			Target:   receipt.Request.Target,
			Reason:   receipt.ReasonCode,
			Receipt:  receipt.DecisionID,
			Occurred: receipt.Request.OccurredAt,
			Source:   "policy_decision_receipt",
		})
	}
}

func loadWorkstationReceipt(path string) (*contracts.AgentRunReceipt, *contracts.WorkstationPolicyDecisionReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var result ImportResult
	if err := json.Unmarshal(data, &result); err == nil && result.Receipt != nil && result.Receipt.ReceiptID != "" {
		return result.Receipt, nil, nil
	}
	var agentReceipt contracts.AgentRunReceipt
	if err := json.Unmarshal(data, &agentReceipt); err == nil && agentReceipt.ReceiptID != "" {
		return &agentReceipt, nil, nil
	}
	var decision contracts.WorkstationPolicyDecisionReceipt
	if err := json.Unmarshal(data, &decision); err == nil && decision.DecisionID != "" {
		return nil, &decision, nil
	}
	return nil, nil, fmt.Errorf("%s: unsupported workstation receipt JSON", path)
}

func expandJSONInputs(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one receipt path or directory is required")
	}
	var files []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(path, "*.json"))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files, nil
}

func sortOperatorView(view *OperatorView) {
	sort.SliceStable(view.Runs, func(i, j int) bool {
		return view.Runs[i].CreatedAt.Before(view.Runs[j].CreatedAt)
	})
	sort.SliceStable(view.DeniedTimeline, func(i, j int) bool {
		return view.DeniedTimeline[i].Occurred.Before(view.DeniedTimeline[j].Occurred)
	})
	sort.SliceStable(view.MemoryReviewQueue, func(i, j int) bool {
		return strings.Compare(view.MemoryReviewQueue[i].EffectID, view.MemoryReviewQueue[j].EffectID) < 0
	})
	sort.SliceStable(view.RecurringLoops, func(i, j int) bool {
		return strings.Compare(view.RecurringLoops[i].EffectID, view.RecurringLoops[j].EffectID) < 0
	})
}

func boolCount(ok bool) int {
	if ok {
		return 1
	}
	return 0
}
