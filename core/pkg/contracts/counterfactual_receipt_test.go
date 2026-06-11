package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedTime() time.Time {
	return time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
}

func validCounterfactual() CounterfactualReceipt {
	return CounterfactualReceipt{
		ReceiptID:          "cf-receipt-mcp-boundary-1",
		Enforcement:        EnforcementCounterfactual,
		WouldHaveVerdict:   VerdictDeny,
		ReasonCode:         ReasonApprovalRequired,
		ObserveGrantID:     "og-1",
		BoundaryRecordID:   "mcp-boundary-1",
		BoundaryRecordHash: "sha256:deadbeef",
		PolicyEpoch:        "epoch-42",
		ToolName:           "deploy",
		MCPServerID:        "srv-1",
		ArgsHash:           "sha256:args",
		CreatedAt:          fixedTime(),
	}
}

// TestP0_CounterfactualNeverPresentableAsEnforced is the acceptance gate for
// MIN-514. A counterfactual receipt coerced to "enforced" MUST fail closed:
// conflating the two is false execution authority.
func TestP0_CounterfactualNeverPresentableAsEnforced(t *testing.T) {
	cf := validCounterfactual()

	// 1. Direct coercion of the enforcement label is rejected at Validate.
	coerced := cf
	coerced.Enforcement = EnforcementEnforced
	if err := coerced.Validate(); err == nil {
		t.Fatal("P0 VIOLATION: a counterfactual receipt relabeled 'enforced' passed validation")
	}
	if _, err := coerced.Seal(); err == nil {
		t.Fatal("P0 VIOLATION: a counterfactual receipt relabeled 'enforced' sealed successfully")
	}

	// 2. An empty/blank enforcement (the historic enforce default) is rejected.
	blank := cf
	blank.Enforcement = ""
	if err := blank.Validate(); err == nil {
		t.Fatal("P0 VIOLATION: a counterfactual receipt with blank enforcement passed validation")
	}

	// 3. The signing payload is enforcement-domain-separated so a signature can
	//    never be replayed across the enforced/counterfactual boundary.
	sealed, err := cf.Seal()
	if err != nil {
		t.Fatalf("valid counterfactual must seal: %v", err)
	}
	if got := sealed.SigningPayload(); got[:len(EnforcementCounterfactual)] != string(EnforcementCounterfactual) {
		t.Fatalf("signing payload is not enforcement-prefixed: %q", got)
	}

	// 4. A summary refuses to fold a non-counterfactual receipt.
	enforcedish := cf
	enforcedish.Enforcement = EnforcementEnforced
	if _, err := SummarizeCounterfactuals([]CounterfactualReceipt{enforcedish}, fixedTime()); err == nil {
		t.Fatal("P0 VIOLATION: summary folded a non-counterfactual receipt")
	}
}

func TestCounterfactualSealIsDeterministic(t *testing.T) {
	a, err := validCounterfactual().Seal()
	if err != nil {
		t.Fatalf("seal a: %v", err)
	}
	b, err := validCounterfactual().Seal()
	if err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if a.ReceiptHash == "" {
		t.Fatal("sealed receipt must carry a content hash")
	}
	if a.ReceiptHash != b.ReceiptHash {
		t.Fatalf("seal not deterministic: %q != %q", a.ReceiptHash, b.ReceiptHash)
	}

	// Mutating any bound field changes the hash (tamper evidence).
	tampered := validCounterfactual()
	tampered.WouldHaveVerdict = VerdictEscalate
	tampered.ReasonCode = ReasonApprovalRequired
	sealedTampered, err := tampered.Seal()
	if err != nil {
		t.Fatalf("seal tampered: %v", err)
	}
	if sealedTampered.ReceiptHash == a.ReceiptHash {
		t.Fatal("changing would-have verdict must change the content hash")
	}
}

func TestCounterfactualRequiresGrantAndBoundaryLinkage(t *testing.T) {
	noGrant := validCounterfactual()
	noGrant.ObserveGrantID = ""
	if err := noGrant.Validate(); err == nil {
		t.Fatal("counterfactual without observe grant must be rejected (no grant, no observe mode)")
	}

	noBoundary := validCounterfactual()
	noBoundary.BoundaryRecordHash = ""
	if err := noBoundary.Validate(); err == nil {
		t.Fatal("counterfactual without boundary record hash must be rejected")
	}

	denyNoReason := validCounterfactual()
	denyNoReason.ReasonCode = ""
	if err := denyNoReason.Validate(); err == nil {
		t.Fatal("counterfactual DENY without reason code must be rejected")
	}

	allowNoReason := validCounterfactual()
	allowNoReason.WouldHaveVerdict = VerdictAllow
	allowNoReason.ReasonCode = ""
	if err := allowNoReason.Validate(); err != nil {
		t.Fatalf("counterfactual ALLOW without reason code should be valid: %v", err)
	}
}

func TestSummarizeCounterfactualsDeterministic(t *testing.T) {
	mk := func(verdict Verdict, reason ReasonCode, tool, server, epoch, grant string) CounterfactualReceipt {
		r := validCounterfactual()
		r.WouldHaveVerdict = verdict
		r.ReasonCode = reason
		r.ToolName = tool
		r.MCPServerID = server
		r.PolicyEpoch = epoch
		r.ObserveGrantID = grant
		return r
	}
	receipts := []CounterfactualReceipt{
		mk(VerdictDeny, ReasonApprovalRequired, "deploy", "srv-1", "epoch-42", "og-1"),
		mk(VerdictEscalate, ReasonApprovalRequired, "delete", "srv-2", "epoch-42", "og-1"),
		mk(VerdictDeny, ReasonApprovalRequired, "deploy", "srv-1", "epoch-42", "og-1"),
		mk(VerdictAllow, "", "read", "srv-1", "epoch-42", "og-1"),
	}

	s1, err := SummarizeCounterfactuals(receipts, fixedTime())
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if s1.TotalEvaluated != 4 || s1.WouldDeny != 2 || s1.WouldEscalate != 1 || s1.WouldAllow != 1 {
		t.Fatalf("unexpected totals: %+v", s1)
	}
	if s1.ObserveGrantID != "og-1" {
		t.Fatalf("observe grant id = %q, want og-1", s1.ObserveGrantID)
	}

	// Byte-identical across runs.
	j1, _ := json.Marshal(s1)
	s2, _ := SummarizeCounterfactuals(receipts, fixedTime())
	j2, _ := json.Marshal(s2)
	if string(j1) != string(j2) {
		t.Fatalf("summary not deterministic:\n%s\n%s", j1, j2)
	}

	// deploy tool: 2 denies; delete tool: 1 escalate.
	byTool := map[string]CounterfactualCountEntry{}
	for _, e := range s1.ByTool {
		byTool[e.Key] = e
	}
	if byTool["deploy"].Deny != 2 {
		t.Fatalf("deploy deny count = %d, want 2", byTool["deploy"].Deny)
	}
	if byTool["delete"].Escalate != 1 {
		t.Fatalf("delete escalate count = %d, want 1", byTool["delete"].Escalate)
	}

	// Mixed grant ids collapse to "mixed".
	mixed := append([]CounterfactualReceipt{}, receipts...)
	mixed = append(mixed, mk(VerdictDeny, ReasonApprovalRequired, "deploy", "srv-1", "epoch-42", "og-2"))
	sm, _ := SummarizeCounterfactuals(mixed, fixedTime())
	if sm.ObserveGrantID != "mixed" {
		t.Fatalf("mixed grant ids should yield 'mixed', got %q", sm.ObserveGrantID)
	}
}

// TestCounterfactualGoldenVector pins the canonical content hash of a fixed
// receipt so cross-platform JCS canonicalization stays byte-identical. The
// golden file doubles as a conformance vector for SDK producers.
func TestCounterfactualGoldenVector(t *testing.T) {
	path := filepath.Join("testdata", "counterfactual_receipt_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden struct {
		Receipt     CounterfactualReceipt `json:"receipt"`
		ReceiptHash string                `json:"expected_receipt_hash"`
		Payload     string                `json:"expected_signing_payload"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	sealed, err := golden.Receipt.Seal()
	if err != nil {
		t.Fatalf("seal golden receipt: %v", err)
	}
	if sealed.ReceiptHash != golden.ReceiptHash {
		t.Fatalf("golden receipt hash drift: got %q, want %q", sealed.ReceiptHash, golden.ReceiptHash)
	}
	if sealed.SigningPayload() != golden.Payload {
		t.Fatalf("golden signing payload drift: got %q, want %q", sealed.SigningPayload(), golden.Payload)
	}
}
