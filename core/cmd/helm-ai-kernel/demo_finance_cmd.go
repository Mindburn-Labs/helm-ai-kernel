package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/financedemo"
)

// financeDemoPolicyID is the policy identity bound into the finance demo's
// EvidencePack manifest.
const financeDemoPolicyID = "finance.payments.approval"

// runDemoFinance implements `helm-ai-kernel demo finance` — a deterministic,
// scripted proof that a payment above a policy limit is escalated for approval
// before it can execute. It performs NO real payment: the connector/action
// boundary is stubbed and every execution receipt is marked simulated
// (risk:r3-external-effect).
//
// Exit codes: 0 success, 1 verification failure, 2 config error.
func runDemoFinance(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("demo finance", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		outDir       string
		limitDollars int64
		payDollars   int64
		jsonOut      bool
	)
	cmd.StringVar(&outDir, "out", "data/evidence-finance", "Output directory for the EvidencePack")
	cmd.Int64Var(&limitDollars, "limit", 10000, "Approval threshold in whole dollars")
	cmd.Int64Var(&payDollars, "amount", 42500, "Payment amount in whole dollars (above limit triggers escalation)")
	cmd.BoolVar(&jsonOut, "json", false, "Emit the scenario result as JSON instead of the narrative")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	res, err := financedemo.RunScenario(financedemo.ScenarioInput{
		LimitCents:   limitDollars * 100,
		PaymentCents: payDollars * 100,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: finance scenario failed: %v\n", err)
		return 2
	}
	if err := res.VerifyChain(); err != nil {
		fmt.Fprintf(stderr, "Error: receipt chain verification failed: %v\n", err)
		return 1
	}

	if jsonOut {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	printFinanceNarrative(stdout, res)

	fmt.Fprintf(stdout, "\n%sExporting EvidencePack...%s\n", ColorBold, ColorReset)
	if err := writeFinanceEvidencePack(outDir, res); err != nil {
		fmt.Fprintf(stderr, "Error sealing EvidencePack: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "  📦 %d receipts → %s/\n", len(res.Receipts), outDir)
	fmt.Fprintf(stdout, "  🔏 Sealed (dev-local) → %s/%s\n", outDir, evidencepkg.EvidencePackSealPath)
	fmt.Fprintf(stdout, "  🔍 Verify: helm-ai-kernel verify %s\n", outDir)

	fmt.Fprintf(stdout, "\n%s🎉 Finance demo complete.%s Payment above limit escalated, approved, then executed (simulated).\n", ColorBold+ColorGreen, ColorReset)
	return 0
}

func printFinanceNarrative(stdout io.Writer, res *financedemo.ScenarioResult) {
	p := res.Policy
	instr := res.Instruction
	fmt.Fprintf(stdout, "\n%s💳 HELM Demo: Finance Payment Approval%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "%s   Scenario: vendor payment above policy limit routes to CFO/Finance approval%s\n", ColorGray, ColorReset)
	fmt.Fprintf(stdout, "%s   Mode: deterministic scripted smoke (no real payment; connector stubbed)%s\n\n", ColorYellow, ColorReset)

	fmt.Fprintf(stdout, "%sThreshold policy:%s %s\n", ColorBold, ColorReset, p.PolicyID)
	fmt.Fprintf(stdout, "  • Limit:    $%s above which approval is required\n", dollars(p.ApprovalRequiredAboveCents))
	fmt.Fprintf(stdout, "  • Approval: quorum %d of %v\n", p.ApprovalQuorum, p.RequiredApprovers)
	fmt.Fprintf(stdout, "  • Hash:     %s\n\n", p.PolicyHash)

	fmt.Fprintf(stdout, "%sConnector/action context:%s\n", ColorBold, ColorReset)
	fmt.Fprintf(stdout, "  • Connector: %s  Action: %s\n", instr.ConnectorID, instr.Action)
	fmt.Fprintf(stdout, "  • Vendor:    %s  Invoice: %s\n", instr.Vendor, instr.InvoiceRef)
	fmt.Fprintf(stdout, "  • Amount:    $%s %s\n\n", dollars(instr.AmountCents), instr.Currency)

	for _, r := range res.Receipts {
		icon, color := "✅", ColorGreen
		switch r.Verdict {
		case "ESCALATE":
			icon, color = "⛔", ColorYellow
		case "PENDING":
			icon, color = "⏳", ColorYellow
		case "DENY":
			icon, color = "❌", ColorRed
		}
		fmt.Fprintf(stdout, "  %s %s[%s]%s %s → %s%s%s %s(%s, L=%d)%s\n",
			icon, color, r.Verdict, ColorReset,
			r.Principal, ColorBold, r.Action, ColorReset,
			ColorGray, r.ReasonCode, r.Lamport, ColorReset)
	}

	fmt.Fprintf(stdout, "\n%sHuman approval result:%s state=%s ceremony_hash=%s\n", ColorBold, ColorReset, res.Ceremony.State, res.Ceremony.CeremonyHash)
	fmt.Fprintf(stdout, "%sExecution receipt:%s simulated=%t hash=%s\n", ColorBold, ColorReset, res.ExecutionReceipt.Simulated, res.ExecutionReceipt.ContentHash)
	fmt.Fprintf(stdout, "%sProof chain:%s %d receipts, root=%s\n", ColorBold, ColorReset, len(res.Receipts), res.RootHash)
}

func dollars(cents int64) string {
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

// writeFinanceEvidencePack seals a canonical, dev-local EvidencePack under
// outDir so that `helm-ai-kernel verify <outDir>` accepts it. It mirrors the
// organization demo's §3.1 layout: receipts under 02_PROOFGRAPH/receipts/, a
// canonical manifest, 01_SCORE.json, 00_INDEX.json, then an in-place dev-local
// seal. All timestamps are the deterministic finance demo clock.
func writeFinanceEvidencePack(outDir string, res *financedemo.ScenarioResult) error {
	if len(res.Receipts) == 0 {
		return fmt.Errorf("no receipts to seal")
	}
	if err := conform.CreateEvidencePackDirs(outDir); err != nil {
		return err
	}

	packID := "demo-finance"
	builder := evidencepack.NewBuilder(packID, res.Policy.TenantID, res.Instruction.PaymentID, financeDemoPolicyID).
		WithCreatedAt(financedemo.FixedClock())
	for i, r := range res.Receipts {
		if err := builder.AddReceipt(fmt.Sprintf("%03d_%s", i+1, r.ReceiptID), r); err != nil {
			return err
		}
	}
	// Bind the threshold policy, approval ceremony, and execution receipt into
	// the pack so a verifier sees every acceptance artifact, not just the chain.
	if err := builder.AddPolicyDecision("payment_policy", res.Policy); err != nil {
		return err
	}
	if err := builder.AddPolicyDecision("approval_ceremony", res.Ceremony); err != nil {
		return err
	}
	if err := builder.AddReceipt("execution_receipt", res.ExecutionReceipt); err != nil {
		return err
	}
	manifest, _, err := builder.Build()
	if err != nil {
		return err
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "04_EXPORTS", "evidence_manifest.json"), append(manifestJSON, '\n'), 0o600); err != nil {
		return err
	}

	receiptsDir := filepath.Join(outDir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		return err
	}
	for i, r := range res.Receipts {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		fname := fmt.Sprintf("%03d_%s.json", i+1, r.ReceiptID)
		if err := os.WriteFile(filepath.Join(receiptsDir, fname), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}

	proofGraph := map[string]any{
		"version":         "1.0.0",
		"pack_id":         packID,
		"scenario":        "finance-payment-approval",
		"tenant_id":       res.Policy.TenantID,
		"payment_id":      res.Instruction.PaymentID,
		"receipt_count":   len(res.Receipts),
		"lamport_final":   res.LamportFinal,
		"root_hash":       res.RootHash,
		"topo_order_rule": "lamport_monotonic",
		"manifest_hash":   manifest.ManifestHash,
		"entries_root":    manifest.EntriesMerkleRoot,
		"policy_hash":     res.Policy.PolicyHash,
		"ceremony_hash":   res.Ceremony.CeremonyHash,
		"execution_hash":  res.ExecutionReceipt.ContentHash,
		"pre_verdict":     string(res.PreApprovalVerdict.Verdict),
	}
	proofGraphJSON, err := json.MarshalIndent(proofGraph, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "02_PROOFGRAPH", "proofgraph.json"), append(proofGraphJSON, '\n'), 0o600); err != nil {
		return err
	}

	score := map[string]any{
		"pass":           true,
		"run_id":         packID,
		"scope":          "demo-finance",
		"receipt_count":  len(res.Receipts),
		"escalate_path":  "pre-execution",
		"effect":         "simulated",
		"tenant_id":      res.Policy.TenantID,
		"payment_id":     res.Instruction.PaymentID,
		"pre_verdict":    string(res.PreApprovalVerdict.Verdict),
		"approval_state": string(res.Ceremony.State),
	}
	scoreJSON, err := json.MarshalIndent(score, "", "  ")
	if err != nil {
		return err
	}
	scoreJSON = append(scoreJSON, '\n')
	if err := os.WriteFile(filepath.Join(outDir, "01_SCORE.json"), scoreJSON, 0o600); err != nil {
		return err
	}
	scoreSum := sha256.Sum256(scoreJSON)
	if err := os.WriteFile(filepath.Join(outDir, "01_SCORE.json.sha256"), []byte(hex.EncodeToString(scoreSum[:])+"\n"), 0o600); err != nil {
		return err
	}

	if err := writeFinanceEvidenceIndex(outDir, packID); err != nil {
		return err
	}

	if _, err := evidencepkg.SealEvidencePack(context.Background(), outDir, evidencepkg.SealEvidencePackOptions{
		PackID:   packID,
		Profile:  evidencepkg.EvidenceTrustProfileDevLocal,
		SignedAt: financedemo.FixedClock(),
	}); err != nil {
		return err
	}
	return nil
}

// writeFinanceEvidenceIndex walks the pack directory and writes 00_INDEX.json,
// mirroring the conform engine's index format. Entries are sorted by path for
// deterministic output.
func writeFinanceEvidenceIndex(outDir, runID string) error {
	type indexEntry struct {
		Path        string `json:"path"`
		SHA256      string `json:"sha256"`
		SizeBytes   int64  `json:"size_bytes"`
		ContentType string `json:"content_type"`
	}
	var entries []indexEntry
	err := filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "00_INDEX.json" || rel == evidencepkg.EvidencePackSealPath {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		ct := "application/json"
		if filepath.Ext(rel) != ".json" {
			ct = "text/plain"
		}
		entries = append(entries, indexEntry{
			Path:        rel,
			SHA256:      hex.EncodeToString(sum[:]),
			SizeBytes:   info.Size(),
			ContentType: ct,
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	index := map[string]any{
		"run_id":          runID,
		"profile":         string(conform.ProfileCore),
		"created_at":      financedemo.FixedClock(),
		"topo_order_rule": "lamport_monotonic",
		"entries":         entries,
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "00_INDEX.json"), append(data, '\n'), 0o600)
}
