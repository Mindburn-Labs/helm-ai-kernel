package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestDefaultEngineAndGateHappyPaths(t *testing.T) {
	ctx := setupConformingGateContext(t)
	if DefaultEngine() == nil {
		t.Fatalf("DefaultEngine returned nil")
	}

	gates := []conform.Gate{
		&G2Replay{},
		&G2ASchemaFirst{},
		&G3Policy{},
		&G3ABudget{},
		&G4Secrets{},
		&G5ToolTrust{},
		&G6Taint{},
		&G7Incident{},
		&G8HITL{},
		&G9Jurisdiction{},
		&G11Operability{},
		&G12SupplyChain{},
		&G13HSM{},
		&G14BundleIntegrity{},
		&G15Condensation{},
		&GXTenantIsolation{},
		&GXEnvelopeBound{},
		&GXSDKDrift{},
		&GXThreatScan{},
		&GXDelegation{},
	}
	for _, gate := range gates {
		if gate.ID() == "" || gate.Name() == "" {
			t.Fatalf("%T returned empty id/name", gate)
		}
		result := gate.Run(ctx)
		if !result.Pass {
			t.Fatalf("%s failed unexpectedly: reasons=%v details=%v metrics=%+v", gate.ID(), result.Reasons, result.Details, result.Metrics)
		}
		if result.Metrics.Counts == nil {
			t.Fatalf("%s did not initialize metrics counts", gate.ID())
		}
	}
	if (&G1ProofReceipts{}).Name() == "" {
		t.Fatalf("G1 name is empty")
	}
}

func TestGateNegativeHelpersAndReceiptBridge(t *testing.T) {
	if !containsSecretPattern([]byte("token=AKIAEXAMPLE")) {
		t.Fatalf("containsSecretPattern missed AWS-style key")
	}
	if containsSecretPattern([]byte("ordinary telemetry")) {
		t.Fatalf("containsSecretPattern flagged clean telemetry")
	}

	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	writeGateFile(t, second, []byte("{}"))
	if got := firstExistingFile(first, second); got != second {
		t.Fatalf("firstExistingFile = %q, want %q", got, second)
	}
	if got := firstExistingFile(first); got != "" {
		t.Fatalf("firstExistingFile missing = %q, want empty", got)
	}

	env := &ReceiptEnvelope{
		RunID:               "run-1",
		Seq:                 42,
		TenantID:            "tenant-a",
		EnvelopeID:          "env-1",
		EnvelopeHash:        "sha256:env",
		Jurisdiction:        "US",
		PolicyHash:          "sha256:policy",
		PolicyVersion:       "v1",
		Actor:               "agent-1",
		ActionType:          "tool_call",
		EffectClass:         "E3",
		EffectType:          "network_call",
		DecisionID:          "decision-1",
		IntentID:            "intent-1",
		EffectDigestHash:    "sha256:effect",
		PhenotypeHash:       "sha256:phenotype",
		ParentReceiptHashes: []string{"parent-1"},
		ReceiptHash:         "receipt-1",
		Signature:           "sig",
		PayloadCommitment:   "sha256:payload",
		TapeRef:             "tape-1",
		ToolName:            "tool",
		ToolManifestHash:    "sha256:tool",
	}
	receipt := env.ToContractsReceipt()
	if receipt.ReceiptID != env.ReceiptHash || receipt.ExecutorID != env.ToolName || receipt.ReplayScript.ScriptID != env.TapeRef {
		t.Fatalf("contract receipt mapping = %+v", receipt)
	}
	if receipt.Provenance == nil || len(receipt.Provenance.Parents) != 1 || receipt.Metadata["tool_manifest_hash"] != env.ToolManifestHash {
		t.Fatalf("contract receipt provenance/metadata = provenance:%+v metadata:%+v", receipt.Provenance, receipt.Metadata)
	}

	roundTrip := FromContractsReceipt(&contracts.Receipt{
		ReceiptID:  "receipt-2",
		DecisionID: "decision-2",
		EffectID:   "effect-2",
		BlobHash:   "sha256:blob",
		Signature:  "sig-2",
		Timestamp:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ExecutorID: "tool-2",
		Metadata: map[string]any{
			"tenant_id":           "tenant-b",
			"envelope_id":         "env-2",
			"envelope_hash":       "sha256:env2",
			"jurisdiction":        "EU",
			"effect_class":        "E4",
			"effect_type":         "write",
			"action_type":         "connector_call",
			"intent_id":           "intent-2",
			"policy_hash":         "sha256:policy2",
			"policy_version":      "v2",
			"phenotype_hash":      "sha256:phenotype2",
			"run_id":              "run-2",
			"seq":                 uint64(7),
			"tool_manifest_hash":  "sha256:tool2",
			"non_string_metadata": 5,
		},
		Provenance:   &contracts.ReceiptProvenance{GeneratedBy: "actor-2", Parents: []string{"parent-2"}},
		ReplayScript: &contracts.ReplayScriptRef{ScriptID: "tape-2"},
	})
	if roundTrip.TenantID != "tenant-b" || roundTrip.Seq != 7 || roundTrip.ToolManifestHash != "sha256:tool2" {
		t.Fatalf("round-trip envelope = %+v", roundTrip)
	}
}

func TestGateSparseEvidenceFailurePaths(t *testing.T) {
	ctx := setupSparseGateContext(t)

	failingGates := []conform.Gate{
		&G2Replay{},
		&G2ASchemaFirst{},
		&G3Policy{},
		&G3ABudget{},
		&G5ToolTrust{},
		&G6Taint{},
		&G7Incident{},
		&G8HITL{},
		&G9Jurisdiction{},
		&G11Operability{},
		&G12SupplyChain{},
		&G14BundleIntegrity{},
		&GXTenantIsolation{},
		&GXEnvelopeBound{},
		&GXSDKDrift{},
	}
	for _, gate := range failingGates {
		result := gate.Run(ctx)
		if result.Pass {
			t.Fatalf("%s passed sparse evidence unexpectedly: %+v", gate.ID(), result)
		}
		if len(result.Reasons) == 0 {
			t.Fatalf("%s failed without reasons", gate.ID())
		}
	}

	threatScan := (&GXThreatScan{}).Run(ctx)
	if !threatScan.Pass || threatScan.Metrics.Counts["scan_results_found"] != 0 {
		t.Fatalf("GXThreatScan sparse result = %+v, want optional pass with zero scans", threatScan)
	}
	delegation := (&GXDelegation{}).Run(ctx)
	if !delegation.Pass {
		t.Fatalf("GXDelegation sparse result = %+v, want vacuous pass", delegation)
	}
}

func TestGateTargetedInvalidEvidenceBranches(t *testing.T) {
	ctx := setupSparseGateContext(t)

	writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "policy_decisions", "bad.json"), map[string]any{
		"tenant_id": "tenant-a",
	})
	if result := (&G3Policy{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, conform.ReasonPolicyDecisionMissing) {
		t.Fatalf("G3 invalid decision result = %+v, want policy missing failure", result)
	}

	writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "tool_manifests", "bad.json"), map[string]any{
		"tool_id": "tool",
	})
	if result := (&G5ToolTrust{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, "TOOL_MANIFEST_INVALID") {
		t.Fatalf("G5 invalid manifest result = %+v, want invalid manifest failure", result)
	}

	writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "taint", "lineage.json"), map[string]any{
		"nodes":      []any{map[string]any{"id": "node-without-lineage-hash"}},
		"violations": []any{map[string]any{"reason": "tainted flow"}},
	})
	if result := (&G6Taint{}).Run(ctx); result.Pass || result.Metrics.Counts["taint_violations"] != 1 {
		t.Fatalf("G6 invalid lineage result = %+v, want taint violation failure", result)
	}

	checkpointDir := filepath.Join(ctx.EvidenceDir, "condensation")
	writeGateJSON(t, filepath.Join(checkpointDir, "valid.json"), map[string]any{"merkle_root": "sha256:root"})
	if result := (&G15Condensation{}).Run(ctx); !result.Pass || result.Metrics.Counts["checkpoints_verified"] != 1 {
		t.Fatalf("G15 valid checkpoint result = %+v, want checkpoint verification pass", result)
	}
	writeGateJSON(t, filepath.Join(checkpointDir, "empty-root.json"), map[string]any{"merkle_root": ""})
	if result := (&G15Condensation{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, "Empty Merkle root") {
		t.Fatalf("G15 empty root result = %+v, want empty root failure", result)
	}

	threatDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "threat_scan")
	writeGateFile(t, filepath.Join(threatDir, "scan_results.json"), []byte("{"))
	if result := (&GXThreatScan{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, conform.ReasonTaintedInputDeny) {
		t.Fatalf("GXThreatScan invalid JSON result = %+v, want tainted input failure", result)
	}
	writeGateJSON(t, filepath.Join(threatDir, "scan_results.json"), map[string]any{"findings": []any{map[string]any{"class": "prompt"}}})
	if result := (&GXThreatScan{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, "THREAT_SCAN_MISSING_ID") || result.Metrics.Counts["total_findings"] != 1 {
		t.Fatalf("GXThreatScan missing fields result = %+v, want missing id/hash failures", result)
	}
}

func TestGateAdditionalMalformedEvidenceBranches(t *testing.T) {
	t.Run("G4 detects leaked secrets in evidence", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "06_LOGS", "agent.log"), []byte("password=super-secret"))

		result := (&G4Secrets{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "SECRET_LEAK_DETECTED") || result.Metrics.Counts["files_scanned"] != 1 {
			t.Fatalf("G4 secret scan result = %+v, want detected secret leak", result)
		}
	})

	t.Run("G9 reports incomplete packs and failed conformance", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		root := filepath.Join(ctx.EvidenceDir, "04_EXPORTS", "jurisdictions")
		for _, name := range []string{"us", "eu"} {
			mkdirGate(t, filepath.Join(root, name, "test_suite"))
			writeGateJSON(t, filepath.Join(root, name, "policy_bundle.json"), map[string]any{"tenant_id": "tenant-a"})
			writeGateJSON(t, filepath.Join(root, name, "conformance_report.json"), map[string]any{"pass": false})
			writeGateJSON(t, filepath.Join(root, name, "test_suite", "case.json"), map[string]any{"tenant_id": "tenant-a"})
		}

		result := (&G9Jurisdiction{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "JURISDICTION_PACK_INCOMPLETE") || !reasonContains(result.Reasons, "JURISDICTION_CONFORMANCE_FAILED") {
			t.Fatalf("G9 incomplete jurisdiction result = %+v, want incomplete and failed reports", result)
		}
		if result.Metrics.Counts["jurisdiction_packs"] != 2 || result.Metrics.Counts["jurisdiction_tests"] != 2 {
			t.Fatalf("G9 metrics = %+v, want two packs and tests", result.Metrics.Counts)
		}
	})

	t.Run("G11 reports partial SLO coverage", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "slo.json"), []map[string]any{
			{"name": "scheduler_latency", "target": "99p"},
		})
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "12_REPORTS", "ops_status_snapshot.json"), map[string]any{"status": "ok"})
		writeGateJSON(t, filepath.Join(ctx.ProjectRoot, "docs", "runbooks", "index.json"), map[string]any{"runbooks": []string{"incident"}})

		result := (&G11Operability{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "SLO_MISSING:policy_decision_latency") || result.Metrics.Counts["slo_definitions"] != 1 {
			t.Fatalf("G11 partial SLO result = %+v, want missing SLO failure", result)
		}
	})

	t.Run("G12 reports unsigned invalid and unrooted packs", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		packsRoot := filepath.Join(ctx.ProjectRoot, "packs")
		mkdirGate(t, filepath.Join(packsRoot, "unsigned"))
		mkdirGate(t, filepath.Join(packsRoot, "invalid"))
		writeGateFile(t, filepath.Join(packsRoot, "invalid", "signature.json"), []byte("{"))

		result := (&G12SupplyChain{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "PACK_UNSIGNED:unsigned") || !reasonContains(result.Reasons, "PACK_SIG_INVALID:invalid") || !reasonContains(result.Reasons, "TRUSTED_ROOTS_MISSING") {
			t.Fatalf("G12 malformed pack result = %+v, want unsigned invalid and missing roots", result)
		}
	})

	t.Run("GX tenant isolation reports missing and cross-tenant ids", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
		writeGateFile(t, filepath.Join(receiptsDir, "bad.json"), []byte("{"))
		writeGateJSON(t, filepath.Join(receiptsDir, "missing-tenant.json"), map[string]any{"receipt_hash": "r1"})
		writeGateJSON(t, filepath.Join(receiptsDir, "tenant-a.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(receiptsDir, "tenant-b.json"), map[string]any{"tenant_id": "tenant-b"})
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "budget_metrics.json"), map[string]any{"spend": map[string]any{"used": 1}})
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "08_TAPES", "tape.json"), map[string]any{"entries": []any{}})

		result := (&GXTenantIsolation{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, conform.ReasonTenantIDMissing) || !reasonContains(result.Reasons, conform.ReasonTenantIsolationViolation) {
			t.Fatalf("GX tenant result = %+v, want missing tenant and isolation failure", result)
		}
		if result.Metrics.Counts["receipts_with_tenant_id"] != 2 || result.Metrics.Counts["artifacts_without_tenant_id"] == 0 {
			t.Fatalf("GX tenant metrics = %+v, want tenant and artifact counts", result.Metrics.Counts)
		}
	})

	t.Run("GX delegation reports wrong proof node kinds", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "01_DECISIONS", "bad.json"), []byte("{"))
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "01_DECISIONS", "plain.json"), map[string]any{"verdict": "ALLOW"})
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "01_DECISIONS", "other-reason.json"), map[string]any{
			"delegation_session_ref": "session-1",
			"verdict":                "DENY",
			"reason_code":            "OTHER_REASON",
		})
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "01_DECISIONS", "allow.json"), map[string]any{
			"delegation_session_ref": "session-2",
			"verdict":                "ALLOW",
		})
		nodesDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "nodes")
		writeGateFile(t, filepath.Join(nodesDir, "bad-node.json"), []byte("{"))
		writeGateJSON(t, filepath.Join(nodesDir, "wrong-bind.json"), map[string]any{
			"kind":    "ATTESTATION",
			"payload": map[string]any{"event": "DELEGATION_BIND"},
		})
		writeGateJSON(t, filepath.Join(nodesDir, "wrong-attestation.json"), map[string]any{
			"kind":    "TRUST_EVENT",
			"payload": map[string]any{"session_id": "session-2"},
		})

		result := (&GXDelegation{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "non-TRUST_EVENT") || !reasonContains(result.Reasons, "non-ATTESTATION") {
			t.Fatalf("GX delegation result = %+v, want wrong node kind failures", result)
		}
		if result.Metrics.Counts["decisions_without_delegation"] != 1 || result.Metrics.Counts["delegation_deny_other_reason"] != 1 || result.Metrics.Counts["delegation_allow"] != 1 {
			t.Fatalf("GX delegation metrics = %+v, want decision branch counts", result.Metrics.Counts)
		}
	})
}

func TestGateRemainingReachableFailureBranches(t *testing.T) {
	t.Run("G2A fails empty schema directory", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		mkdirGate(t, filepath.Join(ctx.EvidenceDir, "09_SCHEMAS", "tool_io"))

		result := (&G2ASchemaFirst{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, conform.ReasonSchemaValidationFailed) || result.Metrics.Counts["schemas"] != 0 {
			t.Fatalf("G2A empty schema result = %+v, want schema validation failure", result)
		}
	})

	t.Run("G3 rejects malformed policy decision JSON", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "policy_decisions", "bad.json"), []byte("{"))

		result := (&G3Policy{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, conform.ReasonPolicyDecisionMissing) {
			t.Fatalf("G3 malformed policy result = %+v, want policy decision failure", result)
		}
	})

	t.Run("G3A detects receipt content and containment miss", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "budget_metrics.json"), []byte("{"))
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts", "receipt.json"), []byte(`{"event":"BudgetExhausted"}`))

		result := (&G3ABudget{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, conform.ReasonContainmentNotTriggered) || reasonContains(result.Reasons, conform.ReasonBudgetExhausted) {
			t.Fatalf("G3A content receipt result = %+v, want containment-only failure", result)
		}
	})

	t.Run("G5 rejects empty and malformed tool manifests", func(t *testing.T) {
		emptyCtx := setupSparseGateContext(t)
		mkdirGate(t, filepath.Join(emptyCtx.EvidenceDir, "02_PROOFGRAPH", "tool_manifests"))
		if result := (&G5ToolTrust{}).Run(emptyCtx); result.Pass || !reasonContains(result.Reasons, "TOOL_MANIFEST_MISSING") {
			t.Fatalf("G5 empty manifest result = %+v, want missing failure", result)
		}

		badCtx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(badCtx.EvidenceDir, "02_PROOFGRAPH", "tool_manifests", "bad.json"), []byte("{"))
		if result := (&G5ToolTrust{}).Run(badCtx); result.Pass || !reasonContains(result.Reasons, "TOOL_MANIFEST_INVALID") {
			t.Fatalf("G5 malformed manifest result = %+v, want invalid failure", result)
		}
	})

	t.Run("G6 rejects malformed taint lineage", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "taint", "lineage.json"), []byte("{"))

		result := (&G6Taint{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, conform.ReasonTaintFlowViolation) {
			t.Fatalf("G6 malformed lineage result = %+v, want taint violation", result)
		}
	})

	t.Run("G7 and G8 fail receipts without containment or operator", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateJSON(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts", "agent.json"), map[string]any{
			"action_type": "effect_attempt",
			"actor":       "agent",
		})

		if result := (&G7Incident{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, conform.ReasonContainmentNotTriggered) {
			t.Fatalf("G7 no containment result = %+v, want containment failure", result)
		}
		if result := (&G8HITL{}).Run(ctx); result.Pass || !reasonContains(result.Reasons, "HITL_RECEIPTS_MISSING") {
			t.Fatalf("G8 no operator result = %+v, want HITL failure", result)
		}
	})

	t.Run("G9 fails when only one complete pack exists", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		packDir := filepath.Join(ctx.EvidenceDir, "04_EXPORTS", "jurisdictions", "us")
		mkdirGate(t, filepath.Join(packDir, "test_suite"))
		writeGateJSON(t, filepath.Join(packDir, "policy_bundle.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(packDir, "evidence_requirements.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(packDir, "retention_rules.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(packDir, "conformance_report.json"), map[string]any{"pass": true})

		result := (&G9Jurisdiction{}).Run(ctx)
		if result.Pass || !reasonContains(result.Reasons, "JURISDICTION_PACKS_INSUFFICIENT") || result.Metrics.Counts["jurisdiction_packs"] != 1 {
			t.Fatalf("G9 one-pack result = %+v, want insufficient pack failure", result)
		}
	})

	t.Run("GX envelope skips malformed receipts without policy directory", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts", "bad.json"), []byte("{"))

		result := (&GXEnvelopeBound{}).Run(ctx)
		if !result.Pass || result.Metrics.Counts["receipts_checked"] != 0 {
			t.Fatalf("GX envelope malformed-only result = %+v, want skipped malformed receipt", result)
		}
	})

	t.Run("GX SDK drift reports missing markers", func(t *testing.T) {
		ctx := setupSparseGateContext(t)
		writeGateFile(t, filepath.Join(ctx.ProjectRoot, "api", "openapi.yaml"), []byte("openapi: 3.0.0\n"))
		mkdirGate(t, filepath.Join(ctx.ProjectRoot, "sdk", "python"))

		result := (&GXSDKDrift{}).Run(ctx)
		if !reasonContains(result.Reasons, "SDK_VERSION_MARKER_MISSING") || result.Metrics.Counts["sdk_directories"] != 1 || result.Metrics.Counts["sdk_version_markers"] != 0 {
			t.Fatalf("GX SDK marker result = %+v, want missing marker reason", result)
		}
	})
}

func TestEnvelopeBoundHelpersDetectFailures(t *testing.T) {
	result := &conform.GateResult{Pass: true, Reasons: []string{}, Metrics: conform.GateMetrics{Counts: map[string]int{}}}
	if decoded, ok := decodeJSONMap([]byte("{")); ok || decoded != nil {
		t.Fatalf("decodeJSONMap accepted invalid JSON")
	}
	denialFound := false
	applyEnvelopeBoundReceiptChecks(result, map[string]any{
		"action_type":    "effect_attempt",
		"envelope_id":    "",
		"envelope_hash":  "",
		"jurisdiction":   "",
		"envelope_extra": "ignored",
	}, &denialFound)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonEnvelopeNotBound) || !reasonContains(result.Reasons, conform.ReasonEnvelopeNotEnforced) {
		t.Fatalf("envelope checks result = %+v, want not-bound and not-enforced failures", result)
	}

	policyDir := filepath.Join(t.TempDir(), "policies")
	mkdirGate(t, policyDir)
	writeGateJSON(t, filepath.Join(policyDir, "deny.json"), map[string]any{"allowed": false})
	result = &conform.GateResult{Pass: true, Reasons: []string{}, Metrics: conform.GateMetrics{Counts: map[string]int{}}}
	checkDenialReceiptsBackedByReceipt(result, policyDir, false)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonEnvelopeDenialNoReceipt) {
		t.Fatalf("denial receipt check result = %+v, want missing denial receipt failure", result)
	}
}

func setupSparseGateContext(t *testing.T) *conform.RunContext {
	t.Helper()
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	projectRoot := filepath.Join(root, "project")
	mkdirGate(t, evidenceDir)
	mkdirGate(t, projectRoot)
	return &conform.RunContext{
		RunID:        "sparse-run",
		Profile:      conform.ProfileCore,
		Jurisdiction: "US",
		EvidenceDir:  evidenceDir,
		ProjectRoot:  projectRoot,
		Clock:        fixedClock,
		ExtraConfig:  map[string]any{"containment_triggered": false},
	}
}

func setupConformingGateContext(t *testing.T) *conform.RunContext {
	t.Helper()
	root := t.TempDir()
	evidenceDir := filepath.Join(root, "evidence")
	projectRoot := filepath.Join(root, "project")
	if err := conform.CreateEvidencePackDirs(evidenceDir); err != nil {
		t.Fatalf("create evidence dirs: %v", err)
	}
	mkdirGate(t, projectRoot)

	ctx := &conform.RunContext{
		RunID:        "run-1",
		Profile:      conform.ProfileCore,
		Jurisdiction: "US",
		EvidenceDir:  evidenceDir,
		ProjectRoot:  projectRoot,
		Clock:        fixedClock,
		ExtraConfig:  map[string]any{"containment_triggered": true},
	}

	setupReplayEvidence(t, evidenceDir)
	setupSchemaEvidence(t, evidenceDir)
	setupPolicyEvidence(t, evidenceDir)
	setupBudgetEvidence(t, evidenceDir)
	setupReceipts(t, evidenceDir)
	setupToolManifest(t, evidenceDir)
	setupTaintEvidence(t, evidenceDir)
	setupIncidentEvidence(t, evidenceDir)
	setupJurisdictionEvidence(t, evidenceDir)
	setupOperabilityEvidence(t, evidenceDir, projectRoot)
	setupSupplyChainEvidence(t, projectRoot)
	setupBundleEvidence(t, evidenceDir)
	setupSDKDriftEvidence(t, projectRoot)
	setupThreatScanEvidence(t, evidenceDir)
	setupDelegationEvidence(t, evidenceDir)

	return ctx
}

func setupReplayEvidence(t *testing.T, evidenceDir string) {
	mkdirGate(t, filepath.Join(evidenceDir, "08_TAPES"))
	mkdirGate(t, filepath.Join(evidenceDir, "05_DIFFS"))
	writeGateJSON(t, filepath.Join(evidenceDir, "08_TAPES", "tape_manifest.json"), map[string]any{"tenant_id": "tenant-a", "entries": []any{}})
	writeGateJSON(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "determinism_manifest.json"), map[string]any{
		"live_hash":   "sha256:same",
		"replay_hash": "sha256:same",
	})
	mkdirGate(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "decisions"))
	writeGateJSON(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "decisions", "decision.json"), map[string]any{
		"policy_backend":        "rego",
		"policy_decision_hash":  "sha256:decision",
		"tenant_id":             "tenant-a",
		"normalized_input_hash": "sha256:normalized",
	})
}

func setupSchemaEvidence(t *testing.T, evidenceDir string) {
	mkdirGate(t, filepath.Join(evidenceDir, "09_SCHEMAS", "tool_io"))
	writeGateJSON(t, filepath.Join(evidenceDir, "09_SCHEMAS", "tool_io", "tool.schema.json"), map[string]any{"tenant_id": "tenant-a", "type": "object"})
	mkdirGate(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "tool_io_commitments"))
	writeGateJSON(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "tool_io_commitments", "commitment.json"), map[string]any{"tenant_id": "tenant-a", "hash": "sha256:io"})
	writeGateJSON(t, filepath.Join(evidenceDir, "01_SCORE.json"), map[string]any{"pass": true})
}

func setupPolicyEvidence(t *testing.T, evidenceDir string) {
	policyDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "policy_decisions")
	mkdirGate(t, policyDir)
	writeGateJSON(t, filepath.Join(policyDir, "deny.json"), map[string]any{
		"policy_hash": "sha256:policy",
		"boundary":    "tool",
		"allowed":     false,
		"tenant_id":   "tenant-a",
	})
}

func setupBudgetEvidence(t *testing.T, evidenceDir string) {
	writeGateJSON(t, filepath.Join(evidenceDir, "03_TELEMETRY", "budget_metrics.json"), map[string]any{
		"tenant_id":   "tenant-a",
		"time":        map[string]any{"limit": 10, "used": 1},
		"tokens":      map[string]any{"limit": 100, "used": 10},
		"tool_calls":  map[string]any{"limit": 10, "used": 1},
		"spend":       map[string]any{"limit": 10, "used": 1},
		"recursion":   map[string]any{"limit": 3, "used": 1},
		"exhaustions": []string{"test"},
	})
}

func setupReceipts(t *testing.T, evidenceDir string) {
	receiptsDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts")
	mkdirGate(t, receiptsDir)
	receipts := []struct {
		name string
		doc  map[string]any
	}{
		{"001_BudgetExhausted.json", baseGateReceipt(1, 1, "budget_exhausted", "system")},
		{"002_freeze.json", baseGateReceipt(2, 2, "FREEZE", "operator")},
		{"003_effect_attempt.json", baseGateReceipt(3, 3, "effect_attempt", "agent")},
		{"004_effect_denied.json", baseGateReceipt(4, 4, "effect_denied", "policy")},
		{"005_pack_install.json", baseGateReceipt(5, 5, "pack_install", "operator")},
	}
	receipts[2].doc["envelope_decision"] = map[string]any{"allowed": true}
	for _, receipt := range receipts {
		writeGateJSON(t, filepath.Join(receiptsDir, receipt.name), receipt.doc)
	}
}

func baseGateReceipt(seq int, lamport int, actionType string, actor string) map[string]any {
	return map[string]any{
		"run_id":                "run-1",
		"seq":                   seq,
		"tenant_id":             "tenant-a",
		"timestamp_virtual":     "2026-01-01T00:00:00Z",
		"schema_version":        "1.0",
		"envelope_id":           "env-1",
		"envelope_hash":         "sha256:env",
		"jurisdiction":          "US",
		"policy_hash":           "sha256:policy",
		"policy_version":        "v1",
		"actor":                 actor,
		"action_type":           actionType,
		"effect_class":          "E3",
		"effect_type":           "test_effect",
		"decision_id":           "decision-1",
		"intent_id":             "intent-1",
		"effect_digest_hash":    "sha256:effect",
		"capability_ref":        "capability-1",
		"budget_snapshot_ref":   "budget-1",
		"phenotype_hash":        "sha256:phenotype",
		"parent_receipt_hashes": []string{"genesis"},
		"receipt_hash":          "receipt-hash",
		"signature":             "sig",
		"payload_commitment":    "sha256:payload",
		"lamport_clock":         lamport,
	}
}

func setupToolManifest(t *testing.T, evidenceDir string) {
	dir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "tool_manifests")
	mkdirGate(t, dir)
	writeGateJSON(t, filepath.Join(dir, "tool.json"), map[string]any{
		"tenant_id":           "tenant-a",
		"tool_id":             "tool",
		"version":             "1.0.0",
		"capabilities":        []string{"read"},
		"side_effect_classes": []string{"E1"},
		"data_classes_in":     []string{"public"},
		"data_classes_out":    []string{"public"},
		"network_scopes":      []string{"none"},
		"fs_scopes":           []string{"none"},
		"required_approvals":  []string{},
		"schemas":             map[string]any{"input": "sha256:input"},
		"signatures":          []string{"sig"},
	})
}

func setupTaintEvidence(t *testing.T, evidenceDir string) {
	writeGateJSON(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "taint", "lineage.json"), map[string]any{
		"tenant_id":    "tenant-a",
		"nodes":        []any{map[string]any{"id": "node-1", "lineage_hash": "sha256:lineage"}},
		"violations":   []any{},
		"lineage_root": "sha256:root",
	})
}

func setupIncidentEvidence(t *testing.T, evidenceDir string) {
	dir := filepath.Join(evidenceDir, "04_EXPORTS", "incidents")
	mkdirGate(t, dir)
	writeGateJSON(t, filepath.Join(dir, "incident.json"), map[string]any{"tenant_id": "tenant-a", "status": "contained"})
}

func setupJurisdictionEvidence(t *testing.T, evidenceDir string) {
	root := filepath.Join(evidenceDir, "04_EXPORTS", "jurisdictions")
	for _, name := range []string{"us", "eu"} {
		packDir := filepath.Join(root, name)
		mkdirGate(t, filepath.Join(packDir, "test_suite"))
		writeGateJSON(t, filepath.Join(packDir, "policy_bundle.json"), map[string]any{"tenant_id": "tenant-a", "jurisdiction": name})
		writeGateJSON(t, filepath.Join(packDir, "evidence_requirements.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(packDir, "retention_rules.json"), map[string]any{"tenant_id": "tenant-a"})
		writeGateJSON(t, filepath.Join(packDir, "conformance_report.json"), map[string]any{"pass": true})
		writeGateJSON(t, filepath.Join(packDir, "test_suite", "case.json"), map[string]any{"tenant_id": "tenant-a"})
	}
}

func setupOperabilityEvidence(t *testing.T, evidenceDir, projectRoot string) {
	required := []string{
		"scheduler_latency",
		"policy_decision_latency",
		"receipt_verification_latency",
		"connector_error_rate",
		"escalation_queue_latency",
	}
	slos := make([]map[string]any, 0, len(required))
	for _, name := range required {
		slos = append(slos, map[string]any{"name": name, "target": "99p"})
	}
	writeGateJSON(t, filepath.Join(evidenceDir, "03_TELEMETRY", "slo.json"), slos)
	writeGateJSON(t, filepath.Join(evidenceDir, "12_REPORTS", "ops_status_snapshot.json"), map[string]any{"status": "ok"})
	writeGateJSON(t, filepath.Join(projectRoot, "docs", "runbooks", "index.json"), map[string]any{"runbooks": []string{"incident"}})
}

func setupSupplyChainEvidence(t *testing.T, projectRoot string) {
	packsRoot := filepath.Join(projectRoot, "packs")
	mkdirGate(t, filepath.Join(packsRoot, "example-pack"))
	writeGateJSON(t, filepath.Join(packsRoot, "example-pack", "signature.json"), map[string]any{"signatures": []string{"sig"}})
	writeGateJSON(t, filepath.Join(packsRoot, "trusted_roots.json"), map[string]any{"roots": []string{"root"}})
}

func setupBundleEvidence(t *testing.T, evidenceDir string) {
	bundleYAML := `
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  name: conformance-bundle
  version: "1.0.0"
rules:
  - id: allow-read
    action: "read.*"
    expression: "true"
    verdict: ALLOW
    reason: "read permitted"
`
	writeGateFile(t, filepath.Join(evidenceDir, "bundles", "bundle.yaml"), []byte(bundleYAML))
}

func setupSDKDriftEvidence(t *testing.T, projectRoot string) {
	writeGateFile(t, filepath.Join(projectRoot, "api", "openapi", "helm.openapi.yaml"), []byte("openapi: 3.0.0\ninfo:\n  title: HELM\n  version: 1.0.0\npaths: {}\n"))
	for _, dir := range []string{"python", "ts", "go"} {
		writeGateFile(t, filepath.Join(projectRoot, "sdk", dir, ".openapi-version"), []byte("1.0.0\n"))
	}
}

func setupThreatScanEvidence(t *testing.T, evidenceDir string) {
	writeGateJSON(t, filepath.Join(evidenceDir, "02_PROOFGRAPH", "threat_scan", "scan_results.json"), []map[string]any{{
		"scan_id":               "scan-1",
		"raw_input_hash":        "sha256:raw",
		"normalized_input_hash": "sha256:normalized",
		"findings":              []any{},
	}})
	writeGateJSON(t, filepath.Join(evidenceDir, "01_DECISIONS", "threat_deny.json"), map[string]any{
		"reason": conform.ReasonTaintedInputDeny,
	})
}

func setupDelegationEvidence(t *testing.T, evidenceDir string) {
	decisionsDir := filepath.Join(evidenceDir, "01_DECISIONS")
	writeGateJSON(t, filepath.Join(decisionsDir, "delegation.json"), map[string]any{
		"delegation_session_ref": "session-1",
		"verdict":                "DENY",
		"reason_code":            conform.ReasonDelegationInvalid,
	})
	nodesDir := filepath.Join(evidenceDir, "02_PROOFGRAPH", "nodes")
	writeGateJSON(t, filepath.Join(nodesDir, "delegation_bind.json"), map[string]any{
		"kind": "TRUST_EVENT",
		"payload": map[string]any{
			"event": "DELEGATION_BIND",
		},
	})
	writeGateJSON(t, filepath.Join(nodesDir, "delegation_attestation.json"), map[string]any{
		"kind": "ATTESTATION",
		"payload": map[string]any{
			"session_id": "session-1",
		},
	})
}

func writeGateJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	writeGateFile(t, path, data)
}

func writeGateFile(t *testing.T, path string, data []byte) {
	t.Helper()
	mkdirGate(t, filepath.Dir(path))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mkdirGate(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func reasonContains(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want || strings.Contains(reason, want) {
			return true
		}
	}
	return false
}
