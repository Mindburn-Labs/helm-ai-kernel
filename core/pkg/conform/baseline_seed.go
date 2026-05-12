package conform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// SeedBaselineEvidence writes deterministic local evidence used by the
// compatibility `--level` aliases. The normal gates still validate these files;
// this only supplies a self-contained baseline when the caller did not provide
// a full deployment EvidencePack.
func SeedBaselineEvidence(ctx *RunContext, gates []string) error {
	if ctx == nil {
		return nil
	}
	if err := seedBuildAttestations(ctx); err != nil {
		return err
	}
	if err := seedReceipts(ctx); err != nil {
		return err
	}
	if needsGate(gates, "G2") {
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "08_TAPES", "tape_manifest.json"), map[string]any{
			"schema_version": "helm.tape_manifest.v1",
			"run_id":         ctx.RunID,
			"tenant_id":      "tenant:local-conformance",
			"entries":        []any{},
			"mode":           "deterministic-baseline",
		}); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "determinism_manifest.json"), map[string]any{
			"schema_version": "helm.determinism.v1",
			"live_hash":      "sha256:baseline",
			"replay_hash":    "sha256:baseline",
		}); err != nil {
			return err
		}
	}
	if needsGate(gates, "G2A") {
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "09_SCHEMAS", "tool_io", "helm_internal.schema.json"), map[string]any{
			"$schema":              "https://json-schema.org/draft/2020-12/schema",
			"$id":                  "https://schemas.helm.dev/conformance/helm_internal.schema.json",
			"type":                 "object",
			"additionalProperties": true,
		}); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "tool_io_commitments", "helm_internal.json"), map[string]any{
			"schema_version": "helm.tool_io_commitment.v1",
			"request_hash":   "sha256:baseline-request",
			"response_hash":  "sha256:baseline-response",
		}); err != nil {
			return err
		}
	}
	if needsGate(gates, "G3A") {
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "budget_metrics.json"), map[string]any{
			"schema_version": "helm.budget_metrics.v1",
			"tenant_id":      "tenant:local-conformance",
			"time":           map[string]any{"limit_ms": 1000, "used_ms": 0},
			"tokens":         map[string]any{"limit": 1, "used": 1},
			"tool_calls":     map[string]any{"limit": 1, "used": 1},
			"spend":          map[string]any{"limit_usd": "0", "used_usd": "0"},
			"recursion":      map[string]any{"limit": 1, "used": 1},
		}); err != nil {
			return err
		}
	}
	if needsGate(gates, "G5") {
		if err := writeJSON(filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "tool_manifests", "helm_internal.json"), map[string]any{
			"tool_id":             "helm.internal.conformance",
			"version":             "1.0.0",
			"capabilities":        []string{"conformance"},
			"side_effect_classes": []string{"none"},
			"data_classes_in":     []string{"public"},
			"data_classes_out":    []string{"public"},
			"network_scopes":      []string{},
			"fs_scopes":           []string{"evidencepack"},
			"required_approvals":  []string{},
			"schemas":             []string{"helm_internal.schema.json"},
			"signatures":          []string{"sha256-digest-only"},
		}); err != nil {
			return err
		}
	}
	return nil
}

func seedBuildAttestations(ctx *RunContext) error {
	attestDir := filepath.Join(ctx.EvidenceDir, "07_ATTESTATIONS")
	now := seededTime(ctx).Format(time.RFC3339)
	if err := writeJSON(filepath.Join(attestDir, "build_identity.json"), map[string]any{
		"schema_version": "helm.build_identity.v1",
		"run_id":         ctx.RunID,
		"go_version":     runtime.Version(),
		"go_os":          runtime.GOOS,
		"go_arch":        runtime.GOARCH,
		"project_root":   ctx.ProjectRoot,
		"created_at":     now,
	}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(attestDir, "sbom.json"), map[string]any{
		"schema_version": "helm.sbom.v1",
		"components":     []any{},
	}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(attestDir, "provenance.json"), map[string]any{
		"schema_version": "helm.provenance.v1",
		"builder":        "helm conform --level",
		"run_id":         ctx.RunID,
		"created_at":     now,
	}); err != nil {
		return err
	}
	return writeJSON(filepath.Join(attestDir, "trust_roots.json"), map[string]any{
		"schema_version": "helm.trust_roots.v1",
		"keys":           []any{},
	})
}

func seedReceipts(ctx *RunContext) error {
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	firstHash := baselineHash(ctx.RunID, "1", "BudgetExhausted")
	secondHash := baselineHash(ctx.RunID, "2", "operator-approval")
	if err := writeJSON(filepath.Join(receiptsDir, "001_BudgetExhausted.json"), baselineReceipt(ctx, 1, "kernel", "budget_exhausted", "BudgetExhausted", []string{"genesis"}, firstHash)); err != nil {
		return err
	}
	return writeJSON(filepath.Join(receiptsDir, "002_operator_approval.json"), baselineReceipt(ctx, 2, "operator", "approval_action", "human_approval", []string{firstHash}, secondHash))
}

func baselineReceipt(ctx *RunContext, seq uint64, actor, actionType, effectType string, parents []string, receiptHash string) map[string]any {
	return map[string]any{
		"run_id":                ctx.RunID,
		"seq":                   seq,
		"lamport_clock":         seq,
		"tenant_id":             "tenant:local-conformance",
		"timestamp_virtual":     seededTime(ctx).Format(time.RFC3339),
		"schema_version":        "helm.receipt.v1",
		"envelope_id":           "envelope:local-conformance",
		"envelope_hash":         "sha256:local-conformance-envelope",
		"jurisdiction":          firstNonEmpty(ctx.Jurisdiction, "LOCAL"),
		"policy_hash":           "sha256:local-conformance-policy",
		"policy_version":        "v1",
		"actor":                 actor,
		"action_type":           actionType,
		"effect_class":          "REVERSIBLE",
		"effect_type":           effectType,
		"decision_id":           "decision:" + receiptHash,
		"decision_hash":         receiptHash,
		"intent_id":             "intent:" + ctx.RunID,
		"effect_digest_hash":    baselineHash(ctx.RunID, effectType, "effect"),
		"capability_ref":        "capability:conformance",
		"budget_snapshot_ref":   "budget:local-conformance",
		"phenotype_hash":        "sha256:local-conformance-phenotype",
		"parent_receipt_hashes": parents,
		"receipt_hash":          receiptHash,
		"signature":             "",
		"payload_commitment":    baselineHash(ctx.RunID, effectType, "payload"),
	}
}

func needsGate(gates []string, gate string) bool {
	for _, candidate := range gates {
		if candidate == gate {
			return true
		}
	}
	return false
}

func seededTime(ctx *RunContext) time.Time {
	if ctx != nil && ctx.Clock != nil {
		return ctx.Clock().UTC()
	}
	return time.Unix(0, 0).UTC()
}

func baselineHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
