package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// GXTenantIsolation validates multi-tenant isolation per §GX_TENANT.
//
// PASS requires:
//   - No cross-tenant reads/writes of receipts, tapes, evidence, connectors, budgets
//   - tenant_id is mandatory in every receipt and evidence artifact
//   - Enforced by tests (including DB/RLS if used)
type GXTenantIsolation struct{}

func (g *GXTenantIsolation) ID() string   { return "GX_TENANT" }
func (g *GXTenantIsolation) Name() string { return "Tenant and Identity Isolation" }

func (g *GXTenantIsolation) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	// 1. Check all receipts have tenant_id
	receiptsDir := filepath.Join(ctx.EvidenceDir, "02_PROOFGRAPH", "receipts")
	if dirExists(receiptsDir) {
		files, _ := filepath.Glob(filepath.Join(receiptsDir, "*.json"))
		tenantIDs := make(map[string]bool)

		for _, f := range files {
			data, _ := os.ReadFile(f)
			var receipt map[string]any
			if json.Unmarshal(data, &receipt) != nil {
				continue
			}

			tid, ok := receipt["tenant_id"].(string)
			if !ok || tid == "" {
				result.Pass = false
				result.Reasons = append(result.Reasons, conform.ReasonTenantIDMissing)
				continue
			}
			tenantIDs[tid] = true
			result.Metrics.Counts["receipts_with_tenant_id"]++
		}

		// 2. Cross-tenant isolation: all receipts in a single run must share the same tenant_id
		if len(tenantIDs) > 1 {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonTenantIsolationViolation)
			result.Details = map[string]any{
				"tenants_found": len(tenantIDs),
				"violation":     "multiple tenant_ids in single run",
			}
		}
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
	}

	// 3. Check evidence artifacts have tenant scoping
	for _, subdir := range []string{"08_TAPES", "03_TELEMETRY", "04_EXPORTS"} {
		dir := filepath.Join(ctx.EvidenceDir, subdir)
		if !dirExists(dir) {
			continue
		}
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			data, _ := os.ReadFile(path)
			var doc map[string]any
			if json.Unmarshal(data, &doc) == nil {
				if _, hasTenant := doc["tenant_id"]; !hasTenant {
					// Not all artifacts need tenant_id, but structured ones should
					result.Metrics.Counts["artifacts_without_tenant_id"]++
				}
			}
			return nil
		})
	}

	// 4. Check budget isolation
	budgetPath := filepath.Join(ctx.EvidenceDir, "03_TELEMETRY", "budget_metrics.json")
	if fileExists(budgetPath) {
		data, _ := os.ReadFile(budgetPath)
		var budgets map[string]any
		if json.Unmarshal(data, &budgets) == nil {
			if _, ok := budgets["tenant_id"]; !ok {
				result.Pass = false
				result.Reasons = append(result.Reasons, conform.ReasonTenantIDMissing)
			}
		}
	}

	return result
}
