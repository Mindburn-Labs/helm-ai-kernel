package agentsafety

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
)

func TestRegistryCoversMarkdownMatrix(t *testing.T) {
	docIDs := readMatrixCaseIDs(t)
	regIDs := map[string]CaseCoverage{}
	for _, entry := range Registry() {
		if entry.CaseID == "" || entry.Group == "" || entry.PolicyRuleID == "" ||
			entry.ConfigGuard == "" || entry.PackageTest == "" ||
			entry.ConformanceScenario == "" || entry.ResidualRisk == "" ||
			entry.ExpectedPolicyAction == "" {
			t.Fatalf("incomplete registry entry: %#v", entry)
		}
		if _, exists := regIDs[entry.CaseID]; exists {
			t.Fatalf("duplicate registry case id %s", entry.CaseID)
		}
		regIDs[entry.CaseID] = entry
	}

	var missing []string
	for _, id := range docIDs {
		if _, ok := regIDs[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("registry missing markdown case ids: %s", strings.Join(missing, ", "))
	}
	if len(regIDs) != len(docIDs) {
		t.Fatalf("registry count = %d, markdown count = %d", len(regIDs), len(docIDs))
	}
}

func TestRegistryRulesExistInBaselineBundle(t *testing.T) {
	rules := map[string]policybundles.PolicyRule{}
	for _, rule := range policybundles.AgentSafetyBaselineBundle().Rules {
		rules[rule.RuleID] = rule
	}

	for _, entry := range Registry() {
		t.Run(entry.CaseID, func(t *testing.T) {
			rule, ok := rules[entry.PolicyRuleID]
			if !ok {
				t.Fatalf("rule %s not found in baseline bundle", entry.PolicyRuleID)
			}
			if rule.Action != entry.ExpectedPolicyAction {
				t.Fatalf("rule action = %q, want %q", rule.Action, entry.ExpectedPolicyAction)
			}
			if entry.ExpectedReasonCode == "" {
				return
			}
			if !contracts.IsCanonicalReasonCode(entry.ExpectedReasonCode) {
				t.Fatalf("expected reason code %q is not canonical", entry.ExpectedReasonCode)
			}
			if got := rule.Parameters["reason_code"]; got != entry.ExpectedReasonCode {
				t.Fatalf("rule reason = %q, want %q", got, entry.ExpectedReasonCode)
			}
		})
	}
}

func TestCaseIDsSorted(t *testing.T) {
	ids := CaseIDs()
	if len(ids) != len(Registry()) {
		t.Fatalf("ids = %d, registry = %d", len(ids), len(Registry()))
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("case IDs are not sorted: %v", ids)
	}
}

func readMatrixCaseIDs(t *testing.T) []string {
	t.Helper()
	path := matrixPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read matrix %s: %v", path, err)
	}

	re := regexp.MustCompile(`\|\s*([A-Z0-9]+-\d{2})\s*\|`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	seen := map[string]bool{}
	var ids []string
	for _, m := range matches {
		id := m[1]
		if seen[id] {
			t.Fatalf("duplicate matrix case id %s", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) != 60 {
		t.Fatalf("matrix case count = %d, want 60: %v", len(ids), ids)
	}
	return ids
}

func matrixPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "docs/security/agent-safety-conformance-cases.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("agent-safety-conformance-cases.md not found")
	return ""
}
