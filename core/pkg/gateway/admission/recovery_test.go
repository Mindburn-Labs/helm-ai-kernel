package admission

import (
	"strings"
	"testing"
)

func TestRecoveryVersionLineageValidation(t *testing.T) {
	legacy := RecoveryBinding{OperationID: "11111111-1111-4111-8111-111111111111", InstallationID: "installation", OrgRef: "org:acme", OrganizationVersionID: "v2"}
	if err := validateRecovery(legacy); err != nil {
		t.Fatal(err)
	}
	valid := legacy
	valid.AuthorityVersionID, valid.ExpectedPlanDigest = "v1", strings.Repeat("a", 64)
	valid.CoveredVersionIDs = []string{"v0", "v1", "v2"}
	if err := validateRecovery(valid); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*RecoveryBinding){
		"missing authority": func(b *RecoveryBinding) { b.AuthorityVersionID = "" },
		"missing digest":    func(b *RecoveryBinding) { b.ExpectedPlanDigest = "" },
		"uppercase digest":  func(b *RecoveryBinding) { b.ExpectedPlanDigest = strings.Repeat("A", 64) },
		"missing set":       func(b *RecoveryBinding) { b.CoveredVersionIDs = nil },
		"duplicate":         func(b *RecoveryBinding) { b.CoveredVersionIDs = []string{"v1", "v1", "v2"} },
		"unsorted":          func(b *RecoveryBinding) { b.CoveredVersionIDs = []string{"v2", "v1"} },
		"missing lifecycle": func(b *RecoveryBinding) { b.CoveredVersionIDs = []string{"v1"} },
		"missing native":    func(b *RecoveryBinding) { b.CoveredVersionIDs = []string{"v2"} },
		"bad version":       func(b *RecoveryBinding) { b.CoveredVersionIDs = []string{"bad version", "v1", "v2"} },
		"oversized set":     func(b *RecoveryBinding) { b.CoveredVersionIDs = make([]string, 4097) },
	} {
		t.Run(name, func(t *testing.T) {
			b := valid
			edit(&b)
			if validateRecovery(b) == nil {
				t.Fatal("invalid lineage accepted")
			}
		})
	}
}
