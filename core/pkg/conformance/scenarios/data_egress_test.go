package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/firewall"
)

// Scenario 6: Data Egress / Exfiltration
//
// Threat: A compromised agent attempts to exfiltrate sensitive data to
// an external endpoint not in the egress allowlist.
// Expected: DENY with DATA_EGRESS_BLOCKED.
func TestDataEgress_UnauthorizedDestinationBlocked(t *testing.T) {
	policy := &firewall.EgressPolicy{
		AllowedDomains:   []string{"api.internal.corp", "storage.googleapis.com"},
		DeniedDomains:    []string{"evil-exfil.io"},
		AllowedProtocols: []string{"https"},
		MaxPayloadBytes:  10 * 1024 * 1024, // 10MB
	}
	ec := firewall.NewEgressChecker(policy)

	// Attempt 1: Exfiltrate to known-bad domain
	d := ec.CheckEgress("evil-exfil.io", "https", 5000)
	if d.Allowed {
		t.Error("evil-exfil.io should be denied")
	}
	if d.ReasonCode != "DATA_EGRESS_BLOCKED" {
		t.Errorf("reason = %s, want DATA_EGRESS_BLOCKED", d.ReasonCode)
	}

	// Attempt 2: Exfiltrate to unknown domain (not in allowlist)
	d = ec.CheckEgress("attacker-dropbox.onion", "https", 5000)
	if d.Allowed {
		t.Error("unknown domain should be denied (fail-closed)")
	}

	// Attempt 3: Exfiltrate via unauthorized protocol
	d = ec.CheckEgress("api.internal.corp", "ssh", 5000)
	if d.Allowed {
		t.Error("ssh should be blocked when only https allowed")
	}

	// Attempt 4: Legitimate internal API call should pass
	d = ec.CheckEgress("api.internal.corp", "https", 1000)
	if !d.Allowed {
		t.Error("api.internal.corp via https should be allowed")
	}
}

func TestDataEgress_OversizedPayloadBlocked(t *testing.T) {
	policy := &firewall.EgressPolicy{
		AllowedDomains:  []string{"api.internal.corp"},
		MaxPayloadBytes: 1024, // 1KB limit
	}
	ec := firewall.NewEgressChecker(policy)

	d := ec.CheckEgress("api.internal.corp", "https", 1024*1024)
	if d.Allowed {
		t.Error("oversized payload should be blocked")
	}
}

func TestDataEgress_EffectClassification(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeDataEgress)
	if et == nil {
		t.Fatal("DATA_EGRESS not found in catalog")
	}
	if et.Classification.Reversibility != "irreversible" {
		t.Errorf("reversibility = %s, want irreversible", et.Classification.Reversibility)
	}
	if et.Classification.BlastRadius != "system_wide" {
		t.Errorf("blast_radius = %s, want system_wide", et.Classification.BlastRadius)
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeDataEgress)
	if rc != "E4" {
		t.Errorf("risk class = %s, want E4", rc)
	}

	rs := contracts.ComputeRiskSummary(contracts.EffectTypeDataEgress, contracts.WithEgressRisk())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("overall risk = %s, want CRITICAL", rs.OverallRisk)
	}
	if !rs.EgressRisk {
		t.Error("EgressRisk flag should be true")
	}
}

func TestDataEgress_EmptyPolicyDeniesAll(t *testing.T) {
	ec := firewall.NewEgressChecker(nil)

	d := ec.CheckEgress("any-server.com", "https", 100)
	if d.Allowed {
		t.Error("nil policy should deny all egress (fail-closed)")
	}

	total, allowed, denied := ec.Stats()
	if total != 1 || allowed != 0 || denied != 1 {
		t.Errorf("stats = (%d, %d, %d), want (1, 0, 1)", total, allowed, denied)
	}
}
