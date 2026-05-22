package hostaction

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestCorrelate_StatusesAndBoundaryDrift(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	receipts := []contracts.Receipt{
		networkReceipt("r-allow", "ALLOW", map[string]any{
			"workload_id":      "workload-allow",
			"destination_ip":   "203.0.113.10",
			"destination_port": "443",
			"protocol":         "tcp",
			"max_egress_bytes": "1024",
			"process_identity": "agent",
		}, now),
		networkReceipt("r-deny", "DENY", map[string]any{
			"workload_id":      "workload-deny",
			"destination_ip":   "203.0.113.20",
			"destination_port": "443",
			"protocol":         "tcp",
		}, now),
		networkReceipt("r-missing-host", "ALLOW", map[string]any{
			"workload_id":      "workload-missing",
			"destination_ip":   "203.0.113.30",
			"destination_port": "443",
			"protocol":         "tcp",
		}, now),
	}
	chain := &contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{
		hostReceipt("h-correlated", "workload-allow", "203.0.113.10", 512, now),
		hostReceipt("h-denied", "workload-deny", "203.0.113.20", 1, now),
		hostReceipt("h-uncorrelated", "rogue", "203.0.113.40", 1, now),
	}}

	results := Correlate(receipts, chain, Options{Clock: fixedClock(now)})
	assertStatus(t, results, "h-correlated", contracts.HostCorrelationCorrelated, "")
	assertStatus(t, results, "h-denied", contracts.HostCorrelationPolicyDeniedHostEgress, string(contracts.ReasonHostEgressAfterDeny))
	assertStatus(t, results, "h-uncorrelated", contracts.HostCorrelationUncorrelatedHostEgress, string(contracts.ReasonHostEgressWithoutIntent))
	assertMissingHost(t, results, "r-missing-host")
}

func TestCorrelate_DestinationMismatchAndVolumeExceeded(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	receipts := []contracts.Receipt{
		networkReceipt("r-dest", "ALLOW", map[string]any{
			"workload_id":      "workload-dest",
			"destination_ip":   "203.0.113.10",
			"destination_port": "443",
			"protocol":         "tcp",
		}, now),
		networkReceipt("r-volume", "ALLOW", map[string]any{
			"workload_id":      "workload-volume",
			"destination_ip":   "203.0.113.20",
			"destination_port": "443",
			"protocol":         "tcp",
			"max_egress_bytes": "10",
		}, now),
	}
	chain := &contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{
		hostReceipt("h-dest", "workload-dest", "198.51.100.7", 1, now),
		hostReceipt("h-volume", "workload-volume", "203.0.113.20", 100, now),
	}}

	results := Correlate(receipts, chain, Options{Clock: fixedClock(now)})
	assertStatus(t, results, "h-dest", contracts.HostCorrelationPartiallyCorrelated, string(contracts.ReasonHostDestinationMismatch))
	assertStatus(t, results, "h-volume", contracts.HostCorrelationPartiallyCorrelated, string(contracts.ReasonHostVolumeExceeded))
}

func networkReceipt(id, verdict string, metadata map[string]any, ts time.Time) contracts.Receipt {
	return contracts.Receipt{
		ReceiptID:      id,
		DecisionID:     "dec-" + id,
		Type:           contracts.ReceiptTypeNetworkEgressAllowed,
		Status:         verdict,
		Verdict:        verdict,
		EffectType:     contracts.EffectTypeWorkstationNetworkEgress,
		EffectID:       "network-egress",
		Timestamp:      ts,
		ExecutorID:     "agent-1",
		Metadata:       metadata,
		SandboxLeaseID: metadataStringValue(metadata, "sandbox_lease_id"),
	}
}

func hostReceipt(id, workload, ip string, bytes int64, ts time.Time) contracts.ExternalHostReceipt {
	return contracts.ExternalHostReceipt{
		ReceiptID:       id,
		ReceiptHash:     "sha256:" + id,
		HostID:          "host-a",
		WorkloadID:      workload,
		ProcessIdentity: "agent",
		Event: contracts.NetworkEgressEvent{
			DestinationIP:   ip,
			DestinationPort: 443,
			Protocol:        "tcp",
			Timestamp:       ts,
			BytesSent:       bytes,
			Verdict:         "OBSERVED",
		},
	}
}

func assertStatus(t *testing.T, results []contracts.HostCorrelationResult, hostID, status, reason string) {
	t.Helper()
	for _, result := range results {
		if result.HostReceiptID != hostID {
			continue
		}
		if result.Status != status || result.ReasonCode != reason {
			t.Fatalf("%s status/reason = %s/%s, want %s/%s", hostID, result.Status, result.ReasonCode, status, reason)
		}
		if reason != "" && result.BoundaryDrift == nil {
			t.Fatalf("%s expected boundary drift receipt", hostID)
		}
		return
	}
	t.Fatalf("missing result for host receipt %s", hostID)
}

func assertMissingHost(t *testing.T, results []contracts.HostCorrelationResult, helmID string) {
	t.Helper()
	for _, result := range results {
		if result.HELMReceiptID == helmID && result.Status == contracts.HostCorrelationMissingHostReceipt {
			return
		}
	}
	t.Fatalf("missing host receipt result for %s", helmID)
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func metadataStringValue(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}
