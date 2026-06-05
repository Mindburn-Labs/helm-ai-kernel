package hostaction

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestCoverageDestinationFieldsMatchBranches(t *testing.T) {
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)
	host := hostReceipt("host-dest", "", "203.0.113.10", 1, now)
	host.Event.DestinationHost = "Example.COM"
	host.Event.Protocol = "TCP"

	cases := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{name: "no destination metadata", metadata: nil, want: false},
		{name: "ip match", metadata: map[string]any{"destination_ip": "203.0.113.10"}, want: true},
		{name: "ip mismatch", metadata: map[string]any{"destination_ip": "198.51.100.7"}, want: false},
		{name: "host case insensitive match", metadata: map[string]any{"destination_host": "example.com"}, want: true},
		{name: "host mismatch", metadata: map[string]any{"destination_host": "other.example"}, want: false},
		{name: "port int match", metadata: map[string]any{"destination_port": 443}, want: true},
		{name: "port mismatch", metadata: map[string]any{"destination_port": "8443"}, want: false},
		{name: "protocol case insensitive match", metadata: map[string]any{"protocol": "tcp"}, want: true},
		{name: "protocol mismatch", metadata: map[string]any{"protocol": "udp"}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt := networkReceipt("receipt-"+tc.name, "ALLOW", tc.metadata, now)
			if got := destinationFieldsMatch(receipt, host); got != tc.want {
				t.Fatalf("destinationFieldsMatch() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCoverageIdentityAndFallbackMatchBranches(t *testing.T) {
	now := time.Date(2026, 6, 5, 10, 0, 0, 0, time.UTC)
	host := hostReceipt("host-match", "workload-a", "203.0.113.20", 1, now)
	host.SandboxLeaseID = "lease-a"
	host.AgentID = "agent-a"
	host.ProcessIdentity = "proc-a"
	host.ProcessAncestry = []string{"parent-a", "grandparent-a"}

	if !exactIdentityMatch(networkReceipt("workload", "ALLOW", map[string]any{"workload_id": "workload-a"}, now), host) {
		t.Fatal("expected workload identity match")
	}
	if !exactIdentityMatch(networkReceipt("lease", "ALLOW", map[string]any{"sandbox_lease_id": "lease-a"}, now), host) {
		t.Fatal("expected metadata lease identity match")
	}
	agentReceipt := networkReceipt("agent", "ALLOW", nil, now)
	agentReceipt.ExecutorID = "agent-a"
	if !exactIdentityMatch(agentReceipt, host) {
		t.Fatal("expected executor identity match")
	}

	processHost := host
	processHost.AgentID = ""
	if processMatch(networkReceipt("no-process", "ALLOW", nil, now), processHost) {
		t.Fatal("receipt without process identity should not match")
	}
	if !processMatch(networkReceipt("process", "ALLOW", map[string]any{"process_identity": "proc-a"}, now), processHost) {
		t.Fatal("expected direct process identity match")
	}
	if !processMatch(networkReceipt("ancestor", "ALLOW", map[string]any{"process_identity": "parent-a"}, now), processHost) {
		t.Fatal("expected process ancestry match")
	}
	if processMatch(networkReceipt("conflict", "ALLOW", map[string]any{
		"workload_id":      "other-workload",
		"process_identity": "proc-a",
		"destination_ip":   "203.0.113.20",
		"destination_port": "443",
		"protocol":         "tcp",
	}, now), processHost) {
		t.Fatal("explicit identity conflict should block process match")
	}

	if destinationTimeMatch(contracts.Receipt{ReceiptID: "not-network"}, processHost, time.Minute) {
		t.Fatal("non-network receipt should not destination-time match")
	}
	if destinationTimeMatch(networkReceipt("outside-window", "ALLOW", map[string]any{"destination_ip": "203.0.113.20"}, now.Add(-2*time.Hour)), processHost, time.Minute) {
		t.Fatal("outside-window receipt should not match")
	}
	if destinationTimeMatch(networkReceipt("destination-conflict", "ALLOW", map[string]any{
		"workload_id":      "other-workload",
		"destination_ip":   "203.0.113.20",
		"destination_port": "443",
	}, now), processHost, time.Minute) {
		t.Fatal("identity conflict should block destination-time match")
	}
	if !destinationTimeMatch(networkReceipt("destination", "ALLOW", map[string]any{
		"destination_host": "example.com",
		"destination_port": int64(443),
		"protocol":         "tcp",
	}, now), processHost, time.Minute) {
		t.Fatal("expected destination-time fallback match")
	}
}

func TestCoverageNetworkMetadataAndMissingHostEdges(t *testing.T) {
	now := time.Date(2026, 6, 5, 11, 0, 0, 0, time.UTC)
	networkByType := contracts.Receipt{ReceiptID: "by-type", Type: contracts.ReceiptTypeNetworkEgressDenied}
	networkByEffectType := contracts.Receipt{ReceiptID: "by-effect-type", EffectType: contracts.EffectTypeWorkstationNetworkEgress}
	networkByEffectID := contracts.Receipt{ReceiptID: "by-effect-id", EffectID: "sandbox-network-egress"}
	networkByMetadata := contracts.Receipt{
		ReceiptID: "by-metadata",
		Metadata:  map[string]any{"effect_type": strings.ToUpper(contracts.EffectTypeWorkstationNetworkEgress)},
	}
	nonNetwork := contracts.Receipt{ReceiptID: "non-network", EffectID: "filesystem-write"}
	for _, receipt := range []contracts.Receipt{networkByType, networkByEffectType, networkByEffectID, networkByMetadata} {
		if !isNetworkReceipt(receipt) {
			t.Fatalf("%s should be detected as network receipt", receipt.ReceiptID)
		}
	}
	if isNetworkReceipt(nonNetwork) {
		t.Fatal("non-network receipt should not be detected as network")
	}

	metadataReceipt := contracts.Receipt{Metadata: map[string]any{
		"nil":    nil,
		"string": "value",
		"int":    443,
		"int64":  int64(8443),
		"float":  float64(1234),
		"bool":   true,
	}}
	for key, want := range map[string]string{
		"missing": "",
		"nil":     "",
		"string":  "value",
		"int":     "443",
		"int64":   "8443",
		"float":   "1234",
		"bool":    "true",
	} {
		if got := metadataString(metadataReceipt, key); got != want {
			t.Fatalf("metadataString(%q) = %q, want %q", key, got, want)
		}
	}
	if got := metadataString(contracts.Receipt{}, "missing"); got != "" {
		t.Fatalf("metadataString nil metadata = %q, want empty", got)
	}

	results := missingHostReceiptResults([]contracts.Receipt{
		networkReceipt("missing-a", "ALLOW", nil, now),
		nonNetwork,
		networkByEffectID,
	}, Options{Clock: fixedClock(now)})
	if len(results) != 2 {
		t.Fatalf("missingHostReceiptResults len = %d, want 2", len(results))
	}
	if results[0].HELMReceiptID != "missing-a" || results[0].CorrelatedAt != now {
		t.Fatalf("unexpected first missing-host result: %+v", results[0])
	}
	if results[1].HELMReceiptID != "by-effect-id" {
		t.Fatalf("unexpected second missing-host result: %+v", results[1])
	}
}

func TestCoverageShortHashEmptyInput(t *testing.T) {
	if got := shortHash(""); len(got) != 16 {
		t.Fatalf("shortHash(empty) len = %d, want 16: %q", len(got), got)
	}
}
