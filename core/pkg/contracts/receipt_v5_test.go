package contracts_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestReceipt_V5Fields_Roundtrip(t *testing.T) {
	receipt := contracts.Receipt{
		ReceiptID:  "rcpt-1",
		DecisionID: "dec-1",
		EffectID:   "eff-1",
		Status:     "succeeded",
		Timestamp:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
		// V5 fields
		NetworkLogRef:     "blob-net-1",
		SecretEventsRef:   "blob-sec-1",
		SandboxLeaseID:    "lease-1",
		EffectGraphNodeID: "step-3",
		PortExposures: []contracts.PortExposureEvent{
			{
				Port:      8080,
				Protocol:  "tcp",
				Direction: "inbound",
				StartedAt: time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
			},
		},
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded contracts.Receipt
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.NetworkLogRef != "blob-net-1" {
		t.Fatalf("network_log_ref: got %s", decoded.NetworkLogRef)
	}
	if decoded.SecretEventsRef != "blob-sec-1" {
		t.Fatalf("secret_events_ref: got %s", decoded.SecretEventsRef)
	}
	if decoded.SandboxLeaseID != "lease-1" {
		t.Fatalf("sandbox_lease_id: got %s", decoded.SandboxLeaseID)
	}
	if decoded.EffectGraphNodeID != "step-3" {
		t.Fatalf("effect_graph_node_id: got %s", decoded.EffectGraphNodeID)
	}
	if len(decoded.PortExposures) != 1 {
		t.Fatalf("port_exposures: expected 1, got %d", len(decoded.PortExposures))
	}
	if decoded.PortExposures[0].Port != 8080 {
		t.Fatalf("port: expected 8080, got %d", decoded.PortExposures[0].Port)
	}
}

func TestReceipt_V5Fields_BackwardCompat(t *testing.T) {
	// Old receipt JSON without V5 fields.
	oldJSON := `{
		"receipt_id": "rcpt-old",
		"decision_id": "dec-old",
		"effect_id": "eff-old",
		"status": "succeeded",
		"timestamp": "2026-04-02T12:00:00Z",
		"prev_hash": "sha256:abc",
		"lamport_clock": 42
	}`

	var receipt contracts.Receipt
	if err := json.Unmarshal([]byte(oldJSON), &receipt); err != nil {
		t.Fatalf("unmarshal old receipt: %v", err)
	}

	if receipt.ReceiptID != "rcpt-old" {
		t.Fatalf("receipt_id: got %s", receipt.ReceiptID)
	}
	if receipt.LamportClock != 42 {
		t.Fatalf("lamport_clock: got %d", receipt.LamportClock)
	}
	// V5 fields should be zero-valued.
	if receipt.NetworkLogRef != "" {
		t.Fatalf("expected empty network_log_ref, got %s", receipt.NetworkLogRef)
	}
	if receipt.SandboxLeaseID != "" {
		t.Fatalf("expected empty sandbox_lease_id, got %s", receipt.SandboxLeaseID)
	}
	if len(receipt.PortExposures) != 0 {
		t.Fatalf("expected empty port_exposures, got %v", receipt.PortExposures)
	}
}

func TestEvidencePack_V2Fields_Roundtrip(t *testing.T) {
	pack := contracts.EvidencePack{
		PackID:        "ep-1",
		FormatVersion: "2.0.0",
		NetworkLogs: []contracts.NetworkLogRef{
			{LogID: "log-1", Hash: "sha256:net", CapturedAt: time.Now()},
		},
		SecretEvents: []contracts.SecretEventRef{
			{EventID: "evt-1", Hash: "sha256:sec", Action: "issue"},
		},
		GitDiffs: []contracts.GitDiffRef{
			{DiffID: "diff-1", Hash: "sha256:diff", FromRef: "abc", ToRef: "def"},
		},
		ReplayManifest: &contracts.ReplayManifestRef{
			ManifestID: "replay-1",
			Hash:       "sha256:replay",
			Mode:       "dry",
		},
	}

	data, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded contracts.EvidencePack
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.NetworkLogs) != 1 || decoded.NetworkLogs[0].LogID != "log-1" {
		t.Fatalf("network_logs mismatch: %v", decoded.NetworkLogs)
	}
	if len(decoded.SecretEvents) != 1 || decoded.SecretEvents[0].Action != "issue" {
		t.Fatalf("secret_events mismatch: %v", decoded.SecretEvents)
	}
	if len(decoded.GitDiffs) != 1 || decoded.GitDiffs[0].FromRef != "abc" {
		t.Fatalf("git_diffs mismatch: %v", decoded.GitDiffs)
	}
	if decoded.ReplayManifest == nil || decoded.ReplayManifest.Mode != "dry" {
		t.Fatalf("replay_manifest mismatch: %v", decoded.ReplayManifest)
	}
}

func TestEvidencePack_V2Fields_BackwardCompat(t *testing.T) {
	// Old evidence pack JSON without V2 fields.
	oldJSON := `{
		"pack_id": "ep-old",
		"format_version": "1.0.0",
		"identity": {"actor_id": "test"},
		"policy": {"decision_id": "dec-1"},
		"effect": {"effect_id": "eff-1"},
		"context": {},
		"execution": {"execution_id": "exec-1", "status": "success"},
		"receipts": {},
		"reconciliation": {},
		"attestation": {"pack_hash": "sha256:old"}
	}`

	var pack contracts.EvidencePack
	if err := json.Unmarshal([]byte(oldJSON), &pack); err != nil {
		t.Fatalf("unmarshal old pack: %v", err)
	}

	if pack.PackID != "ep-old" {
		t.Fatalf("pack_id: got %s", pack.PackID)
	}
	// V2 fields should be nil/empty.
	if len(pack.NetworkLogs) != 0 {
		t.Fatalf("expected no network_logs, got %v", pack.NetworkLogs)
	}
	if pack.ReplayManifest != nil {
		t.Fatalf("expected nil replay_manifest, got %v", pack.ReplayManifest)
	}
}
