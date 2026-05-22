package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHostEvidenceContractsRoundTrip(t *testing.T) {
	ts := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	nonExportable := true
	chain := ExternalReceiptChain{
		SchemaVersion:    ExternalReceiptChainVersion,
		ChainID:          "chain-1",
		SourceVendor:     "vendor-neutral",
		SourceProfile:    "external-evidence-receipt-profile-v0.1",
		EventSchemaHash:  "sha256:event-schema",
		ReceiptChainHash: "sha256:chain",
		PublicKeys: []ExternalVerifierKey{{
			KeyID:        "key-1",
			Algorithm:    "Ed25519",
			PublicKeyHex: "012345",
		}},
		Receipts: []ExternalHostReceipt{{
			SchemaVersion:   ExternalHostReceiptVersion,
			ReceiptID:       "host-r1",
			HostID:          "host-a",
			ProcessIdentity: "pid:1234:/usr/bin/agent",
			ProcessAncestry: []string{"systemd", "agent-supervisor"},
			AgentID:         "agent-1",
			WorkloadID:      "workload-1",
			SandboxLeaseID:  "lease-1",
			Event: NetworkEgressEvent{
				EventID:         "event-1",
				DestinationIP:   "203.0.113.10",
				DestinationPort: 443,
				Protocol:        "tcp",
				Timestamp:       ts,
				BytesSent:       42,
				BytesReceived:   24,
				Verdict:         "OBSERVED",
			},
			ReceiptHash:        "sha256:receipt",
			PrevReceiptHash:    "sha256:prev",
			SigningKeyID:       "key-1",
			SignatureAlgorithm: "Ed25519",
			Signature:          "abcd",
			HardwareRoot: &HardwareRootClaim{
				KernelMeasurementSHA256: "measurement",
				ExecutionProfile:        "TPM_ATTESTED",
				HardwareRootType:        "TPM2",
				QuoteFormat:             "tpm2-quote",
				QuoteBlobB64:            "AQID",
				QuoteVerifier:           "not_verified",
				SigningKeyNonExportable: &nonExportable,
				MeasurementTime:         ts,
				BootSequenceRef:         "boot-1",
				VerificationStatus:      "not_verified",
			},
			RecordedAt: ts,
		}},
	}

	data, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExternalReceiptChain
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != ExternalReceiptChainVersion {
		t.Fatalf("schema_version=%q", decoded.SchemaVersion)
	}
	if got := decoded.Receipts[0].Event.DestinationIP; got != "203.0.113.10" {
		t.Fatalf("destination_ip=%q", got)
	}
	if decoded.Receipts[0].HardwareRoot == nil || decoded.Receipts[0].HardwareRoot.HardwareRootType != "TPM2" {
		t.Fatalf("hardware root did not round trip: %+v", decoded.Receipts[0].HardwareRoot)
	}
}

func TestHostCorrelationResultRoundTrip(t *testing.T) {
	ts := time.Date(2026, 5, 21, 12, 1, 0, 0, time.UTC)
	result := HostCorrelationResult{
		SchemaVersion:     HostCorrelationResultVersion,
		Status:            HostCorrelationPolicyDeniedHostEgress,
		ReasonCode:        string(ReasonHostEgressAfterDeny),
		Confidence:        1,
		HELMReceiptID:     "helm-r1",
		HostReceiptID:     "host-r1",
		HostReceiptHash:   "sha256:host",
		CorrelationMethod: "identity",
		CorrelatedAt:      ts,
		BoundaryDrift: &BoundaryDriftReceipt{
			ReceiptVersion:  BoundaryDriftReceiptVersion,
			ReceiptID:       "boundary_drift:test",
			Type:            ReceiptTypeBoundaryDrift,
			ReasonCode:      string(ReasonHostEgressAfterDeny),
			HostReceiptHash: "sha256:host",
			HELMReceiptID:   "helm-r1",
			CreatedAt:       ts,
			ReceiptHash:     "sha256:drift",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HostCorrelationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != HostCorrelationPolicyDeniedHostEgress {
		t.Fatalf("status=%q", decoded.Status)
	}
	if decoded.BoundaryDrift == nil || decoded.BoundaryDrift.Type != ReceiptTypeBoundaryDrift {
		t.Fatalf("boundary drift did not round trip: %+v", decoded.BoundaryDrift)
	}
}
