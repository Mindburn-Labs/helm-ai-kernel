package evidence

import "testing"

func TestValidateConnectorEvidenceRecordAcceptsCompleteResponseRecord(t *testing.T) {
	record := ConnectorEvidenceRecord{
		ConnectorID:           "tinyfish-web-v1",
		ConnectorContractHash: "sha256:contract",
		PolicyHash:            "sha256:policy",
		RequestHash:           "sha256:request",
		ResponseHash:          "sha256:response",
		SourceURLHashes:       []string{"sha256:url-1", "sha256:url-2"},
		ReceiptRef:            "receipt://tinyfish/rcpt-1",
		EvidencePackRef:       "evidencepack://pack-1",
		Production:            true,
	}
	if got := ValidateConnectorEvidenceRecord(record); len(got) != 0 {
		t.Fatalf("expected complete record to validate, got %v", got)
	}
}

func TestValidateConnectorEvidenceRecordAcceptsErrorRecord(t *testing.T) {
	record := ConnectorEvidenceRecord{
		ConnectorContractHash: "sha256:contract",
		PolicyHash:            "sha256:policy",
		RequestHash:           "sha256:request",
		ErrorHash:             "sha256:error",
		SourceURLHashes:       []string{"sha256:url-1"},
		ReceiptRef:            "receipt://tinyfish/rcpt-1",
		EvidencePackRef:       "evidencepack://pack-1",
	}
	if got := ValidateConnectorEvidenceRecord(record); len(got) != 0 {
		t.Fatalf("expected error record to validate, got %v", got)
	}
}

func TestValidateConnectorEvidenceRecordRejectsMissingHashesAndSamplePromotion(t *testing.T) {
	record := ConnectorEvidenceRecord{
		ConnectorContractHash: "contract",
		PolicyHash:            "sha256:policy",
		RequestHash:           "sha256:request",
		SourceURLHashes:       []string{"url"},
		ReceiptRef:            "receipt://tinyfish/rcpt-1",
		EvidencePackRef:       "evidencepack://pack-1",
		SampleOnly:            true,
		Production:            true,
	}
	missing := ValidateConnectorEvidenceRecord(record)
	for _, want := range []string{
		"connector_contract_hash:sha256",
		"response_hash_or_error_hash",
		"source_url_hashes[0]:sha256",
		"sample_only_production_exclusion",
	} {
		if !containsConnectorEvidenceError(missing, want) {
			t.Fatalf("missing %q in %v", want, missing)
		}
	}
}

func containsConnectorEvidenceError(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
