package evidence

import (
	"fmt"
	"strings"
)

// ConnectorEvidenceRecord is the minimal proof surface an external connector
// result must bind before HELM treats it as production evidence.
type ConnectorEvidenceRecord struct {
	ConnectorID           string   `json:"connector_id,omitempty"`
	ConnectorContractHash string   `json:"connector_contract_hash"`
	PolicyHash            string   `json:"policy_hash"`
	RequestHash           string   `json:"request_hash"`
	ResponseHash          string   `json:"response_hash,omitempty"`
	ErrorHash             string   `json:"error_hash,omitempty"`
	SourceURLHashes       []string `json:"source_url_hashes,omitempty"`
	ReceiptRef            string   `json:"receipt_ref,omitempty"`
	EvidencePackRef       string   `json:"evidence_pack_ref,omitempty"`
	FixtureID             string   `json:"fixture_id,omitempty"`
	SampleOnly            bool     `json:"sample_only,omitempty"`
	Production            bool     `json:"production,omitempty"`
}

// ValidateConnectorEvidenceRecord returns deterministic field-level failures.
func ValidateConnectorEvidenceRecord(record ConnectorEvidenceRecord) []string {
	var missing []string

	requireHash := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, field)
			return
		}
		if !strings.HasPrefix(value, "sha256:") {
			missing = append(missing, fmt.Sprintf("%s:sha256", field))
		}
	}

	requireHash("connector_contract_hash", record.ConnectorContractHash)
	requireHash("policy_hash", record.PolicyHash)
	requireHash("request_hash", record.RequestHash)

	if strings.TrimSpace(record.ResponseHash) == "" && strings.TrimSpace(record.ErrorHash) == "" {
		missing = append(missing, "response_hash_or_error_hash")
	} else {
		if strings.TrimSpace(record.ResponseHash) != "" {
			requireHash("response_hash", record.ResponseHash)
		}
		if strings.TrimSpace(record.ErrorHash) != "" {
			requireHash("error_hash", record.ErrorHash)
		}
	}

	if len(record.SourceURLHashes) == 0 {
		missing = append(missing, "source_url_hashes")
	} else {
		for i, hash := range record.SourceURLHashes {
			if strings.TrimSpace(hash) == "" || !strings.HasPrefix(hash, "sha256:") {
				missing = append(missing, fmt.Sprintf("source_url_hashes[%d]:sha256", i))
			}
		}
	}

	if strings.TrimSpace(record.ReceiptRef) == "" {
		missing = append(missing, "receipt_ref")
	}
	if strings.TrimSpace(record.EvidencePackRef) == "" {
		missing = append(missing, "evidence_pack_ref")
	}
	if record.Production && record.SampleOnly {
		missing = append(missing, "sample_only_production_exclusion")
	}

	return missing
}
