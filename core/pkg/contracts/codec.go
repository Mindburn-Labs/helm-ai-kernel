package contracts

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodeDecisionRecord parses a DecisionRecord from a token string (JSON or Base64).
func DecodeDecisionRecord(token string) (*DecisionRecord, error) {
	// Try Plain JSON
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		var d DecisionRecord
		//nolint:wrapcheck // caller provides context
		if err := json.Unmarshal([]byte(token), &d); err != nil {
			return nil, err
		}
		return &d, nil
	}

	// Try Base64
	bytes, err := base64.StdEncoding.DecodeString(token)
	if err == nil {
		var d DecisionRecord
		if err := json.Unmarshal(bytes, &d); err == nil {
			return &d, nil
		}
	}

	//nolint:wrapcheck // fallback case returns unmarshal error
	return nil, json.Unmarshal([]byte(token), &DecisionRecord{}) // Fallback
}

// EncodeDecisionRecord serializes the decision to a string (token).
func EncodeDecisionRecord(d *DecisionRecord) (string, error) {
	//nolint:wrapcheck // caller provides context
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
