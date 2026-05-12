package acton

import (
	"bytes"
	"encoding/json"
)

type DriftReceipt struct {
	ContractDrift           bool   `json:"contract_drift"`
	SchemaHash              string `json:"schema_hash,omitempty"`
	ObservedOutputShapeHash string `json:"observed_output_shape_hash,omitempty"`
	ReasonCode              string `json:"reason_code,omitempty"`
}

type DriftFixture struct {
	ActionURN       ActionURN `json:"action_urn"`
	OutputShapeHash string    `json:"output_shape_hash"`
}

func DetectOutputDrift(env *ActonCommandEnvelope, stdout []byte, expectedShapeHash string) DriftReceipt {
	shapeHash := outputShapeHash(stdout)
	drift := DriftReceipt{
		SchemaHash:              ContractBundle().SchemaArtifacts.CommandSchemaHash,
		ObservedOutputShapeHash: shapeHash,
	}
	if expectedShapeHash != "" && expectedShapeHash != shapeHash {
		drift.ContractDrift = true
		drift.ReasonCode = string(ReasonConnectorContractDrift)
	}
	return drift
}

func outputShapeHash(stdout []byte) string {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	var value any
	if json.Unmarshal(trimmed, &value) == nil {
		shape := jsonShape(value)
		return "sha256:" + hashString(shape)
	}
	return "sha256:" + hashString("text")
}

func jsonShape(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k, child := range t {
			keys = append(keys, k+":"+jsonShape(child))
		}
		return "object{" + joinSorted(keys) + "}"
	case []any:
		if len(t) == 0 {
			return "array[]"
		}
		return "array[" + jsonShape(t[0]) + "]"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}
