package schemas_test

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommerceOrder_Marshaling verifies that the CommerceOrder struct
// marshals to JSON with the expected field names and structure.
// Invariant: JSON tags must match the contract (canonical_id, etc.)
func TestCommerceOrder_Marshaling(t *testing.T) {
	order := schemas.CommerceOrder{
		CanonicalID: "ord_123",
		ExternalID:  "ext_456",
		Source:      "shopify",
		Status:      "paid",
		TotalAmount: 1000,
		Currency:    "USD",
		Customer: schemas.CommerceCustomer{
			ID:    "cust_789",
			Email: "test@example.com",
		},
		LineItems: []schemas.CommerceLineItem{
			{SKU: "sku_1", Quantity: 1, Price: 500},
			{SKU: "sku_2", Quantity: 2, Price: 250},
		},
		Metadata: map[string]string{
			"fraud_score": "low",
		},
	}

	data, err := json.Marshal(order)
	require.NoError(t, err)

	// Verify key fields are present in JSON
	jsonStr := string(data)
	assert.Contains(t, jsonStr, "canonical_id")
	assert.Contains(t, jsonStr, "ord_123")
	assert.Contains(t, jsonStr, "line_items")
	assert.Contains(t, jsonStr, "total_amount_cents")

	// Verify round-trip
	var decoded schemas.CommerceOrder
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, order, decoded)
}

// TestCommerceOrder_Determinism verifies that the same object always marshals
// to the same JSON (ignoring map order, which standard json.Marshal sorts).
// Invariant: Deterministic serialization is crucial for hashing.
func TestCommerceOrder_Determinism(t *testing.T) {
	order := schemas.CommerceOrder{
		CanonicalID: "ord_det_1",
		Metadata: map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		},
	}

	// Marshaling map keys is deterministic in Go standard library (sorted by key)
	data1, _ := json.Marshal(order)
	data2, _ := json.Marshal(order)

	assert.Equal(t, data1, data2, "JSON marshaling should be deterministic")
}
