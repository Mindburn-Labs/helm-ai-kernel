package constitution_test

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/constitution"
)

func validConstitutionJSON() []byte {
	c := map[string]interface{}{
		"constitution_id": "const-001",
		"agent_id":        "agent-alpha",
		"version":         "1.0.0",
		"principles": []map[string]interface{}{
			{
				"id":          "p-safety",
				"name":        "Avoid harm",
				"description": "Do not take actions that could cause harm to users",
				"priority":    1,
				"category":    "safety",
			},
			{
				"id":          "p-helpful",
				"name":        "Be helpful",
				"description": "Assist users effectively",
				"priority":    2,
				"category":    "helpfulness",
			},
		},
	}
	data, _ := json.Marshal(c)
	return data
}

func TestParser_ParseJSON(t *testing.T) {
	p := constitution.NewParser()
	c, err := p.ParseJSON(validConstitutionJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.ConstitutionID != "const-001" {
		t.Fatalf("expected constitution_id const-001, got %s", c.ConstitutionID)
	}
	if c.AgentID != "agent-alpha" {
		t.Fatalf("expected agent_id agent-alpha, got %s", c.AgentID)
	}
	if len(c.Principles) != 2 {
		t.Fatalf("expected 2 principles, got %d", len(c.Principles))
	}
	if c.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
	if c.Principles[0].ID != "p-safety" {
		t.Fatalf("expected first principle ID p-safety, got %s", c.Principles[0].ID)
	}
}

func TestParser_ParseJSON_Invalid(t *testing.T) {
	p := constitution.NewParser()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "invalid JSON",
			data: []byte(`{not json}`),
		},
		{
			name: "missing constitution_id",
			data: mustMarshal(map[string]interface{}{
				"agent_id": "a",
				"principles": []map[string]interface{}{
					{"id": "p1", "name": "n", "priority": 1},
				},
			}),
		},
		{
			name: "missing agent_id",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"principles": []map[string]interface{}{
					{"id": "p1", "name": "n", "priority": 1},
				},
			}),
		},
		{
			name: "no principles",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"agent_id":        "a",
				"principles":      []map[string]interface{}{},
			}),
		},
		{
			name: "principle missing id",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"agent_id":        "a",
				"principles": []map[string]interface{}{
					{"name": "n", "priority": 1},
				},
			}),
		},
		{
			name: "principle missing name",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"agent_id":        "a",
				"principles": []map[string]interface{}{
					{"id": "p1", "priority": 1},
				},
			}),
		},
		{
			name: "principle zero priority",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"agent_id":        "a",
				"principles": []map[string]interface{}{
					{"id": "p1", "name": "n", "priority": 0},
				},
			}),
		},
		{
			name: "duplicate priorities",
			data: mustMarshal(map[string]interface{}{
				"constitution_id": "c",
				"agent_id":        "a",
				"principles": []map[string]interface{}{
					{"id": "p1", "name": "n1", "priority": 1},
					{"id": "p2", "name": "n2", "priority": 1},
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseJSON(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParser_ParsePrinciples(t *testing.T) {
	p := constitution.NewParser()

	text := `1. Always prioritize user safety and security
2. Be honest and transparent in all communications
3. Protect user privacy and personal data
4. Be helpful and assist users effectively
5. Ensure fairness and avoid discrimination`

	c, err := p.ParsePrinciples("agent-beta", text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.AgentID != "agent-beta" {
		t.Fatalf("expected agent_id agent-beta, got %s", c.AgentID)
	}
	if len(c.Principles) != 5 {
		t.Fatalf("expected 5 principles, got %d", len(c.Principles))
	}

	// Verify category inference.
	expectedCategories := map[int]string{
		1: "safety",
		2: "honesty",
		3: "privacy",
		4: "helpfulness",
		5: "fairness",
	}

	for _, pr := range c.Principles {
		expected, ok := expectedCategories[pr.Priority]
		if !ok {
			t.Fatalf("unexpected priority %d", pr.Priority)
		}
		if pr.Category != expected {
			t.Fatalf("principle priority %d: expected category %q, got %q", pr.Priority, expected, pr.Category)
		}
	}

	if c.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
	if c.ConstitutionID == "" {
		t.Fatal("expected non-empty constitution_id")
	}
}

func TestParser_ParsePrinciples_Empty(t *testing.T) {
	p := constitution.NewParser()

	_, err := p.ParsePrinciples("agent-x", "")
	if err == nil {
		t.Fatal("expected error for empty text")
	}

	_, err = p.ParsePrinciples("", "1. Be safe")
	if err == nil {
		t.Fatal("expected error for empty agent_id")
	}
}

func TestParser_ContentHash(t *testing.T) {
	p := constitution.NewParser()

	// Parse the same constitution twice — hashes should match.
	data := validConstitutionJSON()
	c1, err := p.ParseJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c2, err := p.ParseJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c1.ContentHash != c2.ContentHash {
		t.Fatalf("content hashes should be deterministic: %s != %s", c1.ContentHash, c2.ContentHash)
	}

	// Modify a principle — hash should change.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	principles := m["principles"].([]interface{})
	p0 := principles[0].(map[string]interface{})
	p0["description"] = "Modified description"

	modified, _ := json.Marshal(m)
	c3, err := p.ParseJSON(modified)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c3.ContentHash == c1.ContentHash {
		t.Fatal("content hash should differ after modification")
	}
}

func mustMarshal(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
