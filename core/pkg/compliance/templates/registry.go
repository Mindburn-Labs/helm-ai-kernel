package templates

import (
	"fmt"
	"time"
)

// Template represents a pre-packaged set of compliance controls for a specific jurisdiction.
type Template struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Jurisdiction  string        `json:"jurisdiction"` // e.g. "eu", "us-ca"
	EffectiveDate time.Time     `json:"effective_date"`
	Frameworks    []string      `json:"frameworks"` // Framework IDs included
	Controls      []ControlSpec `json:"controls"`   // Specific control overrides
}

// ControlSpec defines a control requirement within a template.
type ControlSpec struct {
	ControlID   string `json:"control_id"`
	Action      string `json:"action"`       // e.g. "REQUIRE", "RECOMMEND"
	TargetScope string `json:"target_scope"` // e.g. "all_agents", "financial_agents"
}

// Registry manages the set of available templates.
type Registry struct {
	templates map[string]*Template
}

// NewRegistry creates a registry seeded with standard templates.
func NewRegistry() *Registry {
	r := &Registry{
		templates: make(map[string]*Template),
	}
	r.seedDefaults()
	return r
}

func (r *Registry) seedDefaults() {
	// Seed EU AI Act Template
	euAI := &Template{
		ID:            "EU_AI_ACT_2026",
		Name:          "EU AI Act Compliance (High Risk)",
		Description:   "Standard controls for High Risk AI systems under EU AI Act 2026",
		Jurisdiction:  "eu",
		EffectiveDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Frameworks:    []string{"eu_ai_act_v1", "gdpr_v3"},
		Controls: []ControlSpec{
			{ControlID: "RISK_MANAGEMENT", Action: "REQUIRE", TargetScope: "all_agents"},
			{ControlID: "DATA_GOVERNANCE", Action: "REQUIRE", TargetScope: "training_data"},
			{ControlID: "HUMAN_OVERSIGHT", Action: "REQUIRE", TargetScope: "L4_agents"},
		},
	}
	r.templates[euAI.ID] = euAI

	// Seed GDPR Template
	gdpr := &Template{
		ID:            "GDPR_2018",
		Name:          "GDPR Baseline",
		Description:   "Data protection controls for EU citizens",
		Jurisdiction:  "eu",
		EffectiveDate: time.Date(2018, 5, 25, 0, 0, 0, 0, time.UTC),
		Frameworks:    []string{"gdpr_v3"},
		Controls: []ControlSpec{
			{ControlID: "CONSENT_MANAGEMENT", Action: "REQUIRE", TargetScope: "pii_handling"},
			{ControlID: "RIGHT_TO_ERASURE", Action: "REQUIRE", TargetScope: "data_storage"},
		},
	}
	r.templates[gdpr.ID] = gdpr
}

// GetTemplate retrieves a template by ID.
func (r *Registry) GetTemplate(id string) (*Template, error) {
	if t, ok := r.templates[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("template %s not found", id)
}

// ListTemplates returns all available templates.
func (r *Registry) ListTemplates() []*Template {
	list := make([]*Template, 0, len(r.templates))
	for _, t := range r.templates {
		list = append(list, t)
	}
	return list
}
