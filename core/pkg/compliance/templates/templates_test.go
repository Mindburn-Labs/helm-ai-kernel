package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	require.NotNil(t, reg)

	// Should be seeded with at least 2 templates
	templates := reg.ListTemplates()
	require.GreaterOrEqual(t, len(templates), 2)
}

func TestGetTemplate_EUAI(t *testing.T) {
	reg := NewRegistry()

	tmpl, err := reg.GetTemplate("EU_AI_ACT_2026")
	require.NoError(t, err)
	require.Equal(t, "EU AI Act Compliance (High Risk)", tmpl.Name)
	require.Equal(t, "eu", tmpl.Jurisdiction)
	require.Contains(t, tmpl.Frameworks, "eu_ai_act_v1")
	require.GreaterOrEqual(t, len(tmpl.Controls), 3)
}

func TestGetTemplate_GDPR(t *testing.T) {
	reg := NewRegistry()

	tmpl, err := reg.GetTemplate("GDPR_2018")
	require.NoError(t, err)
	require.Equal(t, "GDPR Baseline", tmpl.Name)
	require.Contains(t, tmpl.Frameworks, "gdpr_v3")
}

func TestGetTemplate_NotFound(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.GetTemplate("NONEXISTENT")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestListTemplates(t *testing.T) {
	reg := NewRegistry()
	templates := reg.ListTemplates()

	ids := make(map[string]bool)
	for _, tmpl := range templates {
		require.NotEmpty(t, tmpl.ID)
		require.NotEmpty(t, tmpl.Name)
		require.NotEmpty(t, tmpl.Jurisdiction)
		require.False(t, tmpl.EffectiveDate.IsZero())
		ids[tmpl.ID] = true
	}
	require.True(t, ids["EU_AI_ACT_2026"])
	require.True(t, ids["GDPR_2018"])
}

func TestControlSpec_Structure(t *testing.T) {
	reg := NewRegistry()
	tmpl, _ := reg.GetTemplate("EU_AI_ACT_2026")

	for _, ctrl := range tmpl.Controls {
		require.NotEmpty(t, ctrl.ControlID)
		require.NotEmpty(t, ctrl.Action)
		require.NotEmpty(t, ctrl.TargetScope)
	}
}
