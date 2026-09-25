package conform

// ProfileID identifies a conformance profile per §2.2.
type ProfileID string

const (
	// ProfileSMB is the profile the release pipeline signs. Since HELM-756 it
	// requires only G0, build identity.
	ProfileSMB ProfileID = "SMB"
	// ProfileCore labels demo evidence packs; no gate run uses it any more.
	ProfileCore ProfileID = "CORE"
)

// ProfileDefinition names the gates a profile requires.
type ProfileDefinition struct {
	ID            ProfileID      `json:"id"`
	Description   string         `json:"description"`
	RequiredGates []string       `json:"required_gates"`
	Inherits      ProfileID      `json:"inherits,omitempty"`
	Overrides     map[string]any `json:"overrides,omitempty"`
}

// Profiles returns the runnable profiles. CORE, ENTERPRISE, L3 and the
// regulated and agentic-web profiles were retired in HELM-756 with gates
// G1–G15 and GX: no EvidencePack could pass G1 and G7 together (audit 08-01),
// so none of them could return a truthful result.
func Profiles() map[ProfileID]*ProfileDefinition {
	return map[ProfileID]*ProfileDefinition{
		ProfileSMB: {
			ID:            ProfileSMB,
			Description:   "Release build identity (G0) for the signed release conformance report",
			RequiredGates: []string{"G0"},
		},
	}
}

// GatesForProfile returns the gate IDs required by a profile.
func GatesForProfile(id ProfileID) []string {
	p := Profiles()
	def, ok := p[id]
	if !ok {
		return nil
	}
	return def.RequiredGates
}
