package registry

type MatrixCell struct {
	AppID        string       `json:"app_id"`
	SubstrateID  string       `json:"substrate_id"`
	Availability Availability `json:"availability"`
	Launchable   bool         `json:"launchable"`
	Reason       string       `json:"reason"`
}

func (c *Catalog) Matrix() []MatrixCell {
	cells := make([]MatrixCell, 0, len(c.Apps)*len(c.Substrates))
	for _, app := range c.Apps {
		for _, substrate := range c.Substrates {
			cell := MatrixCell{
				AppID:        app.ID,
				SubstrateID:  substrate.ID,
				Availability: app.Availability,
				Launchable:   false,
				Reason:       "blocked_conformance_not_verified",
			}
			if app.Availability == AvailabilityExternalProprietaryAdapter {
				cell.Reason = "external_byo_license_account_tool"
			}
			if app.Availability == AvailabilityBlockedLicense {
				cell.Reason = "blocked_license_or_redistribution"
			}
			if app.Availability == AvailabilityOSSCandidate {
				cell.Reason = "experimental_candidate_requires_e2e"
			}
			if app.Availability == AvailabilityOSSSupported && app.Conformance.FullyVerified() && substrate.Availability == "supported" {
				cell.Launchable = true
				cell.Reason = "verified"
			}
			cells = append(cells, cell)
		}
	}
	return cells
}
