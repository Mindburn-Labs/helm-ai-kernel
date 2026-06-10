package shadow

import "fmt"

// Grade is the boundary grade computed from a scan Report. It answers one
// question: how much agent execution surface exists in the scanned tree that
// no fail-closed boundary governs?
type Grade struct {
	// Letter is "A" | "B" | "C" | "D" | "F".
	Letter string `json:"letter"`

	// Reason is a one-line human-readable justification.
	Reason string `json:"reason"`

	// BoundaryPresent mirrors HelmCoverage.Present.
	BoundaryPresent bool `json:"boundary_present"`

	// SDKSignals counts non-HELM agent SDK import findings.
	SDKSignals int `json:"sdk_signals"`

	// MCPServersDetected counts MCP server configuration findings.
	MCPServersDetected int `json:"mcp_servers_detected"`

	// APIKeyExposures counts hardcoded API key pattern findings.
	APIKeyExposures int `json:"api_key_exposures"`

	// UngovernedFindings counts findings at MEDIUM or HIGH severity —
	// agent surface with no HELM routing nearby.
	UngovernedFindings int `json:"ungoverned_findings"`
}

// ComputeGrade derives the boundary grade from a Report. Deterministic: the
// same report always produces the same grade.
//
// Grading scale:
//
//	A — boundary present and no ungoverned signals, or no agent surface at all
//	B — boundary present; MEDIUM signals not yet routed through it
//	C — boundary present; HIGH-severity exposures remain
//	D — agent surface detected with no boundary (no HIGH findings)
//	F — agent surface with no boundary and HIGH-severity exposure
func ComputeGrade(r *Report) Grade {
	g := Grade{BoundaryPresent: r.HelmCoverage.Present}

	var high, medium int
	for _, f := range r.Findings {
		switch f.Kind {
		case "sdk_import", "helm_absent":
			if f.Vendor != "helm" {
				g.SDKSignals++
			}
		case "mcp_config":
			g.MCPServersDetected++
		case "api_key":
			g.APIKeyExposures++
		}
		switch f.Severity {
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}
	g.UngovernedFindings = high + medium

	agentSurface := g.SDKSignals + g.MCPServersDetected + g.APIKeyExposures

	switch {
	case g.BoundaryPresent && g.UngovernedFindings == 0:
		g.Letter = "A"
		g.Reason = "execution boundary present; no ungoverned agent signals"
	case g.BoundaryPresent && high == 0:
		g.Letter = "B"
		g.Reason = fmt.Sprintf("boundary present; %d agent signal(s) not yet routed through it", medium)
	case g.BoundaryPresent:
		g.Letter = "C"
		g.Reason = fmt.Sprintf("boundary present but %d HIGH-severity exposure(s) remain", high)
	case agentSurface == 0:
		g.Letter = "A"
		g.Reason = "no agent execution surface detected"
	case high == 0:
		g.Letter = "D"
		g.Reason = fmt.Sprintf("%d agent signal(s) with no execution boundary — nothing receipted, nothing replayable", agentSurface)
	default:
		g.Letter = "F"
		g.Reason = fmt.Sprintf("%d agent signal(s) with no execution boundary and %d HIGH-severity exposure(s)", agentSurface, high)
	}
	return g
}
