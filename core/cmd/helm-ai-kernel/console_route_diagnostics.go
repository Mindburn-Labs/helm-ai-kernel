package main

import (
	"strings"
)

type consoleRouteDiagnostic struct {
	Method            string `json:"method"`
	Path              string `json:"path"`
	MuxPattern        string `json:"mux_pattern"`
	Auth              string `json:"auth"`
	RateLimit         string `json:"rate_limit"`
	ContractStatus    string `json:"contract_status"`
	OperationID       string `json:"operation_id"`
	Owner             string `json:"owner"`
	Group             string `json:"group"`
	UICoverage        string `json:"ui_coverage"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

func consoleRouteDiagnostics() []consoleRouteDiagnostic {
	specs := RuntimeRouteSpecs()
	out := make([]consoleRouteDiagnostic, 0, len(specs))
	for _, spec := range specs {
		out = append(out, consoleRouteDiagnosticForSpec(spec))
	}
	return out
}

func consoleRouteDiagnosticsForSurface(surface string) []consoleRouteDiagnostic {
	all := consoleRouteDiagnostics()
	out := make([]consoleRouteDiagnostic, 0, len(all))
	for _, route := range all {
		if route.Group == surface {
			out = append(out, route)
		}
	}
	return out
}

func consoleRouteDiagnosticForSpec(spec RuntimeRouteSpec) consoleRouteDiagnostic {
	coverage, reason := routeUICoverage(spec)
	return consoleRouteDiagnostic{
		Method:            spec.Method,
		Path:              spec.Path,
		MuxPattern:        spec.MuxPattern,
		Auth:              string(spec.Auth),
		RateLimit:         string(spec.RateLimit),
		ContractStatus:    string(spec.ContractStatus),
		OperationID:       spec.OperationID,
		Owner:             spec.Owner,
		Group:             routeSurfaceGroup(spec.Path),
		UICoverage:        coverage,
		UnsupportedReason: reason,
	}
}

func routeUICoverage(spec RuntimeRouteSpec) (string, string) {
	if spec.Auth == RouteAuthService || spec.ContractStatus == RouteContractInternal {
		return "unsupported", "service-internal route is not callable from the OSS Console"
	}
	if spec.ContractStatus == RouteContractCompatibility || spec.ContractStatus == RouteContractImplementation {
		return "developer-only", "compatibility or implementation route is shown only in Developer diagnostics"
	}
	if strings.HasPrefix(spec.Path, "/api/demo") || strings.HasPrefix(spec.Path, "/api/ag-ui") || strings.HasPrefix(spec.Path, "/.well-known") || spec.Path == "/mcp" || strings.HasPrefix(spec.Path, "/mcp/") {
		return "developer-only", "low-level, demo, or protocol route is not part of the primary operator workflow"
	}
	return "wired", ""
}
