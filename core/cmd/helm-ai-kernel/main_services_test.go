package main

import "testing"

func TestServicesInitFailureIsFatalForProductionOrScopedEmergencyStop(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv(emergencyStopFenceEnabledEnv, "")
	if servicesInitFailureIsFatal() {
		t.Fatal("ordinary development services initialization may remain non-fatal")
	}

	t.Setenv(emergencyStopFenceEnabledEnv, "1")
	if !servicesInitFailureIsFatal() {
		t.Fatal("enabled scoped emergency-stop fence must fail startup on service initialization error")
	}

	t.Setenv(emergencyStopFenceEnabledEnv, "")
	t.Setenv("HELM_PRODUCTION", "true")
	if !servicesInitFailureIsFatal() {
		t.Fatal("production services initialization must remain fatal")
	}
}
