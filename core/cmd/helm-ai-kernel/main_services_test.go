package main

import "testing"

func TestServicesInitFailureIsFatalForProductionOrAuthorityBoundaries(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv(emergencyStopFenceEnabledEnv, "")
	t.Setenv(approvalConsumptionEnabledEnv, "")
	if servicesInitFailureIsFatal() {
		t.Fatal("ordinary development services initialization may remain non-fatal")
	}

	t.Setenv(emergencyStopFenceEnabledEnv, "1")
	if !servicesInitFailureIsFatal() {
		t.Fatal("enabled scoped emergency-stop fence must fail startup on service initialization error")
	}

	t.Setenv(emergencyStopFenceEnabledEnv, "")
	t.Setenv(approvalConsumptionEnabledEnv, "1")
	if !servicesInitFailureIsFatal() {
		t.Fatal("enabled approval consumption authority must fail startup on service initialization error")
	}

	t.Setenv(approvalConsumptionEnabledEnv, "")
	t.Setenv("HELM_PRODUCTION", "true")
	if !servicesInitFailureIsFatal() {
		t.Fatal("production services initialization must remain fatal")
	}
}
