package reasoncodes

import "testing"

func TestRegistryStrings(t *testing.T) {
	if len(All()) != 117 {
		t.Fatalf("All() = %d codes, want the registry's 117", len(All()))
	}
	if !IsRegistered(EmergencyStopFenced) || EmergencyStopFenced != "EMERGENCY_STOP_FENCED" {
		t.Fatal("EMERGENCY_STOP_FENCED must be registered under its wire string")
	}
	if IsRegistered("NOT_A_REGISTERED_CODE") {
		t.Fatal("an unknown code must classify as unregistered, not match")
	}
}
