package runtime

import "testing"

// HELM_GATEWAY_OWNER_ASSERTION_REQUIRED (helm-tracker#334) is off unless it
// says on, and a value that is neither stops the gateway instead of guessing.
func TestOwnerAssertionRequiredIsOffUnlessSetAndRefusesAGuess(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true, " true ": true} {
		cfg, err := admissionConfigFromEnv(env(map[string]string{envOwnerAssertionRequired: raw}))
		if err != nil || cfg.OwnerAssertionRequired != want {
			t.Errorf("%q: required = %v, %v; want %v", raw, cfg.OwnerAssertionRequired, err, want)
		}
	}
	for _, raw := range []string{"yes", "on", "TRUE", "2"} {
		if _, err := admissionConfigFromEnv(env(map[string]string{envOwnerAssertionRequired: raw})); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}
