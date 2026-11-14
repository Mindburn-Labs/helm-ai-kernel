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

func TestOwnerOriginsAreExplicitAndMalformedConfigurationRefusesStartup(t *testing.T) {
	cfg, err := admissionConfigFromEnv(env(map[string]string{envOwnerOrigins: "https://console.helm.example, http://localhost:5173"}))
	if err != nil || len(cfg.OwnerOrigins) != 2 || cfg.OwnerOrigins[0] != "https://console.helm.example" || cfg.OwnerOrigins[1] != "http://localhost:5173" {
		t.Fatalf("origins = %v, %v", cfg.OwnerOrigins, err)
	}
	for _, raw := range []string{"https://*.helm.example", "http://console.helm.example", "https://console.helm.example,", "https://console.helm.example/"} {
		if _, err := admissionConfigFromEnv(env(map[string]string{envOwnerOrigins: raw})); err == nil {
			t.Errorf("gateway accepted invalid origins %q", raw)
		}
	}
}
