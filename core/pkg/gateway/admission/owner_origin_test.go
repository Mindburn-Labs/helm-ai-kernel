package admission

// quantum_posture: tests classical ES256 WebAuthn assertions; no
// post-quantum claim.

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/passkey"
)

func TestOwnerAssertionRefusesUnexpectedOrigins(t *testing.T) {
	k := passkey.New(t, passkey.ES256, testRPID)
	challenge := OwnerChallengeV1("tenant-a", "owner", "attempt-a", make([]byte, 32))
	for name, origin := range map[string]any{
		"missing":    nil,
		"empty":      "",
		"sibling":    "https://other.helm.example",
		"subdomain":  "https://untrusted." + testRPID,
		"http":       "http://" + testRPID,
		"port":       "https://" + testRPID + ":8443",
		"path":       "https://" + testRPID + "/",
		"suffix":     "https://" + testRPID + ".evil.example",
		"not-string": false,
	} {
		t.Run(name, func(t *testing.T) {
			a := k.AssertWith(t, challenge, func(p *passkey.Parts) {
				if origin == nil {
					delete(p.ClientData, "origin")
				} else {
					p.ClientData["origin"] = origin
				}
			})
			if _, err := VerifyAssertion(credentialOf(k), 0, assertionOf(a), challenge); err == nil || !strings.Contains(err.Error(), "origin") {
				t.Fatalf("signed assertion from %v: %v; want an origin refusal", origin, err)
			}
		})
	}
}

func TestOwnerAssertionUsesOnlyConfiguredOrigins(t *testing.T) {
	k := passkey.New(t, passkey.EdDSA, "helm.example")
	challenge := OwnerChallengeV1("tenant-a", "owner", "attempt-a", make([]byte, 32))
	allowed := []string{"https://console.helm.example", "http://localhost:5173"}
	for _, origin := range append(append([]string(nil), allowed...), "https://helm.example", "https://other.helm.example") {
		a := k.AssertWith(t, challenge, func(p *passkey.Parts) { p.ClientData["origin"] = origin })
		_, err := VerifyAssertion(credentialOf(k), 0, assertionOf(a), challenge, allowed...)
		want := origin == allowed[0] || origin == allowed[1]
		if (err == nil) != want {
			t.Fatalf("origin %q: %v; allowed=%v", origin, err, want)
		}
	}
}

func TestOwnerOriginsRefuseAmbiguousConfiguration(t *testing.T) {
	for _, origin := range []string{"", "https://*.helm.example", "http://console.helm.example", "https://console.helm.example/", "https://console.helm.example?", "https://console.helm.example#", "https://user@console.helm.example", "https://CONSOLE.helm.example", "https://console.helm.example:", "https://console.helm.example:65536"} {
		if err := CheckOwnerOrigins([]string{origin}); err == nil {
			t.Errorf("accepted ambiguous origin %q", origin)
		}
	}
	for _, origin := range []string{"https://console.helm.example", "https://console.helm.example:8443", "http://localhost:5173", "http://127.0.0.1:5173", "http://[::1]:5173"} {
		if err := CheckOwnerOrigins([]string{origin}); err != nil {
			t.Errorf("refused exact origin %q: %v", origin, err)
		}
	}
}
