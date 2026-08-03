package contracts

import (
	"strings"
	"testing"
)

func TestStartLaunchEffectAuthorizationEnvelopeV1FinalizerFailsClosed(t *testing.T) {
	called := false
	err := startLaunchEffectAuthorizationEnvelope(
		LaunchEffectAuthorizationEnvelope{},
		LaunchEffectEnvelopeVerificationContext{
			FinalizeDispatch: func(LaunchEffectPermitBinding) error {
				called = true
				return nil
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "v1 FinalizeDispatch cannot prove") {
		t.Fatalf("legacy v1 finalizer unexpectedly passed: %v", err)
	}
	if called {
		t.Fatal("legacy v1 finalizer was called without durable STARTED/interlock proof")
	}
}
