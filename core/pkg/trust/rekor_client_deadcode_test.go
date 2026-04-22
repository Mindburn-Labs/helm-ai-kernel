package trust_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

func TestRekorClient_VerifyEntry_IsReachable(t *testing.T) {
	c, err := trust.NewRekorClient(trust.RekorClientConfig{LogURL: "https://rekor.sigstore.dev"})
	if err != nil {
		t.Fatalf("NewRekorClient failed: %v", err)
	}

	_, err = c.VerifyEntry("deadbeef")
	if err == nil {
		t.Fatal("expected VerifyEntry to fail (placeholder implementation)")
	}
}
