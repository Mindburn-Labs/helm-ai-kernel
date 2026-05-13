package trust_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func TestRekorClient_VerifyEntry_IsReachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	c, err := trust.NewRekorClient(trust.RekorClientConfig{LogURL: server.URL})
	if err != nil {
		t.Fatalf("NewRekorClient failed: %v", err)
	}

	_, err = c.VerifyEntry("deadbeef")
	if err == nil {
		t.Fatal("expected VerifyEntry to fail when the entry is absent")
	}
}
