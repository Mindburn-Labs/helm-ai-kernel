package pdp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func withFailingDecisionHasher(t *testing.T) {
	t.Helper()
	original := computeDecisionHash
	computeDecisionHash = func(*DecisionResponse) (string, error) {
		return "", errors.New("synthetic canonicalization failure")
	}
	t.Cleanup(func() {
		computeDecisionHash = original
	})
}

func assertHashFailureDeny(t *testing.T, resp *DecisionResponse, err error) {
	t.Helper()
	if !errors.Is(err, ErrPDPHashFailure) {
		t.Fatalf("expected ErrPDPHashFailure, got %v", err)
	}
	if resp == nil {
		t.Fatal("expected fail-closed deny response")
	}
	if resp.Allow {
		t.Fatal("hash failure must deny")
	}
	if resp.ReasonCode != string(contracts.ReasonPDPError) {
		t.Fatalf("reason code = %q, want %q", resp.ReasonCode, contracts.ReasonPDPError)
	}
	if resp.DecisionHash != "" {
		t.Fatalf("failed hash response should not invent a decision hash, got %q", resp.DecisionHash)
	}
}

func TestHelmPDPHashFailureReturnsDenyAndError(t *testing.T) {
	withFailingDecisionHasher(t)

	p := NewHelmPDP("v1", map[string]bool{"filesystem": true})
	resp, err := p.Evaluate(context.Background(), &DecisionRequest{Resource: "filesystem"})

	assertHashFailureDeny(t, resp, err)
	if !strings.HasPrefix(resp.PolicyRef, "helm:") {
		t.Fatalf("policy ref = %q", resp.PolicyRef)
	}
}

func TestCedarPDPHashFailureReturnsDenyAndError(t *testing.T) {
	withFailingDecisionHasher(t)

	p, err := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies:  []CedarPolicy{{ID: "permit-filesystem", Effect: "permit", ResourceMatch: `Resource::"filesystem"`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Evaluate(context.Background(), &DecisionRequest{Resource: "filesystem"})

	assertHashFailureDeny(t, resp, err)
	if !strings.HasPrefix(resp.PolicyRef, "cedar:") {
		t.Fatalf("policy ref = %q", resp.PolicyRef)
	}
}

func TestOpaPDPHashFailureReturnsDenyAndError(t *testing.T) {
	withFailingDecisionHasher(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	t.Cleanup(server.Close)

	p, err := NewOpaPDP(OpaConfig{Endpoint: server.URL, PolicyRef: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Evaluate(context.Background(), &DecisionRequest{Resource: "filesystem"})

	assertHashFailureDeny(t, resp, err)
	if !strings.HasPrefix(resp.PolicyRef, "opa:") {
		t.Fatalf("policy ref = %q", resp.PolicyRef)
	}
}

func TestComputeDecisionHashNilResponseIsHashFailure(t *testing.T) {
	_, err := ComputeDecisionHash(nil)
	if !errors.Is(err, ErrPDPHashFailure) {
		t.Fatalf("expected ErrPDPHashFailure, got %v", err)
	}
}
