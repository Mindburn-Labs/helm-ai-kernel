package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

func TestPolicySourceFromEnvDefaultsToMountedFile(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "")
	source, kind, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err != nil {
		t.Fatalf("source from env: %v", err)
	}
	if kind != "mountedFile" {
		t.Fatalf("expected mountedFile, got %s", kind)
	}
	if _, ok := source.(*policyreconcile.MountedFileSource); !ok {
		t.Fatalf("expected MountedFileSource, got %T", source)
	}
}

func TestPolicySourceFromEnvControlPlaneRequiresURL(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "controlplane")
	t.Setenv("HELM_POLICY_CONTROLPLANE_URL", "")
	_, _, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err == nil || !strings.Contains(err.Error(), "HELM_POLICY_CONTROLPLANE_URL") {
		t.Fatalf("expected missing controlplane URL error, got %v", err)
	}
}

func TestPolicySourceFromEnvControlPlaneUsesBearerToken(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "controlplane")
	t.Setenv("HELM_POLICY_CONTROLPLANE_URL", "https://controlplane.example")
	t.Setenv("HELM_POLICY_BEARER_TOKEN", "token-1")
	source, kind, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err != nil {
		t.Fatalf("source from env: %v", err)
	}
	if kind != "controlplane" {
		t.Fatalf("expected controlplane, got %s", kind)
	}
	cp, ok := source.(*policyreconcile.ControlPlaneSource)
	if !ok {
		t.Fatalf("expected ControlPlaneSource, got %T", source)
	}
	if cp.BaseURL != "https://controlplane.example" || cp.BearerToken != "token-1" {
		t.Fatalf("controlplane source not configured from env: %+v", cp)
	}
}

func TestPolicySourceFromEnvControlPlaneAllowsLoopbackHTTP(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "controlplane")
	t.Setenv("HELM_POLICY_CONTROLPLANE_URL", "http://127.0.0.1:18080")
	source, kind, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err != nil {
		t.Fatalf("source from env: %v", err)
	}
	if kind != "controlplane" {
		t.Fatalf("expected controlplane, got %s", kind)
	}
	if _, ok := source.(*policyreconcile.ControlPlaneSource); !ok {
		t.Fatalf("expected ControlPlaneSource, got %T", source)
	}
}

func TestPolicySourceFromEnvControlPlaneRejectsPlainHTTP(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "controlplane")
	t.Setenv("HELM_POLICY_CONTROLPLANE_URL", "http://controlplane.example")
	_, _, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("expected non-HTTPS controlplane URL error, got %v", err)
	}
}

func TestPolicySourceFromEnvCRDFailsClosedInOSSRuntime(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "crd")
	_, _, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err == nil || !strings.Contains(err.Error(), "requires a CRD source implementation") {
		t.Fatalf("expected CRD source fail-closed error, got %v", err)
	}
}

func TestPolicySourceFromEnvRejectsUnknownKind(t *testing.T) {
	t.Setenv("HELM_POLICY_SOURCE_KIND", "surprise")
	_, _, err := policySourceFromEnv("/tmp/policy.toml", policyreconcile.DefaultScope)
	if err == nil || !strings.Contains(err.Error(), "unsupported HELM_POLICY_SOURCE_KIND") {
		t.Fatalf("expected unknown kind error, got %v", err)
	}
}

func TestPolicyLastKnownGoodConfigFromEnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		keep, maxAge, err := policyLastKnownGoodConfigFromEnv()
		if err != nil || !keep || maxAge != policyreconcile.DefaultLKGMaxAge {
			t.Fatalf("default config = keep=%v maxAge=%s err=%v", keep, maxAge, err)
		}
	})

	t.Run("deny", func(t *testing.T) {
		t.Setenv("HELM_POLICY_ON_INVALID_UPDATE", "deny")
		keep, maxAge, err := policyLastKnownGoodConfigFromEnv()
		if err != nil || keep || maxAge != 0 {
			t.Fatalf("deny config = keep=%v maxAge=%s err=%v", keep, maxAge, err)
		}
	})

	t.Run("configured retention", func(t *testing.T) {
		t.Setenv("HELM_POLICY_ON_INVALID_UPDATE", "keepLastKnownGood")
		t.Setenv("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE", "45s")
		keep, maxAge, err := policyLastKnownGoodConfigFromEnv()
		if err != nil || !keep || maxAge != 45*time.Second {
			t.Fatalf("configured retention = keep=%v maxAge=%s err=%v", keep, maxAge, err)
		}
	})

	for _, name := range []string{"unknown action", "invalid duration"} {
		t.Run(name, func(t *testing.T) {
			if name == "unknown action" {
				t.Setenv("HELM_POLICY_ON_INVALID_UPDATE", "allow")
			} else {
				t.Setenv("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE", "later")
			}
			if _, _, err := policyLastKnownGoodConfigFromEnv(); err == nil {
				t.Fatal("expected invalid LKG config to fail")
			}
		})
	}
}

func TestPolicySignatureVerifierFromEnvDefaultsOptional(t *testing.T) {
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", "")
	verifier, required, err := policySignatureVerifierFromEnv("mountedFile")
	if err != nil {
		t.Fatalf("signature verifier from env: %v", err)
	}
	if verifier != nil || required {
		t.Fatalf("expected optional nil verifier, got verifier=%T required=%v", verifier, required)
	}
}

func TestPolicySignatureVerifierFromEnvRequiresPublicKey(t *testing.T) {
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "true")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", "")
	_, required, err := policySignatureVerifierFromEnv("mountedFile")
	if err == nil || !required || !strings.Contains(err.Error(), "HELM_POLICY_TRUST_PUBLIC_KEY") {
		t.Fatalf("expected required public key error, got required=%v err=%v", required, err)
	}
}

func TestPolicySignatureVerifierFromEnvControlPlaneRequiresSignatureFlag(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("policy-source-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", signer.PublicKey())
	_, required, err := policySignatureVerifierFromEnv("controlplane")
	if err == nil || required || !strings.Contains(err.Error(), "HELM_POLICY_SIGNATURE_REQUIRED=true") {
		t.Fatalf("expected required signature flag error, got required=%v err=%v", required, err)
	}
}

func TestPolicySignatureVerifierFromEnvControlPlaneRequiresTrustPublicKey(t *testing.T) {
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "true")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", "")
	_, required, err := policySignatureVerifierFromEnv("controlplane")
	if err == nil || !required || !strings.Contains(err.Error(), "HELM_POLICY_TRUST_PUBLIC_KEY") {
		t.Fatalf("expected controlplane public key error, got required=%v err=%v", required, err)
	}
}

func TestPolicySignatureVerifierFromEnvUsesTrustPublicKey(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("policy-source-test")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "1")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", signer.PublicKey())
	verifier, required, err := policySignatureVerifierFromEnv("controlplane")
	if err != nil {
		t.Fatalf("signature verifier from env: %v", err)
	}
	if !required {
		t.Fatal("expected signatures to be required")
	}
	if _, ok := verifier.(*policyreconcile.Ed25519PolicyVerifier); !ok {
		t.Fatalf("expected Ed25519PolicyVerifier, got %T", verifier)
	}
}

func TestPolicySignatureVerifierFromEnvRejectsInvalidTrustPublicKey(t *testing.T) {
	t.Setenv("HELM_POLICY_SIGNATURE_REQUIRED", "true")
	t.Setenv("HELM_POLICY_TRUST_PUBLIC_KEY", "not-hex")
	_, _, err := policySignatureVerifierFromEnv("mountedFile")
	if err == nil || !strings.Contains(err.Error(), "hex encoded") {
		t.Fatalf("expected invalid trust public key error, got %v", err)
	}
}
