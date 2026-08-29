package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

func TestGenerateSignsResolvablePolicyFixture(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	referencePackPath := filepath.Join(root, "reference_packs", "eu_ai_act_high_risk.v2.json")
	outDir := t.TempDir()
	if err := generate(outDir, "tenant-smoke", "default", referencePackPath); err != nil {
		t.Fatal(err)
	}

	bundle, err := os.ReadFile(filepath.Join(outDir, "bundle.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var head policyreconcile.PolicyHead
	headJSON, err := os.ReadFile(filepath.Join(outDir, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(headJSON, &head); err != nil {
		t.Fatal(err)
	}
	if head.BundleRef != runtimePolicyRef {
		t.Fatalf("bundle_ref = %q, want %q", head.BundleRef, runtimePolicyRef)
	}
	if head.PolicyHash != policyreconcile.HashBytes(bundle) {
		t.Fatal("policy_hash does not bind the generated bundle")
	}

	publicKeyHex, err := os.ReadFile(filepath.Join(outDir, "public-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hex.DecodeString(strings.TrimSpace(string(publicKeyHex)))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(head.Signature)
	if err != nil {
		t.Fatal(err)
	}
	material, err := policyreconcile.PolicyHeadSignatureMaterial(head)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), material, signature) {
		t.Fatal("generated policy head signature is invalid")
	}

	var bundleConfig struct {
		ReferencePack string `toml:"reference_pack"`
	}
	if _, err := toml.Decode(string(bundle), &bundleConfig); err != nil {
		t.Fatal(err)
	}
	resolved, err := policyreconcile.ResolveReferencePackPath(head.BundleRef, bundleConfig.ReferencePack)
	if err != nil {
		t.Fatal(err)
	}
	wantRuntimePack := filepath.Join(filepath.Dir(runtimePolicyRef), runtimeReferencePack)
	if resolved != wantRuntimePack {
		t.Fatalf("resolved reference pack = %q, want %q", resolved, wantRuntimePack)
	}
	referencePack, err := os.ReadFile(referencePackPath)
	if err != nil {
		t.Fatal(err)
	}
	wantSourceRef := "reference_pack:" + wantRuntimePack + "@" + policyreconcile.HashBytes(referencePack)
	if len(head.SourceRefs) != 1 || head.SourceRefs[0] != wantSourceRef {
		t.Fatalf("source_refs = %v, want [%q]", head.SourceRefs, wantSourceRef)
	}
}
