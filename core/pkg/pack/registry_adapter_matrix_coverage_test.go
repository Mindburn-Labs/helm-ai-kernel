package pack

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry"
)

func TestCoverageCompatibilityMatrix(t *testing.T) {
	matrix := &CompatibilityMatrix{
		Entries: []CompatibilityEntry{{
			ComponentA: "kernel",
			VersionA:   ">=1.0.0 <2.0.0",
			ComponentB: "sdk-go",
			VersionB:   "^1.4.0",
			Status:     CompatFull,
		}},
	}

	if got := matrix.IsCompatible("kernel", "1.5.0", "sdk-go", "1.4.3"); got != CompatFull {
		t.Fatalf("forward compatibility = %s, want %s", got, CompatFull)
	}
	if got := matrix.IsCompatible("sdk-go", "1.4.3", "kernel", "1.5.0"); got != CompatFull {
		t.Fatalf("reverse compatibility = %s, want %s", got, CompatFull)
	}
	if got := matrix.IsCompatible("kernel", "2.0.0", "sdk-go", "1.4.3"); got != CompatUntested {
		t.Fatalf("version mismatch compatibility = %s, want %s", got, CompatUntested)
	}
	if got := matrix.IsCompatible("kernel", "1.5.0", "sdk-ts", "1.4.3"); got != CompatUntested {
		t.Fatalf("component mismatch compatibility = %s, want %s", got, CompatUntested)
	}

	if matchesConstraint("not a constraint", "1.0.0") {
		t.Fatal("invalid constraint should not match")
	}
	if matchesConstraint(">=1.0.0", "not-semver") {
		t.Fatal("invalid version should not match")
	}
}

func TestCoverageRegistryAdapter(t *testing.T) {
	ctx := context.Background()
	reg := registry.NewInMemoryRegistry()
	adapter := NewRegistryAdapter(reg)
	if adapter.reg != reg {
		t.Fatal("adapter did not retain registry")
	}

	if _, err := adapter.GetPack(ctx, "missing"); err == nil {
		t.Fatal("expected missing bundle lookup to fail")
	}
	if _, err := adapter.ListVersions(ctx, "missing"); err == nil {
		t.Fatal("expected missing bundle version lookup to fail")
	}

	bundle := &manifest.Bundle{
		Manifest: manifest.Module{
			Name:        "core-pack",
			Version:     "1.2.3",
			Description: "core capabilities",
			Capabilities: []manifest.CapabilityConfig{
				{Name: "capture"},
				{Name: "attest"},
			},
		},
		Signature: "abc123",
	}
	if err := reg.Register(bundle); err != nil {
		t.Fatalf("Register: %v", err)
	}

	pack, err := adapter.GetPack(ctx, "core-pack")
	if err != nil {
		t.Fatalf("GetPack: %v", err)
	}
	if pack.PackID != "core-pack" || pack.Manifest.Version != "1.2.3" {
		t.Fatalf("unexpected pack mapping: %+v", pack)
	}
	if len(pack.Manifest.Capabilities) != 2 || pack.Manifest.Capabilities[0] != "capture" {
		t.Fatalf("capabilities = %#v", pack.Manifest.Capabilities)
	}
	if len(pack.Manifest.Signatures) != 1 || pack.Manifest.Signatures[0].Signature != "abc123" {
		t.Fatalf("signature mapping = %#v", pack.Manifest.Signatures)
	}

	matches, err := adapter.FindByCapability(ctx, "attest")
	if err != nil {
		t.Fatalf("FindByCapability: %v", err)
	}
	if len(matches) != 1 || matches[0].PackID != "core-pack" {
		t.Fatalf("matches = %#v", matches)
	}
	none, err := adapter.FindByCapability(ctx, "missing")
	if err != nil {
		t.Fatalf("FindByCapability missing: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("missing capability returned %#v", none)
	}

	versions, err := adapter.ListVersions(ctx, "core-pack")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 1 || versions[0].PackName != "core-pack" || versions[0].Version != "1.2.3" {
		t.Fatalf("versions = %#v", versions)
	}

	signedPack := &Pack{
		Manifest: PackManifest{
			Name:         "published-pack",
			Version:      "2.0.0",
			Description:  "published from pack",
			Capabilities: []string{"govern"},
			Signatures: []Signature{{
				Signature: "published-signature",
				SignedAt:  time.Now().UTC(),
			}},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := adapter.PublishPack(ctx, signedPack); err != nil {
		t.Fatalf("PublishPack signed: %v", err)
	}
	published, err := reg.Get("published-pack")
	if err != nil {
		t.Fatalf("registry Get published: %v", err)
	}
	if published.Signature != "published-signature" {
		t.Fatalf("published signature = %q", published.Signature)
	}
	if len(published.Manifest.Capabilities) != 1 || published.Manifest.Capabilities[0].Name != "govern" {
		t.Fatalf("published capabilities = %#v", published.Manifest.Capabilities)
	}

	unsignedPack := &Pack{
		Manifest: PackManifest{
			Name:         "unsigned-pack",
			Version:      "1.0.0",
			Capabilities: []string{"observe"},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := adapter.PublishPack(ctx, unsignedPack); err != nil {
		t.Fatalf("PublishPack unsigned: %v", err)
	}
	unsigned, err := reg.Get("unsigned-pack")
	if err != nil {
		t.Fatalf("registry Get unsigned: %v", err)
	}
	if unsigned.Signature != "" {
		t.Fatalf("unsigned signature = %q, want empty", unsigned.Signature)
	}
}
