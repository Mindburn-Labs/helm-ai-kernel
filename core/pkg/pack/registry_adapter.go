package pack

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry"
)

// RegistryAdapter bridges the Bundle Registry to the PackRegistry interface.
// This adapter lives in the pack package to avoid depending on enterprise packages.
type RegistryAdapter struct {
	reg registry.Registry
}

// NewRegistryAdapter creates a new adapter.
func NewRegistryAdapter(reg registry.Registry) *RegistryAdapter {
	return &RegistryAdapter{reg: reg}
}

// GetPack retrieves a pack by ID (mapped from Bundle Name).
func (a *RegistryAdapter) GetPack(ctx context.Context, id string) (*Pack, error) {
	bundle, err := a.reg.Get(id)
	if err != nil {
		return nil, err
	}

	capabilities := make([]string, len(bundle.Manifest.Capabilities))
	for i, c := range bundle.Manifest.Capabilities {
		capabilities[i] = c.Name
	}

	p := &Pack{
		PackID: bundle.Manifest.Name,
		Manifest: PackManifest{
			PackID:       bundle.Manifest.Name,
			Version:      bundle.Manifest.Version,
			Name:         bundle.Manifest.Name,
			Description:  bundle.Manifest.Description,
			Capabilities: capabilities,
		},
		CreatedAt: time.Now(),
	}

	if bundle.Signature != "" {
		p.Manifest.Signatures = []Signature{
			{
				SignerID:  "bundle-registry",
				Signature: bundle.Signature,
				SignedAt:  time.Now(),
				Algorithm: "ed25519",
			},
		}
	}

	return p, nil
}

// FindByCapability finds packs by capability.
func (a *RegistryAdapter) FindByCapability(ctx context.Context, capability string) ([]Pack, error) {
	bundles := a.reg.List()
	var packs []Pack

	for _, b := range bundles {
		for _, cap := range b.Manifest.Capabilities {
			if cap.Name == capability {
				caps := make([]string, len(b.Manifest.Capabilities))
				for i, c := range b.Manifest.Capabilities {
					caps[i] = c.Name
				}
				p := Pack{
					PackID: b.Manifest.Name,
					Manifest: PackManifest{
						PackID:       b.Manifest.Name,
						Version:      b.Manifest.Version,
						Name:         b.Manifest.Name,
						Description:  b.Manifest.Description,
						Capabilities: caps,
					},
				}
				packs = append(packs, p)
				break
			}
		}
	}
	return packs, nil
}

// ListVersions lists versions of a pack.
func (a *RegistryAdapter) ListVersions(ctx context.Context, packName string) ([]PackVersion, error) {
	bundle, err := a.reg.Get(packName)
	if err != nil {
		return nil, err
	}

	return []PackVersion{
		{
			PackName:   bundle.Manifest.Name,
			Version:    bundle.Manifest.Version,
			ReleasedAt: time.Now(),
		},
	}, nil
}

// PublishPack adapts pack.Pack to manifest.Bundle and registers it.
func (a *RegistryAdapter) PublishPack(ctx context.Context, p *Pack) error {
	caps := make([]manifest.CapabilityConfig, len(p.Manifest.Capabilities))
	for i, c := range p.Manifest.Capabilities {
		caps[i] = manifest.CapabilityConfig{
			Name:        c,
			Description: "Auto-mapped from Pack",
		}
	}

	bundle := &manifest.Bundle{
		Manifest: manifest.Module{
			Name:         p.Manifest.Name,
			Version:      p.Manifest.Version,
			Description:  p.Manifest.Description,
			Capabilities: caps,
		},
		CompiledAt: p.CreatedAt.Format(time.RFC3339),
		PowerDelta: 10,
	}

	if len(p.Manifest.Signatures) > 0 {
		bundle.Signature = p.Manifest.Signatures[0].Signature
	}

	return a.reg.Register(bundle)
}
