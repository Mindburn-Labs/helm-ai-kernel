package pack

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry"
)

// RegistryAdapter bridges the Bundle Registry to the PackRegistry interface.
// This adapter lives in the pack package to avoid depending on enterprise packages.
type RegistryAdapter struct {
	reg registry.Registry
}
