package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

// localAPIKeys are the pre-shared keys the server reads from its environment,
// and where a non-production install keeps a generated one.
var localAPIKeys = []struct{ env, file string }{
	{helmauth.AdminAPIKeyEnv, "admin.key"},
	{serviceAPIKeyEnv, "service.key"},
}

// publishedAPIKeys shipped as docker-compose and smoke defaults. Anyone who
// has read the repository holds them.
var publishedAPIKeys = []string{"helm-admin-dev", "helm-service-dev", "helm-admin-smoke", "helm-service-smoke"}

// ensureLocalAPIKeys gives a non-production install its own admin and service
// API keys when none are configured: a random key is generated once, kept at
// <dataDir>/admin.key or service.key (0600), and exported to this process's
// environment, the same way the evidence seed is handled. Production leaves
// an unset key unset, so those routes stay closed. A published default is
// refused in every mode. Only the file path is logged, never the key.
func ensureLocalAPIKeys(dataDir string, logger *slog.Logger) error {
	for _, k := range localAPIKeys {
		value := strings.TrimSpace(os.Getenv(k.env))
		if slices.Contains(publishedAPIKeys, value) {
			return fmt.Errorf("%s is the published default %q; unset it to use a generated per-install key, or set a generated secret", k.env, value)
		}
		if value != "" || envBool("HELM_PRODUCTION") {
			continue
		}
		path := filepath.Join(dataDir, k.file)
		key, err := loadOrCreateSeedFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", k.env, err)
		}
		if err := os.Setenv(k.env, key); err != nil {
			return err
		}
		logger.Warn(k.env+" not set — using this install's generated key; read it from the file", "path", path)
	}
	return nil
}
