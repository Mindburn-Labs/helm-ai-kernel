package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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
		key, err := loadOrCreateLocalSecret(path)
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

// loadOrCreateLocalSecret reads a hex-encoded 32-byte secret from path, or
// creates the file with a random one. Creation is exclusive, so two processes
// starting on one data dir cannot overwrite each other's secret.
func loadOrCreateLocalSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generate %s: %w", path, err)
		}
		secret := hex.EncodeToString(raw)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateLocalSecret(path)
		}
		if err != nil {
			return "", fmt.Errorf("create %s: %w", path, err)
		}
		if _, err = f.WriteString(secret); err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("write %s: %w", path, err)
		}
		return secret, nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("%s is accessible to other users (mode %o); expected 600", path, info.Mode().Perm())
	}
	secret := strings.TrimSpace(string(data))
	if raw, err := hex.DecodeString(secret); err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s does not hold a hex 32-byte secret", path)
	}
	return secret, nil
}
