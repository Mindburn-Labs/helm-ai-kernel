// quantum_posture: local workstation receipts use classical Ed25519 signing;
// this persistence layer is not a post-quantum or hybrid cryptographic control.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	workstationSigningKeyDirectory  = "keys"
	workstationSigningSeedName      = "workstation-ed25519.seed"
	workstationSigningPublicKeyName = "workstation-ed25519.pub"
)

func workstationSigningSeedPath(dataDir string) string {
	return filepath.Join(dataDir, workstationSigningKeyDirectory, workstationSigningSeedName)
}

func workstationSigningPublicKeyPath(dataDir string) string {
	return filepath.Join(dataDir, workstationSigningKeyDirectory, workstationSigningPublicKeyName)
}

func resolveWorkstationSigningSeed(dataDir, seedHex, seedFile string) ([]byte, error) {
	seed, err := loadSigningSeed(seedHex, seedFile)
	if err != nil {
		return nil, err
	}
	if len(seed) != 0 {
		return seed, nil
	}
	return ensureLocalWorkstationSigningSeed(dataDir)
}

func ensureLocalWorkstationSigningSeed(dataDir string) ([]byte, error) {
	if envBool("HELM_PRODUCTION") {
		return nil, errors.New("production mode requires --signing-seed-file")
	}
	dataDir, err := normalizedWorkstationDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	keyDir := filepath.Join(dataDir, workstationSigningKeyDirectory)
	if err := ensurePrivateDirectory(keyDir); err != nil {
		return nil, fmt.Errorf("prepare workstation signing key directory: %w", err)
	}
	seedPath := workstationSigningSeedPath(dataDir)
	seed, err := loadSigningSeed("", seedPath)
	if err == nil {
		if err := ensureWorkstationPublicKey(dataDir, seed); err != nil {
			return nil, err
		}
		return seed, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	seed = make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate workstation signing seed: %w", err)
	}
	if err := writeNewFile(seedPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create workstation signing seed: %w", err)
		}
		seed, err = loadSigningSeed("", seedPath)
		if err != nil {
			return nil, err
		}
	}
	if err := ensureWorkstationPublicKey(dataDir, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func normalizedWorkstationDataDir(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = defaultSetupDataDir()
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("--data-dir is required when the home directory is unavailable")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve workstation data directory: %w", err)
	}
	return abs, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("must be a directory, not a symlink or special file")
	}
	return os.Chmod(path, 0o700)
}

func ensureWorkstationPublicKey(dataDir string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("signing seed must be %d bytes", ed25519.SeedSize)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	expected := hex.EncodeToString(publicKey)
	path := workstationSigningPublicKeyPath(dataDir)
	data, err := readRegularFile(path, "workstation trusted public key")
	if err == nil {
		if strings.TrimSpace(string(data)) != expected {
			return fmt.Errorf("workstation trusted public key does not match signing seed")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := writeNewFile(path, []byte(expected+"\n"), 0o644); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create workstation trusted public key: %w", err)
		}
		data, err := readRegularFile(path, "workstation trusted public key")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) != expected {
			return fmt.Errorf("workstation trusted public key does not match signing seed")
		}
	}
	return nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !written {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	written = true
	return nil
}

func readRegularFile(path, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink or special file", label)
	}
	return os.ReadFile(path)
}

func loadTrustedPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := readRegularFile(path, "trusted public key")
	if err != nil {
		return nil, err
	}
	keyHex := strings.TrimPrefix(strings.TrimSpace(string(data)), "ed25519:")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("trusted public key must be hex: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted public key must decode to %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func resolveTrustedWorkstationPublicKey(dataDir, explicitPath string) (ed25519.PublicKey, string, bool, error) {
	if strings.TrimSpace(explicitPath) != "" {
		key, err := loadTrustedPublicKeyFile(explicitPath)
		if err != nil {
			return nil, explicitPath, false, err
		}
		return key, explicitPath, true, nil
	}
	dataDir, err := normalizedWorkstationDataDir(dataDir)
	if err != nil {
		return nil, "", false, err
	}
	path := workstationSigningPublicKeyPath(dataDir)
	key, err := loadTrustedPublicKeyFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, path, false, nil
	}
	if err != nil {
		return nil, path, false, err
	}
	return key, path, true, nil
}
