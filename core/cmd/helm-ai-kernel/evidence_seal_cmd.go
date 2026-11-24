package main

// quantum_posture: Evidence trust setup and sealing use the configured signer and hash bindings.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func runEvidenceTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel evidence trust <init> [flags]")
		return 2
	}
	switch args[0] {
	case "init":
		return runEvidenceTrustInit(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel evidence trust init --signer file-dev --anchor local-dev --store local-dev [--object-lock]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown evidence trust subcommand: %s\n", args[0])
		return 2
	}
}

func runEvidenceTrustInit(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence trust init", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		profile    string
		signer     string
		anchor     string
		anchorURI  string
		store      string
		storeURI   string
		keyID      string
		dataDir    string
		configPath string
		objectLock bool
		jsonOutput bool
	)
	cmd.StringVar(&profile, "profile", "", "Trust profile: dev-local, team, customer, high-assurance (default: active config or dev-local)")
	cmd.StringVar(&signer, "signer", "", "Signer type: file-dev or kms")
	cmd.StringVar(&anchor, "anchor", "", "Anchor type: local-dev, rekor, rfc3161")
	cmd.StringVar(&anchorURI, "anchor-uri", "", "Anchor URI for external trust profiles")
	cmd.StringVar(&store, "store", "", "Storage type: local-dev or s3")
	cmd.StringVar(&storeURI, "store-uri", "", "Storage URI for external trust profiles")
	cmd.StringVar(&keyID, "key-id", "", "External signer key id for kms profiles")
	cmd.StringVar(&dataDir, "data-dir", "", "HELM data directory for trust config and file-dev keys")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path (for example helm/helm.yaml)")
	cmd.BoolVar(&objectLock, "object-lock", false, "Mark storage metadata as immutable/WORM")
	cmd.BoolVar(&jsonOutput, "json", false, "Output config path as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	profileValue := normalizeEvidenceTrustProfile(profile)
	cfg, err := evidencepkg.NewEvidencePackTrustConfig(profileValue, signer, anchor, store, objectLock, dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error: initialize evidence trust config: %v\n", err)
		return 2
	}
	if anchorURI != "" {
		cfg.Anchor.URI = anchorURI
	}
	if storeURI != "" {
		cfg.Storage.URI = storeURI
	}
	if keyID != "" {
		cfg.Signer.KeyID = keyID
		if cfg.Signer.Type == "kms" {
			cfg.Signer.KMSKeyID = keyID
		}
		if cfg.Signer.PublicKey != "" {
			cfg.TrustedKeys = map[string]string{keyID: cfg.Signer.PublicKey}
		}
	}
	if objectLock {
		cfg.Storage.ObjectLock = true
		cfg.Storage.Immutable = true
	}
	if err := validateTrustInitConfig(cfg); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	writtenConfigPath, err := evidencepkg.SaveEvidencePackTrustConfigWithPath(configPath, dataDir, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: write evidence trust config: %v\n", err)
		return 2
	}
	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{
			"path":           writtenConfigPath,
			"active_profile": cfg.ActiveProfile,
			"signer":         cfg.Signer.Type,
			"key_id":         cfg.Signer.KeyID,
			"anchor":         cfg.Anchor.Type,
			"storage":        cfg.Storage.Type,
			"object_lock":    cfg.Storage.ObjectLock || cfg.Storage.Immutable,
		}, "", "  ")
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	fmt.Fprintf(stdout, "Evidence trust config written to %s\n", writtenConfigPath)
	fmt.Fprintf(stdout, "  profile: %s\n", cfg.ActiveProfile)
	fmt.Fprintf(stdout, "  signer:  %s (%s)\n", cfg.Signer.Type, cfg.Signer.KeyID)
	fmt.Fprintf(stdout, "  anchor:  %s\n", cfg.Anchor.Type)
	fmt.Fprintf(stdout, "  store:   %s\n", cfg.Storage.Type)
	return 0
}

func runEvidenceSeal(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence seal", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle     string
		profile    string
		dataDir    string
		configPath string
		jsonOutput bool
	)
	cmd.StringVar(&bundle, "bundle", "", "Path to EvidencePack directory or archive")
	cmd.StringVar(&profile, "profile", string(evidencepkg.EvidenceTrustProfileDevLocal), "Trust profile: dev-local, team, customer, high-assurance")
	cmd.StringVar(&dataDir, "data-dir", "", "HELM data directory for trust config and file-dev keys")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path (for example helm/helm.yaml)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output seal result as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
	}
	if bundle == "" {
		fmt.Fprintln(stderr, "Error: --bundle is required")
		return 2
	}

	profileOpt := evidencepkg.EvidenceTrustProfile("")
	if strings.TrimSpace(profile) != "" {
		profileOpt = normalizeEvidenceTrustProfile(profile)
	}
	result, err := sealEvidenceBundlePath(context.Background(), bundle, profileOpt, dataDir, configPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: seal evidence pack: %v\n", err)
		return 2
	}
	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(data))
		return 0
	}
	fmt.Fprintf(stdout, "EvidencePack sealed\n")
	fmt.Fprintf(stdout, "  seal:     %s\n", result["seal_path"])
	fmt.Fprintf(stdout, "  subject:  %s\n", result["subject_root"])
	if archive, _ := result["sealed_archive"].(string); archive != "" {
		fmt.Fprintf(stdout, "  archive:  %s\n", archive)
	}
	if storage, _ := result["storage_receipt"].(string); storage != "" {
		fmt.Fprintf(stdout, "  storage:  %s\n", storage)
	}
	return 0
}

func sealEvidenceBundlePath(ctx context.Context, bundle string, profile evidencepkg.EvidenceTrustProfile, dataDir, configPath string) (map[string]any, error) {
	info, err := os.Stat(bundle)
	if err != nil {
		return nil, err
	}
	packDir := bundle
	cleanup := ""
	sealedArchive := ""
	if !info.IsDir() {
		tempDir, err := os.MkdirTemp("", "helm-evidence-seal-*")
		if err != nil {
			return nil, err
		}
		cleanup = tempDir
		defer os.RemoveAll(cleanup)
		if err := extractEvidenceArchive(bundle, tempDir); err != nil {
			return nil, err
		}
		packDir = tempDir
		sealedArchive = strings.TrimSuffix(bundle, ".tar") + ".sealed.tar"
	}
	if sealedArchive == "" {
		sealedArchive = packDir + ".sealed.tar"
	}
	cfg, err := evidencepkg.LoadEvidencePackTrustConfigWithPath(configPath, dataDir)
	if err != nil {
		return nil, err
	}
	if profile == "" && cfg != nil {
		profile = cfg.ActiveProfile
	}
	profile = evidencepkg.NormalizeEvidenceTrustProfile(profile)
	storageReceiptPath := ""
	if evidencepkg.ProfileRequiresExternalTrust(profile) {
		storageReceiptPath = evidencepkg.DefaultStorageReceiptPath(sealedArchive)
	}

	seal, err := evidencepkg.SealEvidencePack(ctx, packDir, evidencepkg.SealEvidencePackOptions{
		Profile:            profile,
		TrustConfig:        cfg,
		DataDir:            dataDir,
		ConfigPath:         configPath,
		StorageReceiptPath: storageReceiptPath,
	})
	if err != nil {
		return nil, err
	}
	if err := deterministicTarArchive(packDir, sealedArchive); err != nil {
		return nil, err
	}
	if storageReceiptPath != "" {
		receipt, err := evidencepkg.StoreArchiveWithS3ObjectLock(ctx, sealedArchive, seal.MerkleRoot, seal.Storage)
		if err != nil {
			return nil, err
		}
		if err := evidencepkg.WriteStorageReceipt(storageReceiptPath, *receipt); err != nil {
			return nil, err
		}
	}

	result := map[string]any{
		"seal_path":      filepath.Join(packDir, evidencepkg.EvidencePackSealPath),
		"pack_id":        seal.PackID,
		"subject_root":   seal.MerkleRoot,
		"sealed_archive": sealedArchive,
		"profile":        seal.Profile,
	}
	if storageReceiptPath != "" {
		result["storage_receipt"] = storageReceiptPath
	}
	return result, nil
}

func normalizeEvidenceTrustProfile(profile string) evidencepkg.EvidenceTrustProfile {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "dev-local", "local-dev", "local", "dev":
		return evidencepkg.EvidenceTrustProfileDevLocal
	case "team":
		return evidencepkg.EvidenceTrustProfileTeam
	case "customer":
		return evidencepkg.EvidenceTrustProfileCustomer
	case "high-assurance":
		return evidencepkg.EvidenceTrustProfileHighAssurance
	default:
		return evidencepkg.EvidenceTrustProfile(profile)
	}
}

func validateTrustInitConfig(cfg evidencepkg.EvidencePackTrustConfig) error {
	switch cfg.ActiveProfile {
	case evidencepkg.EvidenceTrustProfileDevLocal, evidencepkg.EvidenceTrustProfileTeam:
		return nil
	case evidencepkg.EvidenceTrustProfileCustomer, evidencepkg.EvidenceTrustProfileHighAssurance:
		if cfg.Signer.Type == "" || cfg.Signer.Type == "file-dev" || cfg.Signer.Type == "local-dev" {
			return fmt.Errorf("%s profile requires an external signer", cfg.ActiveProfile)
		}
		if cfg.Anchor.Type == "" || cfg.Anchor.Type == "local-dev" {
			return fmt.Errorf("%s profile requires a remote anchor", cfg.ActiveProfile)
		}
		if cfg.Storage.Type == "" || cfg.Storage.Type == "local-dev" {
			return fmt.Errorf("%s profile requires off-host storage metadata", cfg.ActiveProfile)
		}
		if cfg.ActiveProfile == evidencepkg.EvidenceTrustProfileHighAssurance && !cfg.Storage.ObjectLock && !cfg.Storage.Immutable {
			return fmt.Errorf("high-assurance profile requires --object-lock")
		}
		return nil
	default:
		return fmt.Errorf("unknown evidence trust profile %q", cfg.ActiveProfile)
	}
}
