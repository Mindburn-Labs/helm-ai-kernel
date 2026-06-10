package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/ledger"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	_ "modernc.org/sqlite"
)

func setupLiteMode(ctx context.Context) (*sql.DB, ledger.Ledger, store.ReceiptStore, error) {
	return setupLiteModeWithDataDir(ctx, "data")
}

func setupLiteModeWithDataDir(ctx context.Context, dataDir string) (*sql.DB, ledger.Ledger, store.ReceiptStore, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	return setupLiteModeWithDBPath(ctx, filepath.Join(dataDir, "helm.db"))
}

func setupLiteModeWithDBPath(ctx context.Context, dbPath string) (*sql.DB, ledger.Ledger, store.ReceiptStore, error) {
	if dbPath == "" {
		dbPath = filepath.Join("data", "helm.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	log.Printf("[helm] lite mode: using sqlite at %s", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	// Initialize Ledger
	lgr := ledger.NewSQLLedger(db)
	if err := lgr.Init(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to init sqlite ledger: %w", err)
	}

	// Initialize Receipt Store
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to init sqlite receipt store: %w", err)
	}

	return db, lgr, receiptStore, nil
}

func loadOrGenerateSigner() (crypto.Signer, error) {
	return loadOrGenerateSignerWithDataDir("data")
}

// loadOrGenerateSignerWithDataDir builds the kernel root receipt signer.
// The signature profile is selected by HELM_RECEIPT_PROFILE per the
// PQ-hybrid receipt profile RFC (protocols/specs/rfc/receipt-pq-hybrid-profile-v1.md):
// unset/"classical" keeps the Ed25519-only profile; "hybrid" composes the
// Ed25519 root key with an ML-DSA-65 root key (root.mldsa65.key) into a
// dual-signature envelope. Unknown values fail closed.
func loadOrGenerateSignerWithDataDir(dataDir string) (crypto.Signer, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}
	edSigner, err := loadOrGenerateEd25519Root(dataDir)
	if err != nil {
		return nil, err
	}
	switch profile := os.Getenv("HELM_RECEIPT_PROFILE"); profile {
	case "", crypto.ReceiptProfileClassical:
		return edSigner, nil
	case crypto.ReceiptProfileHybrid:
		mldsaSigner, err := loadOrGenerateMLDSARoot(dataDir)
		if err != nil {
			return nil, err
		}
		log.Printf("[helm] trust: PQ-hybrid receipt profile enabled (Ed25519 + ML-DSA-65)")
		return crypto.NewHybridSignerFromSigners(edSigner, mldsaSigner, "root")
	default:
		return nil, fmt.Errorf("unknown HELM_RECEIPT_PROFILE %q (expected %q or %q)", profile, crypto.ReceiptProfileClassical, crypto.ReceiptProfileHybrid)
	}
}

func loadOrGenerateEd25519Root(dataDir string) (*crypto.Ed25519Signer, error) {
	keyPath := filepath.Join(dataDir, "root.key")
	if _, err := os.Stat(keyPath); err == nil {
		// Load existing key
		keyHex, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root.key: %w", err)
		}
		seed, err := hex.DecodeString(string(keyHex))
		if err != nil {
			return nil, fmt.Errorf("invalid root.key format: %w", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		log.Printf("[helm] trust: loaded persistent root key")
		return crypto.NewEd25519SignerFromKey(priv, "root"), nil
	}

	// Generate new persistent key if not in production
	if envBool("HELM_PRODUCTION") {
		return nil, fmt.Errorf("production mode requires root signing key to exist at %s", keyPath)
	}

	log.Printf("[helm] trust: generating new persistent root key at %s", keyPath)
	fmt.Fprintf(os.Stderr, "\n%s⚠️  SECURITY WARNING: Using auto-generated root key.%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Fprintf(os.Stderr, "   Key saved to: %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "   In production, use a hardware security module (HSM) or cloud KMS.\n\n")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	seed := priv.Seed()
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, fmt.Errorf("failed to save root.key: %w", err)
	}

	pubPath := filepath.Join(dataDir, "root.pub")
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		log.Printf("⚠️  failed to save root.pub: %v", err)
	}

	return crypto.NewEd25519SignerFromKey(priv, "root"), nil
}

// loadOrGenerateMLDSARoot loads or generates the ML-DSA-65 (FIPS 204) root
// key used by the PQ-hybrid receipt profile. The key file holds the
// hex-encoded 32-byte seed, mirroring the root.key convention, and rotates
// alongside the Ed25519 root key.
func loadOrGenerateMLDSARoot(dataDir string) (*crypto.MLDSASigner, error) {
	keyPath := filepath.Join(dataDir, "root.mldsa65.key")
	if _, err := os.Stat(keyPath); err == nil {
		keyHex, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root.mldsa65.key: %w", err)
		}
		seedBytes, err := hex.DecodeString(string(keyHex))
		if err != nil {
			return nil, fmt.Errorf("invalid root.mldsa65.key format: %w", err)
		}
		if len(seedBytes) != mldsa65.SeedSize {
			return nil, fmt.Errorf("invalid root.mldsa65.key seed size: %d, expected %d", len(seedBytes), mldsa65.SeedSize)
		}
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], seedBytes)
		_, priv := mldsa65.NewKeyFromSeed(&seed)
		log.Printf("[helm] trust: loaded persistent ml-dsa-65 root key")
		return crypto.NewMLDSASignerFromKey(priv, "root"), nil
	}

	if envBool("HELM_PRODUCTION") {
		return nil, fmt.Errorf("production mode with hybrid receipt profile requires ml-dsa-65 root key to exist at %s", keyPath)
	}

	log.Printf("[helm] trust: generating new persistent ml-dsa-65 root key at %s", keyPath)
	_, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ml-dsa-65 key: %w", err)
	}
	seed := priv.Seed()
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, fmt.Errorf("failed to save root.mldsa65.key: %w", err)
	}
	return crypto.NewMLDSASignerFromKey(priv, "root"), nil
}
