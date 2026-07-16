// quantum_posture: local receipt roots default to classical Ed25519; an
// explicitly selected hybrid profile adds ML-DSA-65 and must not be described
// as a universal or certified quantum-safe posture.
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
	"time"

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
	normalizedDataDir, err := ensureSetupAuthorityDataDir(dataDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid or unsafe lite-mode data dir: %w", err)
	}
	dataDir = normalizedDataDir
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
	// The ledger schema is initialized before the receipt store configures its
	// SQLite pragmas. Set the one-writer pool and busy timeout immediately so
	// two project-scoped setups sharing a deliberate authority data-dir wait
	// for one another rather than leaving one valid recovery journal behind on
	// a transient SQLITE_BUSY during first use.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)
	if _, err := db.Exec("PRAGMA busy_timeout=10000;"); err != nil {
		_ = db.Close()
		return nil, nil, nil, fmt.Errorf("failed to set sqlite busy timeout: %w", err)
	}

	// Initialize Ledger
	lgr := ledger.NewSQLLedger(db)
	if err := lgr.Init(ctx); err != nil {
		_ = db.Close()
		return nil, nil, nil, fmt.Errorf("failed to init sqlite ledger: %w", err)
	}

	// Initialize Receipt Store
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		_ = db.Close()
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
	profile := os.Getenv("HELM_RECEIPT_PROFILE")
	if profile != "" && profile != crypto.ReceiptProfileClassical && profile != crypto.ReceiptProfileHybrid {
		return nil, fmt.Errorf("unknown HELM_RECEIPT_PROFILE %q (expected %q or %q)", profile, crypto.ReceiptProfileClassical, crypto.ReceiptProfileHybrid)
	}
	normalizedDataDir, err := ensureSetupAuthorityDataDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid or unsafe signer data dir: %w", err)
	}
	dataDir = normalizedDataDir
	edSigner, err := loadOrGenerateEd25519Root(dataDir)
	if err != nil {
		return nil, err
	}
	switch profile {
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
		return nil, fmt.Errorf("unsupported HELM_RECEIPT_PROFILE %q", profile)
	}
}

func loadOrGenerateEd25519Root(dataDir string) (*crypto.Ed25519Signer, error) {
	keyPath := filepath.Join(dataDir, "root.key")
	state, err := readSetupExistingPrivateFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect root.key: %w", err)
	}
	if state.Exists {
		signer, err := ed25519SignerFromRootKey(state.Data)
		if err != nil {
			return nil, err
		}
		log.Printf("[helm] trust: loaded persistent root key")
		return signer, nil
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
	created, err := writeSetupPrivateFileIfAbsent(keyPath, []byte(hex.EncodeToString(seed)))
	if err != nil {
		return nil, fmt.Errorf("failed to save root.key: %w", err)
	}
	if !created {
		state, err := readSetupExistingPrivateFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reload concurrently-created root.key: %w", err)
		}
		if !state.Exists {
			return nil, fmt.Errorf("root.key disappeared after concurrent authority creation")
		}
		return ed25519SignerFromRootKey(state.Data)
	}

	pubPath := filepath.Join(dataDir, "root.pub")
	if err := writeSetupPrivateFile(pubPath, []byte(hex.EncodeToString(pub))); err != nil {
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
	state, err := readSetupExistingPrivateFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect root.mldsa65.key: %w", err)
	}
	if state.Exists {
		signer, err := mldsaSignerFromRootKey(state.Data)
		if err != nil {
			return nil, err
		}
		log.Printf("[helm] trust: loaded persistent ml-dsa-65 root key")
		return signer, nil
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
	created, err := writeSetupPrivateFileIfAbsent(keyPath, []byte(hex.EncodeToString(seed)))
	if err != nil {
		return nil, fmt.Errorf("failed to save root.mldsa65.key: %w", err)
	}
	if !created {
		state, err := readSetupExistingPrivateFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reload concurrently-created root.mldsa65.key: %w", err)
		}
		if !state.Exists {
			return nil, fmt.Errorf("root.mldsa65.key disappeared after concurrent authority creation")
		}
		return mldsaSignerFromRootKey(state.Data)
	}
	return crypto.NewMLDSASignerFromKey(priv, "root"), nil
}

// loadExistingSignerWithDataDir is the non-mutating counterpart to
// loadOrGenerateSignerWithDataDir. Recovery and removal provenance must never
// create a new authority, a public-key sidecar, or a database merely by
// checking whether a prior installation is trustworthy.
func loadExistingSignerWithDataDir(dataDir string) (crypto.Signer, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	normalizedDataDir, err := requireSetupAuthorityDataDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("invalid or unsafe signer data dir: %w", err)
	}
	dataDir = normalizedDataDir
	edSigner, err := loadExistingEd25519Root(dataDir)
	if err != nil {
		return nil, err
	}
	switch profile := os.Getenv("HELM_RECEIPT_PROFILE"); profile {
	case "", crypto.ReceiptProfileClassical:
		return edSigner, nil
	case crypto.ReceiptProfileHybrid:
		mldsaSigner, err := loadExistingMLDSARoot(dataDir)
		if err != nil {
			return nil, err
		}
		return crypto.NewHybridSignerFromSigners(edSigner, mldsaSigner, "root")
	default:
		return nil, fmt.Errorf("unknown HELM_RECEIPT_PROFILE %q (expected %q or %q)", profile, crypto.ReceiptProfileClassical, crypto.ReceiptProfileHybrid)
	}
}

func loadExistingEd25519Root(dataDir string) (*crypto.Ed25519Signer, error) {
	state, err := readSetupExistingPrivateFile(filepath.Join(dataDir, "root.key"))
	if err != nil {
		return nil, fmt.Errorf("inspect root.key: %w", err)
	}
	if !state.Exists {
		return nil, fmt.Errorf("root.key does not exist")
	}
	return ed25519SignerFromRootKey(state.Data)
}

func ed25519SignerFromRootKey(raw []byte) (*crypto.Ed25519Signer, error) {
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid root.key format: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid root.key seed size: %d, expected %d", len(seed), ed25519.SeedSize)
	}
	return crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "root"), nil
}

func loadExistingMLDSARoot(dataDir string) (*crypto.MLDSASigner, error) {
	state, err := readSetupExistingPrivateFile(filepath.Join(dataDir, "root.mldsa65.key"))
	if err != nil {
		return nil, fmt.Errorf("inspect root.mldsa65.key: %w", err)
	}
	if !state.Exists {
		return nil, fmt.Errorf("root.mldsa65.key does not exist")
	}
	return mldsaSignerFromRootKey(state.Data)
}

func mldsaSignerFromRootKey(raw []byte) (*crypto.MLDSASigner, error) {
	seedBytes, err := hex.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid root.mldsa65.key format: %w", err)
	}
	if len(seedBytes) != mldsa65.SeedSize {
		return nil, fmt.Errorf("invalid root.mldsa65.key seed size: %d, expected %d", len(seedBytes), mldsa65.SeedSize)
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)
	_, priv := mldsa65.NewKeyFromSeed(&seed)
	return crypto.NewMLDSASignerFromKey(priv, "root"), nil
}
