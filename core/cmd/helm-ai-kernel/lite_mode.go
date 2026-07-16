package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	seed, created, err := loadOrCreateHexSeed(keyPath, ed25519.SeedSize, !envBool("HELM_PRODUCTION"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && envBool("HELM_PRODUCTION") {
			return nil, fmt.Errorf("production mode requires root signing key to exist at %s", keyPath)
		}
		return nil, fmt.Errorf("load root.key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if created {
		log.Printf("[helm] trust: generating new persistent root key at %s", keyPath)
		fmt.Fprintf(os.Stderr, "\n%s⚠️  SECURITY WARNING: Using auto-generated root key.%s\n", ColorBold+ColorYellow, ColorReset)
		fmt.Fprintf(os.Stderr, "   Key saved to: %s\n", keyPath)
		fmt.Fprintf(os.Stderr, "   In production, use a hardware security module (HSM) or cloud KMS.\n\n")
		pubPath := filepath.Join(dataDir, "root.pub")
		if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(priv.Public().(ed25519.PublicKey))), 0o644); err != nil {
			log.Printf("⚠️  failed to save root.pub: %v", err)
		}
	} else {
		log.Printf("[helm] trust: loaded persistent root key")
	}
	return crypto.NewEd25519SignerFromKey(priv, "root"), nil
}

// loadOrGenerateMLDSARoot loads or generates the ML-DSA-65 (FIPS 204) root
// key used by the PQ-hybrid receipt profile. The key file holds the
// hex-encoded 32-byte seed, mirroring the root.key convention, and rotates
// alongside the Ed25519 root key.
func loadOrGenerateMLDSARoot(dataDir string) (*crypto.MLDSASigner, error) {
	keyPath := filepath.Join(dataDir, "root.mldsa65.key")
	seedBytes, created, err := loadOrCreateHexSeed(keyPath, mldsa65.SeedSize, !envBool("HELM_PRODUCTION"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && envBool("HELM_PRODUCTION") {
			return nil, fmt.Errorf("production mode with hybrid receipt profile requires ml-dsa-65 root key to exist at %s", keyPath)
		}
		return nil, fmt.Errorf("load root.mldsa65.key: %w", err)
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)
	_, priv := mldsa65.NewKeyFromSeed(&seed)
	if created {
		log.Printf("[helm] trust: generating new persistent ml-dsa-65 root key at %s", keyPath)
	} else {
		log.Printf("[helm] trust: loaded persistent ml-dsa-65 root key")
	}
	return crypto.NewMLDSASignerFromKey(priv, "root"), nil
}

const (
	rootSeedLoadAttempts   = 25
	rootSeedLoadRetryDelay = 10 * time.Millisecond
)

// loadOrCreateHexSeed is safe for concurrent first startup by independent
// kernel processes. Only the exclusive creator may write the seed; contenders
// reload the winner's durable file and fail closed if it remains malformed.
func loadOrCreateHexSeed(path string, seedSize int, allowCreate bool) ([]byte, bool, error) {
	var lastErr error
	for attempt := 0; attempt < rootSeedLoadAttempts; attempt++ {
		seed, err := loadHexSeed(path, seedSize)
		if err == nil {
			return seed, false, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			if !allowCreate {
				return nil, false, err
			}
			candidate := make([]byte, seedSize)
			if _, err := rand.Read(candidate); err != nil {
				return nil, false, fmt.Errorf("generate root seed: %w", err)
			}
			file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			switch {
			case createErr == nil:
				if err := writeHexSeed(file, candidate); err != nil {
					_ = file.Close()
					return nil, false, fmt.Errorf("save root seed: %w", err)
				}
				if err := file.Close(); err != nil {
					return nil, false, fmt.Errorf("close root seed: %w", err)
				}
				return candidate, true, nil
			case !errors.Is(createErr, fs.ErrExist):
				return nil, false, fmt.Errorf("create root seed: %w", createErr)
			}
		}
		lastErr = err
		if attempt+1 < rootSeedLoadAttempts {
			time.Sleep(rootSeedLoadRetryDelay)
		}
	}
	return nil, false, fmt.Errorf("load concurrently initialized root seed after %d attempts: %w", rootSeedLoadAttempts, lastErr)
}

func loadHexSeed(path string, seedSize int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("invalid root seed format: %w", err)
	}
	if len(seed) != seedSize {
		return nil, fmt.Errorf("invalid root seed size: %d, expected %d", len(seed), seedSize)
	}
	return seed, nil
}

func writeHexSeed(file *os.File, seed []byte) error {
	data := []byte(hex.EncodeToString(seed))
	for len(data) > 0 {
		n, err := file.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return file.Sync()
}
