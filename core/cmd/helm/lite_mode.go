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

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/ledger"

	_ "modernc.org/sqlite"
)

func setupLiteMode(ctx context.Context) (*sql.DB, ledger.Ledger, store.ReceiptStore, error) {
	dataDir := "data"
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "helm.db")
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
	keyPath := "data/root.key"
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
	if os.Getenv("HELM_PRODUCTION") == "1" {
		return nil, fmt.Errorf("production mode requires data/root.key to exist")
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
	
	pubPath := "data/root.pub"
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		log.Printf("⚠️  failed to save root.pub: %v", err)
	}

	return crypto.NewEd25519SignerFromKey(priv, "root"), nil
}
