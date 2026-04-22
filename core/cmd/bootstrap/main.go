package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/ledger"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: bootstrap <db_url>")
	}
	dbURL := os.Args[1]

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	// 1. Initialize Core Schemas
	log.Println("[bootstrap] Initializing Schemas...")

	// Ledger
	lgr := ledger.NewPostgresLedger(db)
	if err := lgr.Init(ctx); err != nil {
		log.Fatalf("Failed to init ledger: %v", err)
	}

	// Registry
	reg := registry.NewPostgresRegistry(db)
	if err := reg.Init(ctx); err != nil {
		log.Fatalf("Failed to init registry: %v", err)
	}

	log.Println("[bootstrap] Schemas Initialized.")

	// 2. Seed Ops Packs
	log.Println("[bootstrap] Seeding Ops Packs...")
	packsDir := "/app/packs"
	if p := os.Getenv("PACKS_DIR"); p != "" {
		packsDir = p
	}

	if err := seedPacks(reg, packsDir); err != nil {
		log.Printf(">> Warning: Failed to seed packs: %v\n", err)
	} else {
		log.Println("[bootstrap] Ops Packs Seeded.")
	}

	log.Println("[bootstrap] Bootstrap Complete.")
}

func seedPacks(reg registry.Registry, root string) error {
	bootKey := os.Getenv("SYSTEM_BOOT_KEY")
	if bootKey == "" {
		return fmt.Errorf("SYSTEM_BOOT_KEY environment variable is required for pack signing (must be a stable secret)")
	}
	signer, err := crypto.NewEd25519Signer(bootKey)
	if err != nil {
		return fmt.Errorf("failed to create system signer: %w", err)
	}

	entries, err := os.ReadDir(root + "/ops")
	if err != nil {
		return err
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := fmt.Sprintf("%s/ops/%s/manifest.json", root, e.Name())
		//nolint:gosec // G304: Local manifest read
		content, err := os.ReadFile(manifestPath)
		if err != nil {
			log.Printf("   Skipping %s: no manifest.json\n", e.Name())
			continue
		}

		var m manifest.Module
		if err := json.Unmarshal(content, &m); err != nil {
			log.Printf("   Skipping %s: invalid manifest: %v\n", e.Name(), err)
			continue
		}

		bundle := &manifest.Bundle{
			Manifest:   m,
			CompiledAt: time.Now().UTC().String(),
		}

		manifestJSON, _ := json.Marshal(m)
		sig, err := signer.Sign(manifestJSON)
		if err != nil {
			log.Printf("   Failed to sign bundle %s: %v\n", m.Name, err)
			continue
		}
		bundle.Signature = sig

		if err := reg.Register(bundle); err != nil {
			log.Printf("   Warning: Failed to register %s: %v\n", m.Name, err)
		} else {
			log.Printf("  Registered and Signed %s@%s (Sig: %s...)\n", m.Name, m.Version, bundle.Signature[:10])
		}
	}
	return nil
}
