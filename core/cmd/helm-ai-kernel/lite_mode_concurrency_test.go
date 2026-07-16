package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadOrGenerateSignerWithDataDirConcurrentFirstInitialization(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	t.Setenv("HELM_RECEIPT_PROFILE", "")
	dataDir := filepath.Join(t.TempDir(), "shared-data")

	const starters = 32
	start := make(chan struct{})
	results := make(chan signerInitResult, starters)
	var group sync.WaitGroup
	for range starters {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			signer, err := loadOrGenerateSignerWithDataDir(dataDir)
			if err != nil {
				results <- signerInitResult{err: err}
				return
			}
			results <- signerInitResult{publicKey: signer.PublicKey()}
		}()
	}
	close(start)
	group.Wait()
	close(results)

	var publicKey string
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent signer initialization: %v", result.err)
		}
		if publicKey == "" {
			publicKey = result.publicKey
			continue
		}
		if result.publicKey != publicKey {
			t.Fatalf("concurrent signer public key = %q, want %q", result.publicKey, publicKey)
		}
	}
	if publicKey == "" {
		t.Fatal("no signer result")
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(string(raw))
	if err != nil {
		t.Fatalf("decode persisted root seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("persisted root seed size = %d, want %d", len(seed), ed25519.SeedSize)
	}
}

type signerInitResult struct {
	publicKey string
	err       error
}
