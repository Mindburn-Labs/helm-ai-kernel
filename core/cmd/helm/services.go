package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/authz"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/config"
	helmcontext "github.com/Mindburn-Labs/helm-oss/core/pkg/context"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/credentials"
	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/governance"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernelruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kms"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/memory"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/merkle"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtime/obligation"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtime/sandbox"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

// Services holds all initialized subsystems for the HELM runtime.
type Services struct {
	// --- Infrastructure ---
	Config        *config.Config
	Observability *observability.Provider

	// --- Authorization ---
	Authz *authz.Engine
	Creds *credentials.Handler

	// --- Memory ---
	MemoryAPI *api.MemoryService

	// --- Kernel & Execution ---
	BoundaryEnforcer *boundary.PerimeterEnforcer
	BoundarySurfaces *boundary.SurfaceRegistry
	MerkleTree       *merkle.MerkleTree
	Sandbox          sandbox.Sandbox
	Obligation       *obligation.ObligationEngine

	// --- Evidence ---
	Evidence      *evidence.DefaultExporter
	ReceiptStore  store.ReceiptStore
	ReceiptSigner helmcrypto.Signer

	// --- Cross-cutting ---
	KernelRT *kernelruntime.Server

	// --- Security ---
	Guardian *guardian.Guardian

	// --- Governed Memory (LKS/CKS) ---
	GovMemory *memory.InMemoryStore

	// --- Context Bundles ---
	BundleStore *helmcontext.BundleStore

	// --- Economic Ledger ---
	EconLedger *economic.Ledger

	// --- Edge Governance ---
	EdgeAssistant *governance.EdgeAssistant

	// --- Compatibility Matrix ---
	CompatMatrix *pack.CompatibilityMatrix
}

// NewServices initializes all subsystems.
func NewServices(ctx context.Context, db *sql.DB, artStore artifacts.Store, logger *slog.Logger) (*Services, error) {
	s := &Services{}

	// --- 1. Config ---
	s.Config = config.Load()
	logger.Info("subsystem ready", "component", " Config loaded")

	// --- 2. Observability ---
	obsCfg := observability.DefaultConfig()
	obs, err := observability.New(ctx, obsCfg)
	if err != nil {
		logger.Warn("Observability init skipped (no OTLP endpoint)", "error", err)
	} else {
		s.Observability = obs
		logger.Info("subsystem ready", "component", " Observability provider initialized")
	}

	// --- 3. Authorization ---
	s.Authz = authz.NewEngine()
	logger.Info("subsystem ready", "component", " ReBAC Authorization Engine initialized")

	// --- 4. Credentials (CRED-001: KMS-backed key management) ---
	keystorePath := "data/keys/credentials.keystore.json"
	keyManager, kmsErr := kms.NewLocalKMS(keystorePath)
	if kmsErr != nil {
		logger.Warn("KMS init failed — credentials store DISABLED", "error", kmsErr)
	} else {
		// Migration: if legacy env key exists, import it as version 0
		credKeyHex := os.Getenv("CREDENTIALS_ENCRYPTION_KEY")
		if credKeyHex != "" {
			encKey, hexErr := hex.DecodeString(credKeyHex)
			if hexErr == nil && len(encKey) == 32 {
				_ = keyManager.ImportKey(encKey, 0)
				logger.Info("KMS: imported legacy env key as version 0")
			}
		}

		credStore := credentials.NewStoreWithKMS(db, keyManager)
		s.Creds = credentials.NewHandler(credStore)
		logger.Info("subsystem ready", "component", " Credentials Handler initialized (KMS-backed)")
	}

	// --- 5. Memory ---
	s.MemoryAPI = api.NewMemoryService()
	logger.Info("subsystem ready", "component", " Memory Service initialized")

	// --- 6. Sandbox ---
	sandboxConfig := sandbox.SandboxConfig{
		MemoryLimitBytes: 64 * 1024 * 1024, // 64MB
		CPUTimeLimit:     500 * time.Millisecond,
		NetworkEnabled:   false,
	}
	s.Sandbox, err = sandbox.NewWasiSandbox(ctx, artStore, sandboxConfig)
	if err != nil {
		return nil, fmt.Errorf("sandbox init: %w", err)
	}
	logger.Info("subsystem ready", "component", " Sandbox initialized")

	// --- 7. Boundary ---
	defaultBoundaryPolicy := &boundary.PerimeterPolicy{
		Version:  "1.0",
		PolicyID: "default",
		Name:     "HELM Default Perimeter",
	}
	perimEnforcer, err := boundary.NewPerimeterEnforcer(defaultBoundaryPolicy)
	if err != nil {
		logger.Warn("Boundary enforcer init", "error", err)
	} else {
		s.BoundaryEnforcer = perimEnforcer
	}
	surfaces, surfaceErr := boundary.NewSQLSurfaceRegistry(ctx, db, time.Now)
	if surfaceErr != nil {
		logger.Warn("Boundary surface registry persistence disabled", "error", surfaceErr)
		surfaces, surfaceErr = boundary.NewFileBackedSurfaceRegistry(defaultBoundaryRegistryPath(), time.Now)
		if surfaceErr != nil {
			logger.Warn("Boundary surface file fallback disabled", "error", surfaceErr)
			surfaces = boundary.NewSurfaceRegistry(time.Now)
		}
	}
	s.BoundarySurfaces = surfaces
	logger.Info("subsystem ready", "component", " Boundary Perimeter Enforcer initialized")

	// --- 8. Merkle ---
	initData := map[string]interface{}{"init": "helm-genesis"}
	mt, _ := merkle.BuildMerkleTree(initData)
	s.MerkleTree = mt
	logger.Info("subsystem ready", "component", " Merkle Tree initialized")

	// --- 9. Obligation ---
	obligationStore := obligation.NewMemoryStore()
	s.Obligation = obligation.NewObligationEngine(obligationStore)
	logger.Info("subsystem ready", "component", " Obligation Engine initialized")

	// --- 10. Evidence ---
	evidenceKey, defaultedEvidenceKey, err := evidenceSigningSeedFromEnv()
	if err != nil {
		return nil, err
	}
	if defaultedEvidenceKey {
		logger.Warn("EVIDENCE_SIGNING_KEY not set — using default seed (not safe for production)")
	}
	evidenceSigner, err := helmcrypto.NewEd25519Signer(evidenceKey)
	if err != nil {
		return nil, fmt.Errorf("evidence signer init: %w", err)
	}
	s.Evidence = evidence.NewExporter(evidenceSigner, evidenceSigner.KeyID)
	logger.Info("subsystem ready", "component", " Evidence Exporter initialized")

	// --- 11. Kernel Runtime ---
	s.KernelRT = kernelruntime.New(s.Config)
	logger.Info("subsystem ready", "component", " KernelRuntime initialized")

	// --- 12. Governed Memory (LKS/CKS) ---
	s.GovMemory = memory.NewInMemoryStore()
	logger.Info("subsystem ready", "component", " Governed Memory (LKS/CKS) initialized")

	// --- 13. Context Bundles ---
	s.BundleStore = helmcontext.NewBundleStore()
	logger.Info("subsystem ready", "component", " Context Bundle Store initialized")

	// --- 14. Economic Ledger ---
	s.EconLedger = economic.NewLedger()
	logger.Info("subsystem ready", "component", " Economic Ledger initialized")

	// --- 15. Edge Governance ---
	s.EdgeAssistant = &governance.EdgeAssistant{
		Config: governance.EdgeConfig{
			Mode:         governance.EdgeFull,
			MaxLatencyMs: 100,
			CacheTTL:     5 * time.Minute,
		},
		Fallback: governance.FallbackPolicy{
			PolicyID: "default-fallback",
			Strategy: governance.FallbackDenyAll,
		},
	}
	logger.Info("subsystem ready", "component", " Edge Governance initialized")

	// --- 16. Compatibility Matrix ---
	s.CompatMatrix = &pack.CompatibilityMatrix{
		MatrixID: "helm-oss-v1",
		Version:  displayVersion(),
	}
	logger.Info("subsystem ready", "component", " Compatibility Matrix initialized")

	logger.Info("subsystem ready", "component", " All subsystems initialized successfully")
	return s, nil
}

func defaultBoundaryRegistryPath() string {
	if path := strings.TrimSpace(os.Getenv("HELM_BOUNDARY_REGISTRY_PATH")); path != "" {
		return path
	}
	dataDir := strings.TrimSpace(os.Getenv("HELM_DATA_DIR"))
	if dataDir == "" {
		dataDir = "data"
	}
	return filepath.Join(dataDir, "boundary", "surfaces.json")
}

func evidenceSigningSeedFromEnv() (string, bool, error) {
	seed := strings.TrimSpace(os.Getenv("EVIDENCE_SIGNING_KEY"))
	if seed != "" {
		return seed, false, nil
	}
	if envBool("HELM_PRODUCTION") {
		return "", false, fmt.Errorf("production mode requires EVIDENCE_SIGNING_KEY")
	}
	return "helm-evidence-bundle", true, nil
}
