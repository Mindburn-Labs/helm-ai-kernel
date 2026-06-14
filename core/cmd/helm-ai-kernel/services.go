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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/authz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/config"
	helmcontext "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/context"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/credentials"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/governance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernelruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kms"
	launchsession "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/memory"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/merkle"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pack"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/obligation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// Services holds all initialized subsystems for the HELM runtime.
type Services struct {
	// --- Runtime metadata ---
	DataDir           string
	DatabaseMode      string
	DatabaseStatus    string
	SQLitePath        string
	ArtifactStorePath string
	LaunchpadStore    *launchsession.Store

	// --- Infrastructure ---
	Config        *config.Config
	Observability *observability.Provider
	AuditStore    *store.AuditStore

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

	// --- Receipt Transparency Log (RFC 6962) ---
	// TranspLog anchors every issued receipt hash in an append-only Merkle
	// log. TranspLogID is the log identity (hex SHA-256 of the kernel public
	// key). TranspLogDegrade, when true, downgrades a transparency append
	// failure from fail-closed (issuance blocked) to a deferred anchor; the
	// production default is false (fail-closed).
	TranspLog        TransparencyAppender
	TranspLogID      string
	TranspLogDegrade bool

	// --- Cross-cutting ---
	KernelRT *kernelruntime.Server

	// --- Security ---
	Guardian *guardian.Guardian

	// --- Runtime Policy Authority ---
	PolicyReconciler    *policyreconcile.Reconciler
	PolicySnapshotStore policyreconcile.PolicySnapshotStore
	PolicyScope         policyreconcile.PolicyScope

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
//
// dataDir is the runtime data directory (CLI --data-dir / HELM_DATA_DIR).
// Subsystems that persist state under dataDir (e.g. the KMS keystore) must
// receive it explicitly instead of resolving relative paths against the
// container CWD, which on a distroless rootfs is `/` and therefore read-only.
func NewServices(ctx context.Context, db *sql.DB, artStore artifacts.Store, logger *slog.Logger, dataDir string) (*Services, error) {
	dataDir = normalizedDataDir(dataDir)
	s := &Services{
		DataDir:           dataDir,
		DatabaseStatus:    "unknown",
		SQLitePath:        filepath.Join(dataDir, "helm.db"),
		ArtifactStorePath: filepath.Join(dataDir, "artifacts"),
		LaunchpadStore:    launchsession.NewStore(launchpadStoreRoot(dataDir)),
		AuditStore:        store.NewAuditStore(),
	}

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
	keystorePath := kmsKeystorePath(dataDir)
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
	// Pack execution is fail-closed until a PackVerifier (trust.PackLoader
	// with TUF roots) is configured; the nil verifier is that explicit
	// posture, not an oversight — Run refuses with ERR_PACK_TRUST_UNVERIFIED.
	s.Sandbox, err = sandbox.NewWasiSandboxWithVerifier(ctx, artStore, sandboxConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox init: %w", err)
	}
	logger.Info("subsystem ready", "component", " Sandbox initialized (pack execution fail-closed: no PackVerifier configured)")

	// --- 7. Boundary ---
	// The version string must match boundary.PolicyVersion exactly; LoadPolicy
	// performs a strict equality check. A mismatch leaves BoundaryEnforcer nil,
	// which causes every CheckNetwork / CheckTool / CheckData to silently pass
	// (see subsystems.go: the /api/v1/boundary/check route returns
	// {"status":"disabled"} when the enforcer is nil). In a fail-closed firewall
	// that is the worst possible default, so production refuses to start when
	// the default policy fails to load.
	perimEnforcer, err := boundary.NewPerimeterEnforcer(defaultBoundaryPolicy())
	if err != nil {
		if envBool("HELM_PRODUCTION") {
			return nil, fmt.Errorf("boundary enforcer init (production): %w", err)
		}
		logger.Warn("Boundary enforcer init — running with enforcer DISABLED (dev mode)", "error", err)
	} else {
		s.BoundaryEnforcer = perimEnforcer
		s.BoundaryEnforcer.SetViolationHandler(func(ctx context.Context, err error, reason string, policyID string) {
			logger.Warn("Boundary violation", "error", err, "reason", reason, "policy_id", policyID)
			metadata := map[string]string{
				"policy_id": policyID,
				"reason":    reason,
			}
			_, appendErr := s.AuditStore.Append(store.EntryTypeViolation, "boundary", "violation", err.Error(), metadata)
			if appendErr != nil {
				logger.Error("Failed to append boundary violation to audit store", "error", appendErr)
			}
		})
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
		MatrixID: "helm-ai-kernel-v1",
		Version:  displayVersion(),
	}
	logger.Info("subsystem ready", "component", " Compatibility Matrix initialized")

	logger.Info("subsystem ready", "component", " All subsystems initialized successfully")
	return s, nil
}

// kmsKeystorePath resolves the on-disk location of the KMS keystore. The path
// is anchored on the runtime data directory (CLI --data-dir, falling back to
// HELM_DATA_DIR, then "data"), never on the container CWD. On distroless the
// CWD is `/`, which is read-only — so a relative path would break the KMS init
// and silently disable the credentials store.
func kmsKeystorePath(dataDir string) string {
	dataDir = normalizedDataDir(dataDir)
	return filepath.Join(dataDir, "keys", "credentials.keystore.json")
}

func normalizedDataDir(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = strings.TrimSpace(os.Getenv("HELM_DATA_DIR"))
	}
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "data"
	}
	return dataDir
}

func launchpadStoreRoot(dataDir string) string {
	if override := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_HOME")); override != "" {
		return override
	}
	return filepath.Join(normalizedDataDir(dataDir), "launchpad")
}

// defaultBoundaryPolicy returns the policy template used at startup before any
// runtime policy bundle is reconciled. Kept as a single source of truth so the
// schema version stays in lockstep with boundary.PolicyVersion.
func defaultBoundaryPolicy() *boundary.PerimeterPolicy {
	return &boundary.PerimeterPolicy{
		Version:  boundary.PolicyVersion,
		PolicyID: "default",
		Name:     "HELM Default Perimeter",
	}
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
