package main

// quantum_posture: runtime wiring retains classical Ed25519 signing and trust;
// it does not add post-quantum cryptographic controls.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
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
	BoundaryEnforcer      *boundary.PerimeterEnforcer
	BoundarySurfaces      *boundary.SurfaceRegistry
	MerkleTree            *merkle.MerkleTree
	Sandbox               sandbox.Sandbox
	Obligation            *obligation.ObligationEngine
	EmergencyStops        *kernel.ScopedStopStore
	ApprovalConsumption   *approvalConsumptionRuntime
	GeneratedSpecApproval *generatedSpecApprovalRuntime
	// ControlPlaneIdentity is nil unless HELM_CP_IDENTITY_* is configured (ADR-0005).
	ControlPlaneIdentity *controlPlaneIdentity

	// --- Evidence ---
	Evidence          *evidence.DefaultExporter
	ReceiptStore      store.ReceiptStore
	ReceiptSigner     helmcrypto.Signer
	PrincipalBindings store.PrincipalBindingStore

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
	Guardian                       *guardian.Guardian
	CompanyActivationPublicKey     ed25519.PublicKey
	CompanyActivationEnvironmentID string

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
func NewServices(ctx context.Context, db *sql.DB, artStore artifacts.Store, logger *slog.Logger, dataDir, databaseMode string) (*Services, error) {
	dataDir = normalizedDataDir(dataDir)
	s := &Services{
		DataDir:           dataDir,
		DatabaseMode:      databaseMode,
		DatabaseStatus:    "unknown",
		SQLitePath:        filepath.Join(dataDir, "helm.db"),
		ArtifactStorePath: filepath.Join(dataDir, "artifacts"),
		LaunchpadStore:    launchsession.NewStore(launchpadStoreRoot(dataDir)),
		AuditStore:        store.NewAuditStore(),
	}

	// --- 1. Config ---
	s.Config = config.Load()
	activationPublicKey, err := configuredCompanyActivationPublicKey()
	if err != nil {
		return nil, err
	}
	organizationRuntimeKey, err := configuredOrganizationRuntimeAPIKey()
	if err != nil {
		return nil, err
	}
	if err := validateCompanyActivationRuntimeConfiguration(activationPublicKey, organizationRuntimeKey); err != nil {
		return nil, err
	}
	s.CompanyActivationPublicKey = activationPublicKey
	s.CompanyActivationEnvironmentID, err = configuredCompanyActivationEnvironmentID()
	if err != nil {
		return nil, err
	}
	logger.Info("subsystem ready", "component", " Config loaded")

	// --- 2. Observability ---
	// Keep tracing inert unless an OTLP endpoint is explicitly configured, but
	// still initialize the local Prometheus provider when the scrape surface is
	// enabled. Without this distinction HELM_METRICS_ENABLED only exposed the
	// bounded governance counters and omitted RED/go/process families.
	if endpoint, insecure := otlpEndpointFromEnv(); !shouldInitializeObservability(endpoint) {
		logger.Info("Observability init skipped (no OTLP endpoint configured)")
	} else {
		obsCfg := observability.DefaultConfig()
		obsCfg.OTLPEndpoint = endpoint
		metricsExporter := observability.MetricsExporterNone
		if configured, exporterErr := metricsExporterFromEnv(); exporterErr != nil {
			logger.Warn("Invalid OTEL_METRICS_EXPORTER; OTLP metric push disabled", "error", exporterErr)
		} else {
			metricsExporter = configured
		}
		if endpoint == "" && metricsExporter == observability.MetricsExporterOTLP {
			logger.Warn("OTEL_METRICS_EXPORTER=otlp requires an OTLP endpoint; metric push disabled")
			metricsExporter = observability.MetricsExporterNone
		}
		obsCfg.MetricsExporter = metricsExporter
		if insecure {
			obsCfg.Insecure = true
		}
		obs, err := observability.New(ctx, obsCfg)
		if err != nil {
			logger.Warn("Observability init failed", "error", err)
		} else {
			s.Observability = obs
			logger.Info("subsystem ready", "component", " Observability provider initialized")
		}
	}

	// --- 3. Authorization ---
	s.Authz = authz.NewEngine()
	logger.Info("subsystem ready", "component", " ReBAC Authorization Engine initialized")

	// --- 3.5 Scoped emergency-stop fences ---
	if !emergencyStopFenceEnabled() {
		logger.Info("Scoped emergency-stop fences disabled")
	} else {
		if _, err := configuredEmergencyStopCommandVerifier(); err != nil {
			return nil, fmt.Errorf("scoped emergency-stop fence command authority: %w", err)
		}
		if db == nil {
			return nil, fmt.Errorf("scoped emergency-stop fence requires a durable database")
		}
		var stopOptions []kernel.ScopedStopStoreOption
		if databaseMode == "postgres" {
			stopOptions = append(stopOptions, kernel.WithPostgresScopeLocks())
		}
		emergencyStops := kernel.NewScopedStopStore(db, time.Now, stopOptions...)
		if databaseMode != "postgres" {
			if err := emergencyStops.Init(ctx); err != nil {
				return nil, fmt.Errorf("init scoped emergency-stop store: %w", err)
			}
		}
		s.EmergencyStops = emergencyStops
		logger.Info("subsystem ready", "component", " Scoped emergency-stop fence store initialized")
	}

	// --- 4. Credentials (CRED-001: KMS-backed key management) ---
	keyManager, kmsErr := openCredentialKeystore(dataDir)
	if kmsErr != nil {
		logger.Warn("KMS init failed — credentials store DISABLED", "error", kmsErr)
	} else {
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
	wasiSandbox, err := sandbox.NewWasiSandboxWithVerifier(ctx, artStore, sandboxConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox init: %w", err)
	}
	s.Sandbox = wasiSandbox
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
	var (
		surfaces   *boundary.SurfaceRegistry
		surfaceErr error
	)
	if databaseMode == "postgres" {
		surfaces, surfaceErr = boundary.NewRuntimeSQLSurfaceRegistry(ctx, db, time.Now)
	} else {
		surfaces, surfaceErr = boundary.NewSQLSurfaceRegistry(ctx, db, databaseMode, time.Now)
	}
	if surfaceErr != nil {
		return nil, fmt.Errorf("boundary surface registry persistence: %w", surfaceErr)
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
	evidenceKey, evidenceKeyPath, err := evidenceSigningSeed(dataDir)
	if err != nil {
		return nil, err
	}
	// evidenceKey is a signing seed, not a key id. It previously reached
	// NewEd25519Signer, which discarded it and generated a random keypair, so
	// the HELM_PRODUCTION guard on this value protected nothing and no exported
	// evidence pack was verifiable after a restart (F-01).
	evidenceSigner, evidenceKeyDerived, err := helmcrypto.NewEd25519SignerFromSecret(evidenceKey, "helm-evidence-bundle")
	if err != nil {
		return nil, fmt.Errorf("evidence signer init: %w", err)
	}
	if evidenceKeyDerived {
		logger.Warn("EVIDENCE_SIGNING_KEY is not a 32-byte hex/base64 seed — deriving one by hashing it; " +
			"supply a generated seed for production")
	}
	if evidenceKeyPath != "" {
		logger.Warn("EVIDENCE_SIGNING_KEY not set — signing evidence with this install's generated key; "+
			"configure an explicit key for production", "path", evidenceKeyPath, "public_key", evidenceSigner.PublicKey())
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

// metricsExporterFromEnv resolves the explicit OTLP metric push switch. The
// trace endpoint is intentionally independent: an endpoint alone still
// enables traces, while metrics remain scrape-only unless this is set to
// "otlp".
func metricsExporterFromEnv() (string, error) {
	value := strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER"))
	switch value {
	case "":
		return observability.MetricsExporterNone, nil
	case observability.MetricsExporterNone, observability.MetricsExporterOTLP:
		return value, nil
	default:
		return "", fmt.Errorf("OTEL_METRICS_EXPORTER must be %q or %q, got %q", observability.MetricsExporterNone, observability.MetricsExporterOTLP, value)
	}
}

func shouldInitializeObservability(endpoint string) bool {
	return strings.TrimSpace(endpoint) != "" || envBool("HELM_METRICS_ENABLED")
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

// openCredentialKeystore opens the keystore that seals stored provider
// credentials. A legacy CREDENTIALS_ENCRYPTION_KEY seeds a new keystore as
// version 0, or is imported into an existing one for decryption only. It never
// re-pins the active version, so a rotation survives restarts (16-02).
func openCredentialKeystore(dataDir string) (*kms.LocalKMS, error) {
	path := kmsKeystorePath(dataDir)
	legacyHex := os.Getenv("CREDENTIALS_ENCRYPTION_KEY")
	if legacyHex == "" {
		return kms.NewLocalKMS(path)
	}
	legacy, err := hex.DecodeString(legacyHex)
	if err != nil || len(legacy) != 32 {
		return nil, errors.New("CREDENTIALS_ENCRYPTION_KEY must be 64 hex characters (32 bytes)")
	}
	return kms.NewLocalKMSWithLegacyKey(path, legacy)
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

// publishedEvidenceSeeds are literals that shipped as defaults in the binary,
// compose file and smoke scripts. Their private keys are derivable by anyone,
// so evidence signed under them proves nothing (C-02).
var publishedEvidenceSeeds = []string{"helm-evidence-bundle", "helm-evidence-dev", "helm-evidence-smoke"}

// evidenceSigningSeed returns the evidence signing secret. EVIDENCE_SIGNING_KEY
// wins; the Helm chart sets it from a random per-install Secret. Without it a
// production process refuses to start, and any other process uses a random
// seed generated once and kept at <dataDir>/evidence.key, whose path is
// returned. Every install therefore has its own key, stable across restarts.
func evidenceSigningSeed(dataDir string) (seed, persistedAt string, err error) {
	seed = strings.TrimSpace(os.Getenv("EVIDENCE_SIGNING_KEY"))
	if slices.Contains(publishedEvidenceSeeds, seed) {
		return "", "", fmt.Errorf("EVIDENCE_SIGNING_KEY is the published default %q, whose private key anyone can derive; unset it to use a generated per-install key, or supply a generated 32-byte seed", seed)
	}
	if seed != "" {
		return seed, "", nil
	}
	if envBool("HELM_PRODUCTION") {
		return "", "", fmt.Errorf("production mode requires EVIDENCE_SIGNING_KEY")
	}
	persistedAt = filepath.Join(dataDir, "evidence.key")
	seed, err = loadOrCreateSeedFile(persistedAt)
	if err != nil {
		return "", "", err
	}
	return seed, persistedAt, nil
}

// loadOrCreateSeedFile reads a hex-encoded 32-byte secret from path, or
// creates the file with a random one. It backs every per-install secret: the
// evidence seed and the generated admin/service API keys. Creation is
// exclusive, so two processes starting on one data dir cannot overwrite each
// other's secret.
func loadOrCreateSeedFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return "", fmt.Errorf("generate %s: %w", path, err)
		}
		encoded := hex.EncodeToString(seed)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateSeedFile(path)
		}
		if err != nil {
			return "", fmt.Errorf("create %s: %w", path, err)
		}
		_, err = f.WriteString(encoded)
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("write %s: %w", path, err)
		}
		return encoded, nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("%s is accessible to other users (mode %o); expected 600", path, info.Mode().Perm())
	}
	seed := strings.TrimSpace(string(data))
	if raw, err := hex.DecodeString(seed); err != nil || len(raw) != ed25519.SeedSize {
		return "", fmt.Errorf("%s does not hold a hex 32-byte secret; restore it from backup", path)
	}
	return seed, nil
}

// otlpEndpointFromEnv returns the OTLP gRPC target from the standard
// OTEL_EXPORTER_OTLP_ENDPOINT variable, or "" when unset. The env value may
// carry a URL scheme; the gRPC exporters want host:port, and an explicit
// http:// scheme means a plaintext collector, so it must flip the connection
// to insecure rather than be silently dropped.
func otlpEndpointFromEnv() (endpoint string, insecure bool) {
	endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	endpoint, insecure = strings.CutPrefix(endpoint, "http://")
	if !insecure {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}
	// URL forms may carry a path/query; the gRPC exporters want pure host:port.
	if host, _, ok := strings.Cut(endpoint, "/"); ok {
		endpoint = host
	}
	return endpoint, insecure
}
