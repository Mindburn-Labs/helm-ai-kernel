// quantum_posture: standalone MCP reuses the kernel receipt.v5 signer and
// verifier; local root files do not provide protected key custody.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// localMCPRuntime owns only the standalone listener's local receipt database
// and stop-fence handle. It does not implement the Postgres gateway ledger.
type localMCPRuntime struct {
	catalog   *mcppkg.ToolCatalog
	executor  mcppkg.GovernedExecutor
	db        *sql.DB
	fence     *standaloneEmergencyStopFence
	closeOnce sync.Once
	closeErr  error
}

func (r *localMCPRuntime) Close() error {
	r.closeOnce.Do(func() { r.closeErr = errors.Join(r.db.Close(), r.fence.Close()) })
	return r.closeErr
}

func openLocalMCPRuntime(dataDir string, graph *prg.Graph) (_ *localMCPRuntime, err error) {
	dataDir = normalizedDataDir(dataDir)
	if err := preflightMCPReceiptKeyFiles(dataDir); err != nil {
		return nil, err
	}
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	if err := ensureMCPReceiptPublicKey(dataDir, signer); err != nil {
		return nil, err
	}
	effects, err := newGitHubEffectsRuntimeFromEnv(dataDir)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "helm.db"))
	if err != nil {
		return nil, fmt.Errorf("open local MCP receipt database: %w", err)
	}
	runtime := &localMCPRuntime{db: db}
	defer func() {
		if err != nil {
			_ = runtime.Close()
		}
	}()
	receipts, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		return nil, fmt.Errorf("initialize local MCP receipts: %w", err)
	}
	// Admission must reach stable local storage before the tool handler runs.
	// SQLiteReceiptStore selects one connection; FULL synchronizes WAL commits.
	if _, err = db.Exec("PRAGMA synchronous=FULL"); err != nil {
		return nil, fmt.Errorf("configure durable local MCP receipts: %w", err)
	}
	runtime.fence, err = openStandaloneEmergencyStopFence(context.Background(), dataDir)
	if err != nil {
		return nil, err
	}
	if graph == nil {
		graph = prg.NewGraph()
	}
	guard, err := newProductionGuardian(signer, graph, nil, utcRuntimeClock{}, runtime.fence.guardianState(dataDir))
	if err != nil {
		return nil, fmt.Errorf("initialize local MCP production Guardian: %w", err)
	}
	evaluator := &receiptPersistingEvaluator{
		svc:   &Services{DataDir: dataDir, ReceiptStore: receipts, ReceiptSigner: signer},
		inner: guard,
	}
	runtime.catalog, runtime.executor, err = newLocalMCPRuntimeWithEvaluatorAndEffects(evaluator, effects)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

// Inspect before invoking the shared generator: it writes a new public key
// when no private key exists. A retained anchor makes that a recovery error,
// not a new installation. Reject irregular files and malformed seed lengths
// before the shared loader can follow links or panic on an invalid seed.
func preflightMCPReceiptKeyFiles(dataDir string) error {
	key, keyErr := os.Lstat(filepath.Join(dataDir, "root.key"))
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return fmt.Errorf("inspect MCP receipt private key: %w", keyErr)
	}
	if keyErr == nil && (!key.Mode().IsRegular() || key.Size() != 64) {
		return fmt.Errorf("MCP receipt private key must be a regular file containing a 32-byte hex seed")
	}
	pub, pubErr := os.Lstat(filepath.Join(dataDir, "root.pub"))
	if pubErr != nil && !errors.Is(pubErr, os.ErrNotExist) {
		return fmt.Errorf("inspect MCP receipt public key: %w", pubErr)
	}
	if pubErr == nil {
		if !pub.Mode().IsRegular() {
			return fmt.Errorf("MCP receipt public key must be a regular file")
		}
		if errors.Is(keyErr, os.ErrNotExist) {
			return fmt.Errorf("MCP receipt private key is missing for the retained public anchor; restore the matching root.key")
		}
	}
	return nil
}

// A public key is an independently retainable trust anchor. Do not silently
// replace a mismatched anchor on restart; that would conceal a key change.
func ensureMCPReceiptPublicKey(dataDir string, signer helmcrypto.Signer) error {
	path := filepath.Join(dataDir, "root.pub")
	expected := hex.EncodeToString(signer.PublicKeyBytes())
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeNewFile(path, []byte(expected+"\n"), 0644); err != nil {
			return fmt.Errorf("export MCP receipt public key: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect MCP receipt public key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("MCP receipt public key must be a regular file")
	}
	actual, err := os.ReadFile(path) // #nosec G304 -- fixed public-anchor filename under operator-selected data directory; contents are compared, never disclosed
	if err != nil {
		return fmt.Errorf("read MCP receipt public key: %w", err)
	}
	if strings.TrimSpace(string(actual)) != expected {
		return fmt.Errorf("MCP receipt public key does not match the configured signer")
	}
	return nil
}

// ReceiptIDForDecision is called only after EvaluateDecision successfully
// persisted the same decision, including portable evidence export. It derives
// the writer's existing identifier without inventing another receipt envelope.
func (e *receiptPersistingEvaluator) ReceiptIDForDecision(ctx context.Context, decision *contracts.DecisionRecord) string {
	principal, err := helmauth.GetPrincipal(ctx)
	if err != nil || principal == nil || decision == nil || strings.TrimSpace(principal.GetTenantID()) == "" {
		return ""
	}
	return executor.ReceiptIDForDecision(strings.TrimSpace(principal.GetTenantID()), decision.ID)
}
