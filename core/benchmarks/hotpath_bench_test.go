// Package benchmarks contains the HELM hot-path overhead benchmark harness.
//
// This measures the incremental latency HELM adds versus direct execution
// for governed tool calls. The hot path is:
//
//	Guardian.EvaluateDecision → crypto.SignReceipt → store.Store
//
// Run: cd core && go test -bench=. -benchmem -count=5 ./benchmarks/
package benchmarks

// quantum_posture: benchmarks time classical Ed25519 receipt signing; harness
// tests check persisted signatures, with no post-quantum security claim.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

// ── Harness helpers ──

type benchHarness struct {
	guardian *guardian.Guardian
	signer   crypto.Signer
	store    *store.SQLiteReceiptStore
	db       *sql.DB
}

func benchHelmVersion() string {
	if version := strings.TrimSpace(os.Getenv("HELM_VERSION")); version != "" {
		return strings.TrimPrefix(version, "v")
	}
	for _, candidate := range []string{
		filepath.Join("..", "..", "VERSION"),
		filepath.Join("..", "VERSION"),
		"VERSION",
	} {
		raw, err := os.ReadFile(candidate)
		if err == nil {
			if version := strings.TrimSpace(string(raw)); version != "" {
				return strings.TrimPrefix(version, "v")
			}
		}
	}
	return "unknown"
}

func newHarness(tb testing.TB) *benchHarness {
	tb.Helper()

	signer, err := crypto.NewEd25519Signer("bench-key")
	if err != nil {
		tb.Fatal(err)
	}

	graph := prg.NewGraph()
	if err := graph.AddRule("safe-tool", prg.RequirementSet{
		ID:    "allow-safe",
		Logic: prg.AND,
	}); err != nil {
		tb.Fatal(err)
	}

	g := guardian.NewGuardian(signer, graph, nil)

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL"} {
		if _, err := db.Exec(pragma); err != nil {
			tb.Fatal(err)
		}
	}

	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		tb.Fatal(err)
	}

	return &benchHarness{
		guardian: g,
		signer:   signer,
		store:    receiptStore,
		db:       db,
	}
}

func (h *benchHarness) close() {
	_ = h.db.Close()
}

// evaluate checks the verdict as well as the error so a denied fixture cannot
// silently become a successful allow-path timing.
func (h *benchHarness) evaluate(ctx context.Context, resource, verdict string) (*contracts.DecisionRecord, error) {
	decision, err := h.guardian.EvaluateDecision(ctx, guardian.DecisionRequest{
		Principal: "bench-agent",
		Action:    "EXECUTE_TOOL",
		Resource:  resource,
		Context:   map[string]interface{}{"key": "value"},
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate decision: %w", err)
	}
	if decision.Verdict != verdict {
		return nil, fmt.Errorf("expected %s, got %s: %s", verdict, decision.Verdict, decision.Reason)
	}
	return decision, nil
}

// allow measures the same evaluated, bound, signed and stored receipt in the
// serial benchmark, parallel benchmark and percentile report.
func (h *benchHarness) allow(ctx context.Context, sequence uint64) error {
	decision, err := h.evaluate(ctx, "safe-tool", "ALLOW")
	if err != nil {
		return err
	}
	decisionHash, err := crypto.DecisionSemanticHash(decision)
	if err != nil {
		return fmt.Errorf("hash decision: %w", err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:    fmt.Sprintf("rcpt-%d", sequence),
		DecisionID:   decision.ID,
		DecisionHash: decisionHash,
		EffectID:     fmt.Sprintf("eff-%d", sequence),
		Status:       "EXECUTED",
		OutputHash:   "sha256:mock-output",
		PrevHash:     "sha256:genesis",
		LamportClock: sequence,
		ArgsHash:     "sha256:mock-args",
		Timestamp:    time.Now(),
	}
	if err := h.signer.SignReceipt(receipt); err != nil {
		return fmt.Errorf("sign receipt: %w", err)
	}
	if err := h.store.Store(ctx, receipt); err != nil {
		return fmt.Errorf("store receipt: %w", err)
	}
	return nil
}

// Check the durable row count outside the timed interval. These fixtures time
// independent receipt writes, not construction of a valid causal chain.
func (h *benchHarness) assertReceiptCount(tb testing.TB, want int) {
	tb.Helper()
	var got int
	if err := h.db.QueryRow("SELECT COUNT(*) FROM receipts").Scan(&got); err != nil {
		tb.Fatal(err)
	}
	if got != want {
		tb.Fatalf("persisted %d receipts, want %d", got, want)
	}
}

// ── Scenario 1: Direct baseline (no HELM in path) ──

// BenchmarkBaseline_NoHELM measures the cost of a mock tool execution
// with zero governance overhead. This is the baseline for overhead calculation.
func BenchmarkBaseline_NoHELM(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Simulate: marshal request, execute mock tool, marshal response
		req := map[string]any{
			"tool": "safe-tool",
			"args": map[string]string{"key": "value"},
		}
		_, _ = json.Marshal(req)
		resp := map[string]any{
			"result": "success",
			"data":   "benchmark-output",
		}
		_, _ = json.Marshal(resp)
	}
}

// ── Scenario 2: HELM pass-through allow ──

// BenchmarkHotPath_Allow measures the full governed allow path:
// Guardian.EvaluateDecision → SignReceipt → SQLite Store
func BenchmarkHotPath_Allow(b *testing.B) {
	h := newHarness(b)
	defer h.close()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := h.allow(ctx, uint64(i)); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	h.assertReceiptCount(b, b.N)
}

// BenchmarkHotPath_Allow_Parallel measures governed allow under concurrency.
func BenchmarkHotPath_Allow_Parallel(b *testing.B) {
	h := newHarness(b)
	defer h.close()
	var sequence atomic.Uint64
	var firstError error
	var errorOnce sync.Once

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			if err := h.allow(ctx, sequence.Add(1)); err != nil {
				errorOnce.Do(func() { firstError = err })
				return
			}
		}
	})
	b.StopTimer()
	if firstError != nil {
		b.Fatal(firstError)
	}
	h.assertReceiptCount(b, b.N)
}

// ── Scenario 3: HELM deny (undeclared tool) ──

// BenchmarkHotPath_Deny measures the cost of a governed deny path.
// The Guardian should deny and sign the deny decision.
func BenchmarkHotPath_Deny(b *testing.B) {
	h := newHarness(b)
	defer h.close()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.evaluate(context.Background(), "undeclared-tool", "DENY"); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Scenario 4: Guardian eval only (isolated) ──

// BenchmarkGuardian_EvalOnly isolates Guardian decision evaluation
// without receipt signing or store persistence.
func BenchmarkGuardian_EvalOnly(b *testing.B) {
	h := newHarness(b)
	defer h.close()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.evaluate(context.Background(), "safe-tool", "ALLOW"); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Scenario 5: Isolated CEL policy evaluation ──

// celBenchPolicy compiles the one-rule authority snapshot the CEL-only
// scenarios decide against, and the input they decide on.
func celBenchPolicy(tb testing.TB) (*authority.Snapshot, authority.Input) {
	tb.Helper()
	graph := prg.NewGraph()
	if err := graph.AddRule("EXECUTE_TOOL", prg.RequirementSet{
		ID:           "bench-rule",
		Requirements: []prg.Requirement{{ID: "low-risk", Expression: `input["action"] == "EXECUTE_TOOL" && input["risk_level"] < 3`}},
	}); err != nil {
		tb.Fatal(err)
	}
	snapshot, err := authority.Compile(graph)
	if err != nil {
		tb.Fatal(err)
	}
	input := authority.Input{
		Action: "EXECUTE_TOOL",
		Attributes: map[string]any{
			"risk_level": 2,
			"principal":  "bench-agent",
			"resource":   "safe-tool",
		},
		Time: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
	}
	if d := authority.Decide(input, snapshot); d.Verdict != contracts.VerdictAllow {
		tb.Fatalf("expected ALLOW from the warm-up decision, got %+v", d)
	}
	return snapshot, input
}

// BenchmarkPolicyEval_CEL_Only measures pure CEL expression evaluation
// with a pre-compiled, cached program. This is the direct apples-to-apples
// comparison to Microsoft Agent Governance Toolkit's claimed 12µs/rule.
func BenchmarkPolicyEval_CEL_Only(b *testing.B) {
	snapshot, input := celBenchPolicy(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if d := authority.Decide(input, snapshot); d.Verdict != contracts.VerdictAllow {
			b.Fatalf("CEL expected ALLOW, got %+v", d)
		}
	}
}

// BenchmarkPolicyEval_Throughput measures concurrent CEL evaluation throughput.
// Use the result to compute ops/sec: b.N / b.Elapsed().Seconds().
// Direct comparison to Microsoft Agent Governance Toolkit's claimed 72K ops/sec.
func BenchmarkPolicyEval_Throughput(b *testing.B) {
	snapshot, input := celBenchPolicy(b)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if d := authority.Decide(input, snapshot); d.Verdict != contracts.VerdictAllow {
				b.Errorf("CEL expected ALLOW, got %+v", d)
				return
			}
		}
	})
}

// ── Scenario 6: Isolated Ed25519 signing ──

// BenchmarkEd25519_SignOnly measures pure Ed25519 receipt signing
// without Guardian evaluation or store persistence. This isolates the
// cryptographic overhead that is included in HELM's full path but absent
// from competitors that skip signing.
func BenchmarkEd25519_SignOnly(b *testing.B) {
	signer, err := crypto.NewEd25519Signer("bench-key")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		receipt := &contracts.Receipt{
			ReceiptID:    fmt.Sprintf("rcpt-%d", i),
			DecisionID:   "decision-bench",
			EffectID:     fmt.Sprintf("eff-%d", i),
			Status:       "EXECUTED",
			OutputHash:   "sha256:mock-output",
			PrevHash:     "sha256:genesis",
			LamportClock: uint64(i),
			ArgsHash:     "sha256:mock-args",
			Timestamp:    time.Now(),
		}
		if err := signer.SignReceipt(receipt); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Composite overhead measurement ──

// TestOverheadReport runs all scenarios and writes a structured JSON report
// measuring HELM's incremental overhead vs direct execution.
//
// Run: go test -v -run TestOverheadReport -count=1 ./benchmarks/
func TestOverheadReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping overhead report in short mode")
	}

	// Compile the policy for the isolated CEL scenario once, as activation does.
	celSnapshot, celInput := celBenchPolicy(t)

	// Measure each scenario with explicit timing
	scenarios := []struct {
		name string
		fn   func(*benchHarness, uint64) (time.Duration, error)
	}{
		{"baseline_no_helm", func(h *benchHarness, sequence uint64) (time.Duration, error) {
			start := time.Now()
			req := map[string]any{"tool": "safe-tool", "args": map[string]string{"key": "value"}}
			_, _ = json.Marshal(req)
			resp := map[string]any{"result": "success"}
			_, _ = json.Marshal(resp)
			return time.Since(start), nil
		}},
		{"helm_allow", func(h *benchHarness, sequence uint64) (time.Duration, error) {
			start := time.Now()
			err := h.allow(context.Background(), sequence)
			return time.Since(start), err
		}},
		{"helm_deny", func(h *benchHarness, _ uint64) (time.Duration, error) {
			start := time.Now()
			_, err := h.evaluate(context.Background(), "undeclared-tool", "DENY")
			return time.Since(start), err
		}},
		{"cel_eval_only", func(_ *benchHarness, _ uint64) (time.Duration, error) {
			start := time.Now()
			if d := authority.Decide(celInput, celSnapshot); d.Verdict != contracts.VerdictAllow {
				return 0, fmt.Errorf("CEL expected ALLOW, got %+v", d)
			}
			return time.Since(start), nil
		}},
		{"ed25519_sign_only", func(h *benchHarness, sequence uint64) (time.Duration, error) {
			receipt := &contracts.Receipt{
				ReceiptID:    fmt.Sprintf("rcpt-%d", time.Now().UnixNano()),
				DecisionID:   "decision-bench",
				EffectID:     "eff-bench",
				Status:       "EXECUTED",
				OutputHash:   "sha256:mock-output",
				PrevHash:     "sha256:genesis",
				LamportClock: 1,
				ArgsHash:     "sha256:mock-args",
				Timestamp:    time.Now(),
			}
			start := time.Now()
			err := h.signer.SignReceipt(receipt)
			return time.Since(start), err
		}},
	}

	iterations := 10000
	h := newHarness(t)
	defer h.close()

	type ScenarioResult struct {
		Name       string  `json:"name"`
		Iterations int     `json:"iterations"`
		P50Us      float64 `json:"p50_us"`
		P95Us      float64 `json:"p95_us"`
		P99Us      float64 `json:"p99_us"`
		MeanUs     float64 `json:"mean_us"`
		StdDevUs   float64 `json:"stddev_us"`
		MinUs      float64 `json:"min_us"`
		MaxUs      float64 `json:"max_us"`
	}

	results := make([]ScenarioResult, 0, len(scenarios))

	for _, sc := range scenarios {
		durations := make([]float64, iterations)

		// Warm up
		for i := 0; i < 100; i++ {
			if _, err := sc.fn(h, uint64(i)); err != nil {
				t.Fatalf("%s warmup %d: %v", sc.name, i, err)
			}
		}

		// Measure
		for i := 0; i < iterations; i++ {
			duration, err := sc.fn(h, uint64(100+i))
			if err != nil {
				t.Fatalf("%s iteration %d: %v", sc.name, i, err)
			}
			durations[i] = float64(duration.Microseconds())
		}

		if sc.name == "helm_allow" {
			h.assertReceiptCount(t, 100+iterations)
		}

		sort.Float64s(durations)

		sum := 0.0
		for _, d := range durations {
			sum += d
		}
		mean := sum / float64(iterations)

		variance := 0.0
		for _, d := range durations {
			diff := d - mean
			variance += diff * diff
		}
		stddev := math.Sqrt(variance / float64(iterations))

		result := ScenarioResult{
			Name:       sc.name,
			Iterations: iterations,
			P50Us:      durations[iterations*50/100],
			P95Us:      durations[iterations*95/100],
			P99Us:      durations[iterations*99/100],
			MeanUs:     mean,
			StdDevUs:   stddev,
			MinUs:      durations[0],
			MaxUs:      durations[iterations-1],
		}
		results = append(results, result)

		t.Logf("%-25s p50=%8.1fµs  p95=%8.1fµs  p99=%8.1fµs  mean=%8.1fµs  σ=%6.1fµs",
			sc.name, result.P50Us, result.P95Us, result.P99Us, result.MeanUs, result.StdDevUs)
	}

	// Compute overhead
	if len(results) >= 2 {
		baseline := results[0]
		allow := results[1]
		overheadP99 := allow.P99Us - baseline.P99Us

		t.Logf("")
		t.Logf("=== OVERHEAD ANALYSIS ===")
		t.Logf("Baseline p99:         %8.1f µs", baseline.P99Us)
		t.Logf("HELM allow p99:       %8.1f µs", allow.P99Us)
		t.Logf("Incremental overhead: %8.1f µs", overheadP99)
		if baseline.P99Us > 0 {
			t.Logf("Ratio (allow/base):   %8.1fx", allow.P99Us/baseline.P99Us)
		}
		t.Logf("Overhead < 5ms:       %v", overheadP99 < 5000)
		threshold := 25000.0
		if raw := os.Getenv("HELM_BENCH_P99_OVERHEAD_US"); raw != "" {
			if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
				threshold = parsed
			}
		}
		if overheadP99 >= threshold {
			t.Fatalf("boundary hot-path p99 overhead %.1fµs exceeds threshold %.1fµs", overheadP99, threshold)
		}
	}

	// Measure CEL throughput (concurrent ops/sec)
	celThroughputOps := 0
	celThroughputDur := 2 * time.Second
	t.Logf("")
	t.Logf("=== CEL THROUGHPUT (concurrent, %v window) ===", celThroughputDur)
	{
		numWorkers := runtime.NumCPU()
		var wg sync.WaitGroup
		counts := make([]int, numWorkers)
		start := time.Now()
		deadline := start.Add(celThroughputDur)
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				localCount := 0
				for time.Now().Before(deadline) {
					if d := authority.Decide(celInput, celSnapshot); d.Verdict != contracts.VerdictAllow {
						t.Errorf("CEL expected ALLOW, got %+v", d)
						return
					}
					localCount++
				}
				counts[idx] = localCount
			}(w)
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		elapsed := time.Since(start)
		totalOps := 0
		for _, c := range counts {
			totalOps += c
		}
		celThroughputOps = int(float64(totalOps) / elapsed.Seconds())
		t.Logf("Workers: %d  Total ops: %d  Elapsed: %v  Throughput: %d ops/sec",
			numWorkers, totalOps, elapsed, celThroughputOps)
	}

	// Write JSON report
	report := map[string]any{
		"helm_version": benchHelmVersion(),
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"go_version":   runtime.Version(),
		"go_os":        runtime.GOOS,
		"go_arch":      runtime.GOARCH,
		"num_cpu":      runtime.NumCPU(),
		"scenarios":    results,
	}
	if len(results) >= 2 {
		threshold := 25000.0
		if raw := os.Getenv("HELM_BENCH_P99_OVERHEAD_US"); raw != "" {
			if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
				threshold = parsed
			}
		}
		report["hot_path_p99_us"] = results[1].P99Us
		report["baseline_p99_us"] = results[0].P99Us
		report["overhead_p99_us"] = results[1].P99Us - results[0].P99Us
		report["overhead_under_5ms"] = (results[1].P99Us - results[0].P99Us) < 5000
		report["p99_gate_us"] = threshold
		report["p99_gate_pass"] = (results[1].P99Us - results[0].P99Us) < threshold
	}

	// Isolated component measurements from this run.
	helmMetrics := map[string]any{
		"measured_throughput_ops_sec": celThroughputOps,
	}
	// Find cel_eval_only and ed25519_sign_only results
	for _, r := range results {
		switch r.Name {
		case "cel_eval_only":
			helmMetrics["measured_cel_eval_p99_us"] = r.P99Us
			helmMetrics["measured_cel_eval_mean_us"] = r.MeanUs
		case "ed25519_sign_only":
			helmMetrics["measured_signing_p99_us"] = r.P99Us
			helmMetrics["measured_signing_mean_us"] = r.MeanUs
		case "helm_allow":
			helmMetrics["measured_total_allow_p99_us"] = r.P99Us
		}
	}
	report["component_metrics"] = helmMetrics

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	// go test runs this package from core/benchmarks, so walk back to the
	// repository root before writing the generated benchmark report.
	outDir := filepath.Join("..", "..", "benchmarks", "results")
	if err := os.MkdirAll(outDir, 0750); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(outDir, "latest.json")
	if err := os.WriteFile(outPath, reportJSON, 0644); err != nil {
		t.Fatalf("write report to %s: %v", outPath, err)
	} else {
		t.Logf("Report written to %s", outPath)
	}

	t.Log(string(reportJSON))
}

// These checks establish that timing helpers cannot report rejected writes as
// completed operations. The benchmark's row-count assertion also runs after
// every serial and parallel benchmark, outside the measured interval.
func TestAllowHarnessPersistsBoundReceipt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.allow(ctx, 1); err != nil {
		t.Fatal(err)
	}
	r, err := h.store.GetByReceiptID(ctx, "rcpt-1")
	if err != nil {
		t.Fatal(err)
	}
	if r.DecisionHash == "" {
		t.Fatal("stored receipt has no decision binding")
	}
	valid, err := h.signer.(*crypto.Ed25519Signer).VerifyReceipt(r)
	if err != nil || !valid {
		t.Fatalf("stored receipt signature: valid=%v err=%v", valid, err)
	}
	h.assertReceiptCount(t, 1)
}

type rejectingReceiptSigner struct {
	crypto.Signer
	err error
}

func (s rejectingReceiptSigner) SignReceipt(*contracts.Receipt) error { return s.err }

func TestAllowHarnessRejectsFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("signing", func(t *testing.T) {
		h := newHarness(t)
		failure := errors.New("signer unavailable")
		h.signer = rejectingReceiptSigner{Signer: h.signer, err: failure}
		if err := h.allow(ctx, 1); !errors.Is(err, failure) {
			t.Fatalf("expected signing failure, got %v", err)
		}
		h.assertReceiptCount(t, 0)
	})
	t.Run("storage", func(t *testing.T) {
		h := newHarness(t)
		if err := h.allow(ctx, 1); err != nil {
			t.Fatal(err)
		}
		// A repeated receipt ID forces a real SQLite constraint failure.
		if err := h.allow(ctx, 1); err == nil || !strings.Contains(err.Error(), "store receipt:") {
			t.Fatalf("expected storage failure, got %v", err)
		}
		h.assertReceiptCount(t, 1)
	})
	t.Run("denied", func(t *testing.T) {
		h := newHarness(t)
		h.guardian = guardian.NewGuardian(h.signer, prg.NewGraph(), nil)
		if err := h.allow(ctx, 1); err == nil || !strings.Contains(err.Error(), "expected ALLOW, got DENY") {
			t.Fatalf("expected denied fixture failure, got %v", err)
		}
		h.assertReceiptCount(t, 0)
	})
}
