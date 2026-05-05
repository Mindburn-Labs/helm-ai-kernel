// Package benchmarks contains the HELM hot-path overhead benchmark harness.
//
// This measures the incremental latency HELM adds versus direct execution
// for governed tool calls. The hot path is:
//
//	Guardian.EvaluateDecision → crypto.SignReceipt → store.Append
//
// Run: cd core && go test -bench=. -benchmem -count=5 ./benchmarks/
package benchmarks

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"

	_ "modernc.org/sqlite"
)

// ── Harness helpers ──

type benchHarness struct {
	guardian *guardian.Guardian
	signer   crypto.Signer
	store    *store.SQLiteReceiptStore
	db       *sql.DB
}

func newHarness(tb testing.TB) *benchHarness {
	tb.Helper()

	signer, err := crypto.NewEd25519Signer("bench-key")
	if err != nil {
		tb.Fatal(err)
	}

	graph := prg.NewGraph()
	_ = graph.AddRule("safe-tool", prg.RequirementSet{
		ID:    "allow-safe",
		Logic: prg.AND,
	})

	g := guardian.NewGuardian(signer, graph, nil)

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		tb.Fatal(err)
	}
	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")

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
		// 1. Guardian evaluates
		decision, err := h.guardian.EvaluateDecision(ctx, guardian.DecisionRequest{
			Principal: "bench-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
			Context:   map[string]interface{}{"key": "value"},
		})
		if err != nil {
			b.Fatal(err)
		}
		if decision.Verdict != "ALLOW" {
			b.Fatalf("expected ALLOW, got %s: %s", decision.Verdict, decision.Reason)
		}

		// 2. Sign receipt
		receipt := &contracts.Receipt{
			ReceiptID:    fmt.Sprintf("rcpt-%d", i),
			DecisionID:   decision.ID,
			EffectID:     fmt.Sprintf("eff-%d", i),
			Status:       "EXECUTED",
			OutputHash:   "sha256:mock-output",
			PrevHash:     "sha256:genesis",
			LamportClock: uint64(i),
			ArgsHash:     "sha256:mock-args",
			Timestamp:    time.Now(),
		}
		if err := h.signer.SignReceipt(receipt); err != nil {
			b.Fatal(err)
		}

		// 3. Persist receipt
		if err := h.store.Store(ctx, receipt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHotPath_Allow_Parallel measures governed allow under concurrency.
func BenchmarkHotPath_Allow_Parallel(b *testing.B) {
	h := newHarness(b)
	defer h.close()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		i := 0
		for pb.Next() {
			decision, err := h.guardian.EvaluateDecision(ctx, guardian.DecisionRequest{
				Principal: "bench-agent",
				Action:    "EXECUTE_TOOL",
				Resource:  "safe-tool",
				Context:   map[string]interface{}{"key": "value"},
			})
			if err != nil {
				b.Fatal(err)
			}

			receipt := &contracts.Receipt{
				ReceiptID:    fmt.Sprintf("rcpt-par-%d-%d", time.Now().UnixNano(), i),
				DecisionID:   decision.ID,
				EffectID:     fmt.Sprintf("eff-par-%d", i),
				Status:       "EXECUTED",
				OutputHash:   "sha256:mock-output",
				PrevHash:     "sha256:genesis",
				LamportClock: uint64(i),
				Timestamp:    time.Now(),
			}
			_ = h.signer.SignReceipt(receipt)
			_ = h.store.Store(ctx, receipt)
			i++
		}
	})
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
		decision, err := h.guardian.EvaluateDecision(context.Background(), guardian.DecisionRequest{
			Principal: "bench-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "undeclared-tool",
			Context:   map[string]interface{}{"key": "value"},
		})
		if err != nil {
			b.Fatal(err)
		}
		if decision.Verdict != "DENY" {
			b.Fatalf("expected DENY, got %s", decision.Verdict)
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
		_, _ = h.guardian.EvaluateDecision(context.Background(), guardian.DecisionRequest{
			Principal: "bench-agent",
			Action:    "EXECUTE_TOOL",
			Resource:  "safe-tool",
			Context:   map[string]interface{}{"key": "value"},
		})
	}
}

// ── Scenario 5: Isolated CEL policy evaluation ──

// BenchmarkPolicyEval_CEL_Only measures pure CEL expression evaluation
// with a pre-compiled, cached program. This is the direct apples-to-apples
// comparison to Microsoft Agent Governance Toolkit's claimed 12µs/rule.
func BenchmarkPolicyEval_CEL_Only(b *testing.B) {
	engine, err := prg.NewPolicyEngine()
	if err != nil {
		b.Fatal(err)
	}

	expression := `input["action"] == "EXECUTE_TOOL" && input["risk_level"] < 3`
	// PolicyEngine.Evaluate passes its argument directly as the CEL activation,
	// so we must wrap the data in an "input" key matching the CEL variable name.
	activation := map[string]interface{}{
		"input": map[string]interface{}{
			"action":     "EXECUTE_TOOL",
			"risk_level": int64(2),
			"principal":  "bench-agent",
			"resource":   "safe-tool",
		},
	}

	// Pre-warm: compile and cache the expression
	result, err := engine.Evaluate(expression, activation)
	if err != nil {
		b.Fatal(err)
	}
	if !result {
		b.Fatal("expected true from pre-warm evaluation")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Evaluate(expression, activation)
	}
}

// BenchmarkPolicyEval_Throughput measures concurrent CEL evaluation throughput.
// Use the result to compute ops/sec: b.N / b.Elapsed().Seconds().
// Direct comparison to Microsoft Agent Governance Toolkit's claimed 72K ops/sec.
func BenchmarkPolicyEval_Throughput(b *testing.B) {
	engine, err := prg.NewPolicyEngine()
	if err != nil {
		b.Fatal(err)
	}

	expression := `input["action"] == "EXECUTE_TOOL" && input["risk_level"] < 3`
	activation := map[string]interface{}{
		"input": map[string]interface{}{
			"action":     "EXECUTE_TOOL",
			"risk_level": int64(2),
			"principal":  "bench-agent",
			"resource":   "safe-tool",
		},
	}

	// Pre-warm
	if _, err := engine.Evaluate(expression, activation); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = engine.Evaluate(expression, activation)
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

	// Set up isolated CEL engine for policy eval scenarios
	celEngine, err := prg.NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	celExpr := `input["action"] == "EXECUTE_TOOL" && input["risk_level"] < 3`
	// PolicyEngine.Evaluate passes its argument directly as the CEL activation,
	// so we must wrap the data in an "input" key matching the CEL variable name.
	celInput := map[string]interface{}{
		"input": map[string]interface{}{
			"action":     "EXECUTE_TOOL",
			"risk_level": int64(2),
			"principal":  "bench-agent",
			"resource":   "safe-tool",
		},
	}
	// Pre-warm CEL cache
	if _, err := celEngine.Evaluate(celExpr, celInput); err != nil {
		t.Fatal(err)
	}

	// Measure each scenario with explicit timing
	scenarios := []struct {
		name string
		fn   func(*benchHarness) time.Duration
	}{
		{"baseline_no_helm", func(h *benchHarness) time.Duration {
			start := time.Now()
			req := map[string]any{"tool": "safe-tool", "args": map[string]string{"key": "value"}}
			_, _ = json.Marshal(req)
			resp := map[string]any{"result": "success"}
			_, _ = json.Marshal(resp)
			return time.Since(start)
		}},
		{"helm_allow", func(h *benchHarness) time.Duration {
			ctx := context.Background()
			start := time.Now()
			decision, _ := h.guardian.EvaluateDecision(ctx, guardian.DecisionRequest{
				Principal: "agent", Action: "EXECUTE_TOOL", Resource: "safe-tool",
				Context: map[string]interface{}{"key": "value"},
			})
			receipt := &contracts.Receipt{
				ReceiptID:  fmt.Sprintf("rcpt-%d", start.UnixNano()),
				DecisionID: decision.ID, EffectID: "eff-1", Status: "EXECUTED",
				OutputHash: "sha256:out", PrevHash: "sha256:prev",
				LamportClock: 1, Timestamp: time.Now(),
			}
			_ = h.signer.SignReceipt(receipt)
			_ = h.store.Store(ctx, receipt)
			return time.Since(start)
		}},
		{"helm_deny", func(h *benchHarness) time.Duration {
			// Guardian deny evaluation only — no receipt signing/store in deny path.
			// This is correct: deny decisions are fail-closed at the Guardian boundary.
			start := time.Now()
			_, _ = h.guardian.EvaluateDecision(context.Background(), guardian.DecisionRequest{
				Principal: "agent", Action: "EXECUTE_TOOL", Resource: "undeclared-tool",
				Context: map[string]interface{}{"key": "value"},
			})
			return time.Since(start)
		}},
		{"cel_eval_only", func(_ *benchHarness) time.Duration {
			start := time.Now()
			_, _ = celEngine.Evaluate(celExpr, celInput)
			return time.Since(start)
		}},
		{"ed25519_sign_only", func(h *benchHarness) time.Duration {
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
			_ = h.signer.SignReceipt(receipt)
			return time.Since(start)
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
			sc.fn(h)
		}

		// Measure
		for i := 0; i < iterations; i++ {
			durations[i] = float64(sc.fn(h).Microseconds())
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
					_, _ = celEngine.Evaluate(celExpr, celInput)
					localCount++
				}
				counts[idx] = localCount
			}(w)
		}
		wg.Wait()
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
		"helm_version": "0.4.0",
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

	// Competitive comparison: isolated component benchmarks vs Microsoft Agent Governance Toolkit
	competitiveComparison := map[string]any{
		"microsoft_agent_os": map[string]any{
			"claimed_policy_eval_us":     12,
			"claimed_throughput_ops_sec": 72000,
		},
	}
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
	competitiveComparison["helm"] = helmMetrics
	report["competitive_comparison"] = competitiveComparison

	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	// Write to benchmarks/results/
	outDir := filepath.Join("..", "benchmarks", "results")
	_ = os.MkdirAll(outDir, 0750)
	outPath := filepath.Join(outDir, "latest.json")
	if err := os.WriteFile(outPath, reportJSON, 0644); err != nil {
		t.Logf("Warning: could not write report to %s: %v", outPath, err)
	} else {
		t.Logf("Report written to %s", outPath)
	}

	t.Log(string(reportJSON))
}
