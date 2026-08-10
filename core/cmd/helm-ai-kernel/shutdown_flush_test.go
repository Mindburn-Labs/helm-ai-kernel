package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// countingExporter records how many spans actually reached an exporter, which
// is the only thing that distinguishes a flush that worked from one that
// returned without draining the queue.
type countingExporter struct {
	mu sync.Mutex
	n  int
}

func (e *countingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.n += len(spans)
	return nil
}

func (e *countingExporter) Shutdown(context.Context) error { return nil }

func (e *countingExporter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}

// recordingFlusher samples the context flushObservability builds — at call
// time, since the builder cancels it on return — then hands it to the real
// provider so the export outcome stays real.
type recordingFlusher struct {
	inner       *sdktrace.TracerProvider
	called      bool
	errAtCall   error
	hasDeadline bool
}

func (f *recordingFlusher) Shutdown(ctx context.Context) error {
	f.called = true
	f.errAtCall = ctx.Err()
	_, f.hasDeadline = ctx.Deadline()
	return f.inner.Shutdown(ctx)
}

// batchingTracerProvider mirrors the daemon's production span pipeline: a batch
// processor on the DefaultConfig BatchTimeout, so an ended span sits in the
// queue and reaches the exporter only if something drains it.
func batchingTracerProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
	)
}

func endOneSpan(tp *sdktrace.TracerProvider) {
	_, span := tp.Tracer("helm.test").Start(context.Background(), "in-flight-request")
	span.End()
}

// TestFlushObservabilityExportsAfterDrainConsumedBudget is the finding-2 guard.
//
// SIGTERM with one Console tailing /api/v1/receipts/tail (receipt_routes.go:178
// — the long-lived SSE route; there is no /api/v1/receipts/stream): that route
// is an unbounded SSE loop that exits only on request-context cancellation, and
// http.Server.Shutdown does not cancel in-flight request contexts — it waits. So
// the drain reliably burns the whole shared grace budget. Handing what is left
// to the span flush hands it a dead context, and sdktrace.TracerProvider.Shutdown
// returns ctx.Err() before it ever stops the span processor: zero spans
// exported, in precisely the shutdown the hook was added to capture.
//
// The control case reproduces that failure so the guard cannot pass vacuously.
func TestFlushObservabilityExportsAfterDrainConsumedBudget(t *testing.T) {
	spent, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-spent.Done() // the drain has consumed the shared budget

	controlExp := &countingExporter{}
	controlTP := batchingTracerProvider(controlExp)
	endOneSpan(controlTP)
	_ = controlTP.Shutdown(spent)
	if got := controlExp.count(); got != 0 {
		t.Fatalf("control exported %d spans on an exhausted budget, want 0: the failure this "+
			"test guards no longer reproduces, so the guard proves nothing", got)
	}

	exp := &countingExporter{}
	tp := batchingTracerProvider(exp)
	endOneSpan(tp)

	flusher := &recordingFlusher{inner: tp}
	if err := flushObservability(flusher); err != nil {
		t.Fatalf("flushObservability: %v", err)
	}

	if !flusher.called {
		t.Fatal("flushObservability never called Shutdown")
	}
	if flusher.errAtCall != nil {
		t.Errorf("the flush ran on an already-consumed context (%v): it must build its own "+
			"budget after the drain returns, not inherit the drain's", flusher.errAtCall)
	}
	if !flusher.hasDeadline {
		t.Error("the flush ran without a deadline: an unreachable collector would hold the pod " +
			"past terminationGracePeriodSeconds and it would be SIGKILLed anyway")
	}
	if got := exp.count(); got != 1 {
		t.Errorf("exported %d spans, want 1: the final batch was dropped on SIGTERM", got)
	}
}

// TestShutdownFlushesObservabilityProvider guards the span-flush hook's
// presence, its budget, and its POSITION at the call site.
//
// runServer cannot be booted from a unit test (it binds ports, opens a database
// and blocks on a signal), so this half is structural: the shutdown closure must
// route the flush through flushObservability — the seam the behavioural test
// above exercises — must not hand the observability provider the drain's
// shutdownCtx, which is the regression that made the flush a no-op, and must run
// the flush AFTER the servers have drained.
//
// The ordering half is not decoration. Presence and budget are both satisfied by
// a closure that flushes FIRST, and that closure exports the spans of every
// request that had already finished while dropping the spans of every request
// still in flight at SIGTERM — which is the traffic a shutdown trace is about,
// and the only reason the flush is worth a budget of its own. Every other test
// in this package stays green through that move; see
// TestShutdownFlushOrderGuardCatchesAFlushBeforeTheDrain, which performs it.
func TestShutdownFlushesObservabilityProvider(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	closure := shutdownClosure(t, file)
	if closure == nil {
		t.Fatal("no `shutdown := func() {...}` closure found in runServer — " +
			"the graceful-shutdown path moved; re-point this guard at its new home " +
			"rather than deleting it")
	}

	if !callsFlushObservability(closure) {
		t.Error("the shutdown closure does not call flushObservability: batched spans " +
			"are dropped on SIGTERM. Add flushObservability(services.Observability) after the " +
			"HTTP servers stop accepting.")
	}
	if passesShutdownCtxToObservability(closure) {
		t.Error("the shutdown closure hands shutdownCtx to the observability flush. That budget " +
			"is already spent by the server drain (an SSE consumer holds it for the full grace " +
			"period), so TracerProvider.Shutdown bails before stopping the span processor and " +
			"exports nothing. Use flushObservability, which builds its own budget.")
	}

	order := shutdownFlushOrder(closure)
	if len(order.drains) == 0 {
		// Loud, not silent. With no drain located there is nothing to order the
		// flush against, and reporting that as a pass is how a guard ends up
		// pinning nothing.
		t.Fatalf("no server drain found in the shutdown closure — this guard looks for " +
			"`<server>.Shutdown(shutdownCtx)` and found none, so it cannot tell whether the " +
			"span flush still runs after the drain. The drain was renamed or restructured; " +
			"re-point shutdownFlushOrder rather than deleting it")
	}
	t.Logf("shutdown closure: %d server drains, %d flush call(s)", len(order.drains), len(order.flushes))

	if problem := order.problem(fset); problem != "" {
		t.Error(problem)
	}
}

// shutdownStep is one call of interest inside the shutdown closure, tagged with
// the index of the closure's TOP-LEVEL statement that contains it.
//
// Index, not token.Pos, is what the ordering compares: positions come from the
// parse and do not move when the AST is rearranged, so a position-based check
// could not be mutation-proven against a reordered tree — it would report the
// original source order and pass.
type shutdownStep struct {
	idx   int
	pos   token.Pos
	call  string
	async bool
}

// shutdownOrder is the shutdown closure's flush-versus-drain layout.
type shutdownOrder struct {
	drains  []shutdownStep
	flushes []shutdownStep
}

// problem states why the layout is wrong, or "" when it is right.
func (o shutdownOrder) problem(fset *token.FileSet) string {
	if len(o.drains) == 0 || len(o.flushes) == 0 {
		return ""
	}

	// A drain or flush reached through `go`/`defer` runs at a time statement
	// order does not describe, so the comparison below would be meaningless.
	// Say that instead of quietly returning a verdict built on it.
	for _, s := range append(append([]shutdownStep{}, o.drains...), o.flushes...) {
		if s.async {
			return fmt.Sprintf("%s at %s runs from a go/defer inside the shutdown closure, so the "+
				"statement order no longer says what runs first and this guard can no longer "+
				"read the flush-after-drain ordering. Re-point shutdownFlushOrder at the new "+
				"shape rather than letting it report a pass it cannot justify",
				s.call, fset.Position(s.pos))
		}
	}

	lastDrain := o.drains[0]
	for _, d := range o.drains[1:] {
		if d.idx > lastDrain.idx || (d.idx == lastDrain.idx && d.pos > lastDrain.pos) {
			lastDrain = d
		}
	}
	firstFlush := o.flushes[0]
	for _, f := range o.flushes[1:] {
		if f.idx < firstFlush.idx || (f.idx == firstFlush.idx && f.pos < firstFlush.pos) {
			firstFlush = f
		}
	}
	if firstFlush.idx > lastDrain.idx ||
		(firstFlush.idx == lastDrain.idx && firstFlush.pos > lastDrain.pos) {
		return ""
	}

	return fmt.Sprintf("the shutdown closure runs %s (statement %d, %s) BEFORE %s "+
		"(statement %d, %s). The flush must come last, after every server has drained: spans "+
		"end when their request ends, so a flush that runs first exports the requests that "+
		"already finished and drops every request still in flight at SIGTERM — the long-lived "+
		"ones (an SSE consumer on /api/v1/receipts/tail), which are exactly the traffic this "+
		"flush was given its own budget to capture. Nothing else in this package notices the "+
		"move: the flush is still called, still on its own budget, still exports a span.",
		firstFlush.call, firstFlush.idx, fset.Position(firstFlush.pos),
		lastDrain.call, lastDrain.idx, fset.Position(lastDrain.pos))
}

// shutdownFlushOrder locates the server drains and the observability flush in
// the closure body.
func shutdownFlushOrder(closure *ast.FuncLit) shutdownOrder {
	var o shutdownOrder
	for i, stmt := range closure.Body.List {
		collectShutdownSteps(stmt, i, false, &o)
	}
	return o
}

func collectShutdownSteps(node ast.Node, idx int, async bool, o *shutdownOrder) {
	ast.Inspect(node, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.GoStmt:
			collectShutdownSteps(v.Call, idx, true, o)
			return false
		case *ast.DeferStmt:
			collectShutdownSteps(v.Call, idx, true, o)
			return false
		case *ast.CallExpr:
			if name, ok := serverDrainCall(v); ok {
				o.drains = append(o.drains, shutdownStep{idx: idx, pos: v.Pos(), call: name, async: async})
			}
			if isFlushObservabilityCall(v) {
				o.flushes = append(o.flushes, shutdownStep{idx: idx, pos: v.Pos(), call: "flushObservability", async: async})
			}
		}
		return true
	})
}

// serverDrainCall matches `<ident>.Shutdown(..., shutdownCtx, ...)` — the API,
// health and metrics servers draining on the shared budget.
//
// The plain-identifier receiver is what excludes the flush itself: the
// observability provider is reached as services.Observability, a selector.
func serverDrainCall(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Shutdown" {
		return "", false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	for _, arg := range call.Args {
		if id, ok := arg.(*ast.Ident); ok && id.Name == "shutdownCtx" {
			return recv.Name + ".Shutdown", true
		}
	}
	return "", false
}

func isFlushObservabilityCall(call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "flushObservability"
}

// TestShutdownFlushOrderGuardCatchesAFlushBeforeTheDrain is the mutation proof
// for the ordering half.
//
// It takes the REAL closure out of main.go, moves the statement holding the
// flush to the top of the body — the refactor that keeps every other test in
// this package green while dropping in-flight spans — and requires the guard to
// report it. The mutation is applied to the parsed tree rather than to main.go
// on disk: another agent owns that file, and a guard that can only be proven by
// editing production source is a guard nobody re-proves.
func TestShutdownFlushOrderGuardCatchesAFlushBeforeTheDrain(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	closure := shutdownClosure(t, file)
	if closure == nil {
		t.Fatal("no `shutdown := func() {...}` closure found in runServer")
	}

	// Control: the tree as written must be clean, or the mutation below proves
	// nothing about the guard.
	if problem := shutdownFlushOrder(closure).problem(fset); problem != "" {
		t.Fatalf("the guard already complains about the unmutated closure, so its "+
			"mutation proof is meaningless: %s", problem)
	}

	mutated := flushHoistedToTop(t, closure)
	order := shutdownFlushOrder(mutated)
	if len(order.drains) == 0 || len(order.flushes) == 0 {
		t.Fatalf("mutated closure lost its drains (%d) or its flush (%d) — the mutation was "+
			"not the one intended", len(order.drains), len(order.flushes))
	}
	problem := order.problem(fset)
	if problem == "" {
		t.Fatal("the flush was moved ahead of every server drain and the guard reported nothing: " +
			"it pins the flush's presence and budget but not its position, which is the half " +
			"that keeps in-flight spans")
	}
	t.Logf("mutant correctly rejected: %s", problem)
}

// flushHoistedToTop returns a copy of the closure whose flush statement is the
// first statement of the body. The original is left untouched.
func flushHoistedToTop(t *testing.T, closure *ast.FuncLit) *ast.FuncLit {
	t.Helper()

	flushIdx := -1
	for i, stmt := range closure.Body.List {
		var probe shutdownOrder
		collectShutdownSteps(stmt, i, false, &probe)
		if len(probe.flushes) > 0 {
			flushIdx = i
			break
		}
	}
	if flushIdx < 0 {
		t.Fatal("no statement in the shutdown closure contains flushObservability — nothing to hoist")
	}

	reordered := []ast.Stmt{closure.Body.List[flushIdx]}
	for i, stmt := range closure.Body.List {
		if i != flushIdx {
			reordered = append(reordered, stmt)
		}
	}
	body := *closure.Body
	body.List = reordered
	mutant := *closure
	mutant.Body = &body
	return &mutant
}

func shutdownClosure(t *testing.T, file *ast.File) *ast.FuncLit {
	t.Helper()
	var found *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || ident.Name != "shutdown" {
			return true
		}
		lit, ok := assign.Rhs[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		found = lit
		return false
	})
	return found
}

func callsFlushObservability(closure *ast.FuncLit) bool {
	found := false
	ast.Inspect(closure, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "flushObservability" {
			return true
		}
		found = true
		return false
	})
	return found
}

// passesShutdownCtxToObservability reports whether any Shutdown call on the
// Observability provider is given the drain's shared context.
func passesShutdownCtxToObservability(closure *ast.FuncLit) bool {
	found := false
	ast.Inspect(closure, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Shutdown" {
			return true
		}
		receiver, ok := sel.X.(*ast.SelectorExpr)
		if !ok || receiver.Sel.Name != "Observability" {
			return true
		}
		for _, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok && ident.Name == "shutdownCtx" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
