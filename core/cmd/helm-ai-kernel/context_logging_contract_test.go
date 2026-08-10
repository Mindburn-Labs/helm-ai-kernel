package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// HELM-495 request-path context contract.
//
// The change this guards converted 48 request-path log/error sites to their
// context-carrying variants (api.WriteInternal -> api.WriteInternalR,
// log.Printf -> slog.ErrorContext) so the record emitted while serving a
// request is stamped with the trace_id of the span serving it and can be joined
// to that span in the backend.
//
// TestServedPathLogRecordCarriesTraceID (serve_path_tracing_test.go) proves the
// HELPER stamps the trace id, but it calls the helper from its own inline test
// handler, so it pins no production call site. A reviewer reverted
// receipt_routes.go:131 from api.WriteInternalR(w, r, err) back to
// api.WriteInternal(w, err) and the whole selection stayed green: in production
// that 500 emits with no trace id and cannot be joined to its span. This file is
// the guard that was missing.
//
// Shape: a go/ast analyzer run as an in-package test, matching how this repo
// already writes contract checks (core/pkg/metrics/label_policy_test.go scans a
// tree for prohibited metric labels; api_handler_chain_test.go pins the
// middleware nesting; core/pkg/observability/config_literal_guard_test.go pins
// config literals). No CI wiring is needed because `go test ./...` already runs
// this package, and a repo script under tools/ would be a second, weaker
// enforcement path that a plain `go test` would not exercise.
//
// The analyzer resolves the INNERMOST enclosing FuncDecl/FuncLit for each call
// and asks whether the request identifier is that function's own *http.Request
// parameter. That precision is required, not decorative: the handlers here are
// `func(w http.ResponseWriter, r *http.Request)` closures passed to
// mux.HandleFunc, so a check that walks back to a column-0 `func` attributes
// every closure body to its enclosing registration function and misreads the
// tree wholesale.
//
// It runs over all three packages the diff touched — this one,
// core/pkg/credentials and core/pkg/api — one test function each, because the
// scanner-rot floors and the tolerated baseline differ per package. The api
// package is scanned READ-ONLY from here on purpose: it is inside the protected
// mirror surface (tools/boundary/protected-dirs.sh), so its guard has to live
// outside it or the boundary manifest goes stale on every test edit.

// ctxlogFinding is one contract violation.
type ctxlogFinding struct {
	pos    string
	class  string
	call   string
	detail string
}

func (f ctxlogFinding) String() string {
	return fmt.Sprintf("%s: %s: %s (%s) — %s", f.pos, f.class, f.call, f.detail, ctxlogRemedy[f.class])
}

// The four failure classes. Every one of them leaves a call site that LOOKS
// converted or is quietly unconverted, and none of them changes the HTTP
// response, so no behavioural test can see them.
const (
	// class 1: the reverted site — the exact mutant that survived review.
	ctxlogClassContextFree = "context-free-call-on-request-path"
	// class 2: converted in shape only — the record carries no trace id
	// because the context it was handed never had a span in it.
	ctxlogClassDeadContext = "dead-context-on-request-path"
	// class 3: converted, but emitted from a goroutine or a deferred closure
	// that may outlive the request, so the context may already be cancelled.
	ctxlogClassAsyncContext = "request-context-in-go-or-defer-closure"
	// class 4: converted against the WRONG request — one captured from an
	// enclosing scope, or a derived upstream request, instead of the
	// handler's own parameter, so the record joins a different span.
	ctxlogClassForeignRequest = "foreign-request-not-own-parameter"
)

var ctxlogRemedy = map[string]string{
	ctxlogClassContextFree:    "use the context-carrying variant (api.WriteInternalR / slog.*Context) with this handler's own *http.Request",
	ctxlogClassDeadContext:    "pass r.Context(); context.Background carries no span, so the record gets no trace_id",
	ctxlogClassAsyncContext:   "the request context may already be cancelled here — capture what you need before the go/defer, or use the context-free variant deliberately",
	ctxlogClassForeignRequest: "pass this function's own *http.Request parameter; another request's context joins the record to the wrong span",
}

// ctxlogContextFreeSelectors are context-free emitters identified by their final
// selector, whatever the import alias (api.WriteInternal, httperr.WriteInternal,
// a bare WriteInternal inside core/pkg/api).
var ctxlogContextFreeSelectors = map[string]bool{
	"WriteInternal": true,
}

// ctxlogContextFreeQualified are context-free emitters that must be matched on
// the full qualified name. Matching bare "Error"/"Print" would collide with
// unrelated methods; these all have a context-carrying twin
// (slog.ErrorContext, and for log.* the slog.*Context family).
var ctxlogContextFreeQualified = map[string]bool{
	"log.Print":   true,
	"log.Printf":  true,
	"log.Println": true,
	"slog.Debug":  true,
	"slog.Info":   true,
	"slog.Warn":   true,
	"slog.Error":  true,
}

// ctxlogSlogContextSelectors is the slog context-carrying family — the exact
// shape HELM-495 converted log/slog call sites INTO. It is counted separately
// from the generic "*Context" tally because the two answer different questions:
// this one says "are the conversions still there", while the generic tally is
// only a liveness canary for the class-2/3/4 detectors and moves with unrelated
// code (database/sql's ExecContext, http.NewRequestWithContext, ...).
var ctxlogSlogContextSelectors = map[string]bool{
	"DebugContext": true,
	"InfoContext":  true,
	"WarnContext":  true,
	"ErrorContext": true,
}

// ctxlogFrame is one enclosing function while walking.
type ctxlogFrame struct {
	// ownRequest is the name of this function's own *http.Request parameter,
	// empty when it has none. This is the field that makes the analyzer
	// correct on closure handlers.
	ownRequest string
	// requests are the *http.Request identifiers bound in this frame — its
	// own parameters plus locals derived from a request.
	requests map[string]bool
	// deadContexts are locals bound to context.Background().
	deadContexts map[string]bool
	// async is true when this frame is reached through a `go`/`defer`
	// closure without crossing a fresh request boundary.
	async bool
}

type ctxlogScanner struct {
	fset     *token.FileSet
	findings []ctxlogFinding
	// counters exist to catch scanner rot: a walker that silently stops
	// seeing the tree would otherwise report a clean bill of health.
	sawWriteInternalR int
	sawContextFree    int
	sawContextCall    int
	sawSlogContext    int
	sawRequestPath    int
	// sawWriteInternalRByFile lets a guard pin the conversions of ONE file
	// without pinning line numbers, which unrelated edits churn.
	sawWriteInternalRByFile map[string]int
}

// ctxlogCalleeName renders a call target as a dotted path ("api.WriteInternalR").
func ctxlogCalleeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if x := ctxlogCalleeName(v.X); x != "" {
			return x + "." + v.Sel.Name
		}
		return v.Sel.Name
	case *ast.CallExpr:
		return ctxlogCalleeName(v.Fun)
	case *ast.IndexExpr:
		return ctxlogCalleeName(v.X)
	case *ast.IndexListExpr:
		return ctxlogCalleeName(v.X)
	case *ast.ParenExpr:
		return ctxlogCalleeName(v.X)
	}
	return ""
}

func ctxlogFinalSelector(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// ctxlogIsRequestType reports whether a type expression is *http.Request.
func ctxlogIsRequestType(e ast.Expr) bool {
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "http" && sel.Sel.Name == "Request"
}

// ctxlogRequestParamNames returns the named, non-blank *http.Request parameters
// of a field list, in declaration order.
func ctxlogRequestParamNames(params *ast.FieldList) []string {
	var out []string
	if params == nil {
		return out
	}
	for _, f := range params.List {
		if !ctxlogIsRequestType(f.Type) {
			continue
		}
		for _, n := range f.Names {
			if n.Name != "" && n.Name != "_" {
				out = append(out, n.Name)
			}
		}
	}
	return out
}

func ctxlogIsDeadContextCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := ctxlogCalleeName(call.Fun)
	return name == "context.Background"
}

// ctxlogClassifyContextArg reads what sits in a context parameter slot.
func ctxlogClassifyContextArg(e ast.Expr) (kind, ident string) {
	switch v := e.(type) {
	case *ast.CallExpr:
		if ctxlogIsDeadContextCall(v) {
			return "dead", ""
		}
		// x.Context() — the request-derived form.
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Context" && len(v.Args) == 0 {
			if id, ok := sel.X.(*ast.Ident); ok {
				return "request", id.Name
			}
		}
	case *ast.Ident:
		return "ident", v.Name
	}
	return "unknown", ""
}

func ctxlogLookup(stack []ctxlogFrame, name string, pick func(ctxlogFrame) map[string]bool) bool {
	for _, f := range stack {
		if pick(f)[name] {
			return true
		}
	}
	return false
}

func ctxlogIsRequestIdent(stack []ctxlogFrame, name string) bool {
	return ctxlogLookup(stack, name, func(f ctxlogFrame) map[string]bool { return f.requests })
}

func ctxlogIsDeadContextIdent(stack []ctxlogFrame, name string) bool {
	return ctxlogLookup(stack, name, func(f ctxlogFrame) map[string]bool { return f.deadContexts })
}

func (s *ctxlogScanner) report(pos token.Pos, class, call, detail string) {
	s.findings = append(s.findings, ctxlogFinding{
		pos:    s.fset.Position(pos).String(),
		class:  class,
		call:   call,
		detail: detail,
	})
}

// ctxlogEnter pushes a frame for a function being entered. Crossing into a
// function that declares its own *http.Request clears the async flag: that
// function serves a fresh, live request, even when it was registered from
// inside a `go func(){...}()` at startup.
func (s *ctxlogScanner) enter(params *ast.FieldList, stack []ctxlogFrame, async bool) []ctxlogFrame {
	f := ctxlogFrame{requests: map[string]bool{}, deadContexts: map[string]bool{}}
	for _, n := range ctxlogRequestParamNames(params) {
		f.requests[n] = true
		if f.ownRequest == "" {
			f.ownRequest = n
		}
	}
	if f.ownRequest != "" {
		async = false
	}
	f.async = async
	return append(append([]ctxlogFrame{}, stack...), f)
}

// ctxlogRegisterBindings tracks locals that hold a request or a dead context, so
// the checks cannot be evaded by one level of indirection
// (ctx := context.Background(); slog.ErrorContext(ctx, ...)).
func (s *ctxlogScanner) registerBindings(n ast.Node, stack []ctxlogFrame) {
	frame := &stack[len(stack)-1]
	switch v := n.(type) {
	case *ast.AssignStmt:
		for i, lhs := range v.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			var rhs ast.Expr
			switch {
			case len(v.Rhs) == len(v.Lhs):
				rhs = v.Rhs[i]
			case len(v.Rhs) == 1 && i == 0:
				// x, err := http.NewRequest(...): only the first result
				// is the request.
				rhs = v.Rhs[0]
			}
			if rhs == nil {
				continue
			}
			if ctxlogIsDeadContextCall(rhs) {
				frame.deadContexts[id.Name] = true
			}
			if alias, ok := rhs.(*ast.Ident); ok && ctxlogIsRequestIdent(stack, alias.Name) {
				frame.requests[id.Name] = true
			}
			if call, ok := rhs.(*ast.CallExpr); ok {
				name := ctxlogCalleeName(call.Fun)
				final := ctxlogFinalSelector(name)
				// http.NewRequest*/r.Clone/r.WithContext all yield a
				// *http.Request that is NOT the served request.
				if strings.HasPrefix(name, "http.NewRequest") || final == "Clone" || final == "WithContext" {
					frame.requests[id.Name] = true
				}
			}
		}
	case *ast.DeclStmt:
		decl, ok := v.Decl.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil || !ctxlogIsRequestType(vs.Type) {
				continue
			}
			for _, name := range vs.Names {
				frame.requests[name.Name] = true
			}
		}
	}
}

func (s *ctxlogScanner) checkCall(call *ast.CallExpr, stack []ctxlogFrame) {
	name := ctxlogCalleeName(call.Fun)
	if name == "" {
		return
	}
	final := ctxlogFinalSelector(name)
	inner := stack[len(stack)-1]

	onRequestPath := false
	for _, f := range stack {
		if f.ownRequest != "" {
			onRequestPath = true
			break
		}
	}
	if onRequestPath {
		s.sawRequestPath++
	}

	// Class 1. A context-free emitter reached while serving a request.
	// Deliberately NOT reported inside a go/defer closure: there the request
	// context may already be cancelled, so the context-free variant is the
	// correct choice, and class 3 covers the converse mistake.
	if ctxlogContextFreeSelectors[final] || ctxlogContextFreeQualified[name] {
		s.sawContextFree++
		if onRequestPath && !inner.async {
			s.report(call.Pos(), ctxlogClassContextFree, name,
				"emitted while serving a request but carries no request context")
		}
		return
	}

	// The context-carrying forms: WriteInternalR takes the request itself in
	// argument 1; the *Context family takes a context.Context in argument 0.
	// "Context" alone is excluded so the r.Context() accessor is not mistaken
	// for an emitter.
	var contextArg ast.Expr
	var requestArg string
	switch {
	case final == "WriteInternalR":
		s.sawWriteInternalR++
		if len(call.Args) >= 2 {
			if id, ok := call.Args[1].(*ast.Ident); ok {
				requestArg = id.Name
			}
		}
		// The PER-FILE counter deliberately counts only a call that is
		// actually correct, while the global counter above stays a raw
		// call-site tally for the scanner-rot floors.
		//
		// A gate that pins "this file holds N WriteInternalR calls" is
		// satisfied by the shape alone, so `WriteInternalR(w, nil, err)`
		// keeps it green — and panics in production, because
		// httperr.WriteInternalR calls r.Context() on the nil request. The
		// same hole covers `WriteInternalR(w, h.req, err)`, a SelectorExpr
		// that never yields an ident at all. Requiring argument 1 to be the
		// enclosing handler's own request closes both.
		if requestArg != "" && (inner.ownRequest == "" || requestArg == inner.ownRequest) {
			s.sawWriteInternalRByFile[filepath.Base(s.fset.Position(call.Pos()).Filename)]++
		}
	case strings.HasSuffix(final, "Context") && final != "Context" && len(call.Args) >= 1:
		s.sawContextCall++
		if ctxlogSlogContextSelectors[final] {
			s.sawSlogContext++
		}
		contextArg = call.Args[0]
	default:
		return
	}

	kind, ident := "", ""
	if contextArg != nil {
		kind, ident = ctxlogClassifyContextArg(contextArg)
		if kind == "ident" {
			switch {
			case ctxlogIsDeadContextIdent(stack, ident):
				kind = "dead"
			default:
				// A plain identifier of unknown provenance. Not
				// provably wrong; a documented limit of the check.
				kind = "unknown"
			}
		}
	}

	// Class 2. context.Background() on a request path: the call looks
	// converted, but the context it carries never held a span.
	if kind == "dead" && onRequestPath {
		s.report(call.Pos(), ctxlogClassDeadContext, name,
			"context.Background in the context slot")
		return
	}

	carrier := ident
	if requestArg != "" {
		carrier = requestArg
	}
	carriesRequest := (kind == "request" && ctxlogIsRequestIdent(stack, ident)) ||
		(requestArg != "" && ctxlogIsRequestIdent(stack, requestArg))
	if !carriesRequest {
		return
	}

	// Class 3. A request context used from a goroutine or a deferred closure,
	// which may run after the request is done and its context cancelled.
	if inner.async {
		s.report(call.Pos(), ctxlogClassAsyncContext, name,
			fmt.Sprintf("request %q used inside a go/defer closure", carrier))
		return
	}

	// Class 4. A request captured from an enclosing scope (or derived, e.g. an
	// upstream http.NewRequestWithContext) used in place of this function's own
	// parameter. Only reported when the function HAS its own parameter — a
	// synchronous helper closure legitimately captures the handler's request.
	if inner.ownRequest != "" && carrier != inner.ownRequest {
		s.report(call.Pos(), ctxlogClassForeignRequest, name,
			fmt.Sprintf("uses request %q, not this function's own parameter %q", carrier, inner.ownRequest))
	}
}

func (s *ctxlogScanner) walk(node ast.Node, stack []ctxlogFrame) {
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil || n == node {
			return true
		}
		switch v := n.(type) {
		case *ast.AssignStmt:
			s.registerBindings(v, stack)
		case *ast.DeclStmt:
			s.registerBindings(v, stack)
		case *ast.GoStmt:
			s.walkAsyncCall(v.Call, stack)
			return false
		case *ast.DeferStmt:
			s.walkAsyncCall(v.Call, stack)
			return false
		case *ast.FuncLit:
			s.walk(v.Body, s.enter(v.Type.Params, stack, stack[len(stack)-1].async))
			return false
		case *ast.CallExpr:
			s.checkCall(v, stack)
		}
		return true
	})
}

// ctxlogWalkAsyncCall handles `go f(...)` and `defer f(...)`. The ARGUMENTS are
// evaluated synchronously at the statement, so they keep the current frame; only
// the callee body runs later.
func (s *ctxlogScanner) walkAsyncCall(call *ast.CallExpr, stack []ctxlogFrame) {
	for _, arg := range call.Args {
		s.walk(arg, stack)
	}
	if lit, ok := call.Fun.(*ast.FuncLit); ok {
		s.walk(lit.Body, s.enter(lit.Type.Params, stack, true))
		return
	}
	// `defer api.WriteInternalR(w, r, err)` — the emitter itself is deferred.
	s.checkCall(call, s.enter(nil, stack, true))
}

func (s *ctxlogScanner) scanFile(f *ast.File) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		stack := s.enter(fn.Type.Params, nil, false)
		if fn.Recv != nil {
			for _, n := range ctxlogRequestParamNames(fn.Recv) {
				stack[0].requests[n] = true
			}
		}
		s.walk(fn.Body, stack)
	}
}

// ctxlogFindingsByFile tallies findings of one class by base file name, so a
// guard can pin a package's known-unconverted sites without pinning line
// numbers.
func ctxlogFindingsByFile(findings []ctxlogFinding, class string) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		if f.class != class {
			continue
		}
		// pos is "path/file.go:LINE:COL".
		file := f.pos
		if i := strings.IndexByte(file, ':'); i >= 0 {
			file = file[:i]
		}
		out[filepath.Base(file)]++
	}
	return out
}

// ctxlogScan runs the contract over already-parsed files.
func ctxlogScan(fset *token.FileSet, files []*ast.File) *ctxlogScanner {
	s := &ctxlogScanner{fset: fset, sawWriteInternalRByFile: map[string]int{}}
	for _, f := range files {
		s.scanFile(f)
	}
	sort.Slice(s.findings, func(i, j int) bool { return s.findings[i].pos < s.findings[j].pos })
	return s
}

// ctxlogErrUnreadable marks a package directory the process may not open. The
// caller must turn this into a loud skip: reporting "no violations" for a
// package that was never read would be a silent pass, which is exactly the
// failure mode this whole file exists to prevent.
var ctxlogErrUnreadable = errors.New("package directory is not readable")

// ctxlogParsePackage parses the non-test .go files of a directory. Test files
// are excluded on purpose: they contain deliberate inline handlers (the one in
// serve_path_tracing_test.go calls WriteInternalR from a test closure), and
// pinning the guard to sibling test files would couple it to unrelated churn.
func ctxlogParsePackage(fset *token.FileSet, dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%w: %s: %v", ctxlogErrUnreadable, dir, err)
		}
		return nil, err
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil, fmt.Errorf("%w: %s: %v", ctxlogErrUnreadable, path, err)
			}
			return nil, err
		}
		// A parse failure fails the gate. Skipping the file would exempt
		// its call sites from the contract.
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		files = append(files, f)
	}
	return files, nil
}

// TestRequestPathLoggingCarriesRequestContext is the HELM-495 regression guard.
// It fails when any request-path log/error site in this package stops carrying
// the served request's context — by reverting to the context-free helper, by
// being handed a context that never held a span, by emitting from a closure that
// outlives the request, or by using the wrong request.
func TestRequestPathLoggingCarriesRequestContext(t *testing.T) {
	fset := token.NewFileSet()
	files, err := ctxlogParsePackage(fset, ".")
	if errors.Is(err, ctxlogErrUnreadable) {
		// Fatal, not Skip. A skip prints only under `go test -v`, so CI sees a
		// bare green `ok` for a contract that never ran — the silent-pass shape
		// this file exists to eliminate. An unreadable package is a reason the
		// gate could not be evaluated, which is a failure, not a pass.
		t.Fatalf("the HELM-495 request-path context contract could NOT be checked — the package "+
			"was NOT scanned and this run proves nothing: %v", err)
	}
	if err != nil {
		t.Fatalf("parsing package: %v", err)
	}

	s := ctxlogScan(fset, files)

	// Visible under `go test -v`: the inventory this gate is standing on.
	t.Logf("scanned %d non-test files: %d api.WriteInternalR sites, %d slog.*Context sites, "+
		"%d *Context call sites, %d context-free emitter calls, %d calls on a request path",
		len(files), s.sawWriteInternalR, s.sawSlogContext, s.sawContextCall, s.sawContextFree, s.sawRequestPath)

	// Scanner-rot self-checks. This package is known to hold dozens of
	// converted sites and thousands of request-path calls; seeing none means
	// the walker went blind, not that the tree is clean.
	// The floor is calibrated against a measured blinding: removing the
	// descent into FuncLit closures — where every mux.HandleFunc handler in
	// this package lives — drops this count from ~2030 to 486.
	if s.sawRequestPath < 1000 {
		t.Fatalf("analyzer saw only %d calls on a request path — the walker is broken, not the tree clean",
			s.sawRequestPath)
	}
	if s.sawWriteInternalR < 40 {
		t.Fatalf("analyzer saw only %d api.WriteInternalR call sites, expected the ~46 HELM-495 conversions — "+
			"either the conversions were reverted wholesale or the analyzer stopped recognizing them",
			s.sawWriteInternalR)
	}
	if s.sawContextFree < 10 {
		t.Fatalf("analyzer saw only %d context-free emitter calls — the class-1 detector is dead, "+
			"so a reverted call site would go unnoticed", s.sawContextFree)
	}
	if s.sawContextCall < 5 {
		t.Fatalf("analyzer saw only %d *Context call sites — the class-2/3/4 detectors are dead",
			s.sawContextCall)
	}

	for _, f := range s.findings {
		t.Errorf("HELM-495 request-path context contract: %s", f)
	}
}

// The measured inventory of core/pkg/credentials and the floors derived from
// it. Sites are what the scanner counts today; floors sit one notch below so a
// single revert is reported as a precise finding rather than as a blunt "the
// package was gutted" fatal. Both are proven against a mutated copy of the
// package by TestCredentialsSlogFloorFiresOnAWholesaleRevert.
const (
	ctxlogCredsWriteInternalRSites = 7
	ctxlogCredsWriteInternalRFloor = 4
	ctxlogCredsSlogSites           = 5
	ctxlogCredsSlogFloor           = 3
)

// TestCredentialsRequestPathLoggingCarriesRequestContext holds core/pkg/credentials
// to the same contract.
//
// It is a separate function rather than a second target inside the test above
// because the scanner-rot floors are calibrated per package: cmd/helm-ai-kernel
// carries thousands of request-path calls and ~46 conversions, this package
// carries twelve sites in one file. Folding them into one set of floors would
// mean floors loose enough to pass a blinded walker on the smaller package.
//
// Why it needs its own guard at all: these twelve sites were the last unconverted
// request-path emitters of the HELM-495 diff, and they were converted after
// everything else because a permission rule made the directory unreadable
// (`Read(//**/credentials)` matched the package path, not just credential files).
// They are also, unlike the cmd/ sites, all reached through the SAME handler
// registration, so a single careless refactor reverts all twelve at once.
func TestCredentialsRequestPathLoggingCarriesRequestContext(t *testing.T) {
	const dir = "../../pkg/credentials"

	fset := token.NewFileSet()
	files, err := ctxlogParsePackage(fset, dir)
	if errors.Is(err, ctxlogErrUnreadable) {
		// NOT a skip. This package was unreadable for real, and a skip here
		// would report a green run for a contract that never executed — the
		// exact silent-pass shape this file exists to eliminate elsewhere.
		t.Fatalf("the HELM-495 request-path context contract could NOT be checked against %s "+
			"and this run proves nothing about it: %v", dir, err)
	}
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	s := ctxlogScan(fset, files)

	t.Logf("scanned %d non-test files in %s: %d api.WriteInternalR sites, %d slog.*Context sites, "+
		"%d *Context call sites, %d context-free emitter calls, %d calls on a request path",
		len(files), dir, s.sawWriteInternalR, s.sawSlogContext, s.sawContextCall, s.sawContextFree, s.sawRequestPath)

	// Scanner-rot floors, calibrated against the measured inventory of this
	// package — measured by RUNNING the scanner, not by counting diff hunks:
	// twelve HELM-495 conversions, namely seven api.WriteInternalR (one per
	// handler that can 500) and five slog.*Context, all in handlers.go.
	//
	// The generic *Context tally is thirteen, and an earlier revision floored
	// on it at 8 while telling the reader the floor caught a wholesale revert.
	// It did not. Only five of those thirteen are HELM-495 conversions; the
	// other eight are database/sql (four ExecContext/QueryRowContext in
	// store.go) and the OAuth client (four http.NewRequestWithContext in
	// google_oauth.go), which no revert of this diff touches. Reverting every
	// conversion left 8, and 8 < 8 is false — a floor that could not fire for
	// the regression its own message named. Hence the split counter: floor the
	// conversion class on itself.
	//
	// An earlier draft of this comment also claimed the old floor WOULD have
	// fired on an unrelated move off database/sql context methods. Measured,
	// it would not have: removing all four store.go context calls leaves 9,
	// and 9 < 8 is false too. The old floor needed six of the eight unrelated
	// sites to vanish before it fired — it was inert in both directions, not
	// merely aimed at the wrong one. Corrected here rather than left standing,
	// because an untrue rationale in a guard is the defect this file exists to
	// remove.
	//
	// The floors sit BELOW the measured counts on purpose. At the exact count
	// they would fire on any single revert and abort before the findings loop
	// ran, so a one-line regression would be reported as "reverted wholesale"
	// instead of naming its file and line. With slack, a single revert produces
	// the precise finding and only a wholesale revert — or a blinded walker —
	// trips the floor. Same shape as the cmd/ floors above.
	if s.sawWriteInternalR < ctxlogCredsWriteInternalRFloor {
		t.Fatalf("analyzer saw only %d api.WriteInternalR call sites in %s, expected %d — "+
			"either the conversions were reverted wholesale or the analyzer stopped recognizing them",
			s.sawWriteInternalR, dir, ctxlogCredsWriteInternalRSites)
	}
	if s.sawSlogContext < ctxlogCredsSlogFloor {
		t.Fatalf("analyzer saw only %d slog.*Context call sites in %s, expected %d — "+
			"either the slog conversions were reverted wholesale or the analyzer stopped recognizing them",
			s.sawSlogContext, dir, ctxlogCredsSlogSites)
	}
	// Pure liveness canary, deliberately floored at 1 rather than at the
	// measured 13: everything above 5 in that tally belongs to code HELM-495
	// never touched, so a higher floor would be a tripwire on somebody else's
	// refactor wearing this contract's failure message.
	if s.sawContextCall < 1 {
		t.Fatalf("analyzer matched no *Context call site at all in %s — the generic detector "+
			"that classes 2/3/4 ride on never ran", dir)
	}

	for _, f := range s.findings {
		t.Errorf("HELM-495 request-path context contract (%s): %s", dir, f)
	}
}

// ctxlogAPIConvertedFile is the one file in core/pkg/api that HELM-495
// converted, and ctxlogAPIConvertedSites is how many sites it converted:
// TrustKeyHandler.HandleAddKey and HandleRevokeKey, both writing a 500 when the
// trust-key registry rejects an Apply.
const (
	ctxlogAPIConvertedFile  = "trust_keys_handler.go"
	ctxlogAPIConvertedSites = 2
)

// ctxlogAPIContextFreeBaseline is the package's KNOWN, COUNTED set of
// context-free emitters still reached while serving a request, by file. EIGHT
// sites, none of them part of the HELM-495 diff:
//
//	handlers.go          2  MemoryService.HandleIngest, .HandleSearch
//	decision_handler.go  4  DecisionHandler.handleList, .handleCreate, .handleResolve,
//	                        plus the slog.Error in .handleResolve's expiry branch
//	autonomy_handler.go  1  AutonomyHandler.HandleGetState
//	governed_gateway.go  1  GovernedGateway.handleInference
//
// Eight, not the seven a `grep WriteInternal` reports. Seven is the count of
// context-free WriteInternal(w, err) calls; the contract is wider than that one
// helper and also catches decision_handler.go's bare
// slog.Error("failed to persist expired decision state", ...), which runs
// inside handleResolve(w, r, id) and drops a trace_id for the same reason. The
// number below is what the scanner measured, not what a grep suggested — this
// baseline was written at seven first and the guard rejected it.
//
// They are recorded rather than converted because core/pkg/api is a protected
// path: it is mirrored read-only into the downstream repo against
// tools/helm-ai-kernel.lock with a SHA256 manifest, so touching it here widens
// this diff into a boundary-sync change for no behavioural gain. Converting
// them is its own PR.
//
// Counts, not file:line. Line numbers churn on every unrelated edit to those
// files and would make this guard a nuisance that gets deleted; a per-file
// count still cannot grow silently, which is the whole point — a ninth
// context-free site anywhere in the package either bumps one of these numbers
// or introduces a file that is not in the table, and both fail.
var ctxlogAPIContextFreeBaseline = map[string]int{
	"handlers.go":         2,
	"decision_handler.go": 4,
	"autonomy_handler.go": 1,
	"governed_gateway.go": 1,
}

// TestAPIRequestPathLoggingCarriesRequestContext holds core/pkg/api to the
// contract.
//
// Why this function has to exist: the HELM-495 diff converted two sites in this
// package, and neither of the two test functions above scans it — the first
// scans ".", the second core/pkg/credentials. Reverting
// trust_keys_handler.go's WriteInternalR pair left the entire suite green, so
// the two conversions were pinned by nothing.
//
// It is a THIRD function rather than a third directory fed to one of the others
// because this package needs something they do not: a tolerated baseline. The
// gate here is two-sided —
//
//   - the two converted sites must stay converted (asserted positively, by
//     count, on the file that holds them), and
//   - the eight that were never in scope must stay exactly eight, in exactly
//     those files.
//
// The second half is not bookkeeping. Without it the honest way to satisfy a
// package-wide "no context-free emitter on a request path" rule would be to
// convert eight sites on a protected path inside an unrelated diff; with it,
// the contract records what is not yet converted and fails the moment that set
// changes in either direction.
//
// Nothing here writes to core/pkg/api. The scanner only reads it, so the
// boundary manifest is unaffected.
func TestAPIRequestPathLoggingCarriesRequestContext(t *testing.T) {
	const dir = "../../pkg/api"

	fset := token.NewFileSet()
	files, err := ctxlogParsePackage(fset, dir)
	if errors.Is(err, ctxlogErrUnreadable) {
		t.Fatalf("the HELM-495 request-path context contract could NOT be checked against %s "+
			"and this run proves nothing about it: %v", dir, err)
	}
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	s := ctxlogScan(fset, files)

	t.Logf("scanned %d non-test files in %s: %d api.WriteInternalR sites (%d in %s), "+
		"%d slog.*Context sites, %d *Context call sites, %d context-free emitter calls, "+
		"%d calls on a request path",
		len(files), dir, s.sawWriteInternalR, s.sawWriteInternalRByFile[ctxlogAPIConvertedFile],
		ctxlogAPIConvertedFile, s.sawSlogContext, s.sawContextCall, s.sawContextFree, s.sawRequestPath)

	// Scanner-rot floor. Measured by running this guard: the package holds
	// thousands of calls on a request path, so a handful means the walker went
	// blind rather than that the package shrank.
	if s.sawRequestPath < 200 {
		t.Fatalf("analyzer saw only %d calls on a request path in %s — the walker is broken, "+
			"not the tree clean", s.sawRequestPath, dir)
	}
	if s.sawContextFree < 1 {
		t.Fatalf("analyzer matched no context-free emitter call at all in %s — the class-1 "+
			"detector never ran, so a reverted call site would go unnoticed", dir)
	}

	byFile := ctxlogFindingsByFile(s.findings, ctxlogClassContextFree)
	if len(byFile) == 0 {
		// Reported here rather than as four "sites were converted" errors from
		// ctxlogAPIProblems, because those two causes need different actions and
		// one of them means this gate is no longer a gate.
		t.Fatalf("no context-free request-path emitter found in %s at all, baseline expects %d in "+
			"%d files. Either every one of them was converted — good news, empty out "+
			"ctxlogAPIContextFreeBaseline — or the class-1 request-path detector is dead "+
			"(it still matched %d context-free emitter calls, %d calls on a request path)",
			dir, ctxlogAPIBaselineTotal(), len(ctxlogAPIContextFreeBaseline),
			s.sawContextFree, s.sawRequestPath)
	}

	for _, p := range ctxlogAPIProblems(dir, s) {
		t.Errorf("HELM-495 request-path context contract: %s", p)
	}
}

// ctxlogAPIProblems is the api gate's judgement, split out from the test so it
// can be run against a MUTATED copy of the package and proven to fail —
// see TestAPIContextContractCatchesRegressions. Returns one string per
// complaint, empty when the package satisfies the contract.
func ctxlogAPIProblems(dir string, s *ctxlogScanner) []string {
	var problems []string

	// Half one: the two sites this diff converted are still converted.
	if got := s.sawWriteInternalRByFile[ctxlogAPIConvertedFile]; got != ctxlogAPIConvertedSites {
		problems = append(problems, fmt.Sprintf("%s/%s holds %d api.WriteInternalR call sites, "+
			"want %d — the HELM-495 conversions in HandleAddKey/HandleRevokeKey were changed. "+
			"Both 500s must keep carrying the request, or they emit with no trace_id and cannot "+
			"be joined to their span.", dir, ctxlogAPIConvertedFile, got, ctxlogAPIConvertedSites))
	}

	// Half two: the tolerated set has not moved, in either direction.
	byFile := ctxlogFindingsByFile(s.findings, ctxlogClassContextFree)
	for file, want := range ctxlogAPIContextFreeBaseline {
		switch n := byFile[file]; {
		case n > want:
			problems = append(problems, fmt.Sprintf("%s/%s now has %d context-free request-path "+
				"emitters, baseline is %d — a NEW one was added. Use WriteInternalR(w, r, err) "+
				"or the slog.*Context form; do not grow the baseline.", dir, file, n, want))
		case n < want:
			problems = append(problems, fmt.Sprintf("%s/%s now has %d context-free request-path "+
				"emitters, baseline is %d — sites were converted, which is good news. Lower the "+
				"number in ctxlogAPIContextFreeBaseline so the remaining ones stay pinned (a "+
				"stale baseline silently tolerates a fresh regression).", dir, file, n, want))
		}
	}
	for file, n := range byFile {
		if _, ok := ctxlogAPIContextFreeBaseline[file]; !ok {
			problems = append(problems, fmt.Sprintf("%s/%s has %d context-free request-path "+
				"emitters and is not in the baseline — this is a new violation, not a recorded one",
				dir, file, n))
		}
	}

	// Classes 2/3/4 have no baseline anywhere: a dead context, an async context
	// or a foreign request is always a defect.
	for _, f := range s.findings {
		if f.class != ctxlogClassContextFree {
			problems = append(problems, fmt.Sprintf("(%s): %s", dir, f))
		}
	}

	sort.Strings(problems)
	return problems
}

func ctxlogAPIBaselineTotal() int {
	total := 0
	for _, n := range ctxlogAPIContextFreeBaseline {
		total += n
	}
	return total
}

// ctxlogCopyPackage copies a package's non-test .go files into a temp directory
// so a mutation can be applied without writing to the tree under test.
//
// core/pkg/api is a PROTECTED path — mirrored read-only downstream against a
// SHA256 manifest — so mutating it in place, even for the length of one test,
// is not an option here. The copy keeps the proof honest and the manifest
// intact.
func ctxlogCopyPackage(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	copied := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatalf("reading %s/%s: %v", src, name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			t.Fatalf("writing %s/%s: %v", dst, name, err)
		}
		copied++
	}
	if copied == 0 {
		t.Fatalf("copied no files from %s — the mutation would be applied to nothing", src)
	}
	return dst
}

// ctxlogMutate rewrites one file of a copied package, failing if the edit did
// not apply: a mutation test whose mutation silently missed proves nothing.
// n is the number of occurrences to replace, -1 for all.
func ctxlogMutate(t *testing.T, dir, file, old, new string, n int) {
	t.Helper()
	path := filepath.Join(dir, file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	src := string(b)
	if !strings.Contains(src, old) {
		t.Fatalf("mutation target %q not found in %s — the guard was not exercised", old, file)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(src, old, new, n)), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestAPIContextContractCatchesRegressions is the mutation proof for the api
// gate. It runs the gate against a copy of core/pkg/api with one regression
// introduced and requires a complaint naming the right file.
//
// Both mutants are the ones the gate exists for: the reverted conversion is
// literally the change the reviewer made to show the suite stayed green, and
// the added context-free 500 is how the baseline would rot upward if it were
// only a floor.
func TestAPIContextContractCatchesRegressions(t *testing.T) {
	cases := []struct {
		name       string
		file       string
		old        string
		new        string
		wantSubstr string
	}{
		{
			name:       "reverted_trust_key_conversion",
			file:       ctxlogAPIConvertedFile,
			old:        "WriteInternalR(w, r, err)",
			new:        "WriteInternal(w, err)",
			wantSubstr: ctxlogAPIConvertedFile,
		},
		{
			name: "new_context_free_500_in_a_baselined_file",
			file: "handlers.go",
			old:  "func (s *MemoryService) HandleSearch(w http.ResponseWriter, r *http.Request) {",
			new: "func (s *MemoryService) HandleFresh(w http.ResponseWriter, r *http.Request) {\n" +
				"\tWriteInternal(w, nil)\n}\n\n" +
				"func (s *MemoryService) HandleSearch(w http.ResponseWriter, r *http.Request) {",
			wantSubstr: "handlers.go",
		},
	}

	// The baseline the mutated runs are judged against. Taken from an
	// UNMUTATED copy, not from the real tree, so a concurrent edit cannot
	// change what "new" means mid-test.
	baseFset := token.NewFileSet()
	baseDir := ctxlogCopyPackage(t, "../../pkg/api")
	baseFiles, err := ctxlogParsePackage(baseFset, baseDir)
	if err != nil {
		t.Fatalf("parsing the unmutated copy: %v", err)
	}
	baseline := map[string]bool{}
	for _, p := range ctxlogAPIProblems(baseDir, ctxlogScan(baseFset, baseFiles)) {
		baseline[ctxlogNormalizeProblem(p, baseDir)] = true
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := ctxlogCopyPackage(t, "../../pkg/api")
			ctxlogMutate(t, dir, tc.file, tc.old, tc.new, 1)

			fset := token.NewFileSet()
			files, err := ctxlogParsePackage(fset, dir)
			if err != nil {
				t.Fatalf("parsing mutated copy: %v", err)
			}
			problems := ctxlogAPIProblems(dir, ctxlogScan(fset, files))
			if len(problems) == 0 {
				t.Fatalf("the api gate reported nothing for a %s regression — it is not a gate", tc.name)
			}
			// The complaint must be NEW, and must name the mutated file.
			//
			// Matching the file name alone is not enough: blind the walker
			// entirely — make scanFile return immediately — and the gate emits
			// a count complaint naming every pinned file, so both subtests find
			// their substring in a complaint that has nothing to do with their
			// mutation and this proof reports PASS while testing nothing.
			// Subtracting the unmutated set is what makes the mutation, rather
			// than the scanner's own collapse, the thing being observed.
			for _, p := range problems {
				if !baseline[ctxlogNormalizeProblem(p, dir)] && strings.Contains(p, tc.wantSubstr) {
					return
				}
			}
			t.Fatalf("the api gate produced no NEW complaint about %s for this mutation.\n"+
				"  after:  %v\n  before: %v\n"+
				"A complaint that the unmutated package already made proves nothing about the mutation.",
				tc.wantSubstr, problems, ctxlogSortedKeys(baseline))
		})
	}
}

// ctxlogNormalizeProblem strips the package copy's directory out of a complaint
// so complaints from two different copies can be compared.
//
// Load-bearing, and it was learned the hard way: complaints embed the path they
// were found at, every copy lives in its own t.TempDir(), so without this every
// complaint from a mutated copy is a string no baseline could ever contain. The
// subtraction then admits everything and the proof passes even for a walker
// blinded to the whole tree — the exact failure this baseline exists to catch.
func ctxlogNormalizeProblem(problem, dir string) string {
	return strings.ReplaceAll(problem, dir, "<pkg>")
}

// ctxlogSortedKeys renders a problem set deterministically for a failure
// message.
func ctxlogSortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCredentialsSlogFloorFiresOnAWholesaleRevert is the mutation proof for the
// re-derived credentials floor, and the executable record of why it was
// re-derived.
//
// It reverts all five slog.*Context conversions in a copy of the package — the
// wholesale revert the floor's message names — and asserts three things:
//
//   - the new floor fires (sawSlogContext drops to 0, below ctxlogCredsSlogFloor);
//   - the OLD floor could not have (the generic *Context tally lands on exactly
//     8, and the previous guard's condition was 8 < 8, which is false — a
//     failure message describing a regression the check could never see);
//   - the revert is reported precisely anyway, as one class-1 finding per site,
//     so the floor never has to be the thing that catches a real revert.
func TestCredentialsSlogFloorFiresOnAWholesaleRevert(t *testing.T) {
	const src = "../../pkg/credentials"
	dir := ctxlogCopyPackage(t, src)
	ctxlogMutate(t, dir, "handlers.go", "slog.WarnContext(r.Context(), ", "slog.Warn(", -1)
	ctxlogMutate(t, dir, "handlers.go", "slog.ErrorContext(r.Context(), ", "slog.Error(", -1)

	fset := token.NewFileSet()
	files, err := ctxlogParsePackage(fset, dir)
	if err != nil {
		t.Fatalf("parsing mutated copy: %v", err)
	}
	s := ctxlogScan(fset, files)

	if s.sawSlogContext >= ctxlogCredsSlogFloor {
		t.Errorf("after reverting every slog conversion the analyzer still counts %d "+
			"slog.*Context sites (floor %d) — the mutation did not land, or the floor cannot fire",
			s.sawSlogContext, ctxlogCredsSlogFloor)
	}
	if s.sawContextCall < 8 {
		t.Errorf("the wholesale revert left %d generic *Context sites, expected the 8 that belong "+
			"to database/sql and the OAuth client — this test's account of why the old floor was "+
			"unfirable no longer matches the package", s.sawContextCall)
	}
	if got := len(ctxlogFindingsByFile(s.findings, ctxlogClassContextFree)); got == 0 {
		t.Error("the wholesale revert produced no class-1 finding — the precise detector, not " +
			"just the floor, is what must catch this")
	}
}

// TestAPIContextContractPassesTheUnmutatedPackage is the other half: without it,
// the mutation test above would still pass if the gate complained about
// everything unconditionally.
func TestAPIContextContractPassesTheUnmutatedPackage(t *testing.T) {
	dir := ctxlogCopyPackage(t, "../../pkg/api")

	fset := token.NewFileSet()
	files, err := ctxlogParsePackage(fset, dir)
	if err != nil {
		t.Fatalf("parsing copy: %v", err)
	}
	if problems := ctxlogAPIProblems(dir, ctxlogScan(fset, files)); len(problems) != 0 {
		t.Fatalf("the api gate complains about an unmutated copy of the package, so its "+
			"mutation proof means nothing: %v", problems)
	}
}

// ctxlogFixtureFindings parses fixture source and returns the classes reported,
// so the guard can be proven against each failure class without mutating the
// production tree.
func ctxlogFixtureFindings(t *testing.T, src string) []ctxlogFinding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return ctxlogScan(fset, []*ast.File{f}).findings
}

const ctxlogFixtureHeader = `package fixture

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"

	"example.test/api"
)

var errBoom = errors.New("boom")

`

// TestContextLoggingContractCatchesEachFailureClass proves the guard can fail,
// once per failure class. Without this, the guard could be a check that never
// fires — the exact defect it was written to close.
func TestContextLoggingContractCatchesEachFailureClass(t *testing.T) {
	cases := []struct {
		name  string
		class string
		body  string
	}{
		{
			name:  "class1_reverted_to_context_free_helper",
			class: ctxlogClassContextFree,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		api.WriteInternal(w, errBoom)
	})
}`,
		},
		{
			name:  "class1_reverted_to_context_free_logger",
			class: ctxlogClassContextFree,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[helm] binding lookup failed: %v", errBoom)
	})
}`,
		},
		{
			name:  "class2_background_context",
			class: ctxlogClassDeadContext,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		slog.ErrorContext(context.Background(), "internal", "error", errBoom)
	})
}`,
		},
		{
			name:  "class3_go_closure",
			class: ctxlogClassAsyncContext,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			slog.ErrorContext(r.Context(), "internal", "error", errBoom)
		}()
	})
}`,
		},
		{
			name:  "class3_defer_closure",
			class: ctxlogClassAsyncContext,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			api.WriteInternalR(w, r, errBoom)
		}()
	})
}`,
		},
		{
			name:  "class3_bare_defer_of_the_emitter",
			class: ctxlogClassAsyncContext,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		defer api.WriteInternalR(w, r, errBoom)
	})
}`,
		},
		{
			name:  "class4_request_captured_from_enclosing_scope",
			class: ctxlogClassForeignRequest,
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/d", func(w http.ResponseWriter, r *http.Request) {
		inner := func(w2 http.ResponseWriter, r2 *http.Request) {
			api.WriteInternalR(w2, r, errBoom)
		}
		inner(w, r)
	})
}`,
		},
		{
			name:  "class4_derived_upstream_request",
			class: ctxlogClassForeignRequest,
			body: `func proxy(w http.ResponseWriter, r *http.Request) {
	upstream, _ := http.NewRequestWithContext(r.Context(), "GET", "http://upstream", nil)
	slog.ErrorContext(upstream.Context(), "internal", "error", errBoom)
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := ctxlogFixtureFindings(t, ctxlogFixtureHeader+tc.body)
			if len(findings) == 0 {
				t.Fatalf("guard reported nothing for %s — it cannot fail on this class, "+
					"so it is not a guard", tc.class)
			}
			for _, f := range findings {
				if f.class != tc.class {
					t.Errorf("got class %q, want %q (%s)", f.class, tc.class, f)
				}
			}
		})
	}
}

// TestContextLoggingContractAcceptsCorrectShapes is the false-positive half. A
// guard that fires on legitimate code gets suppressed, then deleted. In
// particular a naive check that walks back to the nearest column-0 `func`
// misreads every mux.HandleFunc closure in this package.
func TestContextLoggingContractAcceptsCorrectShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "handler_uses_its_own_request",
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		api.WriteInternalR(w, r, errBoom)
		slog.ErrorContext(r.Context(), "internal", "error", errBoom)
	})
}`,
		},
		{
			name: "context_free_logging_outside_any_request",
			body: `func register(mux *http.ServeMux) {
	log.Println("[helm] routes: registering")
	slog.Error("startup failed", "error", errBoom)
}`,
		},
		{
			name: "context_free_logging_inside_a_detached_goroutine",
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/async", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			slog.Error("detached work failed", "error", errBoom)
		}()
	})
}`,
		},
		{
			name: "handler_registered_from_a_startup_goroutine",
			body: `func register(mux *http.ServeMux) {
	go func() {
		mux.HandleFunc("/late", func(w http.ResponseWriter, r *http.Request) {
			api.WriteInternalR(w, r, errBoom)
		})
	}()
}`,
		},
		{
			name: "synchronous_helper_closure_captures_the_handler_request",
			body: `func register(mux *http.ServeMux) {
	mux.HandleFunc("/helper", func(w http.ResponseWriter, r *http.Request) {
		fail := func(e error) { api.WriteInternalR(w, r, e) }
		fail(errBoom)
	})
}`,
		},
		{
			name: "plain_top_level_handler_function",
			body: `func handle(w http.ResponseWriter, r *http.Request) {
	api.WriteInternalR(w, r, errBoom)
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range ctxlogFixtureFindings(t, ctxlogFixtureHeader+tc.body) {
				t.Errorf("false positive on legitimate code: %s", f)
			}
		})
	}
}

// TestContextLoggingContractSkipsLoudlyOnUnreadablePackage proves the
// unreadable-directory path is a visible skip and not a silent clean result —
// the analyzer may legitimately be pointed at a package it has no permission to
// open (core/pkg/credentials is such a path here).
func TestContextLoggingContractSkipsLoudlyOnUnreadablePackage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sealed")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatalf("creating unreadable dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("directory permissions are not enforced for this process (running as root?)")
	}

	files, err := ctxlogParsePackage(token.NewFileSet(), dir)
	if !errors.Is(err, ctxlogErrUnreadable) {
		t.Fatalf("unreadable package returned files=%d err=%v, want a %v sentinel — "+
			"an unreadable package must never be reported as clean", len(files), err, ctxlogErrUnreadable)
	}
}
