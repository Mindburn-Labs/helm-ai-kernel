package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestBuildAPIHandlerLayerOrder pins the middleware nesting of the daemon's
// request pipeline, layer by layer.
//
// The behavioural guards in serve_path_tracing_test.go bracket the tracing
// wrapper — it must be inside CORSMiddleware (no preflight span) and outside the
// rate limiter (a 429 is still a span) — but they cannot see the layer that
// actually matters most: whether the wrapper sits inside RequestIDMiddleware.
// That middleware calls next.ServeHTTP with r.WithContext(ctx), and
// http.ServeMux stamps the matched pattern onto the request object it is handed,
// in place. So from outside the clone, otelhttp holds a request that never
// learns its own route, and per-route span naming becomes structurally
// impossible rather than merely unconfigured (otelhttp v0.65.0 removed
// WithRouteTag, so there is no escape hatch).
//
// The chain ends at rateLimiter.Middleware on purpose. Route identity — the
// span name, the http.route span attribute and the http.route metric attribute
// — is not a layer here; it lives in the otelhttp options inside
// tracing.WrapEdgeHandler, because otelhttp re-runs its span-name formatter
// after the inner handler returns and overwrites anything a middleware set.
// What this chain still owes that machinery is that rateLimiter.Middleware
// forwards the request otelhttp handed it unchanged, so the pointer ServeMux
// stamps Pattern onto is the one otelhttp reads back.
//
// Reordering any two layers turns this red.
func TestBuildAPIHandlerLayerOrder(t *testing.T) {
	want := []string{
		"helmauth.SecurityHeaders",
		"helmauth.CORSMiddleware",
		"helmauth.RequestIDMiddleware",
		"tracing.WrapEdgeHandler",
		"rateLimiter.Middleware",
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	ret := singleReturnExpr(t, file, "buildAPIHandler")
	got := middlewareChain(ret)

	if strings.Join(got, " -> ") != strings.Join(want, " -> ") {
		t.Errorf("buildAPIHandler layer order changed.\n got: %s\nwant: %s\n\n"+
			"Each position is load-bearing: tracing inside RequestIDMiddleware so otelhttp holds "+
			"the request ServeMux stamps, and tracing outside rateLimiter.Middleware so a "+
			"rejected request is still a span. Any layer inserted below the wrapper must forward "+
			"the request unchanged, or per-route naming and http.route both go dark.",
			strings.Join(got, " -> "), strings.Join(want, " -> "))
	}
}

// singleReturnExpr returns the expression of the sole return statement in the
// named top-level function.
func singleReturnExpr(t *testing.T, file *ast.File, fnName string) ast.Expr {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != fnName || fn.Body == nil {
			continue
		}
		if len(fn.Body.List) != 1 {
			t.Fatalf("%s has %d statements, want a single return: re-point this guard rather than deleting it",
				fnName, len(fn.Body.List))
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			t.Fatalf("%s does not end in a single-expression return: re-point this guard", fnName)
		}
		return ret.Results[0]
	}
	t.Fatalf("no func %s found in main.go: the handler chain moved; re-point this guard rather than deleting it", fnName)
	return nil
}

// middlewareChain walks a nest of calls outermost-first, descending into the
// first call-valued argument of each layer.
func middlewareChain(expr ast.Expr) []string {
	var chain []string
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return chain
		}
		chain = append(chain, calleeName(call.Fun))

		var next ast.Expr
		for _, arg := range call.Args {
			if _, ok := arg.(*ast.CallExpr); ok {
				next = arg
				break
			}
		}
		if next == nil {
			return chain
		}
		expr = next
	}
}

// calleeName renders the thing being called. A call expression as the callee is
// a middleware factory (CORSMiddleware(nil)(next)); report the factory's name.
func calleeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return calleeName(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return calleeName(v.Fun)
	default:
		return "?"
	}
}
