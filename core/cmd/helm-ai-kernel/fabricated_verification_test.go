package main

// quantum_posture: these regression tests exercise classical Ed25519 AAT
// signatures and a structurally forged SEV-SNP report; no post-quantum
// assurance is claimed.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// HELM-742 retired these routes to 501 because each reported a verification
// that no check produced (findings 01-01, 01-06, 02-04, 04-07, 05-01, 23-03).
// HELM-756 removes them: none is routed any more, so no caller can reach a
// fabricated PASS, a hash-recompute "verified", or a trust-key mutation that no
// verifier reads.
func TestRetiredVerificationRoutesAreNotRouted(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	surfaces := boundarypkg.NewSurfaceRegistry(time.Now)
	svc.BoundarySurfaces = surfaces
	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	forgedGUIReceipt := `{"receipt_id":"gui-1","grounded_action_ref":"ga-1",` +
		`"screenshot_hash":"sha256:aa","dom_or_ax_snapshot_hash":"sha256:bb","target_ref":"button#pay",` +
		`"bbox_or_element_id":"el-1","action_type":"click","precondition":"visible","postcondition":"paid",` +
		`"postcondition_ref":"pc-1","postcondition_verified":true,"proof_graph_node_ref":"node-1",` +
		`"verification_scope_ref":"scope-1","policy_hash":"sha256:cc","created_at":"2026-09-24T00:00:00Z",` +
		`"receipt_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/conformance/run", `{"level":"L4","profile":"sota-2026"}`},
		{http.MethodGet, "/api/v1/conformance/reports", ""},
		{http.MethodGet, "/api/v1/conformance/reports/conf_any", ""},
		{http.MethodPost, "/api/v1/gui/receipts/verify", forgedGUIReceipt},
		{http.MethodPost, "/api/v1/trust/keys/add", `{"tenant_id":"t1","key_id":"k1","public_key":"` + strings.Repeat("ab", 32) + `"}`},
		{http.MethodPost, "/api/v1/trust/keys/revoke", `{"tenant_id":"t1","key_id":"k1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			authorizeTestRequest(req)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (not routed); body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, claim := range []string{`"PASS"`, `"verified":true`, "key_revoked", "key_added"} {
				if strings.Contains(body, claim) {
					t.Fatalf("retired route still claims %s: %s", claim, body)
				}
			}
		})
	}
	if reports := surfaces.ListReports(); len(reports) != 0 {
		t.Fatalf("retired conformance routes persisted reports: %v", reports)
	}
}

// HELM-742 / 01-02: `certify` issued named-regulation attestations from file
// names, and `gui receipts verify` recomputed the hash it claimed to verify
// (02-04). Both commands are removed.
func TestFabricatedVerificationCommandsAreRemoved(t *testing.T) {
	for _, args := range [][]string{
		{"certify", "--pack", t.TempDir(), "--framework", "hipaa"},
		{"gui", "receipts", "verify", "--input", "receipt.json"},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "Unknown command") {
			t.Fatalf("%v: exit %d, want unknown command (2); stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "PASS") {
			t.Fatalf("%v still prints a PASS: %s", args, stdout.String())
		}
	}
}

// HELM-742 / 04-02: a consistency proof carries its own roots, so verifying it
// without caller-supplied roots proves nothing.
func TestTranslogVerifyConsistencyRequiresTrustedRoots(t *testing.T) {
	root := strings.Repeat("ab", 32)
	forged := fmt.Sprintf(`{"old_size":5,"new_size":5,"old_root":%q,"new_root":%q,"consistency_path":[]}`, root, root)
	path := filepath.Join(t.TempDir(), "forged_consistency.json")
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"log", "verify-consistency", "--proof", path},
		{"log", "verify-consistency", "--proof", path, "--old-root", root},
		{"log", "verify-consistency", "--proof", path, "--new-root", root},
	} {
		code, out, errOut := runLogCLI(t, args...)
		if code != 2 || strings.HasPrefix(out, "OK:") {
			t.Fatalf("%v: exit %d, want 2 (roots required); out=%s err=%s", args[2:], code, out, errOut)
		}
	}
}

// HELM-742 / 02-03: `export aat --verify` must check signatures against a
// caller-supplied key, and must not pass an unsigned, downgraded, re-signed
// or empty chain.
func TestExportAATVerifyRequiresTrustedKey(t *testing.T) {
	dir := t.TempDir()
	inPath := writeAATTestEntries(t, dir)
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	trustedKey := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))

	export := func(name string, signSeed []byte) string {
		t.Helper()
		out := filepath.Join(dir, name)
		args := []string{"aat", "--in", inPath, "--out", out, "--agent-id", "agent-1"}
		if signSeed != nil {
			args = append(args, "--sign-key", hex.EncodeToString(signSeed))
		}
		var stdout, stderr bytes.Buffer
		if code := runExportCmd(args, &stdout, &stderr); code != 0 {
			t.Fatalf("export %s exited %d: %s", name, code, stderr.String())
		}
		return out
	}
	signed := export("signed.jsonl", seed)
	unsigned := export("unsigned.jsonl", nil)
	otherKey := export("other.jsonl", bytes.Repeat([]byte{0x07}, ed25519.SeedSize))

	signedBytes, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	downgraded := filepath.Join(dir, "downgraded.jsonl")
	if err := os.WriteFile(downgraded, bytes.ReplaceAll(signedBytes, []byte(`"algorithm":"Ed25519"`), []byte(`"algorithm":"ed25519"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	verify := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := runExportCmd(append([]string{"aat"}, args...), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}

	if code, out := verify("--verify", signed); code != 2 {
		t.Fatalf("--verify without --public-key: exit %d, want 2; out=%s", code, out)
	}
	for name, path := range map[string]string{
		"unsigned":   unsigned,
		"downgraded": downgraded,
		"other key":  otherKey,
		"empty":      empty,
	} {
		if code, out := verify("--verify", path, "--public-key", trustedKey); code != 1 || strings.Contains(out, "AAT chain OK") {
			t.Fatalf("%s chain: exit %d, want 1; out=%s", name, code, out)
		}
	}
	if code, out := verify("--verify", signed, "--public-key", trustedKey); code != 0 || !strings.Contains(out, "AAT chain OK: 2 records verified") {
		t.Fatalf("signed chain with trusted key: exit %d; out=%s", code, out)
	}
}

// HELM-742 / 04-04: an ALLOW whose receipt cannot be persisted must not reach
// the upstream provider.
func TestGovernedOpenAIProxyFailsClosedWhenReceiptPersistenceFails(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	signer, err := helmcrypto.NewEd25519Signer("openai-receipt-failure-test")
	if err != nil {
		t.Fatal(err)
	}
	rcptStore := &captureReceiptStore{}
	svc := &Services{
		Guardian: guardian.NewGuardian(
			signer,
			allowGraphForExtAuthzTest("LLM_INFERENCE"),
			artifacts.NewRegistry(nil, nil),
			guardian.WithPDP(&evaluateRouteCapturingPDP{}),
		),
		ReceiptStore:  rcptStore,
		ReceiptSigner: signer,
		TranspLog:     &fakeTransparencyLog{appendErr: errors.New("transparency log unavailable")},
		TranspLogID:   "log-test",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[]}`))
	req.Header.Set(workspaceHeader, "workspace-a")
	ctx := auth.WithPrincipal(req.Context(), &auth.BasePrincipal{ID: "proxy-agent", TenantID: "tenant-a"})
	ctx = auth.WithAuthenticatedCredential(ctx, "proxy-credential")
	rec := httptest.NewRecorder()
	handleGovernedOpenAIProxy(rec, req.WithContext(ctx), svc)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream called %d times without a persisted receipt", got)
	}
	if rcptStore.stored != nil {
		t.Fatalf("receipt stored despite failed transparency append: %+v", rcptStore.stored)
	}
}
