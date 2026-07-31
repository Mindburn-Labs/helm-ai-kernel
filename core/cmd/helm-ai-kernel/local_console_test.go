package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestDiscoverLocalConsoleBundleUsesOnlyExecutableRelativeBundle(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "bin", "helm-ai-kernel")
	if err := os.MkdirAll(filepath.Dir(executable), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("kernel"), 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(executable), localConsoleDirectory, localConsoleBundlePrefix+target)
	writeLocalConsoleBundle(t, root, target, "console-server")

	original := localConsoleExecutable
	localConsoleExecutable = func() (string, error) { return executable, nil }
	t.Cleanup(func() { localConsoleExecutable = original })
	bundle, err := discoverLocalConsoleBundle()
	if err != nil {
		t.Fatalf("discover executable-relative bundle: %v", err)
	}
	wantRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Root != wantRoot ||
		bundle.ServerPath != filepath.Join(wantRoot, filepath.FromSlash(localConsoleServerFile)) ||
		bundle.NodePath != filepath.Join(wantRoot, filepath.FromSlash(localConsoleNodeFile)) {
		t.Fatalf("bundle = %#v", bundle)
	}
	if err := os.RemoveAll(filepath.Join(filepath.Dir(executable), localConsoleDirectory)); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverLocalConsoleBundle(); err == nil || err.Error() != "matching console bundle is missing for "+target {
		t.Fatalf("missing bundle error = %v", err)
	}
}

func TestDiscoverLocalConsoleBundleResolvesExecutableSymlink(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	realExecutable := filepath.Join(dir, "real", "helm-ai-kernel")
	if err := os.MkdirAll(filepath.Dir(realExecutable), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realExecutable, []byte("kernel"), 0700); err != nil {
		t.Fatal(err)
	}
	invocationPath := filepath.Join(dir, "bin", "helm-ai-kernel")
	if err := os.MkdirAll(filepath.Dir(invocationPath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realExecutable, invocationPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	wantRoot := filepath.Join(filepath.Dir(realExecutable), localConsoleDirectory, localConsoleBundlePrefix+target)
	writeLocalConsoleBundle(t, wantRoot, target, "console-server")

	original := localConsoleExecutable
	localConsoleExecutable = func() (string, error) { return invocationPath, nil }
	t.Cleanup(func() { localConsoleExecutable = original })
	bundle, err := discoverLocalConsoleBundle()
	if err != nil {
		t.Fatalf("discover symlinked executable bundle: %v", err)
	}
	wantRoot, err = filepath.EvalSymlinks(wantRoot)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Root != wantRoot {
		t.Fatalf("bundle root = %q, want %q", bundle.Root, wantRoot)
	}
}

func TestLocalConsoleBundleRejectsTraversalHashTargetAndSymlink(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{
			name: "traversal",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				writeLocalConsoleInventoryAndProvenance(t, root, target, strings.Repeat("0", 64)+"  ../outside\n", target, "v1")
			},
			want: "inventory path",
		},
		{
			name: "hash mismatch",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				serverHash, err := sha256LocalConsoleFile(filepath.Join(root, filepath.FromSlash(localConsoleServerFile)))
				if err != nil {
					t.Fatal(err)
				}
				inventory := strings.Replace(localConsoleInventoryContents(t, root), serverHash+"  "+localConsoleServerFile, strings.Repeat("0", 64)+"  "+localConsoleServerFile, 1)
				writeLocalConsoleInventoryAndProvenance(t, root, target, inventory, target, "v1")
			},
			want: "file hash",
		},
		{
			name: "target mismatch",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				contents := localConsoleInventoryContents(t, root)
				otherTarget := "linux-amd64"
				if target == otherTarget {
					otherTarget = "darwin-arm64"
				}
				writeLocalConsoleInventoryAndProvenance(t, root, target, contents, otherTarget, "v1")
			},
			want: "target does not match",
		},
		{
			name: "trailing provenance document",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				provenancePath := filepath.Join(root, localConsoleProvenanceFile)
				contents, err := os.ReadFile(provenancePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(provenancePath, append(contents, []byte("{}\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "trailing content",
		},
		{
			name: "non-isolated build provenance",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				mutateLocalConsoleProvenance(t, root, func(contents []byte) []byte {
					return bytes.ReplaceAll(contents, []byte(localConsoleBuildEnvironment), []byte("untrusted ambient environment"))
				})
			},
			want: "isolated build",
		},
		{
			name: "runtime target mismatch",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				mutateLocalConsoleProvenance(t, root, func(contents []byte) []byte {
					return bytes.ReplaceAll(contents, []byte(`"target": "`+target+`"`), []byte(`"target": "wrong-target"`))
				})
			},
			want: "runtime is incomplete",
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("console-server"), 0600); err != nil {
					t.Fatal(err)
				}
				server := filepath.Join(root, filepath.FromSlash(localConsoleServerFile))
				if err := os.Remove(server); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, server); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "symlink",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "bundle")
			writeLocalConsoleBundle(t, root, target, "console-server")
			tc.mutate(t, root)
			if _, err := loadLocalConsoleBundle(root, target); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLocalConsoleBundleRequiresBundledNodeRuntime(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   string
	}{
		{
			name: "missing node inventory record",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				inventory := localConsoleInventoryForPaths(t, root, localConsoleServerFile, localConsoleNodeLicenseFile)
				writeLocalConsoleInventoryAndProvenance(t, root, target, inventory, target, "v1")
			},
			want: "inventory is missing " + localConsoleNodeFile,
		},
		{
			name: "missing node license inventory record",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				inventory := localConsoleInventoryForPaths(t, root, localConsoleServerFile, localConsoleNodeFile)
				writeLocalConsoleInventoryAndProvenance(t, root, target, inventory, target, "v1")
			},
			want: "inventory is missing " + localConsoleNodeLicenseFile,
		},
		{
			name: "non-executable node",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(root, filepath.FromSlash(localConsoleNodeFile)), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "bundled Node is not executable",
		},
		{
			name: "node symlink",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "node")
				if err := os.WriteFile(outside, []byte("node"), 0700); err != nil {
					t.Fatal(err)
				}
				node := filepath.Join(root, filepath.FromSlash(localConsoleNodeFile))
				if err := os.Remove(node); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, node); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "required runtime file is invalid",
		},
		{
			name: "node license symlink",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "LICENSE")
				if err := os.WriteFile(outside, []byte("license"), 0600); err != nil {
					t.Fatal(err)
				}
				license := filepath.Join(root, filepath.FromSlash(localConsoleNodeLicenseFile))
				if err := os.Remove(license); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, license); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "required runtime file is invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "bundle")
			writeLocalConsoleBundle(t, root, target, "console-server")
			tc.mutate(t, root)
			if _, err := loadLocalConsoleBundle(root, target); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLocalConsoleChildEnvIsAllowlistedAndServerOnly(t *testing.T) {
	t.Setenv("HELM_API_ORIGIN", "https://untrusted.example")
	t.Setenv("HELM_SECRET_LEAK", "do-not-inherit")
	t.Setenv("CLERK_SECRET_KEY", "do-not-inherit")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "do-not-inherit")
	runtime := &quickstartRuntime{
		SessionToken: "kernel-secret-token",
		TenantID:     "tenant-local",
		PrincipalID:  "principal-local",
	}
	env, err := localConsoleChildEnv("http://127.0.0.1:7714", 3400, runtime, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string, len(env))
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			t.Fatalf("malformed child env %q", pair)
		}
		got[key] = value
	}
	want := map[string]string{
		"NODE_ENV":                        "production",
		"HOSTNAME":                        "127.0.0.1",
		"PORT":                            "3400",
		"NEXT_PUBLIC_HELM_API_MODE":       "kernel",
		"HELM_CONSOLE_ORIGIN":             "http://127.0.0.1:3400",
		"HELM_KERNEL_ORIGIN":              "http://127.0.0.1:7714",
		"HELM_KERNEL_TOKEN":               "kernel-secret-token",
		"HELM_KERNEL_TENANT":              "tenant-local",
		"HELM_KERNEL_PRINCIPAL":           "principal-local",
		"HELM_LOCAL_SIDECAR_READY_SECRET": strings.Repeat("a", 64),
		"HELM_LOCAL_KERNEL_PEER_SECRET":   strings.Repeat("b", 64),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("child env = %#v, want %#v", got, want)
	}
	for _, forbidden := range []string{"HELM_API_ORIGIN", "HELM_SECRET_LEAK", "CLERK_SECRET_KEY", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("child inherited %s", forbidden)
		}
	}
}

func TestLocalConsoleReadinessRequiresHMACWithoutCredentialsOnWire(t *testing.T) {
	secret := strings.Repeat("a", 64)
	nonce := strings.Repeat("b", 64)
	token := "kernel-secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != localConsoleReadyPath {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get(localConsoleReadyNonceHeader) != nonce {
			t.Fatal("readiness nonce missing")
		}
		for _, value := range r.Header.Values("Authorization") {
			if strings.Contains(value, token) || strings.Contains(value, secret) {
				t.Fatal("readiness request leaked a credential")
			}
		}
		w.Header().Set(localConsoleReadyProofHeader, localConsoleReadyProof(secret, nonce))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if !localConsoleReadyProofValid(testingContext(t), server.URL, secret, nonce) {
		t.Fatal("valid nonce HMAC was rejected")
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(localConsoleReadyProofHeader, strings.Repeat("0", 64))
		w.WriteHeader(http.StatusOK)
	}))
	defer badServer.Close()
	if localConsoleReadyProofValid(testingContext(t), badServer.URL, secret, nonce) {
		t.Fatal("invalid nonce HMAC was accepted")
	}
	if proof := localConsoleReadyProof(secret, nonce); strings.Contains(proof, secret) || strings.Contains(proof, token) {
		t.Fatal("readiness proof exposed a credential")
	}
}

func TestLocalConsolePeerProofRouteRequiresFreshLoopbackNonceWithoutBearer(t *testing.T) {
	secret := strings.Repeat("a", 64)
	peer, err := newLocalConsolePeerProof(secret)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{
		Quickstart:       &quickstartRuntime{SessionToken: "session-secret"},
		ConsoleMode:      true,
		ConsolePeerProof: peer,
	})

	nonce := strings.Repeat("b", 64)
	request := httptest.NewRequest(http.MethodGet, localConsolePeerProofPath, nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set(localConsolePeerNonceHeader, nonce)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("peer proof response = status %d body %q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(localConsolePeerContractHeader); got != localConsolePeerContract {
		t.Fatalf("peer contract = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
	decoded, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, decoded)
	_, _ = mac.Write([]byte(nonce))
	wantProof := hex.EncodeToString(mac.Sum(nil))
	if got := recorder.Header().Get(localConsolePeerProofHeader); !hmac.Equal([]byte(got), []byte(wantProof)) {
		t.Fatalf("peer proof = %q, want %q", got, wantProof)
	}

	// A proof nonce is one-time: replayed proof requests fail closed instead of
	// becoming a reusable peer-authentication oracle.
	replay := httptest.NewRecorder()
	mux.ServeHTTP(replay, request)
	if replay.Code != http.StatusNotFound || replay.Header().Get(localConsolePeerProofHeader) != "" {
		t.Fatalf("replayed peer proof = status %d headers %#v", replay.Code, replay.Header())
	}

	head := httptest.NewRequest(http.MethodHead, localConsolePeerProofPath, nil)
	head.RemoteAddr = "127.0.0.1:12346"
	head.Header.Set(localConsolePeerNonceHeader, strings.Repeat("c", 64))
	headRecorder := httptest.NewRecorder()
	mux.ServeHTTP(headRecorder, head)
	if headRecorder.Code != http.StatusOK || headRecorder.Body.Len() != 0 {
		t.Fatalf("HEAD peer proof = status %d body %q", headRecorder.Code, headRecorder.Body.String())
	}

	for _, tc := range []struct {
		name   string
		remote string
		nonce  string
		bearer string
	}{
		{name: "non-loopback", remote: "192.0.2.25:12345", nonce: strings.Repeat("d", 64)},
		{name: "bearer", remote: "127.0.0.1:12345", nonce: strings.Repeat("e", 64), bearer: "Bearer session-secret"},
		{name: "invalid nonce", remote: "127.0.0.1:12345", nonce: "not-hex"},
		{name: "multiple nonce headers", remote: "127.0.0.1:12345", nonce: strings.Repeat("f", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, localConsolePeerProofPath, nil)
			req.RemoteAddr = tc.remote
			req.Header.Set(localConsolePeerNonceHeader, tc.nonce)
			if tc.name == "multiple nonce headers" {
				req.Header.Add(localConsolePeerNonceHeader, strings.Repeat("0", 64))
			}
			if tc.bearer != "" {
				req.Header.Set("Authorization", tc.bearer)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 || rec.Header().Get(localConsolePeerProofHeader) != "" {
				t.Fatalf("peer proof = status %d body %q headers %#v", rec.Code, rec.Body.String(), rec.Header())
			}
		})
	}
}

func TestLocalConsolePeerProofRouteIsAbsentOutsideConsoleMode(t *testing.T) {
	peer, err := newLocalConsolePeerProof(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{
		Quickstart:       &quickstartRuntime{SessionToken: "session-secret"},
		ConsolePeerProof: peer,
	})
	req := httptest.NewRequest(http.MethodGet, localConsolePeerProofPath, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(localConsolePeerNonceHeader, strings.Repeat("b", 64))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-console peer route status = %d", rec.Code)
	}
}

func TestWriteQuickstartReadyFormatsIPv6KernelURL(t *testing.T) {
	var stdout bytes.Buffer
	writeQuickstartReady(&stdout, quickstartPrepared{PolicyPath: "policy.toml"}, "::1", 7714, "", false)

	if got, want := stdout.String(), "Kernel:  http://[::1]:7714\n"; !strings.Contains(got, want) {
		t.Fatalf("quickstart readiness output = %q, want valid IPv6 Kernel URL %q", got, want)
	}
	if strings.Contains(stdout.String(), "http://::1:") {
		t.Fatalf("quickstart readiness output contains invalid IPv6 URL: %q", stdout.String())
	}
}

func TestLocalConsoleSupervisorUsesDistinctCSPRNGReadinessAndPeerSecrets(t *testing.T) {
	supervisor, err := newLocalConsoleSupervisor(localConsoleBundle{}, 0, &quickstartRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	peer := supervisor.PeerProof()
	if !validLocalConsoleSecret(supervisor.secret) || peer == nil || !validLocalConsoleSecret(peer.secret) {
		t.Fatalf("invalid generated Console secrets readiness=%q peer=%#v", supervisor.secret, peer)
	}
	if hmac.Equal([]byte(supervisor.secret), []byte(peer.secret)) {
		t.Fatal("readiness and peer secrets must be distinct")
	}
}

func TestQuickstartConsoleFailsBeforeMutationForExternalOverrideOrMissingBundle(t *testing.T) {
	t.Setenv("HELM_LOCAL_KERNEL_PEER_SECRET", "untrusted-parent-value")
	err := validateQuickstartOptions(quickstartOptions{
		Addr:        "127.0.0.1",
		Port:        7714,
		DataDir:     filepath.Join(t.TempDir(), "data"),
		Profile:     "mcp",
		Console:     true,
		ConsolePort: 3400,
	})
	if err == nil || !strings.Contains(err.Error(), "HELM_LOCAL_KERNEL_PEER_SECRET") {
		t.Fatalf("external peer secret override error = %v", err)
	}
	t.Setenv("HELM_LOCAL_KERNEL_PEER_SECRET", "")

	dir := t.TempDir()
	executable := filepath.Join(dir, "bin", "helm-ai-kernel")
	if err := os.MkdirAll(filepath.Dir(executable), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("kernel"), 0700); err != nil {
		t.Fatal(err)
	}
	original := localConsoleExecutable
	localConsoleExecutable = func() (string, error) { return executable, nil }
	t.Cleanup(func() { localConsoleExecutable = original })
	dataDir := filepath.Join(dir, "quickstart-data")
	var stdout, stderr bytes.Buffer
	if code := runQuickstartCmdWithReady([]string{"--console", "--dry-run", "--data-dir", dataDir}, &stdout, &stderr, nil); code != 1 {
		t.Fatalf("dry-run exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "matching console bundle is missing") {
		t.Fatalf("missing bundle error = %s", stderr.String())
	}
	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Fatalf("missing bundle dry-run mutated %q: %v", dataDir, statErr)
	}
}

func TestLocalConsoleDoesNotOpenBeforeReadinessProof(t *testing.T) {
	original := openLocalConsoleURL
	opened := false
	openLocalConsoleURL = func(string) error {
		opened = true
		return nil
	}
	t.Cleanup(func() { openLocalConsoleURL = original })
	if err := ensureLocalConsoleReadyThenOpen(func() error { return errors.New("proof failed") }, false, "http://127.0.0.1:3400"); err == nil {
		t.Fatal("missing readiness failure")
	}
	if opened {
		t.Fatal("browser opener ran before readiness proof")
	}
	if err := ensureLocalConsoleReadyThenOpen(func() error { return nil }, false, "http://127.0.0.1:3400"); err != nil || !opened {
		t.Fatalf("opener after proof err=%v opened=%v", err, opened)
	}
	opened = false
	if err := ensureLocalConsoleReadyThenOpen(func() error { return nil }, true, "http://127.0.0.1:3400"); err != nil || opened {
		t.Fatalf("--no-open err=%v opened=%v", err, opened)
	}
}

func TestLocalConsoleSupervisorDetectsCrashAndStopsOnKernelShutdown(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	root := filepath.Join(t.TempDir(), "bundle")
	bundle := writeLocalConsoleBundle(t, root, target, "console-server")
	originalCommand := localConsoleCommand
	gotNodePath := ""
	localConsoleCommand = func(node string, args ...string) *exec.Cmd {
		gotNodePath = node
		if strings.Contains(strings.Join(args, " "), "kernel-secret-token") {
			t.Fatal("token was passed in the child argv")
		}
		return exec.Command(os.Args[0], "-test.run=^TestLocalConsoleHelperProcess$", "--")
	}
	t.Cleanup(func() {
		localConsoleCommand = originalCommand
	})

	crashed, err := newLocalConsoleSupervisor(bundle, 0, &quickstartRuntime{
		SessionToken: "kernel-secret-token",
		TenantID:     "tenant-local",
		PrincipalID:  "local-console-crash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crashed.Start("http://127.0.0.1:7714"); err != nil {
		t.Fatal(err)
	}
	if gotNodePath != bundle.NodePath {
		t.Fatalf("sidecar executable = %q, want bundled Node %q", gotNodePath, bundle.NodePath)
	}
	select {
	case <-crashed.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar crash was not observed")
	}

	running, err := newLocalConsoleSupervisor(bundle, 0, &quickstartRuntime{
		SessionToken: "kernel-secret-token",
		TenantID:     "tenant-local",
		PrincipalID:  "local-console-sleep",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := running.Start("http://127.0.0.1:7714"); err != nil {
		t.Fatal(err)
	}
	running.Stop()
	select {
	case <-running.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Kernel shutdown did not clean up sidecar")
	}
}

func TestLocalConsoleSupervisorGracefullyStopsWrapperChildAndPort(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required to exercise the packaged sidecar signal handoff")
	}
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	bundle := writeLocalConsoleSignalForwardingBundle(t, filepath.Join(t.TempDir(), "bundle"), target, node)
	originalCommand := localConsoleCommand
	localConsoleCommand = exec.Command
	t.Cleanup(func() {
		localConsoleCommand = originalCommand
	})

	supervisor, err := newLocalConsoleSupervisor(bundle, 0, &quickstartRuntime{
		SessionToken: "kernel-secret-token",
		TenantID:     "tenant-local",
		PrincipalID:  "local-console-graceful-stop",
	})
	if err != nil {
		t.Fatal(err)
	}
	consoleURL, err := supervisor.Start("http://127.0.0.1:7714")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(supervisor.Stop)
	waitForLocalConsoleTestListener(t, consoleURL)

	supervisor.Stop()
	select {
	case <-supervisor.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("local Console wrapper did not exit after graceful stop")
	}
	if _, err := os.Stat(filepath.Join(bundle.AppRoot, "graceful-stop")); err != nil {
		t.Fatalf("local Console child did not receive the forwarded interrupt: %v", err)
	}
	assertLocalConsoleTestPortReleased(t, strings.TrimPrefix(consoleURL, "http://"))
}

func TestQuickstartConsoleSuppressesBootstrapExchangeAndSummaryTokens(t *testing.T) {
	runtime := &quickstartRuntime{
		BootstrapToken: "bootstrap-secret",
		SessionToken:   "session-secret",
		TenantID:       "tenant-local",
		PrincipalID:    "principal-local",
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	prepared := quickstartPrepared{Console: true, Runtime: runtime}
	summary := fmt.Sprint(prepared.summary("start"))
	if strings.Contains(summary, runtime.BootstrapToken) || strings.Contains(summary, runtime.SessionToken) || strings.Contains(summary, "local_session_exchange_url") {
		t.Fatalf("console summary exposed bootstrap state: %s", summary)
	}
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{Quickstart: runtime, ConsoleMode: true})
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/local-session/exchange", nil),
		httptest.NewRequest(http.MethodGet, "/__helm/config.json", nil),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", req.Method, req.URL.Path, rec.Code)
		}
	}
}

func TestPrepareQuickstartConsoleSkipsLocalSessionCredential(t *testing.T) {
	target, err := localConsoleTarget()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "bin", "helm-ai-kernel")
	if err := os.MkdirAll(filepath.Dir(executable), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("kernel"), 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(filepath.Dir(executable), localConsoleDirectory, localConsoleBundlePrefix+target)
	writeLocalConsoleBundle(t, root, target, "console-server")
	originalExecutable := localConsoleExecutable
	localConsoleExecutable = func() (string, error) { return executable, nil }
	t.Cleanup(func() { localConsoleExecutable = originalExecutable })

	dataDir := filepath.Join(dir, "state")
	prepared, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
		Console: true,
	})
	if err != nil {
		t.Fatalf("prepare Console quickstart: %v", err)
	}
	if prepared.LocalSessionCredentialPath != "" {
		t.Fatalf("Console quickstart credential path = %q, want empty", prepared.LocalSessionCredentialPath)
	}
	if prepared.Runtime == nil || prepared.Runtime.BootstrapToken != "" || prepared.Runtime.BootstrapCredentialPath != "" {
		t.Fatal("Console quickstart retained bootstrap credential state")
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartSessionCredentialFile)); !os.IsNotExist(err) {
		t.Fatalf("Console quickstart wrote a local session credential: %v", err)
	}
	if marker, err := os.ReadFile(filepath.Join(dataDir, quickstartOwnershipMarker)); err != nil || string(marker) != quickstartOwnershipMarkerContents {
		t.Fatalf("Console quickstart ownership marker = %q, err=%v", marker, err)
	}
	for _, field := range []string{"local_session_exchange_url", "local_session_credential_path", "tenant_id", "principal_id"} {
		if _, present := prepared.summary("start")[field]; present {
			t.Fatalf("Console quickstart summary exposed %s", field)
		}
	}
}

func TestReserveLocalConsolePortUsesLoopbackAndAvoidsActiveCollision(t *testing.T) {
	listener, port, err := reserveLocalConsolePort(0)
	if err != nil {
		t.Fatal(err)
	}
	if port <= 0 || listener.Addr().String() == "" {
		t.Fatalf("reservation = %s, port=%d", listener.Addr(), port)
	}
	if replacement, err := net.Listen("tcp", listener.Addr().String()); err == nil {
		_ = replacement.Close()
		_ = listener.Close()
		t.Fatal("active reservation did not prevent a port collision")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalConsoleHelperProcess(t *testing.T) {
	switch os.Getenv("HELM_KERNEL_PRINCIPAL") {
	case "local-console-crash":
		return
	case "local-console-sleep":
		select {}
	}
}

func waitForLocalConsoleTestListener(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get(url)
		if err == nil {
			_ = response.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("local Console test listener did not start at %s: %v", url, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertLocalConsoleTestPortReleased(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			_ = listener.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("local Console child kept %s bound after wrapper exit: %v", address, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeLocalConsoleBundle(t *testing.T, root, target, server string) localConsoleBundle {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(localConsoleServerFile)), []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	writeLocalConsoleRuntimeFixture(t, root)
	writeLocalConsoleInventoryAndProvenance(t, root, target, localConsoleInventoryContents(t, root), target, "v1")
	bundle, err := loadLocalConsoleBundle(root, target)
	if err != nil {
		t.Fatalf("load test bundle: %v", err)
	}
	return bundle
}

func writeLocalConsoleSignalForwardingBundle(t *testing.T, root, target, node string) localConsoleBundle {
	t.Helper()
	appRoot := filepath.Join(root, "app")
	if err := os.MkdirAll(appRoot, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(localConsoleServerFile)), []byte(localConsoleSignalForwardingWrapper), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appRoot, "server.js"), []byte(localConsoleSignalForwardingChild), 0700); err != nil {
		t.Fatal(err)
	}
	writeLocalConsoleRuntimeLinkFixture(t, root, node)
	inventory := localConsoleInventoryForPaths(t, root, localConsoleServerFile, "app/server.js", localConsoleNodeFile, localConsoleNodeLicenseFile)
	writeLocalConsoleInventoryAndProvenance(t, root, target, inventory, target, "v1")
	bundle, err := loadLocalConsoleBundle(root, target)
	if err != nil {
		t.Fatalf("load signal-forwarding Console bundle: %v", err)
	}
	return bundle
}

func writeLocalConsoleRuntimeFixture(t *testing.T, root string) {
	t.Helper()
	node := filepath.Join(root, filepath.FromSlash(localConsoleNodeFile))
	if err := os.MkdirAll(filepath.Dir(node), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(localConsoleNodeLicenseFile)), []byte("test node license\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeLocalConsoleRuntimeLinkFixture(t *testing.T, root, node string) {
	t.Helper()
	node, err := filepath.EvalSymlinks(node)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(node)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("test Node runtime is not an executable regular file: %v", err)
	}
	bundledNode := filepath.Join(root, filepath.FromSlash(localConsoleNodeFile))
	if err := os.MkdirAll(filepath.Dir(bundledNode), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(node, bundledNode); err != nil {
		t.Skipf("hard links unavailable for bundled Node fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(localConsoleNodeLicenseFile)), []byte("test node license\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

const localConsoleSignalForwardingWrapper = `import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const server = resolve(dirname(fileURLToPath(import.meta.url)), 'server.js');
const child = spawn(process.execPath, [server], { env: process.env, stdio: 'ignore', shell: false });
let forwardedSignal = false;

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    if (!forwardedSignal && !child.killed) {
      forwardedSignal = true;
      child.kill(signal);
    }
  });
}

child.once('error', () => { process.exitCode = 1; });
child.once('exit', (code) => { process.exitCode = code ?? 1; });
`

const localConsoleSignalForwardingChild = `import { writeFileSync } from 'node:fs';
import http from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const marker = resolve(dirname(fileURLToPath(import.meta.url)), 'graceful-stop');
const server = http.createServer((_, response) => {
  response.writeHead(204);
  response.end();
});
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  writeFileSync(marker, 'stopped\\n');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 1000).unref();
}
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
server.listen(Number(process.env.PORT), process.env.HOSTNAME);
`

func localConsoleInventoryContents(t *testing.T, root string) string {
	t.Helper()
	return localConsoleInventoryForPaths(t, root, localConsoleServerFile, localConsoleNodeFile, localConsoleNodeLicenseFile)
}

func localConsoleInventoryForPaths(t *testing.T, root string, paths ...string) string {
	t.Helper()
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	lines := make([]string, 0, len(paths))
	for _, relativePath := range paths {
		fileHash, err := sha256LocalConsoleFile(filepath.Join(root, filepath.FromSlash(relativePath)))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fileHash+"  "+relativePath)
	}
	return strings.Join(lines, "\n") + "\n"
}

func mutateLocalConsoleProvenance(t *testing.T, root string, mutate func([]byte) []byte) {
	t.Helper()
	provenancePath := filepath.Join(root, localConsoleProvenanceFile)
	contents, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(provenancePath, mutate(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeLocalConsoleInventoryAndProvenance(t *testing.T, root, target, inventory, manifestTarget, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, localConsoleInventoryFile), []byte(inventory), 0600); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(manifestTarget, "-")
	if len(parts) != 2 {
		t.Fatal("invalid test target")
	}
	libcFamily := "glibc"
	if parts[0] == "darwin" {
		libcFamily = "libSystem"
	}
	provenance := fmt.Sprintf(`{
  "schema": %q,
  "target": {"os": %q, "arch": %q},
  "build": {"api_mode": "kernel", "closure": %q, "source_snapshot": %q, "environment": %q},
  "source": {"commit": %q, "tree": %q, "version": %q, "package_lock_sha256": %q},
  "bundle_sha256": %q,
  "inventory": "INVENTORY.sha256",
  "bundle_hash_scope": "sorted sha256 records for app payload files; this binds the exact build and is not a cross-checkout byte-reproducibility claim",
  "runtime": {
    "node": "v22.0.0",
    "npm": "10.0.0",
    "next": "15.0.0",
    "platform": {"os": %q, "arch": %q, "target": %q},
    "libc": {"family": %q, "version": "test"}
  },
  "signature": %q
}`, localConsoleProvenanceSchema, parts[0], parts[1], localConsoleBuildClosure, localConsoleBuildSourceSnapshot, localConsoleBuildEnvironment, strings.Repeat("a", 40), strings.Repeat("b", 40), version, strings.Repeat("c", 64), sha256Hex([]byte(inventory)), parts[0], parts[1], manifestTarget, libcFamily, localConsoleUnsignedSignature) + "\n"
	if err := os.WriteFile(filepath.Join(root, localConsoleProvenanceFile), []byte(provenance), 0600); err != nil {
		t.Fatal(err)
	}
}

func testingContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
