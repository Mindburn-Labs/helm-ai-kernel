package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/authz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const surfaceTruthCredential = "synthetic-cli-truth-credential"

// Invoke the same Run entry point that main passes to os.Exit, in a separate
// process so the assertions cover actual exit status and both output streams.
func TestSurfaceTruthCLIProcess(t *testing.T) {
	if os.Getenv("HELM_SURFACE_TRUTH_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(Run(append([]string{"helm-ai-kernel"}, os.Args[i+1:]...), os.Stdout, os.Stderr))
		}
	}
	os.Exit(2)
}

func runSurfaceTruthCLI(t *testing.T, server string, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, append([]string{"-test.run=^TestSurfaceTruthCLIProcess$", "--"}, args...)...)
	values := map[string]string{
		"HELM_SURFACE_TRUTH_PROCESS": "1", "HELM_NO_TUI": "1",
		"HELM_ADMIN_API_KEY": surfaceTruthCredential, "HELM_URL": server,
		"HELM_RUNTIME_TENANT_ID": "default", "HELM_RUNTIME_PRINCIPAL_ID": "system-admin",
		"HELM_RUNTIME_WORKSPACE_ID": "", "HELM_DATA_DIR": filepath.Join(t.TempDir(), "uncreated"),
	}
	for name, value := range env {
		values[name] = value
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, overridden := values[name]; !overridden {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for name, value := range values {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), surfaceTruthCredential) {
		t.Fatal("CLI leaked the synthetic credential")
	}
	if _, err := os.Stat(values["HELM_DATA_DIR"]); !os.IsNotExist(err) {
		t.Fatalf("inspection created local authority state: %v", err)
	}
	return code, stdout.String(), stderr.String()
}

func surfaceTruthSnapshot(t *testing.T, allow bool) contracts.AuthzSnapshot {
	t.Helper()
	engine := authz.NewEngine()
	if allow {
		if err := engine.WriteTuple(t.Context(), authz.RelationTuple{Subject: "agent:anonymous-dev", Object: "tool:file_read", Relation: "can_call"}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := engine.SnapshotCheck(t.Context(), "helm-rebac", "helm-local-v1", "tool:file_read", "can_call", "agent:anonymous-dev", time.Now().UTC(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func surfaceTruthDocument(t *testing.T, command string) string {
	t.Helper()
	if strings.HasPrefix(command, "receipts ") {
		return `{"receipts":[{"receipt_id":"receipt-observed"}],"count":1,"next_cursor":"","has_more":false}`
	}
	snapshot := surfaceTruthSnapshot(t, true)
	var document any = snapshot
	if command == "authz health" {
		document = contracts.AuthzHealth{Status: "ready", Resolver: snapshot.Resolver, ModelID: snapshot.ModelID, RelationshipHash: snapshot.RelationshipHash, CheckedAt: time.Now().UTC()}
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSurfaceTruthCLIResponseMatrix(t *testing.T) {
	commands := []struct{ name, method, path string }{
		{"receipts status", http.MethodGet, "/api/v1/receipts"},
		{"receipts list", http.MethodGet, "/api/v1/receipts"},
		{"authz health", http.MethodGet, "/api/v1/authz/health"},
		{"authz check", http.MethodPost, "/api/v1/authz/check"},
	}
	cases := []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{"valid", 200, "", true},
		{"unauthorized", 401, surfaceTruthCredential, false},
		{"not_found", 404, `{"status":"ready","decision":true}`, false},
		{"unavailable", 503, `{"status":"PASS"}`, false},
		{"redirect", 302, `{"status":"PASS"}`, false},
		{"malformed", 200, `{`, false},
		{"empty_object", 200, `{}`, false},
		{"null", 200, `null`, false},
		{"multiple_documents", 200, `{} {}`, false},
		{"credential_echo", 200, `{"error":"` + surfaceTruthCredential + `"}`, false},
	}
	for _, command := range commands {
		for _, test := range cases {
			for _, format := range []string{"text", "--json", "--format=json"} {
				t.Run(command.name+"/"+test.name+"/"+format, func(t *testing.T) {
					body := test.body
					if test.valid {
						body = surfaceTruthDocument(t, command.name)
					}
					var requests atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.Method != command.method || r.URL.Path != command.path {
							t.Errorf("request = %s %s; want %s %s", r.Method, r.URL.Path, command.method, command.path)
						}
						if r.Header.Get("Authorization") != "Bearer "+surfaceTruthCredential {
							t.Error("request omitted the admin bearer credential")
						}
						if strings.HasPrefix(command.name, "receipts ") && (r.Header.Get(tenantHeader) != "default" || r.Header.Get(principalHeader) != "system-admin" || r.URL.Query().Get("limit") == "") {
							t.Error("receipt request omitted the asserted scope or bounded limit")
						}
						if command.method == http.MethodPost {
							var request map[string]any
							if json.NewDecoder(r.Body).Decode(&request) != nil || request["subject"] != "agent:anonymous-dev" || request["object"] != "tool:file_read" || request["relation"] != "can_call" {
								t.Error("authz request did not bind the selected subject, object and relation")
							}
						}
						w.Header().Set("Content-Type", "application/json")
						if test.status == 302 {
							w.Header().Set("Location", "/must-not-follow")
						}
						w.WriteHeader(test.status)
						_, _ = io.WriteString(w, body)
					}))
					defer server.Close()
					args := strings.Fields(command.name)
					if format != "text" {
						args = append(args, format)
					}
					code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, args...)
					wantCode := 1
					if test.valid {
						wantCode = 0
					}
					if code != wantCode || stderr != "" || requests.Load() != 1 {
						t.Fatalf("exit=%d want=%d requests=%d stdout=%s stderr=%s", code, wantCode, requests.Load(), stdout, stderr)
					}
					if format != "text" && !json.Valid([]byte(stdout)) {
						t.Fatalf("machine output is not JSON: %q", stdout)
					}
					if !test.valid {
						assertSurfaceTruthUnavailable(t, stdout)
					}
				})
			}
		}
	}
}

// Use only flags accepted before this repair so the baseline failure observes
// false success, rather than rejection of a newly introduced option.
func TestSurfaceTruthCLILegacyInvocationRejectsUncheckedState(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	t.Setenv("HELM_URL", server.URL)
	t.Setenv("HELM_ADMIN_API_KEY", surfaceTruthCredential)
	t.Setenv("HELM_RUNTIME_TENANT_ID", "default")
	t.Setenv("HELM_RUNTIME_PRINCIPAL_ID", "system-admin")
	t.Setenv("HELM_DATA_DIR", t.TempDir())
	for _, args := range [][]string{
		{"receipts", "status", "--server", server.URL, "--json"},
		{"receipts", "list", "--server", server.URL, "--json"},
		{"authz", "health", "--json"},
		{"authz", "check", "--json"},
	} {
		t.Run(strings.Join(args[:2], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr)
			if code == 0 {
				t.Fatalf("unchecked or failed remote operation returned success: %s", stdout.String())
			}
		})
	}
}

func assertSurfaceTruthUnavailable(t *testing.T, output string) {
	t.Helper()
	for _, claim := range []string{"PASS", `"ready"`, "health: ready", "ALLOW", `"decision"`, "decision=true", "decision=false"} {
		if strings.Contains(output, claim) {
			t.Fatalf("unchecked output contains %q: %s", claim, output)
		}
	}
}

func TestSurfaceTruthCLIUnavailableTransportAndCredentials(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	for _, command := range []string{"receipts status", "receipts list", "authz health", "authz check"} {
		for _, format := range []string{"text", "--json", "--format=json"} {
			for _, noCredential := range []bool{false, true} {
				t.Run(command+"/"+format+"/missing_key="+strconv.FormatBool(noCredential), func(t *testing.T) {
					var env map[string]string
					if noCredential {
						env = map[string]string{"HELM_ADMIN_API_KEY": ""}
					}
					args := strings.Fields(command)
					if format != "text" {
						args = append(args, format)
					}
					code, stdout, stderr := runSurfaceTruthCLI(t, closed.URL, env, args...)
					if code != 1 || stderr != "" {
						t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout, stderr)
					}
					assertSurfaceTruthUnavailable(t, stdout)
					if format != "text" && !json.Valid([]byte(stdout)) {
						t.Fatalf("invalid failure JSON: %s", stdout)
					}
				})
			}
		}
	}
}

func TestSurfaceTruthCLIRejectsIncompleteAndStaleObservations(t *testing.T) {
	for _, command := range []string{"receipts status", "receipts list", "authz health", "authz check"} {
		valid := surfaceTruthDocument(t, command)
		var document map[string]any
		if err := json.Unmarshal([]byte(valid), &document); err != nil {
			t.Fatal(err)
		}
		mutations := map[string]func(map[string]any){}
		if strings.HasPrefix(command, "receipts ") {
			mutations["missing receipts"] = func(v map[string]any) { delete(v, "receipts") }
			mutations["missing count"] = func(v map[string]any) { delete(v, "count") }
			mutations["wrong count"] = func(v map[string]any) { v["count"] = 2 }
			mutations["not a list"] = func(v map[string]any) { v["receipts"] = map[string]any{} }
			mutations["unidentified receipt"] = func(v map[string]any) { v["receipts"] = []any{map[string]any{}} }
		} else {
			mutations["missing observation"] = func(v map[string]any) { delete(v, "checked_at") }
			mutations["old observation"] = func(v map[string]any) { v["checked_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano) }
			mutations["future observation"] = func(v map[string]any) { v["checked_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano) }
			mutations["missing relationship state"] = func(v map[string]any) { v["relationship_hash"] = "" }
			mutations["stale"] = func(v map[string]any) { v["stale"] = true }
			mutations["model mismatch"] = func(v map[string]any) { v["model_mismatch"] = true }
			if command == "authz check" {
				mutations["missing decision"] = func(v map[string]any) { delete(v, "decision") }
				mutations["wrong subject"] = func(v map[string]any) { v["subject"] = "another-subject" }
				mutations["invalid seal"] = func(v map[string]any) { v["snapshot_hash"] = "wrong-hash" }
			} else {
				mutations["resolver unavailable"] = func(v map[string]any) { v["status"] = "unavailable" }
			}
		}
		for name, mutate := range mutations {
			t.Run(command+"/"+name, func(t *testing.T) {
				var changed map[string]any
				_ = json.Unmarshal([]byte(valid), &changed)
				mutate(changed)
				if command == "authz check" && name != "invalid seal" {
					// Keep the seal consistent where the mutated fields still form
					// a valid snapshot, so stale/mismatched observations fail for
					// their semantics rather than an incidental checksum mismatch.
					data, _ := json.Marshal(changed)
					var snapshot contracts.AuthzSnapshot
					if json.Unmarshal(data, &snapshot) == nil {
						if sealed, err := snapshot.Seal(); err == nil {
							changed["snapshot_hash"] = sealed.SnapshotHash
						}
					}
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(changed) }))
				defer server.Close()
				code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, append(strings.Fields(command), "--json")...)
				if code != 1 || stderr != "" {
					t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout, stderr)
				}
				assertSurfaceTruthUnavailable(t, stdout)
			})
		}
	}
}

func TestSurfaceTruthCLIUsesRealServerRoutes(t *testing.T) {
	t.Setenv("HELM_RUNTIME_TENANT_ID", "default")
	t.Setenv("HELM_RUNTIME_PRINCIPAL_ID", "system-admin")
	t.Setenv("HELM_RUNTIME_WORKSPACE_ID", "")
	t.Setenv("HELM_QUICKSTART_SESSION_EXPIRES_AT", "")
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	t.Setenv("HELM_ADMIN_API_KEY", surfaceTruthCredential)
	svc.Authz = authz.NewEngine()
	if err := svc.Authz.WriteTuple(t.Context(), authz.RelationTuple{Subject: "agent:anonymous-dev", Object: "tool:file_read", Relation: "can_call"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)
	server := httptest.NewServer(mux)
	defer server.Close()
	for _, command := range []string{"receipts status", "receipts list", "authz health", "authz check"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, append(strings.Fields(command), "--json")...)
			if code != 0 || stderr != "" || !json.Valid([]byte(stdout)) {
				t.Fatalf("valid server counterpart failed: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}
	t.Run("checked denial", func(t *testing.T) {
		code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, "authz", "check", "--subject", "agent:no-relationship", "--json")
		var snapshot contracts.AuthzSnapshot
		if code != 1 || stderr != "" || json.Unmarshal([]byte(stdout), &snapshot) != nil || snapshot.Decision || snapshot.SnapshotID == "" || strings.Contains(stdout, "unavailable") {
			t.Fatalf("checked denial was lost: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
	for _, flag := range []string{"--stale", "--model-mismatch"} {
		t.Run(flag, func(t *testing.T) {
			code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, "authz", "check", flag, "--json")
			if code != 1 || stderr != "" {
				t.Fatalf("unusable observation accepted: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			assertSurfaceTruthUnavailable(t, stdout)
		})
	}
	t.Run("server rejects forged scope", func(t *testing.T) {
		code, stdout, stderr := runSurfaceTruthCLI(t, server.URL, nil, "receipts", "list", "--tenant", "another-tenant", "--json")
		if code != 1 || stderr != "" || !strings.Contains(stdout, "HTTP 403") {
			t.Fatalf("forged scope accepted: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
	t.Run("private credential file", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(keyPath, []byte(surfaceTruthCredential), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runSurfaceTruthCLI(t, "http://127.0.0.1:1", map[string]string{"HELM_ADMIN_API_KEY": ""}, "receipts", "list", "--server", server.URL, "--api-key-file", keyPath, "--json")
		if code != 0 || stderr != "" {
			t.Fatalf("explicit server and private key failed: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
	// This is the real handler's nil-resolver response, which currently carries
	// status=ready with an empty relationship hash. It must not become CLI ready.
	t.Run("uninitialized resolver", func(t *testing.T) {
		// Stop all readers before changing the fixture's resolver.
		server.Close()
		svc.Authz = nil
		uninitialized := httptest.NewServer(mux)
		defer uninitialized.Close()
		code, stdout, stderr := runSurfaceTruthCLI(t, uninitialized.URL, nil, "authz", "health", "--json")
		if code != 1 || stderr != "" {
			t.Fatalf("uninitialized resolver accepted: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		assertSurfaceTruthUnavailable(t, stdout)
	})
}

func TestSurfaceTruthCLIDoesNotEchoInvalidURLSecrets(t *testing.T) {
	for _, command := range []string{"receipts status", "receipts list", "authz health", "authz check"} {
		for _, rawURL := range []string{
			"http://user:" + surfaceTruthCredential + "@127.0.0.1:1",
			"http://127.0.0.1:1?token=" + surfaceTruthCredential,
		} {
			t.Run(fmt.Sprint(command, "/", strings.Contains(rawURL, "?")), func(t *testing.T) {
				code, stdout, stderr := runSurfaceTruthCLI(t, rawURL, nil, append(strings.Fields(command), "--json")...)
				if code != 1 || stderr != "" {
					t.Fatalf("invalid URL: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
				}
				assertSurfaceTruthUnavailable(t, stdout)
			})
		}
	}
}
