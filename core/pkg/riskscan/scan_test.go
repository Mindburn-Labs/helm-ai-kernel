package riskscan

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

var testSalt = bytes.Repeat([]byte{0x08}, riskenvelope.SaltBytes)

func TestScanProjectionPreviewsAndPackOmitRawInputs(t *testing.T) {
	root := fixtureRoot(t)
	envelope, err := Scan(root, BuildOptions{
		Salt:   testSalt,
		Cohort: riskenvelope.CohortRepos1To10,
		Now:    time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if envelope.Posture.StaticConfigFilesRead != 2 {
		t.Fatalf("static config files read = %d, want 2", envelope.Posture.StaticConfigFilesRead)
	}
	if envelope.Posture.MCPServerCount != 1 {
		t.Fatalf("mcp server count = %d, want 1", envelope.Posture.MCPServerCount)
	}

	body, err := EnvelopeJSON(envelope)
	if err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	md, err := RenderMarkdown(envelope)
	if err != nil {
		t.Fatalf("markdown: %v", err)
	}
	html, err := RenderHTML(envelope)
	if err != nil {
		t.Fatalf("html: %v", err)
	}
	pack := filepath.Join(t.TempDir(), "pack.tar")
	if err := WriteEvidencePack(pack, envelope, map[string][]byte{
		"preview/report.md":   md,
		"preview/report.html": html,
	}); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	packBytes, err := os.ReadFile(pack)
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}

	for _, raw := range []string{
		"customer/private-game",
		"private-game-prod",
		"deploy-production",
		"sk-12345678901234567890123456789012",
	} {
		for name, payload := range map[string][]byte{
			"envelope": body,
			"markdown": md,
			"html":     html,
			"pack":     packBytes,
		} {
			if bytes.Contains(payload, []byte(raw)) {
				t.Fatalf("%s leaked raw input %q", name, raw)
			}
		}
	}
}

func TestEvidencePackTarIsDeterministicAndLimited(t *testing.T) {
	envelope, err := Scan(fixtureRoot(t), BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	md, _ := RenderMarkdown(envelope)
	html, _ := RenderHTML(envelope)
	previews := map[string][]byte{"preview/report.html": html, "preview/report.md": md}

	first := filepath.Join(t.TempDir(), "a.tar")
	second := filepath.Join(t.TempDir(), "b.tar")
	if err := WriteEvidencePack(first, envelope, previews); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := WriteEvidencePack(second, envelope, previews); err != nil {
		t.Fatalf("write second: %v", err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("evidence pack tar should be deterministic")
	}

	names := tarNames(t, firstBytes)
	want := []string{
		"preview/report.html",
		"preview/report.md",
		"privacy-manifest.json",
		"risk-envelope.json",
		"schema-validation.json",
		"source-pack-hash.json",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("pack names mismatch\ngot:  %#v\nwant: %#v", names, want)
	}
	if bytes.Contains(firstBytes, []byte("scan_salt")) || bytes.Contains(firstBytes, []byte("customer/private-game")) {
		t.Fatal("pack contains local salt metadata or raw source identity")
	}
}

func TestUploadEnvelopeSendsExactBody(t *testing.T) {
	envelope, err := Scan(fixtureRoot(t), BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	body, err := EnvelopeJSON(envelope)
	if err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	var got []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q", r.Header.Get("Content-Type"))
		}
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	if err := UploadEnvelope(context.Background(), server.URL, body); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("upload body did not match printed envelope body")
	}
	if err := UploadEnvelope(context.Background(), "", body); err == nil {
		t.Fatal("empty upload url should be rejected")
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte("import anthropic\nOPENAI_API_KEY='sk-12345678901234567890123456789012'\n"), 0o644); err != nil {
		t.Fatalf("write agent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"private-game-prod":{"command":"deploy-production --token sk-12345678901234567890123456789012"}}}`), 0o644); err != nil {
		t.Fatalf("write mcp: %v", err)
	}
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"permissionMode":"acceptEdits","project":"customer/private-game"}`), 0o644); err != nil {
		t.Fatalf("write claude settings: %v", err)
	}
	return root
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC)
}

func tarNames(t *testing.T, data []byte) []string {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if strings.TrimSpace(header.Name) != "" {
			names = append(names, header.Name)
		}
	}
}
