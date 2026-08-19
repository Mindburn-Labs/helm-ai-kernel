package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func persistEvaluateEvidencePack(t *testing.T) (packPath, keyHex string, receipt *contracts.Receipt) {
	t.Helper()
	isolateEvaluatePackVerify(t)
	dataDir, stored := persistEvaluateArtifacts(t)
	src := portableEvaluateEvidencePackPath(dataDir, stored.ReceiptID)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read persisted pack: %v", err)
	}
	offBox := filepath.Join(t.TempDir(), "evidence-pack.tar")
	if err := os.WriteFile(offBox, raw, 0o600); err != nil {
		t.Fatalf("copy pack off-box: %v", err)
	}
	keyRaw, err := os.ReadFile(portableEvaluatePublicKeyPath(dataDir, stored.ReceiptID))
	if err != nil {
		t.Fatalf("read trusted key: %v", err)
	}
	return offBox, strings.TrimSpace(string(keyRaw)), stored
}

func isolateEvaluatePackVerify(t *testing.T) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_URL", "")
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
}

func TestVerifyEvaluateEvidencePackTrustedCopiedFile(t *testing.T) {
	packPath, keyHex, _ := persistEvaluateEvidencePack(t)
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", keyHex)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "verify", packPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify pack exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestVerifyEvaluateEvidencePackTamperedVerdict(t *testing.T) {
	packPath, keyHex, stored := persistEvaluateEvidencePack(t)
	tampered := rewriteTarEntry(t, packPath, "02_PROOFGRAPH/receipts/"+sanitizeReceiptFileName(stored.ReceiptID)+".json", func(raw []byte) []byte {
		out := strings.Replace(string(raw), `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1)
		if out == string(raw) {
			t.Fatal("packed receipt fixture did not contain signed DENY verdict")
		}
		return []byte(out)
	})
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", keyHex)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "verify", tampered}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("tampered pack must not verify: stdout=%s", stdout.String())
	}
}

func TestVerifyEvaluateEvidencePackMissingTrustedKey(t *testing.T) {
	packPath, _, _ := persistEvaluateEvidencePack(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "verify", packPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("missing trusted key must not verify: stdout=%s", stdout.String())
	}
}

func TestVerifyEvaluateEvidencePackWrongTrustedKey(t *testing.T) {
	packPath, _, _ := persistEvaluateEvidencePack(t)
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", strings.Repeat("f", 64))
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "verify", packPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("wrong trusted key must not verify: stdout=%s", stdout.String())
	}
}

func rewriteTarEntry(t *testing.T, packPath, name string, mutate func([]byte) []byte) string {
	t.Helper()
	src, err := os.Open(packPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	outPath := filepath.Join(t.TempDir(), "tampered-evidence-pack.tar")
	dst, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	tr := tar.NewReader(src)
	tw := tar.NewWriter(dst)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.ToSlash(hdr.Name) == name {
			data = mutate(data)
			hdr.Size = int64(len(data))
			found = true
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("tar entry %s not found", name)
	}
	return outPath
}
