package main

// quantum_posture: these offline CLI tests use the public classical Ed25519
// fixture signature only; no private key or signer is used.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type checkpointCLIFixture struct {
	Descriptor       json.RawMessage `json:"descriptor"`
	Payload          string          `json:"payload_base64"`
	PAE              string          `json:"pae_base64"`
	Signature        string          `json:"signature_base64"`
	Envelope         string          `json:"envelope_base64"`
	Content          string          `json:"snapshot_bytes_base64"`
	PublicKey        string          `json:"public_key_hex"`
	KeyID            string          `json:"key_id"`
	DescriptorDigest string          `json:"descriptor_digest"`
	EnvelopeDigest   string          `json:"envelope_digest"`
	dir              string
}

func checkpointCLISetup(t *testing.T) checkpointCLIFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkg", "evidence", "testdata", "recovery-checkpoint.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v checkpointCLIFixture
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	v.dir = t.TempDir()
	checkpointCLIWrite(t, v.dir, "descriptor", v.Descriptor)
	for name, value := range map[string]string{"payload": v.Payload, "envelope": v.Envelope, "content": v.Content} {
		checkpointCLIWrite(t, v.dir, name, checkpointCLIBytes(t, value))
	}
	return v
}

func checkpointCLIBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func checkpointCLIWrite(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func checkpointCLICall(args []string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel", "evidence", "checkpoint"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func (v checkpointCLIFixture) verifyArgs() []string {
	return []string{"verify", "--envelope=" + filepath.Join(v.dir, "envelope"), "--expected=" + filepath.Join(v.dir, "descriptor"),
		"--public-key-hex=" + v.PublicKey, "--key-id=" + v.KeyID,
		"--purpose=" + contracts.RecoveryCheckpointPurpose, "--payload-type=" + contracts.RecoveryCheckpointPayloadType,
		"--valid-from-unix=1", "--valid-until-unix=10", "--verify-at-unix=5", "--revoked=false"}
}

func checkpointCLIReplace(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if strings.HasPrefix(result[i], "--"+name+"=") {
			result[i] = "--" + name + "=" + value
			return result
		}
	}
	return append(result, "--"+name+"="+value)
}

func TestEvidenceCheckpointGoldenOfflineWorkflow(t *testing.T) {
	v := checkpointCLISetup(t)
	for format, expected := range map[string][]byte{"payload": checkpointCLIBytes(t, v.Payload), "pae": checkpointCLIBytes(t, v.PAE)} {
		code, out, stderr := checkpointCLICall([]string{"prepare", "--descriptor=" + filepath.Join(v.dir, "descriptor"), "--emit=" + format})
		if code != 0 || stderr != "" || !bytes.Equal([]byte(out), expected) {
			t.Fatalf("%s differed from independent UTF-8 vector: code=%d stderr=%s", format, code, stderr)
		}
	}
	code, out, stderr := checkpointCLICall([]string{"prepare", "--descriptor=" + filepath.Join(v.dir, "descriptor")})
	var bundle map[string]string
	if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &bundle) != nil || len(bundle) != 5 || bundle["payload_base64"] != v.Payload || bundle["pae_base64"] != v.PAE || bundle["descriptor_digest"] != v.DescriptorDigest {
		t.Fatalf("prepared public bundle: code=%d stderr=%s", code, stderr)
	}
	code, out, stderr = checkpointCLICall([]string{"assemble", "--payload=" + filepath.Join(v.dir, "payload"), "--key-id=" + v.KeyID,
		"--signature-hex=" + hex.EncodeToString(checkpointCLIBytes(t, v.Signature))})
	if code != 0 || stderr != "" {
		t.Fatalf("assemble: code=%d stderr=%s", code, stderr)
	}
	_, payload, _, err := contracts.DecodeRecoveryCheckpointEnvelope([]byte(out))
	if err != nil || !bytes.Equal(payload, checkpointCLIBytes(t, v.Payload)) {
		t.Fatal("assembly changed exact signed payload or added unsigned result metadata")
	}
	assembled := checkpointCLIWrite(t, v.dir, "assembled", []byte(out))
	for _, content := range []bool{false, true} {
		args := checkpointCLIReplace(v.verifyArgs(), "envelope", assembled)
		scope := "signed_descriptor_only"
		if content {
			args = append(args, "--content="+filepath.Join(v.dir, "content"))
			scope = "signed_descriptor_and_supplied_content"
		}
		code, out, stderr = checkpointCLICall(args)
		var result map[string]string
		if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || len(result) != 4 || result["verification_scope"] != scope || result["descriptor_digest"] != v.DescriptorDigest {
			t.Fatalf("verify scope=%s code=%d stderr=%s result=%s", scope, code, stderr, out)
		}
		for _, private := range []string{v.dir, v.PublicKey, string(checkpointCLIBytes(t, v.Content))} {
			if strings.Contains(out+stderr, private) {
				t.Fatal("verification exposed private content, local paths or key material")
			}
		}
	}
	code, _, _ = checkpointCLICall(append(v.verifyArgs(), "--frozen-envelope-digest="+v.EnvelopeDigest))
	if code != 0 {
		t.Fatal("original exact frozen envelope failed replay verification")
	}
}

func TestEvidenceCheckpointRequiresIndependentTrust(t *testing.T) {
	v := checkpointCLISetup(t)
	base := v.verifyArgs()
	for i := 1; i < len(base); i++ {
		args := append(append([]string(nil), base[:i]...), base[i+1:]...)
		code, out, _ := checkpointCLICall(args)
		if code != 2 || out != "" {
			t.Fatalf("missing %s did not fail closed", strings.SplitN(base[i], "=", 2)[0])
		}
	}
	for name, value := range map[string]string{
		"public-key-hex": strings.Repeat("00", 32), "key-id": "foreign", "purpose": "no_effect", "payload-type": "legacy",
		"valid-until-unix": "4", "verify-at-unix": "10", "revoked": "true", "frozen-envelope-digest": "sha256:" + strings.Repeat("0", 64),
	} {
		code, out, _ := checkpointCLICall(checkpointCLIReplace(base, name, value))
		if code != 1 || out != "" {
			t.Fatalf("foreign %s accepted: code=%d", name, code)
		}
	}
	for _, value := range []string{"01", "+1", "1e0", "1.0", "-1", "9007199254740992", "18446744073709551616"} {
		code, out, _ := checkpointCLICall(checkpointCLIReplace(base, "verify-at-unix", value))
		if code != 2 || out != "" {
			t.Fatalf("noncanonical/range time accepted: %q", value)
		}
	}
	var expected contracts.RecoveryCheckpointDescriptor
	if json.Unmarshal(v.Descriptor, &expected) != nil {
		t.Fatal("fixture descriptor")
	}
	expected.Scope.OperationID = "00000000-0000-0000-0000-000000000001"
	foreign, err := contracts.EncodeRecoveryCheckpoint(expected)
	if err != nil {
		t.Fatal(err)
	}
	path := checkpointCLIWrite(t, v.dir, "foreign", foreign)
	code, out, _ := checkpointCLICall(checkpointCLIReplace(base, "expected", path))
	if code != 1 || out != "" {
		t.Fatal("valid but foreign independently supplied Expected accepted")
	}
}

func TestEvidenceCheckpointAlteredSignatureAndContent(t *testing.T) {
	v := checkpointCLISetup(t)
	sig := checkpointCLIBytes(t, v.Signature)
	sig[0] ^= 1
	code, out, _ := checkpointCLICall([]string{"assemble", "--payload=" + filepath.Join(v.dir, "payload"), "--key-id=" + v.KeyID, "--signature-hex=" + hex.EncodeToString(sig)})
	if code != 0 {
		t.Fatal("assembly should package an external signature without claiming verification")
	}
	path := checkpointCLIWrite(t, v.dir, "altered-signature", []byte(out))
	code, out, _ = checkpointCLICall(checkpointCLIReplace(v.verifyArgs(), "envelope", path))
	if code != 1 || out != "" {
		t.Fatal("altered cryptographic signature accepted")
	}
	private := []byte("PRIVATE_CONTENT_SENTINEL")
	path = checkpointCLIWrite(t, v.dir, "private-content-sentinel", private)
	code, out, stderr := checkpointCLICall(append(v.verifyArgs(), "--content="+path))
	if code != 1 || out != "" || strings.Contains(stderr, path) || bytes.Contains([]byte(stderr), private) {
		t.Fatal("altered private content accepted or exposed")
	}
}

func TestEvidenceCheckpointClosedBoundedLocalInputs(t *testing.T) {
	v := checkpointCLISetup(t)
	payload := checkpointCLIBytes(t, v.Payload)
	for name, raw := range map[string][]byte{
		"duplicate": bytes.Replace(payload, []byte(`"purpose":`), []byte(`"purpose":"provider-recovery-checkpoint","purpose":`), 1),
		"unknown":   append([]byte(`{"secret":"PRIVATE",`), payload[1:]...),
		"trailing":  append(bytes.Clone(payload), []byte(` {}`)...),
		"utf8":      bytes.Replace(payload, []byte("信頼"), []byte{0xff}, 1),
		"fraction":  bytes.Replace(payload, []byte(`"generation":2`), []byte(`"generation":2.0`), 1),
	} {
		path := checkpointCLIWrite(t, v.dir, name, raw)
		for _, args := range [][]string{{"prepare", "--descriptor=" + path}, checkpointCLIReplace(v.verifyArgs(), "expected", path)} {
			code, out, _ := checkpointCLICall(args)
			if code != 1 || out != "" {
				t.Fatalf("ambiguous %s accepted", name)
			}
		}
	}
	envelope := checkpointCLIBytes(t, v.Envelope)
	for name, raw := range map[string][]byte{
		"duplicate-envelope": bytes.Replace(envelope, []byte(`"payloadType":`), []byte(`"payloadType":"foreign","payloadType":`), 1),
		"unknown-envelope":   append([]byte(`{"private_key":"PRIVATE",`), envelope[1:]...),
		"trailing-envelope":  append(bytes.Clone(envelope), []byte(` {}`)...),
	} {
		path := checkpointCLIWrite(t, v.dir, name, raw)
		code, out, _ := checkpointCLICall(checkpointCLIReplace(v.verifyArgs(), "envelope", path))
		if code != 1 || out != "" {
			t.Fatalf("ambiguous %s accepted", name)
		}
	}
	oversized := checkpointCLIWrite(t, v.dir, "oversized", nil)
	if err := os.Truncate(oversized, contracts.RecoveryCheckpointMaxContentBytes+1); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(v.dir, "symlink")
	if err := os.Symlink(filepath.Join(v.dir, "payload"), symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{oversized, symlink, v.dir, filepath.Join(v.dir, "missing-private-path"), "https://invalid.example/no-fetch"} {
		code, out, stderr := checkpointCLICall(append(v.verifyArgs(), "--content="+path))
		if code != 1 || out != "" || strings.Contains(stderr, path) {
			t.Fatal("unbounded/nonregular local content accepted or path exposed")
		}
	}
	for _, args := range [][]string{
		{}, {"unknown"}, {"prepare"}, {"assemble"}, {"verify"},
		{"prepare", "PRIVATE_POSITIONAL"}, {"prepare", "--unknown=PRIVATE_FLAG"},
		{"prepare", "--descriptor=PRIVATE_A", "--descriptor=PRIVATE_B"},
		{"prepare", "--descriptor"}, {"assemble", "--signature-hex=" + strings.Repeat("A", 128), "--key-id=x", "--payload=" + filepath.Join(v.dir, "payload")},
	} {
		code, out, stderr := checkpointCLICall(args)
		if code == 0 || out != "" || strings.Contains(stderr, "PRIVATE_") {
			t.Fatalf("invalid CLI input accepted or disclosed (argument count %d)", len(args))
		}
	}
}

func TestEvidenceCheckpointPreservesExistingHelp(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := runEvidenceCmd([]string{"--help"}, &out, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatal("existing evidence help failed")
	}
	for _, name := range []string{"export", "verify", "seal", "trust", "envelope", "scopes", "inspect", "diff", "attach-host-chain", "correlate-host", "prove-entry", "checkpoint"} {
		if !strings.Contains(out.String(), name) {
			t.Fatalf("evidence help lost %s", name)
		}
	}
	for _, args := range [][]string{{"--help"}, {"prepare", "--help"}, {"assemble", "--help"}, {"verify", "--help"}} {
		code, out, stderr := checkpointCLICall(args)
		if code != 0 || out == "" || stderr != "" {
			t.Fatal("checkpoint help failed")
		}
	}
}
