package anchor

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HELM-738 / audit 19-01: an anchor receipt must be bound to the root it
// claims to anchor. Before this change RFC3161Backend.Verify accepted any DER
// value and RekorBackend.Verify accepted any entry at the claimed index.

func TestRFC3161VerifyRejectsTokenWithoutTSTInfo(t *testing.T) {
	// The verifier PoC (VC 19-01, PoC A): a DER INTEGER passed as the token.
	token, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &AnchorReceipt{
		Backend:   rfc3161BackendName,
		Request:   AnchorRequest{MerkleRoot: strings.Repeat("ff", 32)},
		Signature: base64.StdEncoding.EncodeToString(token),
	}
	if err := NewRFC3161Backend("https://tsa.invalid/").Verify(context.Background(), receipt); err == nil {
		t.Fatal("RFC 3161 Verify accepted a DER INTEGER as a timestamp token")
	}
}

func TestRFC3161VerifyBindsMessageImprintToRoot(t *testing.T) {
	root := hexRoot()
	backend := NewRFC3161Backend("https://tsa.invalid/")
	receipt := &AnchorReceipt{
		Backend:   rfc3161BackendName,
		Request:   AnchorRequest{MerkleRoot: root},
		Signature: base64.StdEncoding.EncodeToString(rfc3161TestResponse(t, 0, rfc3161ImprintForRoot(t, root))),
	}
	if err := backend.Verify(context.Background(), receipt); err != nil {
		t.Fatalf("bound token rejected: %v", err)
	}

	other := strings.Repeat("11", 32)
	mismatched := *receipt
	mismatched.Request.MerkleRoot = other
	if err := backend.Verify(context.Background(), &mismatched); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("token for another root accepted: %v", err)
	}

	rejected := *receipt
	rejected.Signature = base64.StdEncoding.EncodeToString(rfc3161TestResponse(t, 2, rfc3161ImprintForRoot(t, root)))
	if err := backend.Verify(context.Background(), &rejected); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("rejected TSA response accepted: %v", err)
	}

	bareToken := *receipt
	bareToken.Signature = base64.StdEncoding.EncodeToString(rfc3161TestToken(t, rfc3161ImprintForRoot(t, root)))
	if err := backend.Verify(context.Background(), &bareToken); err != nil {
		t.Fatalf("bare TimeStampToken rejected: %v", err)
	}
}

func TestRekorVerifyBindsEntryBodyAndTimeToReceipt(t *testing.T) {
	root := hexRoot()
	integrated := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	entryRoot := root
	entryTime := integrated.Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("logIndex") != "7" {
			t.Fatalf("unexpected Rekor request: %s", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]rekorResponse{"uuid": {
			LogID:          "rekor-log",
			LogIndex:       7,
			IntegratedTime: entryTime,
			Body:           rekorTestBody(t, entryRoot),
		}})
	}))
	defer server.Close()
	backend := NewRekorBackend(WithRekorURL(server.URL), WithHTTPClient(server.Client()))
	receipt := &AnchorReceipt{
		Backend:        rekorBackendName,
		Request:        AnchorRequest{MerkleRoot: root},
		LogID:          "rekor-log",
		LogIndex:       7,
		IntegratedTime: integrated,
	}
	if err := backend.Verify(context.Background(), receipt); err != nil {
		t.Fatalf("bound Rekor entry rejected: %v", err)
	}

	entryRoot = strings.Repeat("11", 32)
	if err := backend.Verify(context.Background(), receipt); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("Rekor entry for another root accepted: %v", err)
	}

	entryRoot = root
	backdated := *receipt
	backdated.IntegratedTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := backend.Verify(context.Background(), &backdated); err == nil || !strings.Contains(err.Error(), "integrated_time") {
		t.Fatalf("backdated Rekor receipt accepted: %v", err)
	}

	entryTime = 0
	if err := backend.Verify(context.Background(), receipt); err == nil {
		t.Fatal("Rekor entry without integratedTime accepted")
	}
}

func rfc3161ImprintForRoot(t testing.TB, root string) []byte {
	t.Helper()
	rootBytes, err := hex.DecodeString(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootBytes)
	return digest[:]
}

// rfc3161TestToken builds an unsigned TimeStampToken whose TSTInfo carries
// hashed as its SHA-256 message imprint.
func rfc3161TestToken(t testing.TB, hashed []byte) []byte {
	t.Helper()
	info, err := asn1.Marshal(struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		SerialNumber   int
		GenTime        time.Time `asn1:"generalized"`
	}{
		Version:        1,
		Policy:         asn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: messageImprint{HashAlgorithm: algorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: hashed},
		SerialNumber:   1,
		GenTime:        time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []algorithmIdentifier `asn1:"set"`
		EncapContentInfo encapsulatedContentInfo
		SignerInfos      []asn1.RawValue `asn1:"set"`
	}{
		Version:          3,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapsulatedContentInfo{EContentType: oidTSTInfo, EContent: info},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A RawValue is emitted as-is, so the explicit [0] wrapper is built here.
	token, err := asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// rfc3161TestResponse wraps rfc3161TestToken in a TimeStampResp with status.
func rfc3161TestResponse(t testing.TB, status int, hashed []byte) []byte {
	t.Helper()
	resp, err := asn1.Marshal(timeStampResp{
		Status:         pkiStatusInfo{Status: status},
		TimeStampToken: asn1.RawValue{FullBytes: rfc3161TestToken(t, hashed)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func rekorTestBody(t testing.TB, root string) string {
	t.Helper()
	spec, err := json.Marshal(rekorHashedRekordSpec{Data: rekorData{Hash: rekorHash{Algorithm: "sha256", Value: root}}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(rekorEntry{APIVersion: "0.0.1", Kind: "hashedrekord", Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(body)
}
