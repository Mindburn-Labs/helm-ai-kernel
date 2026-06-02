package anchor

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func TestRFC3161BackendAnchorAndVerifyBranches(t *testing.T) {
	tsaResponse, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Fatal("timestamp request body was empty")
		}
		_, _ = w.Write(tsaResponse)
	}))
	defer server.Close()

	backend := NewRFC3161Backend("https://unused.example/tsa",
		WithTSAURL(server.URL),
		WithRFC3161HTTPClient(server.Client()),
	)
	if backend.Name() != rfc3161BackendName {
		t.Fatalf("Name = %s, want %s", backend.Name(), rfc3161BackendName)
	}
	receipt, err := backend.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot(), FromLamport: 1, ToLamport: 2, NodeCount: 1})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if receipt.Backend != rfc3161BackendName || receipt.Signature == "" || len(receipt.RawResponse) == 0 {
		t.Fatalf("receipt = %#v, want rfc3161 receipt with signature/raw response", receipt)
	}
	if err := backend.Verify(context.Background(), receipt); err != nil {
		t.Fatalf("Verify valid receipt: %v", err)
	}

	if _, err := backend.Anchor(context.Background(), AnchorRequest{MerkleRoot: "not-hex"}); err == nil {
		t.Fatal("Anchor invalid merkle root error = nil")
	}
	badURLBackend := NewRFC3161Backend("://bad")
	if _, err := badURLBackend.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor invalid URL error = nil")
	}
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	statusBackend := NewRFC3161Backend(statusServer.URL, WithRFC3161HTTPClient(statusServer.Client()))
	if _, err := statusBackend.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor non-200 status error = nil")
	}
	doErrBackend := NewRFC3161Backend("https://tsa.example/tsa",
		WithRFC3161HTTPClient(&http.Client{Transport: anchorRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}),
	)
	if _, err := doErrBackend.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor transport error = nil")
	}
	readErrBackend := NewRFC3161Backend("https://tsa.example/tsa",
		WithRFC3161HTTPClient(&http.Client{Transport: anchorRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       failingReadCloser{},
				Request:    req,
			}, nil
		})}),
	)
	if _, err := readErrBackend.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor read error = nil")
	}

	if err := backend.Verify(context.Background(), &AnchorReceipt{Backend: "other", Signature: receipt.Signature}); err == nil {
		t.Fatal("Verify backend mismatch error = nil")
	}
	if err := backend.Verify(context.Background(), &AnchorReceipt{Backend: rfc3161BackendName}); err == nil {
		t.Fatal("Verify empty signature error = nil")
	}
	if err := backend.Verify(context.Background(), &AnchorReceipt{Backend: rfc3161BackendName, Signature: "not-base64"}); err == nil {
		t.Fatal("Verify invalid base64 error = nil")
	}
	if err := backend.Verify(context.Background(), &AnchorReceipt{Backend: rfc3161BackendName, Signature: "bm90LWFzbjE="}); err == nil {
		t.Fatal("Verify invalid ASN.1 error = nil")
	}
}

func TestEIDASAnchorHTTPBranches(t *testing.T) {
	token := bytes.Repeat([]byte{1}, eidasMinTokenSize)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = w.Write(token)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	anchor := NewEIDASAnchor(server.URL, trust.NewEUTrustedList(),
		WithEIDASHTTPClient(nil),
		WithEIDASHTTPClient(client),
	)
	if anchor.client != client {
		t.Fatal("WithEIDASHTTPClient did not install non-nil client")
	}
	anchor.client = server.Client()
	receipt, err := anchor.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot(), FromLamport: 3, ToLamport: 4, NodeCount: 2})
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if receipt.Backend != EIDASBackendName || receipt.Signature == "" || receipt.LogID != server.URL {
		t.Fatalf("receipt = %#v, want eIDAS receipt for local server", receipt)
	}

	shortServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("short"))
	}))
	defer shortServer.Close()
	shortAnchor := NewEIDASAnchor(shortServer.URL, trust.NewEUTrustedList(), WithEIDASHTTPClient(shortServer.Client()))
	if _, err := shortAnchor.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor short token error = nil")
	}

	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer statusServer.Close()
	statusAnchor := NewEIDASAnchor(statusServer.URL, trust.NewEUTrustedList(), WithEIDASHTTPClient(statusServer.Client()))
	if _, err := statusAnchor.Anchor(context.Background(), AnchorRequest{MerkleRoot: hexRoot()}); err == nil {
		t.Fatal("Anchor non-200 status error = nil")
	}
}

func TestRekorHTTPClientOption(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	backend := NewRekorBackend(WithHTTPClient(client))
	if backend.client != client {
		t.Fatal("WithHTTPClient did not install custom Rekor client")
	}
}

func hexRoot() string {
	return hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
}
