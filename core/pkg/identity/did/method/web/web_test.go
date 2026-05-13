package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriverName(t *testing.T) {
	assert.Equal(t, "web", New().Name())
}

// hostFromTestServer returns the test server's host with the port percent-
// encoded as required by the did:web spec.
func hostFromTestServer(srv *httptest.Server) string {
	raw := strings.TrimPrefix(srv.URL, "http://")
	host, port, found := strings.Cut(raw, ":")
	if !found {
		return raw
	}
	return host + "%3A" + port
}

func TestResolveWellKnown(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	mb, err := did.EncodeEd25519Multibase(pub)
	require.NoError(t, err)

	var didURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/did.json", func(w http.ResponseWriter, r *http.Request) {
		doc := did.ResolvedDocument{
			Context: []string{"https://www.w3.org/ns/did/v1"},
			ID:      didURI,
			VerificationMethod: []did.VerificationMethod{{
				ID:                 didURI + "#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         didURI,
				PublicKeyMultibase: mb,
			}},
			Authentication:  []string{didURI + "#key-1"},
			AssertionMethod: []string{didURI + "#key-1"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	didURI = "did:web:" + hostFromTestServer(srv)

	driver := New(WithScheme("http"), WithHTTPClient(srv.Client()))
	doc, err := driver.Resolve(context.Background(), didURI)
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, didURI, doc.ID)

	got, err := doc.PrimaryAssertionKey()
	require.NoError(t, err)
	assert.Equal(t, pub, got)
}

func TestResolveSubpath(t *testing.T) {
	mux := http.NewServeMux()
	var didURI string
	mux.HandleFunc("/agents/alice/did.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@context":["https://www.w3.org/ns/did/v1"],"id":"` + didURI + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	didURI = "did:web:" + hostFromTestServer(srv) + ":agents:alice"

	doc, err := New(WithScheme("http"), WithHTTPClient(srv.Client())).Resolve(context.Background(), didURI)
	require.NoError(t, err)
	assert.Equal(t, didURI, doc.ID)
}

func TestResolveRejectsMismatchedID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/did.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:web:other.example.com"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := New(WithScheme("http"), WithHTTPClient(srv.Client())).Resolve(context.Background(), "did:web:"+hostFromTestServer(srv))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "document id")
}

func TestResolveRejects404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := New(WithScheme("http"), WithHTTPClient(srv.Client())).Resolve(context.Background(), "did:web:"+hostFromTestServer(srv))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}
