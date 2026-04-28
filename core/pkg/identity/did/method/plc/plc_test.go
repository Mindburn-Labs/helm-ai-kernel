package plc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriverName(t *testing.T) {
	assert.Equal(t, "plc", New().Name())
}

func TestResolve(t *testing.T) {
	const didURI = "did:plc:abcdef123456"
	mux := http.NewServeMux()
	mux.HandleFunc("/"+didURI, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "` + didURI + `",
  "verificationMethod": [{
    "id": "` + didURI + `#atproto",
    "type": "Ed25519VerificationKey2020",
    "controller": "` + didURI + `",
    "publicKeyMultibase": "z6MkfZ6S2nQqXKx2pq3Tzm4eR8E8u6dY8YSm2x4Wz9jXrZP9"
  }],
  "authentication": ["` + didURI + `#atproto"],
  "assertionMethod": ["` + didURI + `#atproto"],
  "service": [{
    "id": "#atproto_pds",
    "type": "AtprotoPersonalDataServer",
    "serviceEndpoint": "https://pds.example.com"
  }]
}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	driver := New(WithDirectoryURL(srv.URL), WithHTTPClient(srv.Client()))
	doc, err := driver.Resolve(context.Background(), didURI)
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, didURI, doc.ID)
	require.Len(t, doc.Service, 1)
	assert.Equal(t, "https://pds.example.com", doc.Service[0].ServiceEndpoint)
}

func TestRejectsWrongMethod(t *testing.T) {
	driver := New()
	_, err := driver.Resolve(context.Background(), "did:web:example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong method")
}

func TestRejects404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	driver := New(WithDirectoryURL(srv.URL), WithHTTPClient(srv.Client()))
	_, err := driver.Resolve(context.Background(), "did:plc:doesnotexist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}
