package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetReceiptJSONPreservesWireInput(t *testing.T) {
	raw := []byte(`{"lamport_clock":1e0,"verdict":"ALLOW","verdict":"DENY"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-test-token" {
			t.Errorf("missing client authentication")
		}
		if r.URL.EscapedPath() != "/api/v1/proofgraph/receipts/id%2Fa%20b" {
			t.Errorf("path=%s", r.URL.EscapedPath())
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	client := New(server.URL)
	client.APIKey = "local-test-token"
	got, err := client.GetReceiptJSON("id/a b")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("receipt bytes were transformed: %s", got)
	}
}
func TestVerifyReceiptRejectsInvalidUTF8(t *testing.T) {
	v := loadVectors(t)[0]
	raw := bytes.Replace([]byte(v.Receipt), []byte("rcpt-001"), []byte{'r', 'c', 'p', 't', '-', 0xff}, 1)
	if got := VerifyReceipt(raw, v.TrustedKeys...); got.Error != "malformed" {
		t.Fatalf("invalid UTF-8: %+v", got)
	}
}
