package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestNetworkAllowedNormalizesOpenRouterURLAllowlist(t *testing.T) {
	allowlist := []string{"https://openrouter.ai/api/v1", "https://api.openrouter.ai/api/v1"}

	if !networkAllowed("openrouter.ai:443", allowlist) {
		t.Fatal("expected openrouter.ai destination to match URL allowlist")
	}
	if !networkAllowed("api.openrouter.ai:443", allowlist) {
		t.Fatal("expected api.openrouter.ai destination to match URL allowlist")
	}
	if networkAllowed("example.com:443", allowlist) {
		t.Fatal("expected non-OpenRouter destination to remain denied")
	}
	// IP-literal fallback (no SNI) must not accidentally match a hostname allowlist.
	if networkAllowed("1.1.1.1:443", allowlist) {
		t.Fatal("expected raw IP destination to remain denied against hostname allowlist")
	}
}

func TestSNIHostExtractsServerName(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// A real TLS handshake puts a ClientHello with SNI on the wire. The handshake
	// will not complete (we never answer), which is fine — we only sniff the head.
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "openrouter.ai", InsecureSkipVerify: true}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReaderSize(server, 8192)
	if host := sniHost(br); host != "openrouter.ai" {
		t.Fatalf("expected SNI openrouter.ai, got %q", host)
	}
}

func TestSNIHostReturnsEmptyOnNonTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReaderSize(server, 8192)
	if host := sniHost(br); host != "" {
		t.Fatalf("expected no SNI for non-TLS traffic, got %q", host)
	}
}
