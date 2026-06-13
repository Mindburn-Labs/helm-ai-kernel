package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestHTTPConnectAllowedTunnelsAndWritesReceipt(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendDone := make(chan error, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			backendDone <- err
			return
		}
		if string(buf) != "ping" {
			backendDone <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("pong"))
		backendDone <- err
	}()

	client, server := net.Pipe()
	defer client.Close()
	receiptDir := t.TempDir()
	p := &proxy{launchID: "launch-1", allowlist: []string{backend.Addr().String()}, receiptDir: receiptDir}
	go p.handle(server)

	clientReader := bufio.NewReader(client)
	_, _ = client.Write([]byte("CONNECT " + backend.Addr().String() + " HTTP/1.1\r\nHost: " + backend.Addr().String() + "\r\n\r\n"))
	response, err := http.ReadResponse(clientReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	_, _ = client.Write([]byte("ping"))
	reply := make([]byte, len("pong"))
	if _, err := io.ReadFull(clientReader, reply); err != nil {
		t.Fatalf("read tunnel reply: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q", reply)
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend error: %v", err)
	}
	assertReceiptContains(t, receiptDir, "connect_allowed")
}

func TestHTTPConnectDeniedWritesReceipt(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	receiptDir := t.TempDir()
	p := &proxy{launchID: "launch-1", allowlist: []string{"openrouter.ai:443"}, receiptDir: receiptDir}
	go p.handle(server)

	clientReader := bufio.NewReader(client)
	_, _ = client.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	response, err := http.ReadResponse(clientReader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
	assertReceiptContains(t, receiptDir, "destination_not_allowlisted")
}

func assertReceiptContains(t *testing.T, dir, text string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), text) {
			return
		}
	}
	t.Fatalf("no receipt in %s contained %q", dir, text)
}
