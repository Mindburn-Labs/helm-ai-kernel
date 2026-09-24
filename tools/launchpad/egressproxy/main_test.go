package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

// Reproduces verification VE, finding 24-01. The workload forges the SNI
// "openrouter.ai" while its connection targets an unrelated TLS server. The
// allowlist names openrouter.ai, but the original destination is not an
// address openrouter.ai resolves to, so the proxy must deny, and the receipt
// must name the IP the workload actually dialed.
func TestTransparentForgedSNIToUnrelatedIPIsDenied(t *testing.T) {
	target, port, received := startTLSTarget(t)
	dir := t.TempDir()
	p := &proxy{
		launchID:   "launch-1",
		allowlist:  []string{"openrouter.ai:" + port},
		receiptDir: dir,
		lookupIP:   staticResolver("203.0.113.10"),
	}
	proxyAddr := startTransparentProxy(t, p, target)

	if body, err := sendSecretWithSNI(proxyAddr, "openrouter.ai"); err == nil {
		t.Fatalf("forged SNI reached the unrelated server: %q", body)
	}
	if n := received.Load(); n != 0 {
		t.Fatalf("unrelated server received %d requests through the proxy", n)
	}
	r := requireReceipt(t, dir, "sni_not_resolved_to_original_dst")
	if r.Verdict != "DENY" {
		t.Fatalf("verdict = %q, want DENY", r.Verdict)
	}
	if got := r.Subject["destination"]; got != "openrouter.ai:"+port {
		t.Fatalf("receipt destination = %v", got)
	}
	if got := r.Subject["remote_addr"]; got != target {
		t.Fatalf("receipt remote_addr = %v, want the dialed IP %s", got, target)
	}
	requireNoReceipt(t, dir, "connect_allowed")
}

func TestTransparentSNIResolvingToOriginalDstTunnels(t *testing.T) {
	target, port, received := startTLSTarget(t)
	dir := t.TempDir()
	p := &proxy{
		launchID:   "launch-1",
		allowlist:  []string{"openrouter.ai:" + port},
		receiptDir: dir,
		lookupIP:   staticResolver("203.0.113.10", "127.0.0.1"),
	}
	proxyAddr := startTransparentProxy(t, p, target)

	body, err := sendSecretWithSNI(proxyAddr, "openrouter.ai")
	if err != nil {
		t.Fatalf("allowed connection failed: %v", err)
	}
	if !strings.Contains(body, "hunter2") || received.Load() != 1 {
		t.Fatalf("allowed connection did not reach the target: %q", body)
	}
	r := requireReceipt(t, dir, "connect_allowed")
	if r.Verdict != "ALLOW" || r.Subject["remote_addr"] != target {
		t.Fatalf("receipt = %+v, want ALLOW naming %s", r, target)
	}
}

func TestTransparentSNIResolutionFailureIsNotTunnelled(t *testing.T) {
	target, port, received := startTLSTarget(t)
	dir := t.TempDir()
	p := &proxy{
		launchID:   "launch-1",
		allowlist:  []string{"openrouter.ai:" + port},
		receiptDir: dir,
		lookupIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("no such host")
		},
	}
	proxyAddr := startTransparentProxy(t, p, target)

	if _, err := sendSecretWithSNI(proxyAddr, "openrouter.ai"); err == nil || received.Load() != 0 {
		t.Fatal("connection was tunnelled although the SNI name did not resolve")
	}
	if r := requireReceipt(t, dir, "sni_resolution_failed"); r.Subject["remote_addr"] != target {
		t.Fatalf("receipt remote_addr = %v, want %s", r.Subject["remote_addr"], target)
	}
	requireNoReceipt(t, dir, "connect_allowed")
}

// A client that never sends a byte (a server-first protocol such as SSH) must
// not pin the handler: the SNI peek has a deadline and the IP literal is denied.
func TestTransparentSilentClientDoesNotHangHandler(t *testing.T) {
	previous := sniffTimeout
	sniffTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sniffTimeout = previous })

	dir := t.TempDir()
	p := &proxy{
		launchID:   "launch-1",
		allowlist:  []string{"openrouter.ai:443"},
		receiptDir: dir,
		recoverDst: func(*net.TCPConn) (string, error) { return "203.0.113.10:22", nil },
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		p.handle(server)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler is still blocked on a client that never sent a byte")
	}
	if r := requireReceipt(t, dir, "destination_not_allowlisted"); r.Subject["destination"] != "203.0.113.10:22" {
		t.Fatalf("receipt destination = %v", r.Subject["destination"])
	}
}

func TestReceiptWriteFailureBlocksTunnel(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		backend, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		backendBytes := make(chan int, 1)
		go func() {
			conn, err := backend.Accept()
			if err != nil {
				backendBytes <- 0
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, _ := io.ReadFull(conn, make([]byte, len("ping")))
			backendBytes <- n
		}()

		client, server := net.Pipe()
		defer client.Close()
		p := &proxy{
			launchID:   "launch-1",
			allowlist:  []string{backend.Addr().String()},
			receiptDir: filepath.Join(t.TempDir(), "missing"),
		}
		go p.handle(server)

		clientReader := bufio.NewReader(client)
		_, _ = client.Write([]byte("CONNECT " + backend.Addr().String() + " HTTP/1.1\r\nHost: " + backend.Addr().String() + "\r\n\r\n"))
		response, err := http.ReadResponse(clientReader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 when the ALLOW receipt cannot be written", response.StatusCode)
		}
		_, _ = client.Write([]byte("ping"))
		if n := <-backendBytes; n != 0 {
			t.Fatalf("backend received %d bytes without an ALLOW receipt", n)
		}
	})

	t.Run("transparent", func(t *testing.T) {
		target, port, received := startTLSTarget(t)
		p := &proxy{
			launchID:   "launch-1",
			allowlist:  []string{"openrouter.ai:" + port},
			receiptDir: filepath.Join(t.TempDir(), "missing"),
			lookupIP:   staticResolver("127.0.0.1"),
		}
		proxyAddr := startTransparentProxy(t, p, target)
		if _, err := sendSecretWithSNI(proxyAddr, "openrouter.ai"); err == nil || received.Load() != 0 {
			t.Fatal("connection was tunnelled without an ALLOW receipt")
		}
	})
}

func TestReceiptsAreNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	p := &proxy{launchID: "launch-1", receiptDir: dir}
	const n = 200
	for i := 0; i < n; i++ {
		if err := p.writeReceipt("DENY", "example.com:443", "", "destination_not_allowlisted"); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("%d receipts on disk after %d writes", len(entries), n)
	}
}

// startTLSTarget runs an arbitrary TLS server and counts the requests it sees.
func startTLSTarget(t *testing.T) (addr, port string, received *atomic.Int32) {
	t.Helper()
	received = new(atomic.Int32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "target received: %s", body)
	}))
	t.Cleanup(server.Close)
	addr = strings.TrimPrefix(server.URL, "https://")
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return addr, port, received
}

// startTransparentProxy serves p over real TCP, as the iptables REDIRECT hands
// connections to the sidecar. origDst stands in for SO_ORIGINAL_DST.
func startTransparentProxy(t *testing.T, p *proxy, origDst string) string {
	t.Helper()
	p.recoverDst = func(*net.TCPConn) (string, error) { return origDst, nil }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return ln.Addr().String()
}

func staticResolver(addrs ...string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(context.Context, string, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// sendSecretWithSNI is the VE client: TLS through the proxy with the given
// SNI, then an HTTP POST carrying a secret.
func sendSecretWithSNI(proxyAddr, sni string) (string, error) {
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	secret := "exfiltrated-secret=hunter2"
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", sni, len(secret), secret); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func readReceipts(t *testing.T, dir string) []receipt {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []receipt
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var r receipt
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		out = append(out, r)
	}
	return out
}

func requireReceipt(t *testing.T, dir, reason string) receipt {
	t.Helper()
	for _, r := range readReceipts(t, dir) {
		if r.Subject["reason"] == reason {
			return r
		}
	}
	t.Fatalf("no receipt in %s with reason %q", dir, reason)
	return receipt{}
}

func requireNoReceipt(t *testing.T, dir, reason string) {
	t.Helper()
	for _, r := range readReceipts(t, dir) {
		if r.Subject["reason"] == reason {
			t.Fatalf("unexpected receipt with reason %q: %+v", reason, r)
		}
	}
}
