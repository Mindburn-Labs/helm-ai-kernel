// helm-launchpad-egress-proxy is the launchpad egress sidecar. It supports two
// enforced modes: Kubernetes transparent egress, where an init-container installs
// an iptables REDIRECT and the proxy recovers SO_ORIGINAL_DST, and Docker
// local-container egress, where the workload is on an internal network and must
// use this sidecar through HTTP CONNECT proxy env. In both modes the proxy checks
// the allowlist, writes a receipt, and only then tunnels allowed traffic.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type receipt struct {
	Kind      string         `json:"kind"`
	LaunchID  string         `json:"launch_id"`
	Verdict   string         `json:"verdict"`
	Subject   map[string]any `json:"subject"`
	CreatedAt string         `json:"created_at"`
}

func main() {
	launchID := strings.TrimSpace(os.Getenv("HELM_EGRESS_LAUNCH_ID"))
	if launchID == "" {
		log.Fatal("HELM_EGRESS_LAUNCH_ID is required")
	}
	allowlist := splitAllowlist(os.Getenv("HELM_EGRESS_ALLOWLIST"))
	if len(allowlist) == 0 {
		log.Fatal("HELM_EGRESS_ALLOWLIST is required")
	}
	listen := strings.TrimSpace(os.Getenv("HELM_EGRESS_LISTEN"))
	if listen == "" {
		listen = ":15001"
	}
	receiptDir := strings.TrimSpace(os.Getenv("HELM_EGRESS_RECEIPT_DIR"))
	if receiptDir == "" {
		receiptDir = "/receipts"
	}
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		log.Fatalf("create receipt dir: %v", err)
	}
	p := &proxy{launchID: launchID, allowlist: allowlist, receiptDir: receiptDir}
	_ = p.writeReceipt("ALLOW", "", "proxy_started")

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("transparent egress proxy listening on %s", listen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go p.handle(conn)
	}
}

type proxy struct {
	launchID   string
	allowlist  []string
	receiptDir string
}

// handle services one intercepted (iptables-REDIRECTed) connection. The original
// destination is recovered from the kernel via SO_ORIGINAL_DST; the hostname, when
// present, comes from the TLS ClientHello SNI without terminating TLS.
func (p *proxy) handle(client net.Conn) {
	br := bufio.NewReaderSize(client, 8192)
	if isConnectRequest(client, br) {
		p.handleCONNECT(client, br)
		return
	}
	tcp, ok := client.(*net.TCPConn)
	if !ok {
		_ = client.Close()
		return
	}
	origDst, err := originalDst(tcp)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", "", "original_dst_unavailable")
		_ = client.Close()
		return
	}

	// Buffer the client side so the peeked ClientHello bytes are preserved for
	// forwarding. SNI is best-effort: ECH, non-TLS, or IP-literal traffic yields
	// no hostname and we fall back to the original IP:port for the allowlist.
	host := sniHost(br)
	destination := origDst
	if host != "" {
		if _, port, err := net.SplitHostPort(origDst); err == nil {
			destination = net.JoinHostPort(host, port)
		} else {
			destination = host
		}
	}

	if !networkAllowed(destination, p.allowlist) {
		_ = p.writeReceipt("DENY", destination, "destination_not_allowlisted")
		_ = client.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	// Dial the original IP:port the workload targeted (not the SNI hostname) so we
	// connect exactly where it intended and avoid a re-resolution / DNS-rebind gap.
	upstream, err := d.DialContext(ctx, "tcp", origDst)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", destination, "upstream_dial_failed")
		_ = client.Close()
		return
	}
	_ = p.writeReceipt("ALLOW", destination, "connect_allowed")
	tunnel(client, br, upstream)
}

func isConnectRequest(conn net.Conn, br *bufio.Reader) bool {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	head, err := br.Peek(len("CONNECT "))
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return false
	}
	return strings.EqualFold(string(head[:len("CONNECT")]), "CONNECT") && head[len("CONNECT")] == ' '
}

func (p *proxy) handleCONNECT(client net.Conn, br *bufio.Reader) {
	request, err := http.ReadRequest(br)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", "", "connect_request_parse_failed")
		_ = client.Close()
		return
	}
	if request.Method != http.MethodConnect {
		_ = p.writeReceipt("DENY", request.Host, "unsupported_proxy_method")
		_, _ = client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		_ = client.Close()
		return
	}
	destination := normalizeDestination(request.Host)
	if destination == "" && request.URL != nil {
		destination = normalizeDestination(request.URL.Host)
	}
	if !networkAllowed(destination, p.allowlist) {
		_ = p.writeReceipt("DENY", destination, "destination_not_allowlisted")
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		_ = client.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", destination)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", destination, "upstream_dial_failed")
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = client.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_connect_response_failed")
		return
	}
	_ = p.writeReceipt("ALLOW", destination, "connect_allowed")
	tunnel(client, br, upstream)
}

// tunnel splices the client connection and its buffered reader to the upstream.
// The buffered reader carries any bytes already peeked for SNI, so the TLS
// handshake reaches the upstream intact.
func tunnel(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	var once sync.Once
	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		once.Do(closeBoth)
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		once.Do(closeBoth)
	}()
}

// sniHost best-effort extracts the SNI server name from the TLS ClientHello at the
// head of the connection without consuming it (Peek only). Returns "" on any parse
// failure or when no SNI is present.
func sniHost(br *bufio.Reader) string {
	// TLS record header: type(1) version(2) length(2). Want a handshake record.
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return ""
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 8192-5 {
		return ""
	}
	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return ""
	}
	return parseSNI(buf[5:])
}

// parseSNI walks a TLS handshake ClientHello body and returns the server_name
// extension value, or "" if absent/malformed.
func parseSNI(b []byte) string {
	// Handshake header: msgType(1)=ClientHello(0x01) length(3).
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	b = b[4:]
	// client_version(2) + random(32).
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	// session_id.
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return ""
	}
	b = b[sidLen:]
	// cipher_suites.
	if len(b) < 2 {
		return ""
	}
	csLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < csLen {
		return ""
	}
	b = b[csLen:]
	// compression_methods.
	if len(b) < 1 {
		return ""
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return ""
	}
	b = b[cmLen:]
	// extensions.
	if len(b) < 2 {
		return ""
	}
	extLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) > extLen {
		b = b[:extLen]
	}
	for len(b) >= 4 {
		extType := int(b[0])<<8 | int(b[1])
		l := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < l {
			return ""
		}
		body := b[:l]
		b = b[l:]
		if extType != 0x0000 { // server_name
			continue
		}
		// ServerNameList: list_length(2) then entries of type(1) len(2) name.
		if len(body) < 2 {
			return ""
		}
		body = body[2:]
		for len(body) >= 3 {
			nameType := body[0]
			nameLen := int(body[1])<<8 | int(body[2])
			body = body[3:]
			if len(body) < nameLen {
				return ""
			}
			if nameType == 0x00 { // host_name
				return strings.ToLower(string(body[:nameLen]))
			}
			body = body[nameLen:]
		}
	}
	return ""
}

func (p *proxy) writeReceipt(verdict, destination, reason string) error {
	if p.receiptDir == "" {
		return errors.New("receipt dir missing")
	}
	data, err := json.MarshalIndent(receipt{
		Kind:     "launchpad.egress_proxy",
		LaunchID: p.launchID,
		Verdict:  verdict,
		Subject: map[string]any{
			"destination": destination,
			"reason":      reason,
			"allowlist":   append([]string{}, p.allowlist...),
		},
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, "", "  ")
	if err != nil {
		return err
	}
	name := sanitize(time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + verdict + "-" + reason + ".json")
	return os.WriteFile(filepath.Join(p.receiptDir, name), append(data, '\n'), 0o600)
}

func splitAllowlist(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func networkAllowed(destination string, allowlist []string) bool {
	normalized := normalizeDestination(destination)
	for _, allowed := range allowlist {
		if normalized == normalizeDestination(allowed) {
			return true
		}
	}
	return false
}

func normalizeDestination(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Host != "" {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			switch parsed.Scheme {
			case "https":
				host += ":443"
			case "http":
				host += ":80"
			}
		}
		return strings.ToLower(host)
	}
	if !strings.Contains(trimmed, ":") {
		trimmed += ":443"
	}
	return strings.ToLower(trimmed)
}

func sanitize(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
