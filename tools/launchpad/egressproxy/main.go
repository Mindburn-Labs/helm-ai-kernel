package main

import (
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
		listen = ":8080"
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
	server := &http.Server{Addr: listen, Handler: p, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

type proxy struct {
	launchID   string
	allowlist  []string
	receiptDir string
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		_ = p.writeReceipt("DENY", r.Host, "unsupported_proxy_method")
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	destination := normalizeDestination(r.Host)
	if !networkAllowed(destination, p.allowlist) {
		_ = p.writeReceipt("DENY", destination, "destination_not_allowlisted")
		http.Error(w, "destination not allowlisted", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", destination)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", destination, "upstream_dial_failed")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_hijack_unavailable")
		http.Error(w, "proxy hijack unavailable", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_hijack_failed")
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_connect_response_failed")
		return
	}
	_ = p.writeReceipt("ALLOW", destination, "connect_allowed")
	tunnel(client, upstream)
}

func tunnel(a net.Conn, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	go func() {
		_, _ = io.Copy(a, b)
		once.Do(closeBoth)
	}()
	go func() {
		_, _ = io.Copy(b, a)
		once.Do(closeBoth)
	}()
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
