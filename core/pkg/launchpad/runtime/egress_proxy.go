package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
)

type LaunchOwnedEgressProxy struct {
	ListenAddr  string
	ReceiptDir  string
	DialTimeout time.Duration
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func NewLaunchOwnedEgressProxy() LaunchOwnedEgressProxy {
	return LaunchOwnedEgressProxy{
		ListenAddr:  "127.0.0.1:0",
		DialTimeout: 10 * time.Second,
	}
}

func (p LaunchOwnedEgressProxy) Start(req EgressProxyRequest) (EgressProxyHandle, error) {
	if strings.TrimSpace(req.LaunchID) == "" {
		return EgressProxyHandle{}, errors.New("egress proxy launch id is required")
	}
	if err := ValidateModelProviderAllowlist(req.Allowlist); err != nil {
		return EgressProxyHandle{}, err
	}
	listenAddr := strings.TrimSpace(p.ListenAddr)
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	receiptDir := strings.TrimSpace(req.ReceiptDir)
	if receiptDir == "" {
		receiptDir = strings.TrimSpace(p.ReceiptDir)
	}
	if receiptDir == "" {
		receiptDir = defaultEgressReceiptDir(req.LaunchID)
	}
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		return EgressProxyHandle{}, fmt.Errorf("create egress receipt dir: %w", err)
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return EgressProxyHandle{}, fmt.Errorf("start egress proxy listener: %w", err)
	}
	proxy := &egressProxyServer{
		launchID:           req.LaunchID,
		allowlist:          append([]string{}, req.Allowlist...),
		receiptDir:         receiptDir,
		dialTimeout:        p.DialTimeout,
		dialContext:        p.dialContext,
		payloadInspection:  payloadInspection(req.PayloadInspection),
		networkProof:       networkProof(req.NetworkProof),
		tokenBrokerEnabled: req.TokenBrokerEnabled,
	}
	if proxy.dialTimeout == 0 {
		proxy.dialTimeout = 10 * time.Second
	}
	if proxy.dialContext == nil {
		dialer := &net.Dialer{Timeout: proxy.dialTimeout}
		proxy.dialContext = dialer.DialContext
	}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			_ = proxy.writeReceipt("ESCALATE", "", "proxy_server_error", map[string]any{"error": serveErr.Error()})
		}
	}()
	startReceipt := proxy.writeReceipt("ALLOW", listener.Addr().String(), "proxy_started", map[string]any{
		"listen_addr": listener.Addr().String(),
	})
	return EgressProxyHandle{
		ProxyURL:           "http://" + listener.Addr().String(),
		ReceiptRef:         startReceipt,
		ReceiptDir:         receiptDir,
		Allowlist:          append([]string{}, req.Allowlist...),
		PayloadInspection:  proxy.payloadInspection,
		NetworkProof:       proxy.networkProof,
		TokenBrokerEnabled: proxy.tokenBrokerEnabled,
		Stop: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stopErr := server.Shutdown(ctx)
			_ = proxy.writeReceipt("ALLOW", listener.Addr().String(), "proxy_stopped", nil)
			return stopErr
		},
	}, nil
}

type egressProxyServer struct {
	launchID           string
	allowlist          []string
	receiptDir         string
	dialTimeout        time.Duration
	dialContext        func(context.Context, string, string) (net.Conn, error)
	payloadInspection  string
	networkProof       string
	tokenBrokerEnabled bool
}

func (p *egressProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		_ = p.writeReceipt("DENY", r.Host, "unsupported_proxy_method", map[string]any{"method": r.Method})
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	destination := normalizeDestination(r.Host)
	if !NetworkAllowed(destination, p.allowlist) {
		_ = p.writeReceipt("DENY", destination, "destination_not_allowlisted", nil)
		http.Error(w, "destination not allowlisted", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.dialTimeout)
	defer cancel()
	upstream, err := p.dialContext(ctx, "tcp", destination)
	if err != nil {
		_ = p.writeReceipt("ESCALATE", destination, "upstream_dial_failed", map[string]any{"error": err.Error()})
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_hijack_unavailable", nil)
		http.Error(w, "proxy hijack unavailable", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_hijack_failed", map[string]any{"error": err.Error()})
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		_ = p.writeReceipt("ESCALATE", destination, "proxy_connect_response_failed", map[string]any{"error": err.Error()})
		return
	}
	_ = p.writeReceipt("ALLOW", destination, "connect_allowed", nil)
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

func (p *egressProxyServer) writeReceipt(verdict, destination, reason string, extra map[string]any) string {
	subject := map[string]any{
		"destination":          destination,
		"reason":               reason,
		"allowlist":            append([]string{}, p.allowlist...),
		"payload_inspection":   payloadInspection(p.payloadInspection),
		"network_proof":        networkProof(p.networkProof),
		"token_broker_enabled": p.tokenBrokerEnabled,
	}
	for key, value := range extra {
		subject[key] = value
	}
	receipt := receipts.NewReceipt("launchpad.egress_proxy", p.launchID, verdict, subject)
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return receipt.ReceiptID
	}
	path := filepath.Join(p.receiptDir, safeFileComponent(receipt.Hash)+".json")
	tmp, writeErr := os.CreateTemp(p.receiptDir, ".egress-receipt-*.tmp")
	if writeErr != nil {
		return receipt.ReceiptID
	}
	tmpPath := tmp.Name()
	if _, writeErr = tmp.Write(append(data, '\n')); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return receipt.ReceiptID
	}
	if writeErr = tmp.Chmod(0o600); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return receipt.ReceiptID
	}
	if writeErr = tmp.Close(); writeErr != nil {
		_ = os.Remove(tmpPath)
		return receipt.ReceiptID
	}
	if writeErr = os.Rename(tmpPath, path); writeErr != nil {
		_ = os.Remove(tmpPath)
		return receipt.ReceiptID
	}
	return receipt.ReceiptID
}

func defaultEgressReceiptDir(launchID string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".helm", "launchpad", "egress", safeFileComponent(launchID), "receipts")
	}
	return filepath.Join(os.TempDir(), "helm-launchpad-egress", safeFileComponent(launchID), "receipts")
}

func safeFileComponent(value string) string {
	value = strings.TrimPrefix(value, "sha256:")
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
	component := strings.Trim(b.String(), "-.")
	if component == "" {
		return "launch"
	}
	return component
}
