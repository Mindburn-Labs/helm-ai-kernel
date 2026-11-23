// quantum_posture: local Console integrity uses classical SHA-256/HMAC and
// Sigstore-verified release evidence; it makes no post-quantum assurance.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func rejectLocalConsoleOverrides() error {
	for _, key := range []string{
		"HELM_CONSOLE_ASSETS",
		"HELM_CONSOLE_BUNDLE",
		"HELM_CONSOLE_DIR",
		"HELM_CONSOLE_ORIGIN",
		"HELM_CONSOLE_URL",
		"HELM_API_ORIGIN",
		"HELM_KERNEL_ORIGIN",
		"HELM_KERNEL_TOKEN",
		"HELM_KERNEL_TENANT",
		"HELM_KERNEL_PRINCIPAL",
		"HELM_LOCAL_SIDECAR_READY_SECRET",
		"HELM_LOCAL_KERNEL_PEER_SECRET",
		"NEXT_PUBLIC_HELM_API_MODE",
	} {
		if value, present := os.LookupEnv(key); present && strings.TrimSpace(value) != "" {
			return fmt.Errorf("--console rejects external %s override", key)
		}
	}
	return nil
}

func reserveLocalConsolePort(requested int) (net.Listener, int, error) {
	if requested < 0 || requested > 65535 {
		return nil, 0, fmt.Errorf("--console-port must be between 0 and 65535")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(requested)))
	if err != nil {
		return nil, 0, fmt.Errorf("reserve local Console port: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || tcpAddr.Port <= 0 {
		_ = listener.Close()
		return nil, 0, fmt.Errorf("local Console port is not loopback")
	}
	return listener, tcpAddr.Port, nil
}

func localConsoleChildEnv(kernelOrigin string, consolePort int, quickstart *quickstartRuntime, readinessSecret, peerSecret string) ([]string, error) {
	if quickstart == nil || quickstart.SessionToken == "" || quickstart.TenantID == "" || quickstart.PrincipalID == "" ||
		!validLoopbackHTTPOrigin(kernelOrigin) || consolePort <= 0 || consolePort > 65535 || !validLocalConsoleSecret(readinessSecret) || !validLocalConsoleSecret(peerSecret) {
		return nil, fmt.Errorf("local Console runtime configuration is invalid")
	}
	consoleOrigin := localConsoleOrigin(consolePort)
	return []string{
		"NODE_ENV=production",
		"HOSTNAME=127.0.0.1",
		"PORT=" + strconv.Itoa(consolePort),
		"NEXT_PUBLIC_HELM_API_MODE=kernel",
		"HELM_CONSOLE_ORIGIN=" + consoleOrigin,
		"HELM_KERNEL_ORIGIN=" + kernelOrigin,
		"HELM_KERNEL_TOKEN=" + quickstart.SessionToken,
		"HELM_KERNEL_TENANT=" + quickstart.TenantID,
		"HELM_KERNEL_PRINCIPAL=" + quickstart.PrincipalID,
		"HELM_LOCAL_SIDECAR_READY_SECRET=" + readinessSecret,
		"HELM_LOCAL_KERNEL_PEER_SECRET=" + peerSecret,
	}, nil
}

func localConsoleOrigin(port int) string {
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func localKernelOrigin(bindAddr string, port int) string {
	return "http://" + net.JoinHostPort(bindAddr, strconv.Itoa(port))
}

func validLoopbackHTTPOrigin(value string) bool {
	parsed, err := http.NewRequest(http.MethodGet, value, nil)
	if err != nil || parsed.URL.Scheme != "http" || parsed.URL.User != nil || parsed.URL.Port() == "" || parsed.URL.Path != "" || parsed.URL.RawQuery != "" || parsed.URL.Fragment != "" {
		return false
	}
	host := parsed.URL.Hostname()
	return host == "127.0.0.1" || host == "::1"
}

func validLocalConsoleSecret(secret string) bool {
	return validLowerHex(secret, sha256.Size)
}

type localConsolePeerProof struct {
	secret string
}

func newLocalConsolePeerProof(secret string) (*localConsolePeerProof, error) {
	if !validLocalConsoleSecret(secret) {
		return nil, fmt.Errorf("local Console peer secret is invalid")
	}
	return &localConsolePeerProof{secret: secret}, nil
}

func (p *localConsolePeerProof) prove(nonce string) (string, bool) {
	if p == nil || !validLocalConsoleReadyNonce(nonce) {
		return "", false
	}
	proof := localConsolePeerProofValue(p.secret, nonce)
	if proof == "" {
		return "", false
	}
	return proof, true
}

func localConsolePeerProofValue(secret, nonce string) string {
	if !validLocalConsoleSecret(secret) || !validLocalConsoleReadyNonce(nonce) {
		return ""
	}
	key, err := hex.DecodeString(secret)
	if err != nil || len(key) != sha256.Size {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

type localConsoleSupervisor struct {
	bundle        localConsoleBundle
	requestedPort int
	quickstart    *quickstartRuntime

	mu      sync.Mutex
	command *exec.Cmd
	done    chan struct{}
	url     string
	secret  string
	nonce   string
	peer    *localConsolePeerProof
	started bool
}

func newLocalConsoleSupervisor(bundle localConsoleBundle, requestedPort int, quickstart *quickstartRuntime) (*localConsoleSupervisor, error) {
	readinessSecret, err := randomTokenHex(sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("generate local Console readiness secret: %w", err)
	}
	peerSecret := readinessSecret
	for peerSecret == readinessSecret {
		peerSecret, err = randomTokenHex(sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("generate local Console peer secret: %w", err)
		}
	}
	peer, err := newLocalConsolePeerProof(peerSecret)
	if err != nil {
		return nil, err
	}
	return &localConsoleSupervisor{
		bundle:        bundle,
		requestedPort: requestedPort,
		quickstart:    quickstart,
		done:          make(chan struct{}),
		secret:        readinessSecret,
		peer:          peer,
	}, nil
}

func (s *localConsoleSupervisor) Start(kernelOrigin string) (string, error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return "", fmt.Errorf("local Console is already started")
	}
	s.started = true
	s.mu.Unlock()

	node := s.bundle.NodePath
	if node == "" || !filepath.IsAbs(node) {
		return "", fmt.Errorf("local Console bundled Node is not configured")
	}
	reservation, port, err := reserveLocalConsolePort(s.requestedPort)
	if err != nil {
		return "", err
	}
	nonce, err := randomTokenHex(32)
	if err != nil {
		_ = reservation.Close()
		return "", fmt.Errorf("generate local Console readiness nonce: %w", err)
	}
	s.mu.Lock()
	readinessSecret := s.secret
	peer := s.peer
	s.mu.Unlock()
	if peer == nil {
		_ = reservation.Close()
		return "", fmt.Errorf("local Console peer proof is not configured")
	}
	childEnv, err := localConsoleChildEnv(kernelOrigin, port, s.quickstart, readinessSecret, peer.secret)
	if err != nil {
		_ = reservation.Close()
		return "", err
	}

	command := localConsoleCommand(node, s.bundle.ServerPath)
	command.Dir = s.bundle.AppRoot
	command.Env = childEnv
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := reservation.Close(); err != nil {
		return "", fmt.Errorf("release local Console port reservation: %w", err)
	}
	if err := command.Start(); err != nil {
		return "", fmt.Errorf("start local Console: %w", err)
	}

	url := "http://127.0.0.1:" + strconv.Itoa(port)
	s.mu.Lock()
	s.command = command
	s.url = url
	s.nonce = nonce
	s.mu.Unlock()
	go func() {
		_ = command.Wait()
		close(s.done)
	}()
	return url, nil
}

func (s *localConsoleSupervisor) WaitReady() error {
	s.mu.Lock()
	url, secret, nonce := s.url, s.secret, s.nonce
	s.mu.Unlock()
	if url == "" || secret == "" || nonce == "" {
		return fmt.Errorf("local Console was not started")
	}
	return localConsoleReadiness(context.Background(), url, secret, nonce, s.done)
}

func (s *localConsoleSupervisor) Done() <-chan struct{} {
	return s.done
}

func (s *localConsoleSupervisor) PeerProof() *localConsolePeerProof {
	if s == nil {
		return nil
	}
	return s.peer
}

func (s *localConsoleSupervisor) Stop() {
	s.mu.Lock()
	command := s.command
	s.mu.Unlock()
	if command == nil || command.Process == nil {
		return
	}
	// The packaged sidecar entrypoint owns server.js and forwards SIGINT/SIGTERM
	// to it. Killing that wrapper first can leave the child listener alive, so
	// give the wrapper a cross-platform interrupt grace period before forcing a
	// last-resort kill.
	_ = command.Process.Signal(os.Interrupt)
	if waitForLocalConsoleExit(s.done, localConsoleStopTimeout) {
		return
	}
	_ = command.Process.Kill()
	_ = waitForLocalConsoleExit(s.done, localConsoleStopTimeout)
}

func waitForLocalConsoleExit(done <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}

}

func waitForLocalConsoleReady(ctx context.Context, url, secret, nonce string, done <-chan struct{}) error {
	deadline := time.NewTimer(localConsoleReadyTimeout)
	defer deadline.Stop()
	retry := time.NewTimer(0)
	defer retry.Stop()
	for {
		select {
		case <-done:
			return fmt.Errorf("local Console exited before readiness")
		case <-ctx.Done():
			return fmt.Errorf("local Console readiness canceled")
		case <-deadline.C:
			return fmt.Errorf("local Console readiness proof timed out")
		case <-retry.C:
			if localConsoleReadyProofValid(ctx, url, secret, nonce) {
				return nil
			}
			retry.Reset(localConsoleReadyRetry)
		}
	}
}

func localConsoleReadyProofValid(ctx context.Context, url, secret, nonce string) bool {
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodHead, url+localConsoleReadyPath, nil)
	if err != nil {
		return false
	}
	request.Header.Set(localConsoleReadyNonceHeader, nonce)
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: time.Second,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || len(body) != 0 || response.StatusCode != http.StatusOK {
		return false
	}
	expected := localConsoleReadyProof(secret, nonce)
	return expected != "" && hmac.Equal([]byte(response.Header.Get(localConsoleReadyProofHeader)), []byte(expected))
}

func localConsoleReadyProof(secret, nonce string) string {
	return localConsoleHMAC(secret, nonce)
}

func localConsoleHMAC(secret, nonce string) string {
	if !validLocalConsoleSecret(secret) || !validLocalConsoleReadyNonce(nonce) {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, nonce)
	return hex.EncodeToString(mac.Sum(nil))
}

func validLocalConsoleReadyNonce(nonce string) bool {
	if len(nonce) < 32 || len(nonce) > 128 || len(nonce)%2 != 0 || strings.ToLower(nonce) != nonce {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}

func ensureLocalConsoleReadyThenOpen(wait func() error, noOpen bool, url string) error {
	if err := wait(); err != nil {
		return err
	}
	if noOpen {
		return nil
	}
	return openLocalConsoleURL(url)
}

func openLocalConsoleBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Start()
}
