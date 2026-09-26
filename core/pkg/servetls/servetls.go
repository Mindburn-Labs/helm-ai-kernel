// Package servetls builds a server's TLS configuration from the HELM_TLS_*
// environment: a certificate pair re-read on rotation, and optional client
// certificate verification against a pinned CA. The kernel's API listener and
// the effect gateway share it.
package servetls

// quantum_posture: the API listener serves classical TLS 1.2+ with whatever
// X.509 certificate the operator mounts. This file claims no post-quantum or
// hybrid key exchange beyond what the Go crypto/tls defaults negotiate.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	EnvCertFile     = "HELM_TLS_CERT_FILE"
	EnvKeyFile      = "HELM_TLS_KEY_FILE"
	EnvClientCAFile = "HELM_TLS_CLIENT_CA_FILE"
	EnvClientAuth   = "HELM_TLS_CLIENT_AUTH"

	ClientAuthRequire       = "require"
	ClientAuthVerifyIfGiven = "verify-if-given"
)

// ConfigFromEnv returns the listener's TLS configuration read through getenv,
// or nil when HELM_TLS_CERT_FILE and HELM_TLS_KEY_FILE are both unset and the
// listener stays plain HTTP. Any partial or unusable configuration is an
// error so that the server refuses to start rather than fall back to plain
// HTTP.
func ConfigFromEnv(getenv func(string) string) (*tls.Config, error) {
	certFile := strings.TrimSpace(getenv(EnvCertFile))
	keyFile := strings.TrimSpace(getenv(EnvKeyFile))
	clientCAFile := strings.TrimSpace(getenv(EnvClientCAFile))
	clientAuth := strings.TrimSpace(getenv(EnvClientAuth))

	if certFile == "" && keyFile == "" {
		if clientCAFile != "" || clientAuth != "" {
			return nil, fmt.Errorf("%s and %s require %s and %s", EnvClientCAFile, EnvClientAuth, EnvCertFile, EnvKeyFile)
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("set both %s and %s, or neither", EnvCertFile, EnvKeyFile)
	}

	reloader, err := newServeCertReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.getCertificate,
	}

	switch clientAuth {
	case "":
		if clientCAFile != "" {
			return nil, fmt.Errorf("%s is set but %s is not; set it to %q or %q", EnvClientCAFile, EnvClientAuth, ClientAuthRequire, ClientAuthVerifyIfGiven)
		}
		return config, nil
	case ClientAuthRequire:
		config.ClientAuth = tls.RequireAndVerifyClientCert
	case ClientAuthVerifyIfGiven:
		config.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		return nil, fmt.Errorf("%s must be %q or %q, got %q", EnvClientAuth, ClientAuthRequire, ClientAuthVerifyIfGiven, clientAuth)
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("%s=%s requires %s", EnvClientAuth, clientAuth, EnvClientCAFile)
	}
	// ponytail: the client CA pool is read once at startup; rotating the
	// client-trust CA needs a restart. Reload it like the serving certificate
	// if CA rotation without a restart becomes an operational need.
	pem, err := os.ReadFile(clientCAFile) // #nosec G304 -- operator-configured client CA path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", EnvClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", EnvClientCAFile)
	}
	config.ClientCAs = pool
	return config, nil
}

// serveCertReloader serves a certificate pair from disk and re-reads it when
// either file's modification time or size changes, so a Secret-mounted pair
// that cert-manager rotates in place is picked up without a restart.
type serveCertReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	certSig serveFileSignature
	keySig  serveFileSignature
}

type serveFileSignature struct {
	modTime time.Time
	size    int64
}

func newServeCertReloader(certFile, keyFile string) (*serveCertReloader, error) {
	r := &serveCertReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reloadIfChanged(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *serveCertReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if err := r.reloadIfChanged(); err != nil {
		// A rotation can be caught half-written. Keep serving the last good
		// pair and retry on the next handshake.
		slog.Warn("TLS certificate reload failed; serving the previous certificate", "error", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert, nil
}

func (r *serveCertReloader) reloadIfChanged() error {
	certSig, err := statServeFile(r.certFile)
	if err != nil {
		return fmt.Errorf("stat %s: %w", EnvCertFile, err)
	}
	keySig, err := statServeFile(r.keyFile)
	if err != nil {
		return fmt.Errorf("stat %s: %w", EnvKeyFile, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && certSig == r.certSig && keySig == r.keySig {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate from %s and %s: %w", EnvCertFile, EnvKeyFile, err)
	}
	r.cert, r.certSig, r.keySig = &cert, certSig, keySig
	return nil
}

func statServeFile(path string) (serveFileSignature, error) {
	info, err := os.Stat(path)
	if err != nil {
		return serveFileSignature{}, err
	}
	if !info.Mode().IsRegular() {
		return serveFileSignature{}, errors.New("not a regular file")
	}
	return serveFileSignature{modTime: info.ModTime(), size: info.Size()}, nil
}
