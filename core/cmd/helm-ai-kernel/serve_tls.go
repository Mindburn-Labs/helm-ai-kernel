package main

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
	serveTLSCertFileEnv     = "HELM_TLS_CERT_FILE"
	serveTLSKeyFileEnv      = "HELM_TLS_KEY_FILE"
	serveTLSClientCAFileEnv = "HELM_TLS_CLIENT_CA_FILE"
	serveTLSClientAuthEnv   = "HELM_TLS_CLIENT_AUTH"

	serveTLSClientAuthRequire       = "require"
	serveTLSClientAuthVerifyIfGiven = "verify-if-given"
)

// serveTLSConfigFromEnv returns the API listener's TLS configuration, or nil
// when HELM_TLS_CERT_FILE and HELM_TLS_KEY_FILE are both unset and the listener
// stays plain HTTP. Any partial or unusable configuration is an error so that
// serve refuses to start rather than fall back to plain HTTP.
func serveTLSConfigFromEnv() (*tls.Config, error) {
	certFile := strings.TrimSpace(os.Getenv(serveTLSCertFileEnv))
	keyFile := strings.TrimSpace(os.Getenv(serveTLSKeyFileEnv))
	clientCAFile := strings.TrimSpace(os.Getenv(serveTLSClientCAFileEnv))
	clientAuth := strings.TrimSpace(os.Getenv(serveTLSClientAuthEnv))

	if certFile == "" && keyFile == "" {
		if clientCAFile != "" || clientAuth != "" {
			return nil, fmt.Errorf("%s and %s require %s and %s", serveTLSClientCAFileEnv, serveTLSClientAuthEnv, serveTLSCertFileEnv, serveTLSKeyFileEnv)
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("set both %s and %s, or neither", serveTLSCertFileEnv, serveTLSKeyFileEnv)
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
			return nil, fmt.Errorf("%s is set but %s is not; set it to %q or %q", serveTLSClientCAFileEnv, serveTLSClientAuthEnv, serveTLSClientAuthRequire, serveTLSClientAuthVerifyIfGiven)
		}
		return config, nil
	case serveTLSClientAuthRequire:
		config.ClientAuth = tls.RequireAndVerifyClientCert
	case serveTLSClientAuthVerifyIfGiven:
		config.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		return nil, fmt.Errorf("%s must be %q or %q, got %q", serveTLSClientAuthEnv, serveTLSClientAuthRequire, serveTLSClientAuthVerifyIfGiven, clientAuth)
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("%s=%s requires %s", serveTLSClientAuthEnv, clientAuth, serveTLSClientCAFileEnv)
	}
	// ponytail: the client CA pool is read once at startup; rotating the
	// client-trust CA needs a restart. Reload it like the serving certificate
	// if CA rotation without a restart becomes an operational need.
	pem, err := os.ReadFile(clientCAFile) // #nosec G304 -- operator-configured client CA path
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", serveTLSClientCAFileEnv, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", serveTLSClientCAFileEnv)
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
		return fmt.Errorf("stat %s: %w", serveTLSCertFileEnv, err)
	}
	keySig, err := statServeFile(r.keyFile)
	if err != nil {
		return fmt.Errorf("stat %s: %w", serveTLSKeyFileEnv, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && certSig == r.certSig && keySig == r.keySig {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate from %s and %s: %w", serveTLSCertFileEnv, serveTLSKeyFileEnv, err)
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
