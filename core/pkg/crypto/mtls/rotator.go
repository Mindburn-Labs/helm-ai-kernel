package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"sync"
	"time"
)

// CertRotator provides zero-downtime certificate rotation.
// It monitors certificate expiry and automatically renews before the
// renewal window closes, swapping the TLS certificate atomically.
type CertRotator struct {
	ca            *CertificateAuthority
	identity      string
	renewBefore   time.Duration
	checkInterval time.Duration
	logger        *slog.Logger

	mu      sync.RWMutex
	current *tls.Certificate
	stopCh  chan struct{}
}

// RotatorConfig configures the certificate rotator.
type RotatorConfig struct {
	CA            *CertificateAuthority
	Identity      string        // SPIFFE-compatible identity string
	RenewBefore   time.Duration // How long before expiry to renew (default: 4h)
	CheckInterval time.Duration // How often to check (default: 1h)
	Logger        *slog.Logger
}

// NewCertRotator creates a new certificate rotator.
func NewCertRotator(cfg RotatorConfig) (*CertRotator, error) {
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = 4 * time.Hour
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 1 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	r := &CertRotator{
		ca:            cfg.CA,
		identity:      cfg.Identity,
		renewBefore:   cfg.RenewBefore,
		checkInterval: cfg.CheckInterval,
		logger:        cfg.Logger,
		stopCh:        make(chan struct{}),
	}

	// Issue initial certificate.
	if err := r.rotate(); err != nil {
		return nil, err
	}

	return r, nil
}

// GetCertificate returns the current TLS certificate for use in tls.Config.GetCertificate.
func (r *CertRotator) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current, nil
}

// Start begins the background rotation loop.
func (r *CertRotator) Start() {
	go func() {
		ticker := time.NewTicker(r.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.mu.RLock()
				cert := r.current
				r.mu.RUnlock()

				if cert == nil || len(cert.Certificate) == 0 {
					r.logger.Warn("mtls: no current certificate, rotating now")
					_ = r.rotate()
					continue
				}

				// Parse leaf to check expiry.
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					_ = r.rotate()
					continue
				}

				if time.Until(leaf.NotAfter) < r.renewBefore {
					r.logger.Info("mtls: certificate nearing expiry, rotating",
						"not_after", leaf.NotAfter,
						"renew_before", r.renewBefore,
					)
					if err := r.rotate(); err != nil {
						r.logger.Error("mtls: rotation failed", "error", err)
					}
				}

			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop halts the background rotation loop.
func (r *CertRotator) Stop() {
	close(r.stopCh)
}

// rotate issues a new certificate and atomically swaps it.
func (r *CertRotator) rotate() error {
	issued, err := r.ca.IssueCertificate(context.Background(), r.identity)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.current = issued.TLSCert
	r.mu.Unlock()

	r.logger.Info("mtls: certificate rotated successfully",
		"identity", r.identity,
		"valid_until", issued.NotAfter,
	)
	return nil
}

// CACertPool returns the CA certificate pool for TLS verification.
func (ca *CertificateAuthority) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	return pool
}

// NewRotatingTLSConfig creates a tls.Config that uses the rotator for certificate provisioning.
func NewRotatingTLSConfig(rotator *CertRotator, ca *CertificateAuthority) *tls.Config {
	return &tls.Config{
		GetCertificate: rotator.GetCertificate,
		RootCAs:        ca.CACertPool(),
		ClientCAs:      ca.CACertPool(),
		ClientAuth:     tls.RequireAndVerifyClientCert,
		MinVersion:     tls.VersionTLS13,
	}
}
