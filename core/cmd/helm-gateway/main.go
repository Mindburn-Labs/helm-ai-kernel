// Command helm-gateway is the effect gateway (Zone C, HELM-751): the server
// of the gateway effect API, helm.gateway.v1.EffectGatewayService.
//
//	helm-gateway migrate   apply the gateway schema to HELM_GATEWAY_DATABASE_URL
//	helm-gateway serve     serve the API on :8443 (TLS) and health on :8081
//
// serve requires TLS (HELM_TLS_CERT_FILE, HELM_TLS_KEY_FILE, and for mutual
// TLS HELM_TLS_CLIENT_AUTH=require with HELM_TLS_CLIENT_CA_FILE) and the
// ADR-0005 token configuration (HELM_CP_IDENTITY_*, with the gateway's own
// audience, helm-gateway:<env>). --dev-insecure-listen serves plain HTTP on a
// loopback address instead, for local development only; it relaxes nothing
// else.
package main

// quantum_posture: the listener serves classical TLS 1.2+ (pkg/servetls) and
// verifies classical RS256 tokens (pkg/auth/jwks); no post-quantum claim.

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/servetls"
)

const (
	envDatabaseURL    = "HELM_GATEWAY_DATABASE_URL"
	envPermitTTL      = "HELM_GATEWAY_PERMIT_TTL"
	envApprovalWindow = "HELM_GATEWAY_APPROVAL_WINDOW"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "helm-gateway:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: helm-gateway migrate | serve [--listen :8443] [--health-listen :8081] [--dev-insecure-listen 127.0.0.1:PORT]")
	}
	switch args[0] {
	case "migrate":
		db, err := openDatabase(getenv)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		if err := admission.Migrate(ctx, db); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "gateway schema at version %d\n", admission.HeadVersion())
		return nil
	case "serve":
		return serve(ctx, args[1:], getenv, stderr)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

type serveConfig struct {
	listen, healthListen, devInsecureListen string
}

func parseServeFlags(args []string, stderr io.Writer) (serveConfig, error) {
	var c serveConfig
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.listen, "listen", ":8443", "API listener (TLS)")
	fs.StringVar(&c.healthListen, "health-listen", ":8081", "health listener (/healthz, /readyz)")
	fs.StringVar(&c.devInsecureListen, "dev-insecure-listen", "", "serve the API over plain HTTP on this loopback address instead of TLS (development only)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments %v", fs.Args())
	}
	if c.devInsecureListen != "" {
		if err := requireLoopback(c.devInsecureListen); err != nil {
			return c, err
		}
	}
	return c, nil
}

// requireLoopback accepts only a literal loopback IP: a name could resolve
// anywhere.
func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("--dev-insecure-listen %q: %w", address, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--dev-insecure-listen %q must be a loopback IP such as 127.0.0.1:8443; plain HTTP never listens beyond this host", address)
	}
	return nil
}

func serve(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	cfg, err := parseServeFlags(args, stderr)
	if err != nil {
		return err
	}
	identity, err := jwks.ControlPlaneIdentityFromEnv(getenv)
	if err != nil {
		return err
	}
	if identity == nil {
		return fmt.Errorf("%s, %s, %s and %s are required: the gateway takes identity only from tokens",
			jwks.EnvCPIdentityJWKSURL, jwks.EnvCPIdentityIssuer, jwks.EnvCPIdentityAudience, jwks.EnvCPIdentityActor)
	}
	var tlsConfig *tls.Config
	if cfg.devInsecureListen == "" {
		if tlsConfig, err = servetls.ConfigFromEnv(getenv); err != nil {
			return err
		}
		if tlsConfig == nil {
			return fmt.Errorf("%s and %s are required; use --dev-insecure-listen on a loopback address for local development",
				servetls.EnvCertFile, servetls.EnvKeyFile)
		}
	}
	admissionConfig, err := admissionConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	db, err := openDatabase(getenv)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	svc, err := admission.New(db, admissionConfig)
	if err != nil {
		return err
	}
	api := &server.Server{
		Admission: svc,
		Auth:      &server.Authenticator{Validator: identity.Validator(false), Actor: identity.Actor, RequireCNF: identity.RequireCNF},
	}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	apiServer := &http.Server{Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second}
	address := cfg.listen
	if cfg.devInsecureListen != "" {
		// gRPC needs HTTP/2; without TLS that is h2c.
		protocols.SetUnencryptedHTTP2(true)
		address = cfg.devInsecureListen
		slog.Warn("serving the gateway API over plain HTTP on loopback; never use this outside development", "address", address)
	}
	apiServer.Protocols = protocols
	healthServer := &http.Server{Addr: cfg.healthListen, Handler: healthHandler(db), ReadHeaderTimeout: 10 * time.Second}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	errs := make(chan error, 2)
	go func() {
		if tlsConfig != nil {
			errs <- apiServer.ServeTLS(listener, "", "")
		} else {
			errs <- apiServer.Serve(listener)
		}
	}()
	go func() { errs <- healthServer.ListenAndServe() }()
	slog.Info("helm-gateway serving", "api", listener.Addr().String(), "health", cfg.healthListen, "tls", tlsConfig != nil)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return errors.Join(apiServer.Shutdown(shutdown), healthServer.Shutdown(shutdown))
}

// healthHandler serves /healthz (the process is up) and /readyz (the
// database answers and its gateway schema is at this binary's head).
func healthHandler(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		version, err := admission.SchemaVersion(ctx, db)
		switch {
		case err != nil:
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		case version != admission.HeadVersion():
			http.Error(w, fmt.Sprintf("gateway schema at version %d, want %d: run helm-gateway migrate", version, admission.HeadVersion()), http.StatusServiceUnavailable)
		default:
			_, _ = io.WriteString(w, "ready\n")
		}
	})
	return mux
}

func openDatabase(getenv func(string) string) (*sql.DB, error) {
	dsn := strings.TrimSpace(getenv(envDatabaseURL))
	if dsn == "" {
		return nil, fmt.Errorf("%s is required", envDatabaseURL)
	}
	return sql.Open("postgres", dsn)
}

func admissionConfigFromEnv(getenv func(string) string) (admission.Config, error) {
	var c admission.Config
	for name, target := range map[string]*time.Duration{envPermitTTL: &c.PermitTTL, envApprovalWindow: &c.ApprovalWindow} {
		raw := strings.TrimSpace(getenv(name))
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("%s must be a positive duration", name)
		}
		*target = d
	}
	return c, nil
}
