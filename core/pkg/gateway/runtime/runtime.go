// Command helm-gateway is the effect gateway (Zone C, HELM-751): the server
// of the gateway effect API, helm.gateway.v1.EffectGatewayService, and of its
// authority administration API, helm.gateway.v1.AuthorityAdminService, on the
// same listener.
//
//	helm-gateway migrate   apply the gateway schema and River's to HELM_GATEWAY_DATABASE_URL
//	helm-gateway serve     serve the API on :8443 (TLS) and health on :8081
//	helm-gateway db scram-verifier
//	                       print a PostgreSQL SCRAM-SHA-256 verifier of a password
//
// serve requires TLS (HELM_TLS_CERT_FILE, HELM_TLS_KEY_FILE, and for mutual
// TLS HELM_TLS_CLIENT_AUTH=require with HELM_TLS_CLIENT_CA_FILE) and the
// ADR-0005 token configuration (HELM_CP_IDENTITY_*, with the gateway's own
// audience, helm-gateway:<env>). --dev-insecure-listen serves plain HTTP on a
// loopback address instead, for local development only; it relaxes nothing
// else.
//
// Dispatch and Observe act on GitHub through the GitHub App whose files the
// chart mounts into the gateway Pod only (R8): HELM_GATEWAY_GITHUB_APP_ID_FILE,
// HELM_GATEWAY_GITHUB_APP_PRIVATE_KEY_FILE and
// HELM_GATEWAY_GITHUB_INSTALLATIONS_FILE, all or none, and optionally
// HELM_GATEWAY_GITHUB_API_URL. Without them every GitHub dispatch is NOT_SENT
// (PROVIDER_CREDENTIAL_REJECTED).
//
// With HELM_GATEWAY_MODEL_ROUTES_FILE the gateway also serves the model
// gateway (package modelgw) under /v1/ on its main listener, for the Control
// Plane, and each provider's API key is read from the key file that routes file
// names. With --worker-listen it serves the same endpoints on a second
// listener for episode workers: server TLS without client certificates, the
// worker audience HELM_GATEWAY_WORKER_AUDIENCE (helm-gateway-worker:<env>) and
// tokens of up to HELM_GATEWAY_WORKER_MAX_TTL (at most one hour). A token minted
// for one listener is not valid on the other. The worker listener also serves
// the gateway's effect types as MCP tools at /mcp (package mcpserver), to the
// same episode tokens.
package runtime

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
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/jobs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/mcpserver"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/modelgw"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pgdsn"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/servetls"
)

const (
	envDatabaseURL     = "HELM_GATEWAY_DATABASE_URL"
	envPermitTTL       = "HELM_GATEWAY_PERMIT_TTL"
	envApprovalWindow  = "HELM_GATEWAY_APPROVAL_WINDOW"
	envDispatchTimeout = "HELM_GATEWAY_DISPATCH_TIMEOUT"
	// The worker listener's token audience and lifetime (HELM-752 K7).
	envWorkerAudience = "HELM_GATEWAY_WORKER_AUDIENCE"
	envWorkerMaxTTL   = "HELM_GATEWAY_WORKER_MAX_TTL"
)

// Configure installs gateway-owned adapters in this same server and lifecycle.
// It runs after identity/TLS validation and opening the gateway database, before
// admission and reconciliation start. It must not create another listener.
type Configure func(context.Context, *sql.DB, *admission.Config) error

// Run is the shared gateway command used by the OSS and HELM OS compositions.
func Run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, extensions ...Configure) error {
	if len(args) == 0 {
		return errors.New("usage: helm-gateway migrate | serve [--listen :8443] [--worker-listen :8444] [--health-listen :8081] [--dev-insecure-listen 127.0.0.1:PORT] | db scram-verifier")
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
		if err := jobs.Migrate(ctx, db); err != nil {
			return fmt.Errorf("river migration: %w", err)
		}
		fmt.Fprintf(stderr, "gateway schema at version %d\n", admission.HeadVersion())
		return nil
	case "serve":
		return serve(ctx, args[1:], getenv, stderr, extensions...)
	case "db":
		return runDB(args[1:], os.Stdin, os.Stdout, stderr)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

type serveConfig struct {
	listen, healthListen, devInsecureListen string
	// workerListen is the worker listener's address; empty serves none. With
	// --dev-insecure-listen it is plain HTTP on a loopback address, and
	// otherwise TLS without client certificates.
	workerListen string
}

func parseServeFlags(args []string, stderr io.Writer) (serveConfig, error) {
	var c serveConfig
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.listen, "listen", ":8443", "API listener (TLS)")
	fs.StringVar(&c.healthListen, "health-listen", ":8081", "health listener (/healthz, /readyz)")
	fs.StringVar(&c.devInsecureListen, "dev-insecure-listen", "", "serve the API over plain HTTP on this loopback address instead of TLS (development only)")
	fs.StringVar(&c.workerListen, "worker-listen", "", "worker listener for episode workers (TLS without client certificates; plain HTTP on a loopback address with --dev-insecure-listen)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments %v", fs.Args())
	}
	if c.devInsecureListen != "" {
		if err := requireLoopback("--dev-insecure-listen", c.devInsecureListen); err != nil {
			return c, err
		}
		if c.workerListen != "" {
			if err := requireLoopback("--worker-listen (plain HTTP with --dev-insecure-listen)", c.workerListen); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// requireLoopback accepts only a literal loopback IP: a name could resolve
// anywhere.
func requireLoopback(flagName, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s %q: %w", flagName, address, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s %q must be a loopback IP such as 127.0.0.1:8443; plain HTTP never listens beyond this host", flagName, address)
	}
	return nil
}

func serve(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, extensions ...Configure) error {
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
	models, err := modelsFromEnv(getenv, cfg, identity)
	if err != nil {
		return err
	}
	db, err := openDatabase(getenv)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	// The gateway's own authority effects (helm.authority.provision.v1 and
	// narrow.v1) act on its own database, so their adapter needs no credential.
	provisioner, err := provision.New(db)
	if err != nil {
		return err
	}
	admissionConfig.Adapters = append(admissionConfig.Adapters, provisioner)
	for _, configure := range extensions {
		if configure != nil {
			if err := configure(ctx, db, &admissionConfig); err != nil {
				return fmt.Errorf("gateway composition: %w", err)
			}
		}
	}
	models.install(&admissionConfig)
	// River works the expiry and reconciliation jobs in this process, from
	// the same database: one deployable, and a leader-elected client, so
	// replicas share the queue (TA §6.1).
	runner, err := jobs.New(db, jobs.Config{})
	if err != nil {
		return err
	}
	admissionConfig.Jobs = runner
	svc, err := admission.New(db, admissionConfig)
	if err != nil {
		return err
	}
	runner.Bind(svc)
	go runner.Run(ctx, 5*time.Second)
	defer func() {
		stopping, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = runner.Stop(stopping)
	}()
	// Every adapter is configured by now, the compositions' included: the
	// catalog lists what this process performs.
	catalog, err := server.BuildCatalog(admissionConfig.Adapters)
	if err != nil {
		return fmt.Errorf("effect-type catalog: %w", err)
	}
	api := &server.Server{
		Admission: svc,
		Auth:      &server.Authenticator{Validator: identity.Validator(false), Actor: identity.Actor, RequireCNF: identity.RequireCNF},
	}
	admin := &server.AdminServer{Rows: provisioner.Store(), Auth: api.Auth, Catalog: catalog}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())
	mux.Handle(admin.Handler())
	plain := cfg.devInsecureListen != ""

	// The model gateway: on the main listener for the Control Plane's calls,
	// and on the worker listener for episode workers. One gateway, two
	// authentications: a token is valid on the listener its audience names.
	// The worker listener also serves the effect types as MCP tools (package
	// mcpserver) at /mcp, to the same episode tokens, so a worker has one
	// network exit for its model calls and its effects.
	var workerServer *http.Server
	if models != nil {
		gateway := &modelgw.Gateway{Config: models.config, Ledger: svc, Keys: models.keys}
		mux.Handle("/v1/", server.WithTLSState(gateway.Handler(modelgw.Listener{Name: "main", Auth: api.Auth})))
		if models.worker != nil {
			workerAuth := &server.Authenticator{Validator: models.worker, Actor: identity.Actor, RequireEpisode: true}
			tools, err := mcpserver.NewGateway(svc, admissionConfig.Adapters)
			if err != nil {
				return fmt.Errorf("MCP tools: %w", err)
			}
			workerMux := http.NewServeMux()
			workerMux.Handle("/v1/", gateway.Handler(modelgw.Listener{Name: "worker", Auth: workerAuth, Worker: true}))
			workerMux.Handle("/mcp", &mcpserver.Handler{Authenticate: mcpAuthenticate(workerAuth), Backend: tools})
			workerServer = newAPIServer(workerMux, workerTLS(tlsConfig), plain)
		}
	}

	apiServer := newAPIServer(mux, tlsConfig, plain)
	address := cfg.listen
	if plain {
		address = cfg.devInsecureListen
		slog.Warn("serving the gateway API over plain HTTP on loopback; never use this outside development", "address", address)
	}
	healthServer := &http.Server{Addr: cfg.healthListen, Handler: healthHandler(db), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	errs := make(chan error, 3)
	go func() {
		if tlsConfig != nil {
			errs <- apiServer.ServeTLS(listener, "", "")
		} else {
			errs <- apiServer.Serve(listener)
		}
	}()
	go func() { errs <- healthServer.ListenAndServe() }()
	workerAddress := ""
	if workerServer != nil {
		workerListener, err := net.Listen("tcp", cfg.workerListen)
		if err != nil {
			_ = listener.Close()
			return err
		}
		workerAddress = workerListener.Addr().String()
		go func() {
			if tlsConfig != nil {
				errs <- workerServer.ServeTLS(workerListener, "", "")
			} else {
				errs <- workerServer.Serve(workerListener)
			}
		}()
	}
	slog.Info("helm-gateway serving", "api", listener.Addr().String(), "worker", workerAddress, "health", cfg.healthListen, "tls", tlsConfig != nil)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stopped := []error{apiServer.Shutdown(shutdown), healthServer.Shutdown(shutdown)}
	if workerServer != nil {
		stopped = append(stopped, workerServer.Shutdown(shutdown))
	}
	return errors.Join(stopped...)
}

// newAPIServer serves handler over HTTP/1.1 and HTTP/2 (h2c without TLS, which
// gRPC needs in development).
func newAPIServer(handler http.Handler, tlsConfig *tls.Config, plain bool) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	if plain {
		protocols.SetUnencryptedHTTP2(true)
	}
	return &http.Server{Handler: handler, TLSConfig: tlsConfig, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
}

// mcpAuthenticate is the MCP endpoint's token check: the worker listener's own,
// for a token that proposes or reads. The endpoint takes its identity from
// nothing else.
func mcpAuthenticate(auth *server.Authenticator) mcpserver.Authenticate {
	return func(ctx context.Context, header http.Header) (mcpserver.Caller, error) {
		id, err := auth.Authenticate(ctx, header, server.ScopePropose, server.ScopeRead)
		if err != nil {
			return mcpserver.Caller{}, err
		}
		return mcpserver.Caller{Caller: id.Caller, Scope: id.Scope}, nil
	}
}

// workerTLS is the worker listener's TLS configuration: the same serving
// certificate, and no client certificate. Unmodified agent frameworks cannot
// present one, so the worker listener authenticates by token alone and the
// chart's NetworkPolicy admits only the workers' namespace.
func workerTLS(main *tls.Config) *tls.Config {
	if main == nil {
		return nil
	}
	c := main.Clone()
	c.ClientAuth, c.ClientCAs = tls.NoClientCert, nil
	return c
}

// models is the model gateway's startup configuration: the routes, the custody
// of the provider keys and, with --worker-listen, the worker token validator.
type models struct {
	config *modelgw.Config
	keys   *custody.ProviderKeys
	worker *jwks.JWKSValidator
}

// install declares model.inference to admission, so the effect type is in the
// gateway's catalog and a call left UNKNOWN is reconciled. A gateway with no
// model routes declares nothing.
func (m *models) install(c *admission.Config) {
	if m != nil {
		c.Adapters = append(c.Adapters, modelgw.NewAdapter())
	}
}

// modelsFromEnv reads the routes file and the worker profile. It returns nil
// when no routes file is set, and refuses a configuration that would serve the
// worker listener with nothing to serve or a token audience it cannot check.
func modelsFromEnv(getenv func(string) string, cfg serveConfig, identity *jwks.ControlPlaneIdentity) (*models, error) {
	path := strings.TrimSpace(getenv(modelgw.EnvRoutesFile))
	audience := strings.TrimSpace(getenv(envWorkerAudience))
	switch {
	case path == "" && cfg.workerListen != "":
		return nil, fmt.Errorf("--worker-listen serves the model endpoints and needs %s", modelgw.EnvRoutesFile)
	case path == "" && audience != "":
		return nil, fmt.Errorf("%s is set without %s", envWorkerAudience, modelgw.EnvRoutesFile)
	case path == "":
		return nil, nil
	case cfg.workerListen == "" && audience != "":
		return nil, fmt.Errorf("%s is set without --worker-listen", envWorkerAudience)
	}
	config, err := modelgw.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	keys, err := custody.NewProviderKeys(config.KeyFiles())
	if err != nil {
		return nil, err
	}
	m := &models{config: config, keys: keys}
	if cfg.workerListen == "" {
		return m, nil
	}
	if audience == "" {
		return nil, fmt.Errorf("%s is required with --worker-listen: the worker listener accepts only tokens of its own audience", envWorkerAudience)
	}
	ttl := jwks.WorkerTokenMaxTTLCeiling
	if raw := strings.TrimSpace(getenv(envWorkerMaxTTL)); raw != "" {
		if ttl, err = time.ParseDuration(raw); err != nil {
			return nil, fmt.Errorf("%s must be a duration: %w", envWorkerMaxTTL, err)
		}
	}
	if m.worker, err = identity.WorkerValidator(audience, ttl); err != nil {
		return nil, fmt.Errorf("%s: %w", envWorkerAudience, err)
	}
	return m, nil
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
		case jobs.Ready(ctx, db) != nil:
			http.Error(w, "the job tables are not current: run helm-gateway migrate", http.StatusServiceUnavailable)
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
	utcDSN, err := pgdsn.WithUTCTimeZone(dsn)
	if err != nil {
		return nil, err
	}
	return sql.Open("postgres", utcDSN)
}

func admissionConfigFromEnv(getenv func(string) string) (admission.Config, error) {
	var c admission.Config
	for name, target := range map[string]*time.Duration{envPermitTTL: &c.PermitTTL, envApprovalWindow: &c.ApprovalWindow,
		envDispatchTimeout: &c.DispatchTimeout} {
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
	return c, effectsFromEnv(getenv, &c)
}

// effectsFromEnv wires the GitHub adapter and the GitHub App custody.
func effectsFromEnv(getenv func(string) string, c *admission.Config) error {
	apiURL, err := custody.GitHubAPIURL(getenv)
	if err != nil {
		return err
	}
	c.Adapters = []adapters.Adapter{github.New(github.WithBaseURL(apiURL))}
	app, err := custody.GitHubAppFromEnv(getenv)
	if err != nil {
		return err
	}
	if app == nil {
		slog.Warn("no GitHub App is configured; every GitHub dispatch is NOT_SENT", "set", custody.EnvGitHubAppIDFile)
		return nil
	}
	c.Credentials = app
	return nil
}
