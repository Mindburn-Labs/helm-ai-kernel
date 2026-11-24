package reconcile

// quantum_posture: Policy source adapters load snapshots and configure control-plane TLS.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// MountedFileSource is the OSS/local policy backend. The mounted file is
// delivery only; Reconciler still verifies and compiles before installing.
type MountedFileSource struct {
	Path          string
	SignaturePath string
	Scope         PolicyScope
}

func NewMountedFileSource(path string, scope PolicyScope) *MountedFileSource {
	return &MountedFileSource{Path: path, Scope: scope.Normalize()}
}

func (s *MountedFileSource) ListScopes(context.Context) ([]PolicyScope, error) {
	return []PolicyScope{s.Scope.Normalize()}, nil
}

func (s *MountedFileSource) Head(ctx context.Context, scope PolicyScope) (PolicyHead, error) {
	data, epoch, err := s.read(ctx)
	if err != nil {
		return PolicyHead{}, err
	}
	scope = s.Scope.Normalize()
	signature, signatureRef, err := s.readSignature(ctx)
	if err != nil {
		return PolicyHead{}, err
	}
	sourceRefs := []string{s.Path}
	if ref, refEpoch, err := mountedReferencePackSourceRef(s.Path, data); err != nil {
		return PolicyHead{}, err
	} else if ref != "" {
		sourceRefs = append(sourceRefs, ref)
		if refEpoch > epoch {
			epoch = refEpoch
		}
	}
	policyHash := HashBytes(data)
	if len(digestSourceRefs(sourceRefs)) > 0 {
		policyHash = PolicyHashWithSourceRefs(data, sourceRefs)
	}
	if signatureRef != "" {
		sourceRefs = append(sourceRefs, signatureRef)
	}
	return PolicyHead{
		Scope:       scope,
		PolicyEpoch: epoch,
		PolicyHash:  policyHash,
		BundleRef:   s.Path,
		Signature:   signature,
		SourceRefs:  sourceRefs,
	}, nil
}

func (s *MountedFileSource) Load(ctx context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	data, _, err := s.read(ctx)
	return data, err
}

func (s *MountedFileSource) read(ctx context.Context) ([]byte, uint64, error) {
	if strings.TrimSpace(s.Path) == "" {
		return nil, 0, fmt.Errorf("mounted policy path is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		return nil, 0, err
	}
	epoch := uint64(info.ModTime().UnixNano())
	if epoch == 0 {
		epoch = 1
	}
	return data, epoch, nil
}

func (s *MountedFileSource) readSignature(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	path := strings.TrimSpace(s.SignaturePath)
	if path == "" {
		path = strings.TrimSpace(s.Path) + ".sig"
	}
	if strings.TrimSpace(path) == "" {
		return "", "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(data)), path, nil
}

type mountedPolicyRef struct {
	ReferencePack string `toml:"reference_pack"`
}

func mountedReferencePackSourceRef(policyPath string, policyBytes []byte) (string, uint64, error) {
	if strings.ToLower(filepath.Ext(policyPath)) != ".toml" {
		return "", 0, nil
	}
	var ref mountedPolicyRef
	if _, err := toml.Decode(string(policyBytes), &ref); err != nil {
		return "", 0, fmt.Errorf("decode mounted policy reference_pack: %w", err)
	}
	if strings.TrimSpace(ref.ReferencePack) == "" {
		return "", 0, nil
	}
	refPath, err := ResolveReferencePackPath(policyPath, ref.ReferencePack)
	if err != nil {
		return "", 0, err
	}
	refData, err := os.ReadFile(refPath)
	if err != nil {
		return "", 0, fmt.Errorf("read reference_pack %s: %w", ref.ReferencePack, err)
	}
	info, err := os.Stat(refPath)
	if err != nil {
		return "", 0, fmt.Errorf("stat reference_pack %s: %w", ref.ReferencePack, err)
	}
	epoch := uint64(info.ModTime().UnixNano())
	if epoch == 0 {
		epoch = 1
	}
	return fmt.Sprintf("reference_pack:%s@%s", refPath, HashBytes(refData)), epoch, nil
}

func ResolveReferencePackPath(policyPath, referencePack string) (string, error) {
	referencePack = strings.TrimSpace(referencePack)
	if referencePack == "" {
		return "", fmt.Errorf("reference_pack is required")
	}
	if filepath.IsAbs(referencePack) {
		return "", fmt.Errorf("reference_pack must be relative to the policy file")
	}
	base, err := filepath.Abs(filepath.Dir(policyPath))
	if err != nil {
		return "", err
	}
	target := filepath.Clean(filepath.Join(base, referencePack))
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, targetAbs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("reference_pack must not escape the policy directory")
	}
	return targetAbs, nil
}

// ControlPlaneSource is the HTTP contract for managed policy publication.
// The payload format is intentionally opaque to the source; the compiler owns
// policy semantics.
type ControlPlaneSource struct {
	BaseURL     string
	HTTPClient  *http.Client
	Scope       PolicyScope
	BearerToken string
	// BearerTokenFile is re-read for every request so projected Kubernetes
	// ServiceAccount token rotation takes effect without restarting Kernel.
	BearerTokenFile string
}

func NewControlPlaneSource(baseURL string, scope PolicyScope) *ControlPlaneSource {
	return &ControlPlaneSource{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: http.DefaultClient, Scope: scope.Normalize()}
}

// NewControlPlaneHTTPClient returns a private-CA client for managed policy
// publication. The CA file is re-read for every new TLS connection so a
// projected Kubernetes Secret can rotate without widening trust to system
// roots or requiring a Kernel restart.
func NewControlPlaneHTTPClient(baseURL, caFile string) (*http.Client, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || !strings.EqualFold(parsedURL.Scheme, "https") || parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("private-CA controlplane policy URL must be absolute HTTPS")
	}
	serverName := parsedURL.Hostname()
	caFile = strings.TrimSpace(caFile)
	if !filepath.IsAbs(caFile) {
		return nil, fmt.Errorf("controlplane policy CA file must be an absolute path")
	}
	if _, err := loadControlPlaneRoots(caFile); err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = true
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		roots, err := loadControlPlaneRoots(caFile)
		if err != nil {
			return nil, err
		}
		return (&tls.Dialer{
			NetDialer: &net.Dialer{Timeout: controlPlaneRequestTimeout},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: serverName,
				RootCAs:    roots,
				NextProtos: []string{"h2", "http/1.1"},
			},
		}).DialContext(ctx, network, address)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   controlPlaneRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func loadControlPlaneRoots(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("read controlplane policy CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("controlplane policy CA contains no certificates")
	}
	return roots, nil
}

func ValidateControlPlaneURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("controlplane URL is invalid: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("controlplane URL must be an absolute URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackControlPlaneHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("controlplane URL must use https unless the host is localhost or loopback")
	default:
		return fmt.Errorf("controlplane URL must use https")
	}
}

func IsLoopbackControlPlaneURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(parsed.Scheme, "http") && isLoopbackControlPlaneHost(parsed.Hostname())
}

func isLoopbackControlPlaneHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *ControlPlaneSource) ListScopes(ctx context.Context) ([]PolicyScope, error) {
	return []PolicyScope{s.Scope.Normalize()}, nil
}

func (s *ControlPlaneSource) Head(ctx context.Context, scope PolicyScope) (PolicyHead, error) {
	endpoint, err := s.url("/api/v1/policy/head", scope.Normalize(), 0)
	if err != nil {
		return PolicyHead{}, err
	}
	var head PolicyHead
	if err := s.getJSON(ctx, endpoint, &head); err != nil {
		return PolicyHead{}, err
	}
	return head, nil
}

func (s *ControlPlaneSource) Load(ctx context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	endpoint, err := s.url("/api/v1/policy/bundle", scope.Normalize(), epoch)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(req); err != nil {
		return nil, err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("controlplane load failed: %s", resp.Status)
	}
	return readControlPlaneResponse(resp.Body, maxControlPlaneBundleBytes, "bundle")
}

func (s *ControlPlaneSource) url(path string, scope PolicyScope, epoch uint64) (string, error) {
	if strings.TrimSpace(s.BaseURL) == "" {
		return "", fmt.Errorf("controlplane URL is required")
	}
	if err := ValidateControlPlaneURL(s.BaseURL); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimRight(s.BaseURL, "/") + path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("tenant_id", scope.TenantID)
	q.Set("workspace_id", scope.WorkspaceID)
	if epoch > 0 {
		q.Set("policy_epoch", fmt.Sprintf("%d", epoch))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *ControlPlaneSource) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if err := s.authorize(req); err != nil {
		return err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("controlplane head failed: %s", resp.Status)
	}
	body, err := readControlPlaneResponse(resp.Body, maxControlPlaneHeadBytes, "head")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("controlplane head decode: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("controlplane head must contain exactly one JSON value")
	}
	return nil
}

func readControlPlaneResponse(body io.Reader, maxBytes int64, kind string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("controlplane %s read: %w", kind, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("controlplane %s exceeds %d bytes", kind, maxBytes)
	}
	return data, nil
}

func (s *ControlPlaneSource) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func (s *ControlPlaneSource) authorize(req *http.Request) error {
	token, err := s.currentBearerToken()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (s *ControlPlaneSource) currentBearerToken() (string, error) {
	token := s.BearerToken
	tokenFile := strings.TrimSpace(s.BearerTokenFile)
	if tokenFile != "" {
		if strings.TrimSpace(token) != "" {
			return "", fmt.Errorf("controlplane policy authentication must use either a bearer token or a token file")
		}
		if !filepath.IsAbs(tokenFile) {
			return "", fmt.Errorf("controlplane policy authentication token file must be an absolute path")
		}
		data, err := os.ReadFile(filepath.Clean(tokenFile))
		if err != nil {
			return "", fmt.Errorf("read controlplane policy authentication token: %w", err)
		}
		token = string(data)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("controlplane policy authentication token is empty")
	}
	if len(token) > 64*1024 || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("controlplane policy authentication token is invalid")
	}
	return token, nil
}

// StaticSource is useful for tests and bootstrap code.
type StaticSource struct {
	Heads   map[string]PolicyHead
	Bundles map[string][]byte
}

func NewStaticSource(head PolicyHead, bundle []byte) *StaticSource {
	head.Scope = head.Scope.Normalize()
	return &StaticSource{
		Heads:   map[string]PolicyHead{head.Scope.Key(): head},
		Bundles: map[string][]byte{head.Scope.Key(): append([]byte(nil), bundle...)},
	}
}

func (s *StaticSource) ListScopes(context.Context) ([]PolicyScope, error) {
	scopes := make([]PolicyScope, 0, len(s.Heads))
	for _, head := range s.Heads {
		scopes = append(scopes, head.Scope.Normalize())
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Key() < scopes[j].Key() })
	return scopes, nil
}

func (s *StaticSource) Head(_ context.Context, scope PolicyScope) (PolicyHead, error) {
	head, ok := s.Heads[scope.Normalize().Key()]
	if !ok {
		return PolicyHead{}, ErrPolicyNotReady
	}
	return head, nil
}

func (s *StaticSource) Load(_ context.Context, scope PolicyScope, epoch uint64) ([]byte, error) {
	bundle, ok := s.Bundles[scope.Normalize().Key()]
	if !ok {
		return nil, ErrPolicyNotReady
	}
	return append([]byte(nil), bundle...), nil
}

// MountedFileBundleHash computes the hash used by MountedFileSource.
func MountedFileBundleHash(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	return HashBytes(data), nil
}
