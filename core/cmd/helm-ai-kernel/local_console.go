package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	localConsoleDirectory                 = "console"
	localConsoleBundlePrefix              = "helm-console-local-sidecar-"
	localConsoleProvenanceFile            = "PROVENANCE.json"
	localConsoleInventoryFile             = "INVENTORY.sha256"
	localConsoleServerFile                = "app/helm-local-sidecar.mjs"
	localConsoleNodeFile                  = "runtime/node/bin/node"
	localConsoleNodeLicenseFile           = "runtime/node/LICENSE"
	localConsoleProvenanceSchema          = "helm.console.local-sidecar.provenance.v1"
	localConsoleBuildClosure              = ".next/standalone plus .next/static plus helm-local-sidecar.mjs plus runtime/node"
	localConsoleBuildSourceSnapshot       = "fresh git archive of recorded commit; npm ci and next build ran only inside the ephemeral snapshot"
	localConsoleBuildEnvironment          = "strict platform allowlist plus fixed kernel build flags; dotenv inputs rejected"
	localConsoleUnsignedSignature         = "none; this unsigned local artifact has no release authority"
	localConsoleInventoryMaxBytes         = 16 * 1024 * 1024
	localConsoleBundleMaxBytes      int64 = 512 * 1024 * 1024
	localConsoleReadyPath                 = "/api/runtime/local-sidecar-ready"
	localConsoleReadyNonceHeader          = "x-helm-local-sidecar-nonce"
	localConsoleReadyProofHeader          = "x-helm-local-sidecar-proof"
	localConsolePeerProofPath             = "/api/v1/local-sidecar/peer-proof"
	localConsolePeerNonceHeader           = "x-helm-local-kernel-nonce"
	localConsolePeerProofHeader           = "x-helm-local-kernel-proof"
	localConsolePeerContractHeader        = "x-helm-local-kernel-contract"
	localConsolePeerContract              = "helm.local-console.peer.v1"
	localConsoleReadyTimeout              = 5 * time.Second
	localConsoleReadyRetry                = 50 * time.Millisecond
	localConsoleStopTimeout               = 3 * time.Second
	localConsolePeerReplayTTL             = 10 * time.Minute
	localConsolePeerReplayLimit           = 4096
)

var (
	localConsoleExecutable = os.Executable
	localConsoleCommand    = exec.Command
	openLocalConsoleURL    = openLocalConsoleBrowser
	localConsoleReadiness  = waitForLocalConsoleReady
)

type localConsoleBundle struct {
	Root       string
	AppRoot    string
	ServerPath string
	NodePath   string
	Target     string
}

type localConsoleProvenance struct {
	Schema string `json:"schema"`
	Target struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"target"`
	Build struct {
		APIMode        string `json:"api_mode"`
		Closure        string `json:"closure"`
		SourceSnapshot string `json:"source_snapshot"`
		Environment    string `json:"environment"`
	} `json:"build"`
	Source struct {
		Commit            string `json:"commit"`
		Tree              string `json:"tree"`
		Version           string `json:"version"`
		PackageLockSHA256 string `json:"package_lock_sha256"`
	} `json:"source"`
	BundleSHA256    string `json:"bundle_sha256"`
	Inventory       string `json:"inventory"`
	BundleHashScope string `json:"bundle_hash_scope"`
	Runtime         struct {
		Node     string `json:"node"`
		NPM      string `json:"npm"`
		Next     string `json:"next"`
		Platform struct {
			OS     string `json:"os"`
			Arch   string `json:"arch"`
			Target string `json:"target"`
		} `json:"platform"`
		Libc struct {
			Family  string `json:"family"`
			Version string `json:"version"`
		} `json:"libc"`
	} `json:"runtime"`
	Signature string `json:"signature"`
}

type localConsoleInventoryEntry struct {
	Path   string
	SHA256 string
}

func localConsoleTarget() (string, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return "", fmt.Errorf("local Console is unsupported on %s", runtime.GOOS)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", fmt.Errorf("local Console is unsupported on %s-%s", runtime.GOOS, runtime.GOARCH)
	}
	return runtime.GOOS + "-" + runtime.GOARCH, nil
}

func discoverLocalConsoleBundle() (localConsoleBundle, error) {
	target, err := localConsoleTarget()
	if err != nil {
		return localConsoleBundle{}, err
	}
	executable, err := localConsoleExecutable()
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("locate Kernel executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("resolve Kernel executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("resolve Kernel executable symlinks: %w", err)
	}
	return loadLocalConsoleBundle(filepath.Join(filepath.Dir(executable), localConsoleDirectory, localConsoleBundlePrefix+target), target)
}

func loadLocalConsoleBundle(root, target string) (localConsoleBundle, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("resolve local Console bundle: %w", err)
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return localConsoleBundle{}, fmt.Errorf("matching console bundle is missing for %s", target)
	}
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("inspect local Console bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return localConsoleBundle{}, fmt.Errorf("invalid local Console bundle root")
	}

	provenanceBytes, err := readLocalConsoleBundleFile(root, localConsoleProvenanceFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read local Console provenance: %w", err)
	}
	var provenance localConsoleProvenance
	decoder := json.NewDecoder(strings.NewReader(string(provenanceBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&provenance); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode local Console provenance: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return localConsoleBundle{}, fmt.Errorf("decode local Console provenance: trailing content is not allowed")
	}
	if err := validateLocalConsoleProvenance(provenance, target); err != nil {
		return localConsoleBundle{}, err
	}

	inventoryBytes, err := readLocalConsoleBundleFile(root, localConsoleInventoryFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read local Console inventory: %w", err)
	}
	if actual := sha256Hex(inventoryBytes); !hmac.Equal([]byte(actual), []byte(provenance.BundleSHA256)) {
		return localConsoleBundle{}, fmt.Errorf("local Console inventory hash does not match provenance")
	}
	entries, err := parseLocalConsoleInventory(inventoryBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	nodePath, err := validateLocalConsoleBundledRuntime(root, entries)
	if err != nil {
		return localConsoleBundle{}, err
	}
	if err := validateLocalConsoleInventoryFiles(root, entries); err != nil {
		return localConsoleBundle{}, err
	}
	if err := validateLocalConsoleBundleTree(root, entries); err != nil {
		return localConsoleBundle{}, err
	}
	serverPath, err := localConsoleBundlePath(root, localConsoleServerFile)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("local Console server is invalid: %w", err)
	}
	if _, ok := entries[localConsoleServerFile]; !ok {
		return localConsoleBundle{}, fmt.Errorf("local Console inventory is missing %s", localConsoleServerFile)
	}
	return localConsoleBundle{
		Root:       root,
		AppRoot:    filepath.Join(root, "app"),
		ServerPath: serverPath,
		NodePath:   nodePath,
		Target:     target,
	}, nil
}

func validateLocalConsoleProvenance(provenance localConsoleProvenance, target string) error {
	if provenance.Schema != localConsoleProvenanceSchema {
		return fmt.Errorf("local Console provenance schema is invalid")
	}
	parts := strings.Split(target, "-")
	if len(parts) != 2 || provenance.Target.OS != parts[0] || provenance.Target.Arch != parts[1] {
		return fmt.Errorf("local Console provenance target does not match %s", target)
	}
	if provenance.Build.APIMode != "kernel" || provenance.Build.Closure != localConsoleBuildClosure {
		return fmt.Errorf("local Console provenance does not describe the kernel sidecar closure")
	}
	if provenance.Build.SourceSnapshot != localConsoleBuildSourceSnapshot || provenance.Build.Environment != localConsoleBuildEnvironment {
		return fmt.Errorf("local Console provenance does not describe an isolated build")
	}
	if provenance.Inventory != localConsoleInventoryFile {
		return fmt.Errorf("local Console provenance inventory path is invalid")
	}
	if provenance.Signature != localConsoleUnsignedSignature {
		return fmt.Errorf("local Console provenance signature state is invalid")
	}
	if provenance.Runtime.Platform.OS != parts[0] || provenance.Runtime.Platform.Arch != parts[1] || provenance.Runtime.Platform.Target != target ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Node) || !strings.HasPrefix(provenance.Runtime.Node, "v") ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.NPM) || !validLocalConsoleRuntimeValue(provenance.Runtime.Next) ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Libc.Version) ||
		(provenance.Runtime.Libc.Family != "glibc" && provenance.Runtime.Libc.Family != "libSystem" && provenance.Runtime.Libc.Family != "unknown") {
		return fmt.Errorf("local Console provenance runtime is incomplete")
	}
	if (parts[0] == "darwin" && provenance.Runtime.Libc.Family != "libSystem") ||
		(parts[0] == "linux" && provenance.Runtime.Libc.Family == "libSystem") {
		return fmt.Errorf("local Console provenance runtime does not match %s", target)
	}
	if !validLowerHex(provenance.BundleSHA256, sha256.Size) || !validLowerHex(provenance.Source.PackageLockSHA256, sha256.Size) ||
		!validLowerHex(provenance.Source.Commit, 20) || !validLowerHex(provenance.Source.Tree, 20) ||
		!validLocalConsoleRuntimeValue(provenance.Source.Version) || !validLocalConsoleRuntimeValue(provenance.BundleHashScope) {
		return fmt.Errorf("local Console provenance is incomplete")
	}
	return nil
}

func validLocalConsoleRuntimeValue(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseLocalConsoleInventory(contents []byte) (map[string]localConsoleInventoryEntry, error) {
	if len(contents) == 0 || len(contents) > localConsoleInventoryMaxBytes || contents[len(contents)-1] != '\n' {
		return nil, fmt.Errorf("local Console inventory is invalid")
	}
	entries := make(map[string]localConsoleInventoryEntry)
	lastPath := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !validLowerHex(parts[0], sha256.Size) {
			return nil, fmt.Errorf("local Console inventory record is invalid")
		}
		relativePath, err := canonicalLocalConsoleRelativePath(parts[1])
		if err != nil || !validLocalConsoleInventoryPath(relativePath) || relativePath <= lastPath {
			return nil, fmt.Errorf("local Console inventory path is invalid")
		}
		if _, duplicate := entries[relativePath]; duplicate {
			return nil, fmt.Errorf("local Console inventory path is duplicated")
		}
		entries[relativePath] = localConsoleInventoryEntry{Path: relativePath, SHA256: parts[0]}
		lastPath = relativePath
	}
	return entries, nil
}

func validLocalConsoleInventoryPath(relativePath string) bool {
	return strings.HasPrefix(relativePath, "app/") ||
		relativePath == localConsoleNodeFile ||
		relativePath == localConsoleNodeLicenseFile
}

func validateLocalConsoleBundledRuntime(root string, entries map[string]localConsoleInventoryEntry) (string, error) {
	nodePath, nodeInfo, err := localConsoleRequiredRuntimeFile(root, entries, localConsoleNodeFile)
	if err != nil {
		return "", err
	}
	if nodeInfo.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("local Console bundled Node is not executable")
	}
	if _, _, err := localConsoleRequiredRuntimeFile(root, entries, localConsoleNodeLicenseFile); err != nil {
		return "", err
	}
	return nodePath, nil
}

func localConsoleRequiredRuntimeFile(root string, entries map[string]localConsoleInventoryEntry, relativePath string) (string, fs.FileInfo, error) {
	if _, ok := entries[relativePath]; !ok {
		return "", nil, fmt.Errorf("local Console inventory is missing %s", relativePath)
	}
	filePath, err := localConsoleBundlePath(root, relativePath)
	if err != nil {
		return "", nil, fmt.Errorf("local Console required runtime file is invalid: %s", relativePath)
	}
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("local Console required runtime file is invalid: %s", relativePath)
	}
	return filePath, info, nil
}

func validateLocalConsoleInventoryFiles(root string, entries map[string]localConsoleInventoryEntry) error {
	var total int64
	for _, entry := range entries {
		filePath, err := localConsoleBundlePath(root, entry.Path)
		if err != nil {
			return fmt.Errorf("local Console inventory path is invalid: %w", err)
		}
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("local Console inventory file is invalid")
		}
		total += info.Size()
		if total < 0 || total > localConsoleBundleMaxBytes {
			return fmt.Errorf("local Console bundle exceeds the validation limit")
		}
		actual, err := sha256LocalConsoleFile(filePath)
		if err != nil || !hmac.Equal([]byte(actual), []byte(entry.SHA256)) {
			return fmt.Errorf("local Console inventory file hash does not match")
		}
	}
	return nil
}

func validateLocalConsoleBundleTree(root string, entries map[string]localConsoleInventoryEntry) error {
	return filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("local Console bundle contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("local Console bundle contains an unsupported entry")
		}
		relativePath, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		relativePath = filepath.ToSlash(relativePath)
		if relativePath == localConsoleProvenanceFile || relativePath == localConsoleInventoryFile {
			return nil
		}
		if _, ok := entries[relativePath]; !ok {
			return fmt.Errorf("local Console bundle contains an unverified file")
		}
		return nil
	})
}

func readLocalConsoleBundleFile(root, relativePath string, maxBytes int) ([]byte, error) {
	filePath, err := localConsoleBundlePath(root, relativePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("invalid local Console file")
	}
	return os.ReadFile(filePath)
}

func localConsoleBundlePath(root, relativePath string) (string, error) {
	relativePath, err := canonicalLocalConsoleRelativePath(relativePath)
	if err != nil {
		return "", err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", err
	}
	current := root
	for _, component := range strings.Split(relativePath, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("local Console bundle path contains a symlink")
		}
	}
	rel, err := filepath.Rel(root, current)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("local Console bundle path escapes root")
	}
	return current, nil
}

func canonicalLocalConsoleRelativePath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || path.IsAbs(value) || filepath.IsAbs(value) {
		return "", fmt.Errorf("path must be a relative slash path")
	}
	clean := path.Clean(value)
	if clean == "." || clean != value || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes root")
	}
	return clean, nil
}

func sha256LocalConsoleFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

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

	mu   sync.Mutex
	used map[string]time.Time
}

func newLocalConsolePeerProof(secret string) (*localConsolePeerProof, error) {
	if !validLocalConsoleSecret(secret) {
		return nil, fmt.Errorf("local Console peer secret is invalid")
	}
	return &localConsolePeerProof{secret: secret, used: make(map[string]time.Time)}, nil
}

func (p *localConsolePeerProof) prove(nonce string) (string, bool) {
	if p == nil || !validLocalConsoleReadyNonce(nonce) {
		return "", false
	}
	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used == nil {
		p.used = make(map[string]time.Time)
	}
	for previousNonce, issuedAt := range p.used {
		if now.Sub(issuedAt) >= localConsolePeerReplayTTL {
			delete(p.used, previousNonce)
		}
	}
	if _, seen := p.used[nonce]; seen || len(p.used) >= localConsolePeerReplayLimit {
		return "", false
	}
	proof := localConsolePeerProofValue(p.secret, nonce)
	if proof == "" {
		return "", false
	}
	p.used[nonce] = now
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
