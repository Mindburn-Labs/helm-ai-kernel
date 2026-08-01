// quantum_posture: local Console integrity uses classical SHA-256/HMAC and
// Sigstore-verified release evidence; it makes no post-quantum assurance.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	localConsoleDirectory                       = "console"
	localConsoleBundlePrefix                    = "helm-console-local-sidecar-"
	localConsoleReleaseManifestFile             = "helm-console-local-sidecar-release-manifest.json"
	localConsoleReleaseManifestBundleFile       = localConsoleReleaseManifestFile + ".cosign.bundle"
	localConsoleKernelManifestBundleFile        = localConsoleReleaseManifestFile + ".kernel.cosign.bundle"
	localConsoleProvenanceFile                  = "PROVENANCE.json"
	localConsoleInventoryFile                   = "INVENTORY.sha256"
	localConsoleServerFile                      = "app/helm-local-sidecar.mjs"
	localConsoleNodeFile                        = "runtime/node/bin/node"
	localConsoleNodeLicenseFile                 = "runtime/node/LICENSE"
	localConsoleProvenanceSchema                = "helm.console.local-sidecar.provenance.v1"
	localConsoleBuildClosure                    = ".next/standalone plus .next/static plus helm-local-sidecar.mjs plus runtime/node"
	localConsoleBuildSourceSnapshot             = "fresh git archive of recorded commit; npm ci and next build ran only inside the ephemeral snapshot"
	localConsoleBuildEnvironment                = "strict platform allowlist plus fixed kernel build flags; dotenv inputs rejected"
	localConsoleBundleHashScope                 = "sorted sha256 records for all closure payload files, including the bundled Node runtime; this binds the exact build and is not a cross-checkout byte-reproducibility claim"
	localConsoleUnsignedSignature               = "none; this unsigned local artifact has no release authority"
	localConsoleReleaseManifestSchema           = "helm.console.local-sidecar.release-manifest.v1"
	localConsoleReleaseComponent                = "app-helm-console"
	localConsoleReleaseRepository               = "Mindburn-Labs/app-helm-console"
	localConsoleCosignIssuer                    = "https://token.actions.githubusercontent.com"
	localConsoleCosignIdentity                  = "https://github.com/Mindburn-Labs/app-helm-console/.github/workflows/release-local-sidecar.yml@refs/heads/main"
	localConsoleInventoryMaxBytes               = 16 * 1024 * 1024
	localConsoleBundleMaxBytes            int64 = 512 * 1024 * 1024
	localConsoleReadyPath                       = "/api/runtime/local-sidecar-ready"
	localConsoleReadyNonceHeader                = "x-helm-local-sidecar-nonce"
	localConsoleReadyProofHeader                = "x-helm-local-sidecar-proof"
	localConsolePeerProofPath                   = "/api/v1/local-sidecar/peer-proof"
	localConsolePeerNonceHeader                 = "x-helm-local-kernel-nonce"
	localConsolePeerProofHeader                 = "x-helm-local-kernel-proof"
	localConsolePeerContractHeader              = "x-helm-local-kernel-contract"
	localConsolePeerContract                    = "helm.local-console.peer.v1"
	localConsoleReadyTimeout                    = 5 * time.Second
	localConsoleReadyRetry                      = 50 * time.Millisecond
	localConsoleStopTimeout                     = 3 * time.Second
	localConsolePeerReplayTTL                   = 10 * time.Minute
	localConsolePeerReplayLimit                 = 4096
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

type localConsoleTargetDescriptor struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type localConsoleBuildProvenance struct {
	APIMode        string `json:"api_mode"`
	Closure        string `json:"closure"`
	SourceSnapshot string `json:"source_snapshot"`
	Environment    string `json:"environment"`
}

type localConsoleSource struct {
	Commit            string `json:"commit"`
	Tree              string `json:"tree"`
	Version           string `json:"version"`
	PackageLockSHA256 string `json:"package_lock_sha256"`
}

type localConsoleRuntimePlatform struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Target string `json:"target"`
}

type localConsoleRuntimeLibc struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

type localConsoleBundledNode struct {
	Executable    string `json:"executable"`
	LicenseNotice string `json:"license_notice"`
}

type localConsoleRuntimeProvenance struct {
	Node        string                      `json:"node"`
	BundledNode localConsoleBundledNode     `json:"bundled_node"`
	NPM         string                      `json:"npm"`
	Next        string                      `json:"next"`
	Platform    localConsoleRuntimePlatform `json:"platform"`
	Libc        localConsoleRuntimeLibc     `json:"libc"`
}

type localConsoleArtifactRecord struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type localConsoleProvenance struct {
	Schema          string                        `json:"schema"`
	Target          localConsoleTargetDescriptor  `json:"target"`
	Build           localConsoleBuildProvenance   `json:"build"`
	Source          localConsoleSource            `json:"source"`
	BundleSHA256    string                        `json:"bundle_sha256"`
	Inventory       string                        `json:"inventory"`
	BundleHashScope string                        `json:"bundle_hash_scope"`
	Runtime         localConsoleRuntimeProvenance `json:"runtime"`
	Signature       string                        `json:"signature"`
}

type localConsoleExternalProvenance struct {
	localConsoleProvenance
	Archive localConsoleArtifactRecord `json:"archive"`
}

type localConsoleReleaseArtifacts struct {
	Archive         localConsoleArtifactRecord `json:"archive"`
	ArchiveChecksum localConsoleArtifactRecord `json:"archive_checksum"`
	Inventory       localConsoleArtifactRecord `json:"inventory"`
	Provenance      localConsoleArtifactRecord `json:"provenance"`
}

type localConsoleInnerArtifact struct {
	ProvenanceSchema string `json:"provenance_schema"`
	Signature        string `json:"signature"`
	ReleaseAuthority *bool  `json:"release_authority"`
	BundleSHA256     string `json:"bundle_sha256"`
}

type localConsoleReleaseTarget struct {
	Target        localConsoleTargetDescriptor `json:"target"`
	InnerArtifact localConsoleInnerArtifact    `json:"inner_artifact"`
	Artifacts     localConsoleReleaseArtifacts `json:"artifacts"`
}

type localConsoleOuterSignature struct {
	SignedFile          string `json:"signed_file"`
	Bundle              string `json:"bundle"`
	Issuer              string `json:"issuer"`
	CertificateIdentity string `json:"certificate_identity"`
}

type localConsoleReleaseManifest struct {
	Schema               string                      `json:"schema"`
	Component            string                      `json:"component"`
	SourceRepository     string                      `json:"source_repository"`
	KernelReleaseVersion string                      `json:"kernel_release_version"`
	Source               localConsoleSource          `json:"source"`
	Targets              []localConsoleReleaseTarget `json:"targets"`
	OuterSignature       localConsoleOuterSignature  `json:"outer_signature"`
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
	consoleRoot := filepath.Join(filepath.Dir(executable), localConsoleDirectory)
	return verifyTrustedLocalConsoleRelease(consoleRoot, target)
}

func verifyTrustedLocalConsoleRelease(consoleRoot, target string) (localConsoleBundle, error) {
	expectedDigest, err := compiledLocalConsoleManifestDigest()
	if err != nil {
		return localConsoleBundle{}, err
	}
	manifestBytes, err := readLocalConsoleReleaseFile(consoleRoot, localConsoleReleaseManifestFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read local Console release manifest: %w", err)
	}
	if actual := sha256Hex(manifestBytes); !hmac.Equal([]byte(actual), []byte(expectedDigest)) {
		return localConsoleBundle{}, fmt.Errorf("local Console release manifest does not match the compiled digest")
	}
	var manifest localConsoleReleaseManifest
	if err := decodeLocalConsoleJSON(manifestBytes, &manifest); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode local Console release manifest: %w", err)
	}
	targetRecord, err := validateLocalConsoleReleaseManifest(manifest, target)
	if err != nil {
		return localConsoleBundle{}, err
	}
	if err := validateLocalConsoleReleaseLayout(consoleRoot, manifest); err != nil {
		return localConsoleBundle{}, err
	}
	return verifyLocalConsoleReleaseTarget(consoleRoot, target, manifest.Source, targetRecord)
}

func compiledLocalConsoleManifestDigest() (string, error) {
	if !validLowerHex(consoleLocalSidecarManifestSHA256, sha256.Size) {
		return "", fmt.Errorf("local Console requires a valid compiled release manifest digest")
	}
	return consoleLocalSidecarManifestSHA256, nil
}

func decodeLocalConsoleJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing content is not allowed")
		}
		return err
	}
	return nil
}

func validateLocalConsoleReleaseManifest(manifest localConsoleReleaseManifest, runtimeTarget string) (localConsoleReleaseTarget, error) {
	if manifest.Schema != localConsoleReleaseManifestSchema || manifest.Component != localConsoleReleaseComponent || manifest.SourceRepository != localConsoleReleaseRepository {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest identity is invalid")
	}
	if !validLocalConsoleReleaseVersion(manifest.KernelReleaseVersion) || manifest.KernelReleaseVersion != displayVersion() {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest is bound to a different Kernel release")
	}
	if !validLocalConsoleSource(manifest.Source) {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest source is invalid")
	}
	if manifest.OuterSignature != (localConsoleOuterSignature{
		SignedFile:          localConsoleReleaseManifestFile,
		Bundle:              localConsoleReleaseManifestBundleFile,
		Issuer:              localConsoleCosignIssuer,
		CertificateIdentity: localConsoleCosignIdentity,
	}) {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest outer signature contract is invalid")
	}
	expectedTargets := []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}
	if len(manifest.Targets) != len(expectedTargets) {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest targets are invalid")
	}
	var selected localConsoleReleaseTarget
	for index, expectedTarget := range expectedTargets {
		record := manifest.Targets[index]
		if localConsoleTargetName(record.Target) != expectedTarget || !validLocalConsoleReleaseTarget(record, expectedTarget) {
			return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest target %q is invalid", expectedTarget)
		}
		if expectedTarget == runtimeTarget {
			selected = record
		}
	}
	if localConsoleTargetName(selected.Target) != runtimeTarget {
		return localConsoleReleaseTarget{}, fmt.Errorf("local Console release manifest is missing %s", runtimeTarget)
	}
	return selected, nil
}

func validLocalConsoleReleaseTarget(record localConsoleReleaseTarget, expectedTarget string) bool {
	if record.InnerArtifact.ProvenanceSchema != localConsoleProvenanceSchema ||
		record.InnerArtifact.Signature != localConsoleUnsignedSignature ||
		record.InnerArtifact.ReleaseAuthority == nil || *record.InnerArtifact.ReleaseAuthority ||
		!validLowerHex(record.InnerArtifact.BundleSHA256, sha256.Size) {
		return false
	}
	archiveName := localConsoleBundlePrefix + expectedTarget + ".tar.gz"
	return validLocalConsoleArtifactRecord(record.Artifacts.Archive, archiveName) &&
		validLocalConsoleArtifactRecord(record.Artifacts.ArchiveChecksum, archiveName+".sha256") &&
		validLocalConsoleArtifactRecord(record.Artifacts.Inventory, archiveName+".inventory.sha256") &&
		validLocalConsoleArtifactRecord(record.Artifacts.Provenance, archiveName+".provenance.json")
}

func validLocalConsoleArtifactRecord(record localConsoleArtifactRecord, expectedFile string) bool {
	return record.File == expectedFile && validLocalConsoleReleaseFileName(record.File) && validLowerHex(record.SHA256, sha256.Size)
}

func validLocalConsoleReleaseFileName(value string) bool {
	return value != "" && value == filepath.Base(value) && value == path.Base(value) && !strings.Contains(value, "\\") && !strings.Contains(value, "/") && value != "." && value != ".."
}

func localConsoleTargetName(target localConsoleTargetDescriptor) string {
	return target.OS + "-" + target.Arch
}

func validLocalConsoleReleaseVersion(value string) bool {
	if !strings.HasPrefix(value, "v") {
		return false
	}
	return validLocalConsoleSemver(strings.TrimPrefix(value, "v"))
}

func validLocalConsoleSemver(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validLocalConsoleSource(source localConsoleSource) bool {
	return validLowerHex(source.Commit, 20) && validLowerHex(source.Tree, 20) &&
		validLocalConsoleSemver(source.Version) && validLowerHex(source.PackageLockSHA256, sha256.Size)
}

func validateLocalConsoleReleaseLayout(consoleRoot string, manifest localConsoleReleaseManifest) error {
	for _, name := range []string{localConsoleReleaseManifestBundleFile, localConsoleKernelManifestBundleFile} {
		contents, err := readLocalConsoleReleaseFile(consoleRoot, name, localConsoleInventoryMaxBytes)
		if err != nil || len(contents) == 0 {
			return fmt.Errorf("local Console release evidence is missing or invalid: %s", name)
		}
	}
	for _, record := range manifest.Targets {
		for _, artifact := range []localConsoleArtifactRecord{record.Artifacts.Archive, record.Artifacts.ArchiveChecksum, record.Artifacts.Inventory, record.Artifacts.Provenance} {
			if _, err := localConsoleReleaseFilePath(consoleRoot, artifact.File, localConsoleBundleMaxBytes); err != nil {
				return fmt.Errorf("local Console release asset is missing or invalid: %s", artifact.File)
			}
		}
	}
	return nil
}

func verifyLocalConsoleReleaseTarget(consoleRoot, target string, source localConsoleSource, record localConsoleReleaseTarget) (localConsoleBundle, error) {
	archivePath, err := verifyLocalConsoleReleaseArtifact(consoleRoot, record.Artifacts.Archive, localConsoleBundleMaxBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	checksumBytes, err := verifyLocalConsoleReleaseArtifactBytes(consoleRoot, record.Artifacts.ArchiveChecksum, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	inventoryBytes, err := verifyLocalConsoleReleaseArtifactBytes(consoleRoot, record.Artifacts.Inventory, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	provenanceBytes, err := verifyLocalConsoleReleaseArtifactBytes(consoleRoot, record.Artifacts.Provenance, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	archiveDigest, err := sha256LocalConsoleFile(archivePath)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("hash local Console release archive: %w", err)
	}
	if string(checksumBytes) != archiveDigest+"  "+record.Artifacts.Archive.File+"\n" {
		return localConsoleBundle{}, fmt.Errorf("local Console release archive checksum does not bind the archive exactly")
	}
	var external localConsoleExternalProvenance
	if err := decodeLocalConsoleJSON(provenanceBytes, &external); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode local Console release provenance: %w", err)
	}
	if err := validateLocalConsoleProvenance(external.localConsoleProvenance, target); err != nil {
		return localConsoleBundle{}, err
	}
	if external.Source != source || external.BundleSHA256 != record.InnerArtifact.BundleSHA256 || external.Signature != record.InnerArtifact.Signature || external.Archive != record.Artifacts.Archive {
		return localConsoleBundle{}, fmt.Errorf("local Console release provenance does not match its manifest")
	}
	if err := verifyLocalConsoleRawArchive(archivePath, target, source, record.InnerArtifact, inventoryBytes, external); err != nil {
		return localConsoleBundle{}, err
	}
	bundleRoot := filepath.Join(consoleRoot, localConsoleBundlePrefix+target)
	embeddedInventory, err := readLocalConsoleBundleFile(bundleRoot, localConsoleInventoryFile, localConsoleInventoryMaxBytes)
	if err != nil || !bytes.Equal(embeddedInventory, inventoryBytes) {
		return localConsoleBundle{}, fmt.Errorf("extracted local Console inventory does not match the released archive")
	}
	embeddedProvenance, err := readLocalConsoleBundleFile(bundleRoot, localConsoleProvenanceFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read extracted local Console provenance: %w", err)
	}
	var embedded localConsoleProvenance
	if err := decodeLocalConsoleJSON(embeddedProvenance, &embedded); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode extracted local Console provenance: %w", err)
	}
	if embedded != external.localConsoleProvenance {
		return localConsoleBundle{}, fmt.Errorf("extracted local Console provenance does not match the released archive")
	}
	bundle, err := loadLocalConsoleBundle(bundleRoot, target)
	if err != nil {
		return localConsoleBundle{}, err
	}
	return bundle, nil
}

func verifyLocalConsoleReleaseArtifact(consoleRoot string, record localConsoleArtifactRecord, maxBytes int64) (string, error) {
	filePath, err := localConsoleReleaseFilePath(consoleRoot, record.File, maxBytes)
	if err != nil {
		return "", fmt.Errorf("local Console release artifact is invalid: %s", record.File)
	}
	actual, err := sha256LocalConsoleFile(filePath)
	if err != nil || !hmac.Equal([]byte(actual), []byte(record.SHA256)) {
		return "", fmt.Errorf("local Console release artifact hash does not match: %s", record.File)
	}
	return filePath, nil
}

func verifyLocalConsoleReleaseArtifactBytes(consoleRoot string, record localConsoleArtifactRecord, maxBytes int64) ([]byte, error) {
	contents, err := readLocalConsoleReleaseFile(consoleRoot, record.File, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("read local Console release artifact %s: %w", record.File, err)
	}
	if actual := sha256Hex(contents); !hmac.Equal([]byte(actual), []byte(record.SHA256)) {
		return nil, fmt.Errorf("local Console release artifact hash does not match: %s", record.File)
	}
	return contents, nil
}

func readLocalConsoleReleaseFile(root, name string, maxBytes int64) ([]byte, error) {
	filePath, err := localConsoleReleaseFilePath(root, name, maxBytes)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filePath)
}

func localConsoleReleaseFilePath(root, name string, maxBytes int64) (string, error) {
	if !validLocalConsoleReleaseFileName(name) || maxBytes <= 0 {
		return "", fmt.Errorf("invalid local Console release file")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("local Console release root is invalid")
	}
	filePath := filepath.Join(root, name)
	info, err = os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxBytes {
		return "", fmt.Errorf("invalid local Console release file")
	}
	return filePath, nil
}

type localConsoleArchiveFile struct {
	SHA256 string
	Mode   int64
	Data   []byte
}

func verifyLocalConsoleRawArchive(archivePath, target string, source localConsoleSource, inner localConsoleInnerArtifact, inventoryBytes []byte, external localConsoleExternalProvenance) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open local Console release archive: %w", err)
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("read local Console release archive: %w", err)
	}

	expectedRoot := localConsoleBundlePrefix + target
	reader := tar.NewReader(compressed)
	files := make(map[string]localConsoleArchiveFile)
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read local Console release archive: %w", err)
		}
		relativePath, err := localConsoleArchiveRelativePath(header.Name, expectedRoot, header.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		if header.Typeflag == tar.TypeDir {
			if header.Linkname != "" {
				return fmt.Errorf("local Console release archive directory is invalid")
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("local Console release archive contains an unsupported entry")
		}
		if relativePath == "" || header.Linkname != "" || header.Size < 0 || header.Size > localConsoleBundleMaxBytes || total > localConsoleBundleMaxBytes-header.Size {
			return fmt.Errorf("local Console release archive payload is invalid")
		}
		total += header.Size
		if _, duplicate := files[relativePath]; duplicate {
			return fmt.Errorf("local Console release archive contains a duplicate payload")
		}
		hash := sha256.New()
		writer := io.Writer(hash)
		var contents bytes.Buffer
		capture := relativePath == localConsoleInventoryFile || relativePath == localConsoleProvenanceFile
		if capture {
			if header.Size > localConsoleInventoryMaxBytes {
				return fmt.Errorf("local Console release archive metadata exceeds the validation limit")
			}
			writer = io.MultiWriter(hash, &contents)
		}
		written, err := io.Copy(writer, reader)
		if err != nil || written != header.Size {
			return fmt.Errorf("read local Console release archive payload")
		}
		files[relativePath] = localConsoleArchiveFile{
			SHA256: hex.EncodeToString(hash.Sum(nil)),
			Mode:   header.Mode,
			Data:   contents.Bytes(),
		}
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return fmt.Errorf("read local Console release archive trailer: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("close local Console release archive: %w", err)
	}
	for _, required := range []string{localConsoleInventoryFile, localConsoleProvenanceFile, localConsoleServerFile, localConsoleNodeFile, localConsoleNodeLicenseFile} {
		if _, ok := files[required]; !ok {
			return fmt.Errorf("local Console release archive is missing %s", required)
		}
	}
	if !bytes.Equal(files[localConsoleInventoryFile].Data, inventoryBytes) {
		return fmt.Errorf("local Console release archive inventory does not match the release asset")
	}
	if files[localConsoleNodeFile].Mode&0111 == 0 {
		return fmt.Errorf("local Console release archive bundled Node is not executable")
	}
	entries, err := parseLocalConsoleInventory(inventoryBytes)
	if err != nil {
		return err
	}
	payloadCount := 0
	for relativePath, file := range files {
		if relativePath == localConsoleInventoryFile || relativePath == localConsoleProvenanceFile {
			continue
		}
		payloadCount++
		entry, ok := entries[relativePath]
		if !ok || !hmac.Equal([]byte(file.SHA256), []byte(entry.SHA256)) {
			return fmt.Errorf("local Console release archive payload does not match its inventory")
		}
	}
	if payloadCount != len(entries) {
		return fmt.Errorf("local Console release archive payload does not match its inventory")
	}
	if actual := sha256Hex(inventoryBytes); !hmac.Equal([]byte(actual), []byte(inner.BundleSHA256)) {
		return fmt.Errorf("local Console release archive inventory hash does not match its manifest")
	}
	var embedded localConsoleProvenance
	if err := decodeLocalConsoleJSON(files[localConsoleProvenanceFile].Data, &embedded); err != nil {
		return fmt.Errorf("decode embedded local Console provenance: %w", err)
	}
	if err := validateLocalConsoleProvenance(embedded, target); err != nil {
		return err
	}
	if embedded != external.localConsoleProvenance || embedded.Source != source || embedded.BundleSHA256 != inner.BundleSHA256 || embedded.Signature != inner.Signature {
		return fmt.Errorf("embedded local Console provenance does not match the release manifest")
	}
	return nil
}

func localConsoleArchiveRelativePath(name, expectedRoot string, directory bool) (string, error) {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	canonical := name
	if directory && strings.HasSuffix(canonical, "/") {
		canonical = strings.TrimSuffix(canonical, "/")
		if canonical == "" || strings.HasSuffix(canonical, "/") {
			return "", fmt.Errorf("local Console release archive path is invalid")
		}
	}
	if !directory && strings.HasSuffix(canonical, "/") {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	if canonical == "." || canonical == ".." || strings.HasPrefix(canonical, "../") || path.Clean(canonical) != canonical {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	parts := strings.Split(canonical, "/")
	if len(parts) == 0 || parts[0] != expectedRoot {
		return "", fmt.Errorf("local Console release archive escapes the expected bundle root")
	}
	if len(parts) == 1 {
		if !directory {
			return "", fmt.Errorf("local Console release archive root is not a directory")
		}
		return "", nil
	}
	relativePath := strings.Join(parts[1:], "/")
	if _, err := canonicalLocalConsoleRelativePath(relativePath); err != nil {
		return "", fmt.Errorf("local Console release archive path is invalid")
	}
	return relativePath, nil
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
	if err := decodeLocalConsoleJSON(provenanceBytes, &provenance); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode local Console provenance: %w", err)
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
	if provenance.Runtime.BundledNode != (localConsoleBundledNode{Executable: localConsoleNodeFile, LicenseNotice: localConsoleNodeLicenseFile}) ||
		provenance.Runtime.Platform.OS != parts[0] || provenance.Runtime.Platform.Arch != parts[1] || provenance.Runtime.Platform.Target != target ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Node) || !strings.HasPrefix(provenance.Runtime.Node, "v") ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.NPM) || !validLocalConsoleRuntimeValue(provenance.Runtime.Next) ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Libc.Version) ||
		(provenance.Runtime.Libc.Family != "glibc" && provenance.Runtime.Libc.Family != "libSystem") {
		return fmt.Errorf("local Console provenance runtime is incomplete")
	}
	if (parts[0] == "darwin" && provenance.Runtime.Libc.Family != "libSystem") ||
		(parts[0] == "linux" && provenance.Runtime.Libc.Family != "glibc") ||
		(parts[0] == "darwin" && provenance.Runtime.Libc.Version != "host-reported-unavailable") {
		return fmt.Errorf("local Console provenance runtime does not match %s", target)
	}
	if provenance.BundleHashScope != localConsoleBundleHashScope || !validLowerHex(provenance.BundleSHA256, sha256.Size) || !validLocalConsoleSource(provenance.Source) {
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
