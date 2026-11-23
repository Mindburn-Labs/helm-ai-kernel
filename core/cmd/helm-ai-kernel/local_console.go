// quantum_posture: local Console integrity uses classical SHA-256/HMAC and
// Sigstore-verified release evidence; it makes no post-quantum assurance.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
	localConsoleCosignIdentityPrefix            = "https://github.com/Mindburn-Labs/app-helm-console/.github/workflows/release-local-sidecar.yml@"
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
	if _, err := os.Lstat(consoleRoot); os.IsNotExist(err) {
		return localConsoleBundle{}, fmt.Errorf("local Console starts only from a Console-including packaged layout (helm-ai-kernel-<os>-<arch>-console.tar.gz or equivalent); Homebrew and raw release binaries are headless")
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
		return "", fmt.Errorf("local Console requires a valid compiled release manifest digest from a Console-including packaged layout (helm-ai-kernel-<os>-<arch>-console.tar.gz or equivalent); source builds, Homebrew, and raw release binaries are headless")
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
	outerSignature := manifest.OuterSignature
	if outerSignature.SignedFile != localConsoleReleaseManifestFile ||
		outerSignature.Bundle != localConsoleReleaseManifestBundleFile ||
		outerSignature.Issuer != localConsoleCosignIssuer ||
		!validLocalConsoleCosignIdentity(outerSignature.CertificateIdentity) {
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

func validLocalConsoleCosignIdentity(value string) bool {
	workflowRef, ok := strings.CutPrefix(value, localConsoleCosignIdentityPrefix)
	return ok && validLocalConsoleWorkflowRef(workflowRef)
}

func validLocalConsoleWorkflowRef(value string) bool {
	const prefix = "refs/tags/"
	tag, ok := strings.CutPrefix(value, prefix)
	if !ok || tag == "" {
		return false
	}
	for index, character := range tag {
		if (index == 0 && !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9'))) ||
			!((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' || character == '/' || character == '+') {
			return false
		}
	}
	return true
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
