package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/tools/riskscan/internal/riskscan"
)

// maxBundleBytes bounds how much a scan EvidencePack archive may extract.
const maxBundleBytes = 32 << 20

// runVerify checks a local scan EvidencePack's artifact integrity. It verifies
// archived artifacts only, not runtime authorization, governed execution,
// provenance, or live posture.
func runVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet(binaryName+" verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var bundle string
	var jsonOutput bool
	cmd.StringVar(&bundle, "bundle", "", "Path to a scan EvidencePack archive or directory")
	cmd.BoolVar(&jsonOutput, "json", false, "Output the offline integrity result as JSON")
	if err := cmd.Parse(flagsFirst(args)); err != nil {
		return exitUsage
	}
	consumed := 0
	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
		consumed = 1
	}
	if cmd.NArg() > consumed {
		return usageError(stderr, "unexpected argument: %s", cmd.Arg(consumed))
	}
	if bundle == "" {
		return usageError(stderr, "scan EvidencePack path is required")
	}
	target := bundle
	info, err := os.Stat(bundle)
	if err != nil {
		return usageError(stderr, "verification failed: %v", err)
	}
	if !info.IsDir() {
		tempDir, err := os.MkdirTemp("", "helm-risk-scan-verify-*")
		if err != nil {
			return usageError(stderr, "cannot create verification workspace: %v", err)
		}
		defer os.RemoveAll(tempDir)
		if err := extractArchive(bundle, tempDir); err != nil {
			return usageError(stderr, "verification failed: %v", err)
		}
		target = tempDir
	}
	result := riskscan.VerifyEvidencePack(target)
	switch {
	case jsonOutput:
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return usageError(stderr, "serialize verification result: %v", err)
		}
		fmt.Fprintln(stdout, string(data))
	case result.Verified:
		fmt.Fprintln(stdout, "VERIFIED · local scan EvidencePack artifact integrity")
		fmt.Fprintf(stdout, "Envelope: %s\n", result.EnvelopeID)
		fmt.Fprintln(stdout, "Scope: artifact integrity only; no runtime authorization, governed execution, provenance, or live-posture claim was verified.")
	default:
		fmt.Fprintln(stdout, "FAILED · local scan EvidencePack artifact integrity")
		for _, issue := range result.Errors {
			fmt.Fprintf(stdout, "  - %s\n", issue)
		}
	}
	if result.Verified {
		return exitOK
	}
	return exitFailed
}

// flagsFirst moves flags ahead of positional arguments so `verify pack.tar
// --json` parses the same as `verify --json pack.tar`.
func flagsFirst(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		if (arg == "--bundle" || arg == "-bundle") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// extractArchive unpacks a tar (optionally gzip) EvidencePack into dstDir,
// refusing entries that escape it, non-regular entries, and archives larger
// than maxBundleBytes.
func extractArchive(bundlePath, dstDir string) error {
	file, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(bundlePath, ".gz") || strings.HasSuffix(bundlePath, ".tgz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	var extracted int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		target, err := entryPath(dstDir, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}
		case tar.TypeReg:
			if header.Size < 0 || extracted+header.Size > maxBundleBytes {
				return fmt.Errorf("archive exceeds %d extracted bytes", maxBundleBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("prepare file %s: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			written, copyErr := io.Copy(out, io.LimitReader(tr, header.Size))
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("extract file %s: %w", target, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close file %s: %w", target, closeErr)
			}
			if written != header.Size {
				return fmt.Errorf("archive entry %s size mismatch", header.Name)
			}
			extracted += written
		default:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		}
	}
}

func entryPath(dstDir, name string) (string, error) {
	normalized := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if normalized == "." || normalized == ".." || path.IsAbs(normalized) || strings.HasPrefix(normalized, "../") ||
		(len(normalized) >= 2 && normalized[1] == ':') {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	local := filepath.Clean(filepath.FromSlash(normalized))
	if !filepath.IsLocal(local) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return filepath.Join(dstDir, local), nil
}
