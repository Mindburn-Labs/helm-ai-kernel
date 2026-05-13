package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto/tee"
)

// runTeeCmd implements `helm-ai-kernel tee <status|selftest|verify>`.
//
// The subcommand surface mirrors `helm-ai-kernel trust` and `helm-ai-kernel did`: a thin
// dispatcher with one flagset per subcommand, JSON output behind --json,
// and exit codes 0 (ok), 1 (verification failed), 2 (usage error).
func runTeeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel tee <subcommand> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  status     Print the configured TEE attester (platform, measurement, host)")
		fmt.Fprintln(stderr, "  selftest   Mint a quote against a fresh nonce and verify it round-trip")
		fmt.Fprintln(stderr, "  verify     Verify a quote file against an expected nonce")
		return 2
	}

	switch args[0] {
	case "status":
		return runTeeStatus(args[1:], stdout, stderr)
	case "selftest":
		return runTeeSelftest(args[1:], stdout, stderr)
	case "verify":
		return runTeeVerify(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel tee <subcommand> [flags]")
		fmt.Fprintln(stdout, "  status     Print the configured TEE attester")
		fmt.Fprintln(stdout, "  selftest   Mint a quote against a fresh nonce and verify it round-trip")
		fmt.Fprintln(stdout, "  verify     Verify a quote file against an expected nonce")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown tee subcommand: %s\n", args[0])
		return 2
	}
}

// runTeeStatus prints the platform and measurement of the locally configured
// TEE attester. On a non-TEE host this falls back to the mock attester so
// developers can verify their wiring without confidential-VM hardware.
func runTeeStatus(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("tee status", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		jsonOut  bool
		platform string
	)
	cmd.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	cmd.StringVar(&platform, "platform", "", "Force a specific platform (sevsnp|tdx|nitro|mock); default: mock")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	att, plat, _, err := selectTeeAttester(platform)
	if err != nil {
		if jsonOut {
			emitTeeJSON(stdout, map[string]any{
				"ok":       false,
				"platform": platform,
				"error":    err.Error(),
			})
			return 1
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	measurement, mErr := att.Measurement()
	measurementHex := ""
	if mErr == nil {
		measurementHex = hex.EncodeToString(measurement)
	}

	if jsonOut {
		emitTeeJSON(stdout, map[string]any{
			"ok":               mErr == nil,
			"platform":         string(plat),
			"runtime_os":       runtime.GOOS,
			"runtime_arch":     runtime.GOARCH,
			"measurement_hex":  measurementHex,
			"measurement_size": len(measurement),
			"measurement_err":  errString(mErr),
		})
		if mErr != nil {
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "platform:    %s\n", plat)
	fmt.Fprintf(stdout, "host:        %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if mErr != nil {
		fmt.Fprintf(stdout, "measurement: <unavailable: %v>\n", mErr)
		return 1
	}
	fmt.Fprintf(stdout, "measurement: %s\n", measurementHex)
	if plat == tee.PlatformMock {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "note: mock attester. Real-hardware quotes require Linux + SEV-SNP/TDX/Nitro guest device.")
	}
	return 0
}

// runTeeSelftest mints a quote over a fresh nonce and verifies it round-trip.
// Useful as a smoke test on confidential-VM nodes and for documenting the
// expected format on dev hosts.
func runTeeSelftest(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("tee selftest", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		jsonOut  bool
		platform string
	)
	cmd.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	cmd.StringVar(&platform, "platform", "", "Force a specific platform (sevsnp|tdx|nitro|mock); default: mock")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	att, plat, mockPub, err := selectTeeAttester(platform)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// Synthesize a deterministic-looking nonce derived from the current
	// time. The quote is bound to this nonce; replaying it with a different
	// nonce will fail verification.
	nonceSeed := []byte(time.Now().UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256(nonceSeed)
	nonce := sum[:]

	quote, err := att.Quote(context.Background(), nonce)
	if err != nil {
		emitTeeOrFprint(stdout, stderr, jsonOut, map[string]any{
			"ok":       false,
			"platform": string(plat),
			"stage":    "quote",
			"error":    err.Error(),
		}, "Quote failed: %v\n", err)
		return 1
	}

	roots := tee.TrustRoots{AllowMock: plat == tee.PlatformMock}
	if mockPub != nil {
		roots.MockPublicKeys = []ed25519.PublicKey{mockPub}
	}

	res, err := tee.Verify(plat, quote, nonce, roots)
	if err != nil {
		emitTeeOrFprint(stdout, stderr, jsonOut, map[string]any{
			"ok":         false,
			"platform":   string(plat),
			"stage":      "verify",
			"quote_size": len(quote),
			"nonce_hex":  hex.EncodeToString(nonce),
			"error":      err.Error(),
		}, "Verify failed: %v\n", err)
		return 1
	}

	out := map[string]any{
		"ok":               true,
		"platform":         string(plat),
		"quote_size":       len(quote),
		"nonce_hex":        hex.EncodeToString(nonce),
		"measurement_hex":  hex.EncodeToString(res.Measurement),
		"measurement_size": len(res.Measurement),
	}
	if jsonOut {
		emitTeeJSON(stdout, out)
		return 0
	}
	fmt.Fprintln(stdout, "tee selftest: ok")
	fmt.Fprintf(stdout, "  platform:    %s\n", plat)
	fmt.Fprintf(stdout, "  quote_size:  %d bytes\n", len(quote))
	fmt.Fprintf(stdout, "  measurement: %s\n", hex.EncodeToString(res.Measurement))
	return 0
}

// runTeeVerify verifies a quote file against an expected nonce. Useful for
// auditors who receive a quote out-of-band and want to validate it.
func runTeeVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("tee verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		jsonOut  bool
		platform string
		nonceHex string
	)
	cmd.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	cmd.StringVar(&platform, "platform", "", "Platform of the quote (sevsnp|tdx|nitro|mock); REQUIRED")
	cmd.StringVar(&nonceHex, "nonce", "", "Expected nonce as hex; REQUIRED")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if platform == "" || nonceHex == "" || cmd.NArg() < 1 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel tee verify --platform=<...> --nonce=<hex> <quote-file>")
		return 2
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		fmt.Fprintf(stderr, "Error: --nonce must be hex: %v\n", err)
		return 2
	}

	quote, err := os.ReadFile(cmd.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "Error reading quote: %v\n", err)
		return 1
	}

	plat := tee.Platform(platform)
	res, err := tee.Verify(plat, quote, nonce, tee.TrustRoots{AllowMock: plat == tee.PlatformMock})
	if err != nil {
		emitTeeOrFprint(stdout, stderr, jsonOut, map[string]any{
			"ok":       false,
			"platform": platform,
			"error":    err.Error(),
		}, "Verify failed: %v\n", err)
		return 1
	}

	out := map[string]any{
		"ok":              true,
		"platform":        string(res.Platform),
		"measurement_hex": hex.EncodeToString(res.Measurement),
	}
	if jsonOut {
		emitTeeJSON(stdout, out)
		return 0
	}
	fmt.Fprintln(stdout, "tee verify: ok")
	fmt.Fprintf(stdout, "  platform:    %s\n", res.Platform)
	fmt.Fprintf(stdout, "  measurement: %s\n", hex.EncodeToString(res.Measurement))
	return 0
}

// selectTeeAttester picks an attester for the requested platform.
// On empty/"mock" the mock attester is returned along with its public key,
// so callers can plug it into TrustRoots.MockPublicKeys for round-trip tests.
// For "sevsnp"/"tdx"/"nitro" the real adapter is returned; its Quote() method
// will surface ErrNoHardware on non-TEE hosts.
func selectTeeAttester(platform string) (tee.RemoteAttester, tee.Platform, ed25519.PublicKey, error) {
	switch platform {
	case "", "mock":
		m, err := tee.NewMockAttester()
		if err != nil {
			return nil, "", nil, err
		}
		return m, tee.PlatformMock, m.PublicKey(), nil
	case "sevsnp":
		return tee.NewSEVSNPAttester(), tee.PlatformSEVSNP, nil, nil
	case "tdx":
		return tee.NewTDXAttester(), tee.PlatformTDX, nil, nil
	case "nitro":
		return tee.NewNitroAttester(), tee.PlatformNitro, nil, nil
	default:
		return nil, "", nil, fmt.Errorf("unknown platform %q (want sevsnp|tdx|nitro|mock)", platform)
	}
}

func emitTeeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emitTeeOrFprint(stdout, stderr io.Writer, jsonOut bool, j map[string]any, format string, args ...any) {
	if jsonOut {
		emitTeeJSON(stdout, j)
		return
	}
	fmt.Fprintf(stderr, format, args...)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func init() {
	Register(Subcommand{
		Name:    "tee",
		Aliases: []string{},
		Usage:   "Inspect and verify TEE attestations (status, selftest, verify)",
		RunFn:   runTeeCmd,
	})
}
