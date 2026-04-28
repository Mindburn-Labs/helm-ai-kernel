// did_cmd.go — `helm did` CLI surface.
//
// Subcommands:
//
//	helm did resolve <did>          Resolve a DID and print its DID Document.
//	helm did verify <vc.json>       Verify a Verifiable Credential against its issuer DID.
//	helm did list                   Show DIDs in the local DID keystore.
//	helm did rotate [--key=<id>]    Rotate the local DID's signing key.
//
// The local keystore is a single JSON file at
// `${HELM_DATA_DIR}/did_keystore.json` (or `data/did_keystore.json`). The
// CLI is read-only against external DID Documents apart from the rotate
// path which generates a new key and rewrites the keystore.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did/method/jwk"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did/method/key"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did/method/plc"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did/method/web"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

// didKeystoreEntry is a single record in the local DID keystore.
type didKeystoreEntry struct {
	DID          string    `json:"did"`
	KeyID        string    `json:"key_id"`
	PublicKeyHex string    `json:"public_key_hex"`
	CreatedAt    time.Time `json:"created_at"`
}

// didKeystoreFile is the on-disk representation of the local DID keystore.
type didKeystoreFile struct {
	Version int                `json:"version"`
	Entries []didKeystoreEntry `json:"entries"`
}

func didKeystorePath() string {
	dir := os.Getenv("HELM_DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	return filepath.Join(dir, "did_keystore.json")
}

func loadDIDKeystore() (*didKeystoreFile, error) {
	data, err := os.ReadFile(didKeystorePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &didKeystoreFile{Version: 1}, nil
		}
		return nil, err
	}
	ks := &didKeystoreFile{}
	if err := json.Unmarshal(data, ks); err != nil {
		return nil, fmt.Errorf("did: parsing keystore: %w", err)
	}
	if ks.Version == 0 {
		ks.Version = 1
	}
	return ks, nil
}

func saveDIDKeystore(ks *didKeystoreFile) error {
	path := didKeystorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// newCLIResolver builds a Resolver wired to all four method drivers.
func newCLIResolver() *did.Resolver {
	r := did.NewResolver(did.WithCacheTTL(5 * time.Minute))
	r.Register(key.New())
	r.Register(web.New())
	r.Register(jwk.New())
	r.Register(plc.New())
	return r
}

func runDIDCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm did <resolve|verify|list|rotate> [args]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  resolve <did>          Resolve a DID and print its DID Document")
		fmt.Fprintln(stderr, "  verify <vc-path>       Verify a Verifiable Credential against issuer DID")
		fmt.Fprintln(stderr, "  list                   Show DIDs in the local keystore")
		fmt.Fprintln(stderr, "  rotate [--key=<id>]    Rotate the keystore's primary DID signing key")
		return 2
	}

	switch args[0] {
	case "resolve":
		return runDIDResolve(args[1:], stdout, stderr)
	case "verify":
		return runDIDVerify(args[1:], stdout, stderr)
	case "list":
		return runDIDList(args[1:], stdout, stderr)
	case "rotate":
		return runDIDRotate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown did command: %s\n", args[0])
		return 2
	}
}

func runDIDResolve(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("did resolve", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	timeoutSec := cmd.Int("timeout", 5, "Resolution timeout in seconds")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() < 1 {
		fmt.Fprintln(stderr, "Usage: helm did resolve <did>")
		return 2
	}
	target := cmd.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	resolver := newCLIResolver()
	doc, err := resolver.Resolve(ctx, target)
	if err != nil {
		fmt.Fprintf(stderr, "Resolve failed: %v\n", err)
		return 1
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Marshal failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

func runDIDVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("did verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Emit JSON status output")
	timeoutSec := cmd.Int("timeout", 5, "Resolution timeout in seconds")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() < 1 {
		fmt.Fprintln(stderr, "Usage: helm did verify <vc-path>")
		return 2
	}
	path := cmd.Arg(0)

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "Read failed: %v\n", err)
		return 1
	}
	vc := &vcredentials.VerifiableCredential{}
	if err := json.Unmarshal(raw, vc); err != nil {
		fmt.Fprintf(stderr, "Parse failed: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	resolver := newCLIResolver()
	verifier := did.NewVerifier(resolver)
	if err := verifier.VerifyVC(ctx, vc); err != nil {
		if *jsonOutput {
			out, _ := json.MarshalIndent(map[string]any{
				"valid":  false,
				"issuer": vc.Issuer.ID,
				"reason": err.Error(),
			}, "", "  ")
			fmt.Fprintln(stdout, string(out))
		} else {
			fmt.Fprintf(stderr, "VC verification failed: %v\n", err)
		}
		return 1
	}
	if *jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{
			"valid":  true,
			"issuer": vc.Issuer.ID,
			"id":     vc.ID,
		}, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintf(stdout, "VC %s verified (issuer %s)\n", vc.ID, vc.Issuer.ID)
	}
	return 0
}

func runDIDList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("did list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Emit JSON output")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	ks, err := loadDIDKeystore()
	if err != nil {
		fmt.Fprintf(stderr, "Load keystore failed: %v\n", err)
		return 1
	}
	sort.Slice(ks.Entries, func(i, j int) bool { return ks.Entries[i].DID < ks.Entries[j].DID })

	if *jsonOutput {
		out, _ := json.MarshalIndent(ks, "", "  ")
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	if len(ks.Entries) == 0 {
		fmt.Fprintln(stdout, "No DIDs registered. Run `helm did rotate --key=<id>` to mint one.")
		return 0
	}
	for _, e := range ks.Entries {
		fmt.Fprintf(stdout, "  %s  key=%s  created=%s\n", e.DID, e.KeyID, e.CreatedAt.Format(time.RFC3339))
	}
	return 0
}

func runDIDRotate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("did rotate", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	keyID := cmd.String("key", "", "Key identifier label (default: derived from timestamp)")
	jsonOutput := cmd.Bool("json", false, "Emit JSON output")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if *keyID == "" {
		*keyID = "did-key-" + time.Now().UTC().Format("20060102-150405")
	}

	signer, err := crypto.NewEd25519Signer(*keyID)
	if err != nil {
		fmt.Fprintf(stderr, "Key generation failed: %v\n", err)
		return 1
	}

	d, err := did.FromEd25519PublicKey(signer.PublicKeyBytes())
	if err != nil {
		fmt.Fprintf(stderr, "DID derivation failed: %v\n", err)
		return 1
	}

	ks, err := loadDIDKeystore()
	if err != nil {
		fmt.Fprintf(stderr, "Load keystore failed: %v\n", err)
		return 1
	}
	entry := didKeystoreEntry{
		DID:          string(d),
		KeyID:        *keyID,
		PublicKeyHex: hex.EncodeToString(signer.PublicKeyBytes()),
		CreatedAt:    time.Now().UTC(),
	}
	ks.Entries = append(ks.Entries, entry)
	if err := saveDIDKeystore(ks); err != nil {
		fmt.Fprintf(stderr, "Save keystore failed: %v\n", err)
		return 1
	}

	if *jsonOutput {
		out, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintf(stdout, "rotated: %s (key=%s)\n", entry.DID, entry.KeyID)
	}
	return 0
}

func init() {
	Register(Subcommand{
		Name:    "did",
		Aliases: []string{},
		Usage:   "Resolve, verify, and rotate W3C Decentralized Identifiers",
		RunFn:   runDIDCmd,
	})
}
