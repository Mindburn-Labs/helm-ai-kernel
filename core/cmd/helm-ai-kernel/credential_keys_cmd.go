package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kms"
)

const credentialKeysUsage = `Usage: helm-ai-kernel credential-keys <status|rotate|revoke VERSION> [--data-dir DIR]

Manages the keystore that seals stored provider credentials
(<data-dir>/keys/credentials.keystore.json). The server loads it at start, so
a change takes effect on the server's next start.

  status          show the active version and the usable and revoked versions
  rotate          add a new key and make it active; older versions still decrypt
  revoke VERSION  delete a retired version for good

Rows are re-sealed under the active key when the server reads them. Revoke a
version only after rotating, restarting and letting the credentials be read:
a row still sealed under a revoked version no longer opens.
`

func init() {
	Register(Subcommand{
		Name:   "credential-keys",
		Usage:  "Rotate or revoke the keys that seal stored provider credentials",
		RunFn:  runCredentialKeysCmd,
		HelpFn: func(stdout io.Writer) { fmt.Fprint(stdout, credentialKeysUsage) },
	})
}

func runCredentialKeysCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, credentialKeysUsage)
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, credentialKeysUsage)
		return 0
	}
	action := args[0]
	fs := flag.NewFlagSet("credential-keys "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "", "runtime data directory (default: $HELM_DATA_DIR, then ./data)")
	// Flags may come before or after the VERSION argument.
	var positional []string
	for rest := args[1:]; ; {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	wantArgs := 0
	if action == "revoke" {
		wantArgs = 1
	}
	if action != "status" && action != "rotate" && action != "revoke" || len(positional) != wantArgs {
		fmt.Fprint(stderr, credentialKeysUsage)
		return 2
	}

	// Never create a keystore here: an empty one would only hide a wrong
	// --data-dir. The server creates it on first start.
	path := kmsKeystorePath(*dataDir)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "credential-keys: no keystore at %s: %v\n", path, err)
		return 1
	}
	k, err := kms.NewLocalKMS(path)
	if err != nil {
		fmt.Fprintf(stderr, "credential-keys: %v\n", err)
		return 1
	}

	switch action {
	case "rotate":
		version, err := k.Rotate()
		if err != nil {
			fmt.Fprintf(stderr, "credential-keys: rotate: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "rotated: v%d is active; restart the server to use it\n", version)
	case "revoke":
		version, err := strconv.Atoi(positional[0])
		if err != nil {
			fmt.Fprintf(stderr, "credential-keys: revoke: version must be a number, got %q\n", positional[0])
			return 2
		}
		if err := k.Revoke(version); err != nil {
			fmt.Fprintf(stderr, "credential-keys: revoke: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "revoked: v%d\n", version)
	}

	active, usable, revoked := k.KeyVersions()
	fmt.Fprintf(stdout, "keystore: %s\nactive: v%d\nusable: %s\nrevoked: %s\n", path, active, versionList(usable), versionList(revoked))
	return 0
}

func versionList(versions []int) string {
	if len(versions) == 0 {
		return "none"
	}
	parts := make([]string, len(versions))
	for i, v := range versions {
		parts[i] = "v" + strconv.Itoa(v)
	}
	return strings.Join(parts, " ")
}
