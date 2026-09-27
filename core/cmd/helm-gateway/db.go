package main

// quantum_posture: writes a classical SCRAM-SHA-256 verifier (pkg/gateway/
// pgscram); no post-quantum claim.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/pgscram"
)

const dbUsage = "usage: helm-gateway db scram-verifier [--password-file PATH|-] [--out PATH|-]"

// runDB serves `helm-gateway db scram-verifier`: it reads a password from
// --password-file (stdin by default) and writes its PostgreSQL SCRAM-SHA-256
// verifier to --out (stdout by default). The chart's database bootstrap runs
// it in a container of its own, so the runtime role's password reaches no
// psql process, no PostgreSQL statement log and no wire (HELM-789).
func runDB(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "scram-verifier" {
		return errors.New(dbUsage)
	}
	fs := flag.NewFlagSet("db scram-verifier", flag.ContinueOnError)
	fs.SetOutput(stderr)
	passwordFile := fs.String("password-file", "-", "file holding the password, - for stdin; one trailing newline is ignored")
	out := fs.String("out", "-", "file to write the verifier to (mode 0600), - for stdout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments %v; %s", fs.Args(), dbUsage)
	}
	in := stdin
	if *passwordFile != "-" {
		f, err := os.Open(*passwordFile) // #nosec G304 -- operator-supplied Secret mount path
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	raw, err := io.ReadAll(io.LimitReader(in, pgscram.MaxPasswordLen+3))
	if err != nil {
		return err
	}
	raw = bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	verifier, err := pgscram.New(string(raw))
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = fmt.Fprintln(stdout, verifier)
		return err
	}
	return os.WriteFile(*out, []byte(verifier+"\n"), 0o600)
}
