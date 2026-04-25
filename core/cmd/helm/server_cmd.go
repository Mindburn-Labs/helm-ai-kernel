package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func runServerCommand(name string, args []string, stdout, stderr io.Writer) int {
	if name == "server" && len(args) == 0 {
		startServer()
		return 0
	}

	cmd := flag.NewFlagSet(name, flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var opts serverOptions
	opts.Mode = name
	opts.Stdout = stdout
	opts.Stderr = stderr

	cmd.StringVar(&opts.PolicyPath, "policy", "", "Path to HELM boundary policy (.toml)")
	cmd.StringVar(&opts.BindAddr, "addr", "", "Bind address")
	cmd.IntVar(&opts.Port, "port", 0, "Listen port")
	cmd.StringVar(&opts.DataDir, "data-dir", "", "Data directory for local SQLite state and keys")
	cmd.BoolVar(&opts.JSON, "json", false, "Print startup status as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(0))
		return 2
	}
	if name == "serve" && opts.PolicyPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: helm serve requires --policy <path>")
		return 2
	}

	if opts.PolicyPath != "" {
		policy, err := loadServePolicy(opts.PolicyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: invalid policy: %v\n", err)
			return 2
		}
		if opts.BindAddr == "" {
			opts.BindAddr = policy.Server.Bind
		}
		if opts.Port == 0 {
			opts.Port = policy.Server.Port
		}
		switch strings.ToLower(policy.Receipts.Store) {
		case "sqlite", "sqlite3":
			if opts.DataDir == "" {
				opts.SQLitePath = policy.Receipts.Path
			}
		case "postgres", "postgresql":
			if os.Getenv("DATABASE_URL") == "" {
				_, _ = fmt.Fprintln(stderr, "Error: policy receipts.store=postgres requires DATABASE_URL")
				return 2
			}
		default:
			_, _ = fmt.Fprintf(stderr, "Error: unsupported receipts.store %q\n", policy.Receipts.Store)
			return 2
		}
	}

	if opts.BindAddr == "" {
		opts.BindAddr = "127.0.0.1"
	}
	if opts.Port == 0 {
		if name == "serve" {
			opts.Port = 7714
		} else {
			opts.Port = 8080
		}
	}

	runServerWithOptions(opts)
	return 0
}
