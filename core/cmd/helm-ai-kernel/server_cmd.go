package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

func runServerCommand(name string, args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printGlobalCommandHelp(name, stdout)
		return 0
	}
	logger, logFormat, logConfigErr := configureServerLogger(stderr, name)
	if logConfigErr != nil {
		logger = slog.New(newServerLogHandler(stderr, "json"))
		writeServerCommandError(logger, "json", stderr, logConfigErr)
		return 2
	}
	if name == "server" && len(args) == 0 {
		if err := startServer(); err != nil {
			writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("start server: %w", err))
			return 1
		}
		return 0
	}

	cmd := flag.NewFlagSet(name, flag.ContinueOnError)
	if logFormat == "json" {
		cmd.SetOutput(io.Discard)
	} else {
		cmd.SetOutput(stderr)
	}

	var opts serverOptions
	opts.Mode = name
	opts.Stdout = stdout
	opts.Stderr = stderr

	cmd.StringVar(&opts.PolicyPath, "policy", "", "Path to HELM boundary policy (.toml)")
	cmd.StringVar(&opts.BindAddr, "addr", "", "Bind address")
	cmd.IntVar(&opts.Port, "port", 0, "Listen port")
	cmd.StringVar(&opts.DataDir, "data-dir", "", "Data directory for local SQLite state and keys")
	cmd.BoolVar(&opts.DesktopTransportV1, "desktop-transport-v1", false, "Enable the packaged Desktop transport (requires transport-v1 environment values)")
	cmd.BoolVar(&opts.JSON, "json", false, "Print startup status as JSON")

	if err := cmd.Parse(args); err != nil {
		if logFormat == "json" {
			writeServerCommandError(logger, logFormat, stderr, err)
		}
		return 2
	}
	if cmd.NArg() > 0 {
		writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("unexpected argument: %s", cmd.Arg(0)))
		return 2
	}
	if name == "serve" && opts.PolicyPath == "" {
		writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("helm-ai-kernel serve requires --policy <path>"))
		return 2
	}

	if opts.PolicyPath != "" {
		policy, err := loadServePolicy(opts.PolicyPath)
		if err != nil {
			writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("invalid policy: %w", err))
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
				writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("policy receipts.store=postgres requires DATABASE_URL"))
				return 2
			}
		default:
			writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("unsupported receipts.store %q", policy.Receipts.Store))
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

	if err := runServerWithOptions(opts); err != nil {
		writeServerCommandError(logger, logFormat, stderr, fmt.Errorf("start server: %w", err))
		return 1
	}
	return 0
}

func writeServerCommandError(logger *slog.Logger, logFormat string, stderr io.Writer, err error) {
	if logFormat == "json" {
		logger.Error("server command failed", "error", err)
		return
	}
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
}
