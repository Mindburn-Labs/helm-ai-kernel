package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"
)

func init() {
	Register(Subcommand{
		Name:    "explorer",
		Aliases: []string{},
		Usage:   "Launch the Receipt Explorer web UI",
		RunFn: func(args []string, stdout, stderr io.Writer) int {
			if err := serveWebApp("explorer", args, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		},
	})
	Register(Subcommand{
		Name:    "dashboard",
		Aliases: []string{},
		Usage:   "Launch the live Governance Dashboard",
		RunFn: func(args []string, stdout, stderr io.Writer) int {
			if err := serveWebApp("dashboard", args, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		},
	})
	Register(Subcommand{
		Name:    "simulator",
		Aliases: []string{},
		Usage:   "Launch the Attack Simulator",
		RunFn: func(args []string, stdout, stderr io.Writer) int {
			if err := serveWebApp("simulator", args, stdout, stderr); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return 0
		},
	})
}

func serveWebApp(name string, args []string, stdout, stderr io.Writer) error {
	port := "8090"
	if len(args) > 0 {
		port = args[0]
	}

	webDir := findWebDir(name)
	if webDir == "" {
		return fmt.Errorf("cannot find web/%s directory; ensure HELM is installed or run from project root", name)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh
		server.Close()
	}()

	url := fmt.Sprintf("http://localhost:%s", port)
	fmt.Fprintf(stderr, "⬡ HELM %s running at %s\n", name, url)
	fmt.Fprintln(stderr, "Press Ctrl+C to stop")

	go openBrowser(url)

	return server.Serve(listener)
}

func findWebDir(name string) string {
	candidates := []string{
		filepath.Join("web", name),
		filepath.Join("..", "web", name),
		filepath.Join("..", "..", "web", name),
	}
	if execPath, err := os.Executable(); err == nil {
		dir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(dir, "web", name),
			filepath.Join(dir, "..", "web", name),
			filepath.Join(dir, "..", "..", "web", name),
		)
	}
	if root := os.Getenv("HELM_ROOT"); root != "" {
		candidates = append(candidates, filepath.Join(root, "web", name))
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "rundll32"
		url = "url.dll,FileProtocolHandler " + url
	default:
		return
	}
	exec.Command(cmd, url).Start()
}
