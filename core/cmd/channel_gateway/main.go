// Command channel_gateway starts a standalone HTTP server that receives
// channel webhooks, normalises them into ChannelEnvelopes, and logs them.
//
// Usage: channel_gateway [-port 8080] [-channels slack,telegram]
//
// Exits 0 on clean shutdown, 1 on startup failure.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels/slack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/channels/telegram"
)

func main() {
	os.Exit(run())
}

func run() int {
	portFlag := flag.Int("port", 8080, "HTTP listen port")
	channelsFlag := flag.String("channels", "slack,telegram", "comma-separated list of enabled channels")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: channel_gateway [-port 8080] [-channels slack,telegram]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Build the adapter registry.
	registry := channels.NewAdapterRegistry()
	enabled := parseChannelList(*channelsFlag)

	for _, ch := range enabled {
		switch ch {
		case string(channels.ChannelSlack):
			token := os.Getenv("SLACK_BOT_TOKEN")
			if err := registry.Register(slack.New(token)); err != nil {
				logger.Error("failed to register slack adapter", "error", err)
				return 1
			}
			logger.Info("adapter registered", "channel", channels.ChannelSlack)

		case string(channels.ChannelTelegram):
			token := os.Getenv("TELEGRAM_BOT_TOKEN")
			if err := registry.Register(telegram.New(token)); err != nil {
				logger.Error("failed to register telegram adapter", "error", err)
				return 1
			}
			logger.Info("adapter registered", "channel", channels.ChannelTelegram)

		default:
			logger.Warn("unknown channel, skipping", "channel", ch)
		}
	}

	mux := http.NewServeMux()

	// POST /webhook/{channel} — receive webhook, normalise, and log envelope.
	mux.HandleFunc("/webhook/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract channel name from path: /webhook/<channel>
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/webhook/"), "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "missing channel in path", http.StatusBadRequest)
			return
		}
		channelName := parts[0]

		adapter, err := registry.Get(channels.ChannelKind(channelName))
		if err != nil {
			http.Error(w, fmt.Sprintf("no adapter for channel %q", channelName), http.StatusNotFound)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB limit
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		env, err := adapter.NormalizeInbound(r.Context(), body)
		if err != nil {
			logger.Warn("normalisation failed", "channel", channelName, "error", err)
			http.Error(w, fmt.Sprintf("normalisation error: %v", err), http.StatusUnprocessableEntity)
			return
		}

		// Log the normalised envelope as structured JSON.
		envBytes, _ := json.Marshal(env)
		logger.Info("envelope received",
			"channel", channelName,
			"envelope_id", env.EnvelopeID,
			"sender_id", env.SenderID,
			"tenant_id", env.TenantID,
			"session_id", env.SessionID,
			"envelope", json.RawMessage(envBytes),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		resp := map[string]string{
			"status":      "accepted",
			"envelope_id": env.EnvelopeID,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// GET /health — liveness probe.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		adapters := registry.List()
		kinds := make([]string, 0, len(adapters))
		for _, k := range adapters {
			kinds = append(kinds, string(k))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"status":   "ok",
			"channels": kinds,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *portFlag),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("channel_gateway starting", "port", *portFlag, "channels", *channelsFlag)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	// Graceful shutdown on SIGINT / SIGTERM.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down channel_gateway")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "error", err)
		return 1
	}
	logger.Info("channel_gateway stopped")
	return 0
}

// parseChannelList splits a comma-separated channel list and trims whitespace.
func parseChannelList(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
