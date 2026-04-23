package config

import "os"

// Config holds server configuration.
type Config struct {
	Port          string
	LogLevel      string
	DatabaseURL   string
	LLMServiceURL string
	ShadowMode    bool
}

// Load loads configuration from environment variables.
func Load() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Default to local generic postgres
		dbURL = "postgres://helm@localhost:5433/helm?sslmode=disable"
	}

	llmURL := os.Getenv("LLM_SERVICE_URL")
	if llmURL == "" {
		// Default to LM Studio Local
		llmURL = "http://host.docker.internal:1234/v1/chat/completions"
	}

	shadowMode := os.Getenv("SHADOW_MODE") == "true"

	return &Config{
		Port:          port,
		LogLevel:      logLevel,
		DatabaseURL:   dbURL,
		LLMServiceURL: llmURL,
		ShadowMode:    shadowMode,
	}
}
