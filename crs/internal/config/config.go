package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// Config holds all configuration for CRS
type Config struct {
	Mode     string `envconfig:"CRS_MODE" default:"server"` // server/worker/local
	Auth     AuthConfig
	Server   ServerConfig
	Worker   WorkerConfig
	Services ServicesConfig
	AI       AIConfig
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	KeyID string `envconfig:"CRS_KEY_ID" default:"api_key_id"`
	Token string `envconfig:"CRS_KEY_TOKEN" default:"api_key_token"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port           string `envconfig:"SERVER_PORT" default:"7080"`
	WorkerBasePort int    `envconfig:"WORKER_BASE_PORT" default:"9081"`
}

// WorkerConfig holds worker-specific configuration
type WorkerConfig struct {
	Nodes         int    `envconfig:"WORKER_NODES" default:"24"`
	Port          int    `envconfig:"WORKER_PORT" default:"9081"`
	Index         string `envconfig:"WORKER_INDEX"`
	PodName       string `envconfig:"POD_NAME"`
	WebServiceURL string `envconfig:"WEB_SERVICE_URL" default:"http://localhost:7080"`
}

// ServicesConfig holds external service URLs
type ServicesConfig struct {
	SubmissionURL string `envconfig:"SUBMISSION_SERVICE" default:"http://crs-sub"`
	AnalysisURL   string `envconfig:"ANALYSIS_SERVICE" default:"http://crs-analysis"`
}

// AIConfig holds AI model configuration (for local mode)
type AIConfig struct {
	Model           string `envconfig:"AI_MODEL" default:"claude-sonnet-4-20250514"`
	AnthropicAPIKey string `envconfig:"ANTHROPIC_API_KEY"`
	GeminiAPIKey    string `envconfig:"GEMINI_API_KEY"`
	OpenAIAPIKey    string `envconfig:"OPENAI_API_KEY"`
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Try to load .env file (optional)
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process config: %w", err)
	}

	// Handle test mode overrides
	if os.Getenv("LOCAL_TEST") != "" ||
	   os.Getenv("ANALYSIS_SERVICE_TEST") != "" ||
	   os.Getenv("SUBMISSION_SERVICE_TEST") != "" {
		cfg.Services.AnalysisURL = "http://localhost:7082"
		cfg.Services.SubmissionURL = "http://localhost:7081"
	}

	// Auto-extract worker index from pod name if not set
	if cfg.Worker.Index == "" && cfg.Worker.PodName != "" {
		parts := strings.Split(cfg.Worker.PodName, "-")
		if len(parts) > 0 {
			cfg.Worker.Index = parts[len(parts)-1]
		}
	}

	return &cfg, nil
}

// Validate checks if required configuration is present based on mode
func (c *Config) Validate() error {
	switch c.Mode {
	case "server":
		if c.Server.Port == "" {
			return fmt.Errorf("server port is required")
		}
	case "worker":
		if c.Worker.Port == 0 {
			return fmt.Errorf("worker port is required")
		}
	case "local":
		// Check if appropriate API key is set based on model
		if strings.Contains(c.AI.Model, "claude") && c.AI.AnthropicAPIKey == "" {
			return fmt.Errorf("ANTHROPIC_API_KEY is required for model %s", c.AI.Model)
		}
		if strings.Contains(c.AI.Model, "gemini") && c.AI.GeminiAPIKey == "" {
			return fmt.Errorf("GEMINI_API_KEY is required for model %s", c.AI.Model)
		}
		if (strings.Contains(c.AI.Model, "gpt") || strings.HasPrefix(c.AI.Model, "o")) && c.AI.OpenAIAPIKey == "" {
			return fmt.Errorf("OPENAI_API_KEY is required for model %s", c.AI.Model)
		}
	default:
		return fmt.Errorf("unknown mode: %s", c.Mode)
	}
	return nil
}

// GetListenAddress returns the appropriate listen address based on mode
func (c *Config) GetListenAddress() string {
	switch c.Mode {
	case "server":
		if os.Getenv("LOCAL_TEST") != "" {
			return ":5080"
		}
		return ":" + c.Server.Port
	case "worker":
		return fmt.Sprintf(":%d", c.Worker.Port)
	default:
		return ":8080"
	}
}
