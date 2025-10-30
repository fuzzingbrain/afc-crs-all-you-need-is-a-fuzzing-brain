package main

import (
	"flag"
	"log"
	"path/filepath"

	"crs/internal/config"
	"crs/internal/handlers"
	"crs/internal/services"
)

func main() {
	// Parse command line flags
	modelFlag := flag.String("model", "", "Specify the model to use (e.g., claude-sonnet-4-20250514, gpt-4o, gemini-2.5-pro)")
	mFlag := flag.String("m", "", "Specify the model to use (shorthand for --model)")
	flag.Parse()

	// Check if task path is provided
	if len(flag.Args()) < 1 {
		log.Fatal("Task path is required as an argument")
	}
	taskPath := flag.Arg(0)

	// Get absolute paths
	absTaskDir, err := filepath.Abs(taskPath)
	if err != nil {
		log.Fatalf("Failed to get absolute task dir path: %v", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set mode to local
	cfg.Mode = "local"

	// Override model from command line if provided
	if *modelFlag != "" {
		cfg.AI.Model = *modelFlag
	} else if *mFlag != "" {
		cfg.AI.Model = *mFlag
	}

	// Validate configuration (will check API keys)
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize services - use LocalService for local mode
	crsService := services.NewLocalService(cfg)

	// Initialize handlers with task distribution capability
	h := handlers.NewHandler(crsService, cfg.Services.AnalysisURL, cfg.Services.SubmissionURL)

	h.SubmitLocalTask(absTaskDir)
}