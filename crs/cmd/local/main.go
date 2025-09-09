package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"crs/internal/handlers"
	"crs/internal/services"
	"github.com/joho/godotenv"
)

func main() {

	// default model is claude-sonnet-4-20250514
    modelFlag := flag.String("model", "", "Specify the model to use (e.g., claude-sonnet-4-20250514, gpt-4o, gemini-2.5-pro)")
	mFlag := flag.String("m", "", "Specify the model to use (shorthand for --model)")
	flag.Parse()

	model := "claude-sonnet-4-20250514" // Default model
	if *modelFlag != "" {
		model = *modelFlag
	} else if *mFlag != "" {
		model = *mFlag
	}

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

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found, using default values")
	}

	// API Key check based on model
	if strings.Contains(model, "claude") {
		if os.Getenv("ANTHROPIC_API_KEY") == "" {
			log.Fatal("Model requires ANTHROPIC_API_KEY. Please set it in your environment.")
		}
	} else if strings.Contains(model, "gemini") {
		if os.Getenv("GEMINI_API_KEY") == "" {
			log.Fatal("Model requires GEMINI_API_KEY. Please set it in your environment.")
		}
	} else if strings.Contains(model, "gpt") || strings.HasPrefix(model, "o") {
		if os.Getenv("OPENAI_API_KEY") == "" {
			log.Fatal("Model requires OPENAI_API_KEY. Please set it in your environment.")
		}
	} else {
		log.Printf("Warning: Unknown model type for '%s'. Assuming API key is not required or handled elsewhere.", model)
	}

	// Get credentials from environment variables with fallback values
	apiKeyID := os.Getenv("CRS_KEY_ID")
	if apiKeyID == "" {
		apiKeyID = "api_key_id"
	}
	apiToken := os.Getenv("CRS_KEY_TOKEN")
	if apiToken == "" {
		apiToken = "api_key_token"
	}

	// Get worker configuration
	workerNodesStr := os.Getenv("WORKER_NODES")
	workerNodes, err := strconv.Atoi(workerNodesStr)
	if err != nil || workerNodes <= 0 {
		workerNodes = 24 // Default to 24 worker nodes
	}

	workerBasePortStr := os.Getenv("WORKER_BASE_PORT")
	workerBasePort, err := strconv.Atoi(workerBasePortStr)
	if err != nil || workerBasePort <= 0 {
		workerBasePort = 9081 // Default base port
	}

	submissionService := os.Getenv("SUBMISSION_SERVICE")
	if submissionService == "" {
		submissionService = "http://crs-sub"
	}

	analysisService := os.Getenv("ANALYSIS_SERVICE")
	if analysisService == "" {
		analysisService = "http://localhost:7082"
	}

	if os.Getenv("ANALYSIS_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
		analysisService = "http://localhost:7082"
	}
	if os.Getenv("SUBMISSION_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
		submissionService = "http://localhost:7081"
	}

	// Initialize services
	crsService := services.NewCRSService(workerNodes, workerBasePort, model)
	crsService.SetAnalysisServiceUrl(analysisService)
	crsService.SetSubmissionEndpoint(submissionService)

	// Initialize handlers with task distribution capability
	h := handlers.NewHandler(crsService, analysisService, submissionService)

	h.SubmitLocalTask(absTaskDir)
}