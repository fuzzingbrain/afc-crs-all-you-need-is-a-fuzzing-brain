package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"os/exec"
	"crs/internal/handlers"
	"crs/internal/services"
	"github.com/joho/godotenv"
)

func main() {

    modelFlag := flag.String("model", "", "Specify the model to use (e.g., claude-sonnet-4-5-20250929, gpt-5, gemini-3-pro)")
	mFlag := flag.String("m", "", "Specify the model to use (shorthand for --model)")
	workspacePathFlag := flag.String("workspace-path", "", "Specify the workspace directory path (default: workspace)")
	strategyDirFlag := flag.String("strategy-path", "", "Specify the strategy directory path (default: strategy)")
	flag.Parse()

	model := "claude-sonnet-4-5-20250929" // Default model
	if *modelFlag != "" {
		model = *modelFlag
	} else if *mFlag != "" {
		model = *mFlag
	}

	// Check if task path is provided
	if len(flag.Args()) < 1 {
		log.Fatal("Project's URL is required, e.g., https://github.com/libexpat/libexpat]")
	}

	// set LOCAL_TEST to true
	os.Setenv("LOCAL_TEST", "1")

	//TODO 
	// 1 workspacePath := "workspace" folder under current dir by default (create "workspace" if not exist)
	// 2. in workspacePath must exist oss-fuzz, if not do git clone https://github.com/google/oss-fuzz 
	// 3 user can specify workspacePath optionally

	// Set workspace path: CLI flag > Environment variable > Default
	workspacePath := "workspace"
	if *workspacePathFlag != "" {
		workspacePath = *workspacePathFlag
	} else if envWorkspacePath := os.Getenv("WORKSPACE_PATH"); envWorkspacePath != "" {
		workspacePath = envWorkspacePath
	}
	// Create workspace directory if it doesn't exist
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		log.Fatalf("Failed to create workspace directory: %v", err)
	}

	// Ensure oss-fuzz exists in workspacePath
	ossFuzzPath := filepath.Join(workspacePath, "oss-fuzz")
	if _, err := os.Stat(ossFuzzPath); os.IsNotExist(err) {
		log.Printf("oss-fuzz not found, cloning from https://github.com/google/oss-fuzz...")
		// Note: You'll need to import "os/exec" for this
		cmd := exec.Command("git", "clone", "https://github.com/google/oss-fuzz", ossFuzzPath)
		if err := cmd.Run(); err != nil {
			log.Fatalf("Failed to clone oss-fuzz: %v", err)
		}
		log.Printf("Successfully cloned oss-fuzz")
	}


	targetProjectUrl := flag.Arg(0)
	var focusName string
	var projectName string
	// Clone project if it is a git repo into workspacePath
	if strings.HasPrefix(targetProjectUrl, "http://") || strings.HasPrefix(targetProjectUrl, "https://") || strings.HasPrefix(targetProjectUrl, "git@") {
		// Extract project name from URL
		focusName = filepath.Base(strings.TrimSuffix(targetProjectUrl, ".git"))
		projectPath := filepath.Join(workspacePath, focusName)
		
		if _, err := os.Stat(projectPath); os.IsNotExist(err) {
			log.Printf("Cloning project %s into %s...", targetProjectUrl, projectPath)
			cmd := exec.Command("git", "clone", targetProjectUrl, projectPath)
			if err := cmd.Run(); err != nil {
				log.Fatalf("Failed to clone project: %v", err)
			}
			log.Printf("Successfully cloned project")
		} else {
			log.Printf("Project already exists at %s", projectPath)
		}
		
		// Try to find the corresponding oss-fuzz project name
		// Check oss-fuzz/projects directory for matching project
		ossFuzzProjectsDir := filepath.Join(workspacePath, "oss-fuzz", "projects")
		files, err := os.ReadDir(ossFuzzProjectsDir)
		if err == nil {
			// First, try exact match
			found := false
			for _, file := range files {
				if file.IsDir() && file.Name() == focusName {
					projectName = focusName
					found = true
					log.Printf("Found exact match: projectName='%s', focusName='%s'", projectName, focusName)
					break
				}
			}
			
			// If no exact match, try to find a project that matches when we remove "lib" prefix
			if !found {
				// For cases like libexpat -> expat
				shortName := strings.TrimPrefix(focusName, "lib")
				for _, file := range files {
					if file.IsDir() && file.Name() == shortName {
						projectName = shortName
						found = true
						log.Printf("Found match after removing 'lib' prefix: projectName='%s', focusName='%s'", projectName, focusName)
						break
					}
				}
			}
		// If still not found, check if focusName contains projectName (for other patterns)
			if !found {
				for _, file := range files {
					if file.IsDir() && strings.Contains(focusName, file.Name()) {
						projectName = file.Name()
						found = true
						log.Printf("Found partial match: projectName='%s', focusName='%s'", projectName, focusName)
						break
					}
				}
			}
			
			if !found {
				log.Printf("Warning: Could not find matching oss-fuzz project for '%s', will use '%s' as projectName", focusName, focusName)
				projectName = focusName
			}
		} else {
			log.Printf("Warning: Could not read oss-fuzz/projects directory: %v, using focusName as projectName", err)
			projectName = focusName
		}
	} else {
		// If not a git URL, use the path as-is
		focusName = targetProjectUrl
		projectName = targetProjectUrl
	}
	// Set strategy directory: CLI flag > Environment variable > Default
	strategyDirectory := "strategy"
	if *strategyDirFlag != "" {
		strategyDirectory = *strategyDirFlag
	} else if envStrategyDir := os.Getenv("STRATEGY_DIRECTORY"); envStrategyDir != "" {
		strategyDirectory = envStrategyDir
	}
	strategyDir, err := filepath.Abs(strategyDirectory)
	if err != nil {
		log.Fatalf("Failed to get absolute strategyDir path: %v", err)
	}

	if err := os.MkdirAll(strategyDir, 0755); err != nil {
		log.Fatalf("Failed to create strategy directory: %v", err)
	}

	// Get absolute paths
	absTaskDir, err := filepath.Abs(workspacePath)
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
		workerNodes = 1 // Default to 1 worker nodes
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
	crsService.SetStrategyDirectory(strategyDir)
	crsService.SetSubmissionEndpoint(submissionService)

	// Initialize handlers with task distribution capability
	h := handlers.NewHandler(crsService, analysisService, submissionService)

	h.SubmitLocalTask(absTaskDir, projectName, focusName)
}