package services

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"crs/internal/competition"
)

// Common errors
var (
	errNotSupportedInLocalMode  = errors.New("operation not supported in local mode")
	errNotSupportedInServerMode = errors.New("operation not supported in server mode")
	errNotSupportedInWorkerMode = errors.New("operation not supported in worker mode")
)

// baseService contains fields and methods shared by all service implementations
type baseService struct {
	workDir            string
	competitionClient  *competition.Client
	submissionEndpoint string
	analysisServiceUrl string
	model              string

	// POV metadata directories (used by Local and Worker services)
	povMetadataDir         string
	povMetadataDir0        string
	povAdvcancedMetadataDir string
	patchWorkDir           string
}

// GetWorkDir returns the working directory path
func (b *baseService) GetWorkDir() string {
	return b.workDir
}

// SetSubmissionEndpoint sets the submission endpoint URL
func (b *baseService) SetSubmissionEndpoint(endpoint string) {
	b.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (b *baseService) SetAnalysisServiceUrl(url string) {
	b.analysisServiceUrl = url
}

// initializeWorkDir initializes and returns the working directory
func initializeWorkDir() string {
	workDir := "/crs-workdir"

	if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
		workDir = envWorkDir
	}

	if err := ensureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := ensureWorkDir(workDir); err != nil {
				log.Printf("Warning: Could not create fallback work directory: %v", err)
				tempDir, err := os.MkdirTemp("", "crs-workdir-")
				if err == nil {
					workDir = tempDir
					log.Printf("Using temporary directory as work directory: %s", workDir)
				} else {
					workDir = "."
					log.Printf("Warning: Using current directory as work directory")
				}
			}
		} else {
			workDir = "."
			log.Printf("Warning: Using current directory as work directory")
		}
	}

	return workDir
}

// initializeCompetitionAPI initializes competition API credentials
func initializeCompetitionAPI() (endpoint, keyID, token string) {
	endpoint = os.Getenv("COMPETITION_API_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:7081"
	}

	keyID = os.Getenv("CRS_KEY_ID")
	token = os.Getenv("CRS_KEY_TOKEN")

	if keyID == "" || token == "" {
		log.Printf("Warning: CRS_KEY_ID or CRS_KEY_TOKEN not set")
	}

	return endpoint, keyID, token
}

// initializeCompetitionClient creates a new competition client
func initializeCompetitionClient(endpoint, keyID, token string) *competition.Client {
	return competition.NewClient(endpoint, keyID, token)
}
