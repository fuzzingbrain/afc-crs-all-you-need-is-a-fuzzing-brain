package services

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"crs/internal/competition"
	"crs/internal/models"
	"crs/internal/utils/helpers"
	"github.com/shirou/gopsutil/v3/cpu"
)

// Common errors
var (
	errNotSupportedInLocalMode  = errors.New("operation not supported in local mode")
	errNotSupportedInWebMode    = errors.New("operation not supported in web mode")
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

	if err := helpers.EnsureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := helpers.EnsureWorkDir(workDir); err != nil {
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

// ============================================================================
// Shared Types (migrated from crs_services.go)
// ============================================================================

// WorkerFuzzerPair represents a fuzzer assigned to a worker
type WorkerFuzzerPair struct {
	Worker int
	Fuzzer string
}

// WorkerStatus tracks the status of a worker node
type WorkerStatus struct {
	LastAssignedTime time.Time
	FailureCount     int
	BlacklistedUntil time.Time
	AssignedTasks    int
}

// ============================================================================
// System Utilities (migrated from crs_services.go)
// ============================================================================

// getAverageCPUUsage returns the average CPU usage percentage
func getAverageCPUUsage() (float64, error) {
	// cpu.Percent returns percent used per CPU, over the interval
	percents, err := cpu.Percent(2*time.Second, true)
	if err != nil {
		return 0, err
	}
	var sum float64
	for _, p := range percents {
		sum += p
	}
	return sum / float64(len(percents)), nil
}

// ============================================================================
// Service Interface (migrated from crs_services.go)
// ============================================================================

// CRSService defines the interface for CRS service operations
type CRSService interface {
	GetStatus() models.Status
	SubmitTask(task models.Task) error
	SubmitLocalTask(taskPath string) error
	SubmitWorkerTask(task models.WorkerTask) error
	CancelTask(taskID string) error
	CancelAllTasks() error
	SubmitSarif(sarifBroadcast models.SARIFBroadcast) error
	HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error
	SetWorkerIndex(index string)
	SetSubmissionEndpoint(endpoint string)
	SetAnalysisServiceUrl(url string)
	GetWorkDir() string
}

// ============================================================================
// Constants (migrated from crs_services.go)
// ============================================================================

const (
	UNHARNESSED = "UNHARNESSED"
)

// ============================================================================
// Package-level variables (migrated from crs_services.go)
// ============================================================================

var (
	workerTaskMutex   sync.RWMutex
	activeWorkerTasks = make(map[string]bool)
)

// ============================================================================
// Unharnessed Task Functions (temporary stubs - need full migration)
// ============================================================================

// cloneOssFuzzAndMainRepoOnce - TODO: migrate full implementation from deleted crs_services.go
func cloneOssFuzzAndMainRepoOnce(taskDir, projectName, sanitizerDir string) error {
	// Temporary: These functions were in crs_services.go and need to be properly migrated
	// They are complex functions related to unharnessed tasks
	log.Printf("WARNING: cloneOssFuzzAndMainRepoOnce called but not yet fully migrated")
	return nil // Return nil for now to allow compilation
}

// generateFuzzerForUnharnessedTask - TODO: migrate full implementation from deleted crs_services.go
func generateFuzzerForUnharnessedTask(taskDir, focus, sanitizerDir, projectName, sanitizer string) (string, string, error) {
	// Temporary: These functions were in crs_services.go and need to be properly migrated
	// They are complex functions related to unharnessed tasks
	log.Printf("WARNING: generateFuzzerForUnharnessedTask called but not yet fully migrated")
	return "", "", nil // Return empty strings for now to allow compilation
}
