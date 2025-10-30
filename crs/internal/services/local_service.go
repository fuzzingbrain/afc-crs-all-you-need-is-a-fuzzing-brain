package services

import (
	"crs/internal/models"
	"crs/internal/executor"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LocalCRSService implements CRSService for local CLI mode
type LocalCRSService struct {
	// Embed defaultCRSService temporarily to reuse helper methods
	// TODO: Remove this once all methods are migrated
	*defaultCRSService
}

// NewLocalService creates a new local service instance
func NewLocalService(model string) CRSService {
	// Create the embedded defaultCRSService for helper methods
	embedded := NewCRSService(0, 0, model).(*defaultCRSService)

	return &LocalCRSService{
		defaultCRSService: embedded,
	}
}

// GetStatus returns empty status for local mode (no task tracking)
func (s *LocalCRSService) GetStatus() models.Status {
	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: models.StatusTasksState{},
		},
	}
}

// SubmitLocalTask implements local task submission
func (s *LocalCRSService) SubmitLocalTask(taskDir string) error {
	myFuzzer := ""

	// --- ensure LOCAL_TEST mode is enabled ---
	if os.Getenv("LOCAL_TEST") == "" {
		log.Printf("Setting LOCAL_TEST to 1")
		_ = os.Setenv("LOCAL_TEST", "1")
	}

	//----------------------------------------------------------
	// Locate and load task_detail*.json (if present)
	//----------------------------------------------------------
	var (
		taskDetail models.TaskDetail
		jsonFound  bool
	)

	walkErr := filepath.WalkDir(taskDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // Skip errors & directories
		}

		name := d.Name()
		if strings.HasPrefix(name, "task_detail") && strings.HasSuffix(name, ".json") {
			data, rdErr := os.ReadFile(p)
			if rdErr != nil {
				log.Printf("Failed to read %s: %v (continuing search)", p, rdErr)
				return nil
			}
			if umErr := json.Unmarshal(data, &taskDetail); umErr != nil {
				log.Printf("Failed to unmarshal %s: %v (continuing search)", p, umErr)
				return nil
			}
			jsonFound = true
			return filepath.SkipDir // Stop walking once we succeed
		}
		return nil
	})
	if walkErr != nil {
		log.Printf("Directory walk error: %v", walkErr)
	}

	// Fallback to stub when JSON isn't found / can't be parsed
	if !jsonFound {
		log.Printf("No valid task_detail.json found – falling back to default task detail")

		projectName := "test"
		focusName := "test"

		projectsDir := filepath.Join(taskDir, "fuzz-tooling/projects/")
		files, err := os.ReadDir(projectsDir)
		if err == nil {
			for _, file := range files {
				if file.IsDir() {
					projectName = file.Name()
					focusName = "afc-" + projectName
					log.Printf("Found project '%s' in fuzz-tooling/projects, setting focus to '%s'", projectName, focusName)
					break // Use the first one
				}
			}
		} else {
			log.Printf("Could not read fuzz-tooling/projects/ directory: %v", err)
		}

		// Determine task type based on presence of "diff" directory
		taskType := models.TaskTypeFull
		diffPath := filepath.Join(taskDir, "diff")
		if info, err := os.Stat(diffPath); err == nil && info.IsDir() {
			taskType = models.TaskTypeDelta
			log.Printf("Found 'diff' directory, setting task type to 'delta'")
		} else {
			log.Printf("No 'diff' directory found, setting task type to 'full'")
		}

		log.Printf("Saving Task Detail")

		taskDetail = models.TaskDetail{
			TaskID:            uuid.New(),
			ProjectName:       projectName,
			Focus:             focusName,
			Type:              taskType,
			Deadline:          time.Now().Add(time.Hour).Unix() * 1000,
			HarnessesIncluded: true,
			Metadata:          make(map[string]string),
		}

		log.Printf("Completed Task Detail, setting task detail to %v", taskDetail)
	}
	//----------------------------------------------------------

	// Get absolute paths
	log.Printf("-------------------- Getting absolute task dir path ----------------------")
	absTaskDir, err := filepath.Abs(taskDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute task dir path: %v", err)
	}

	projectDir := path.Join(absTaskDir, taskDetail.Focus)
	dockerfilePath := path.Join(absTaskDir, "fuzz-tooling/projects", taskDetail.ProjectName)
	dockerfileFullPath := path.Join(dockerfilePath, "Dockerfile")
	fuzzerDir := path.Join(taskDir, "fuzz-tooling/build/out", taskDetail.ProjectName)

	log.Printf("Project dir: %s", projectDir)
	log.Printf("Dockerfile: %s", dockerfileFullPath)

	// Use executor package to prepare environment
	params := executor.PrepareEnvironmentParams{
		MyFuzzer:          &myFuzzer,
		TaskDir:           taskDir,
		TaskDetail:        taskDetail,
		DockerfilePath:    dockerfilePath,
		DockerfileFullPath: dockerfileFullPath,
		FuzzerDir:         fuzzerDir,
		ProjectDir:        projectDir,
		FuzzerBuilder:     s.buildFuzzersDocker,
		FindFuzzers:       executor.FindFuzzers,
	}
	cfg, sanitizerDirs, err := executor.PrepareEnvironment(params)
	if err != nil {
		return err
	}

	// Collect all fuzzers from all sanitizer builds and run them in parallel
	log.Printf("-------------------- Collecting all fuzzers ----------------------")
	var allFuzzers []string
	sanitizerDirsCopy := make([]string, len(sanitizerDirs))
	copy(sanitizerDirsCopy, sanitizerDirs)

	// Now use the copy to find fuzzers
	for _, sdir := range sanitizerDirsCopy {
		fuzzers, err := executor.FindFuzzers(sdir)
		if err != nil {
			log.Printf("Warning: failed to find fuzzers in %s: %v", sdir, err)
			continue // Skip this directory but continue with others
		}

		// Mark these fuzzers with the sanitizer directory so we know where they live
		for _, fz := range fuzzers {
			// We'll store the absolute path so we can directly call run_fuzzer
			fuzzerPath := filepath.Join(sdir, fz)
			allFuzzers = append(allFuzzers, fuzzerPath)
		}
	}

	if len(allFuzzers) == 0 {
		log.Printf("No fuzzers found after building all sanitizers")
		return nil
	}

	//TODO: skip memory and undefined sanitizers if too many fuzzers
	// keep only address sanitizer
	const MAX_FUZZERS = 10
	if true {
		var allFilteredFuzzers []string
		for _, fuzzerPath := range allFuzzers {
			if strings.Contains(fuzzerPath, "-address/") || (strings.Contains(fuzzerPath, "-memory/") && len(allFuzzers) < MAX_FUZZERS) {
				allFilteredFuzzers = append(allFilteredFuzzers, fuzzerPath)
			}
		}
		allFuzzers = sortFuzzersByGroup(allFilteredFuzzers)
	}

	log.Printf("Found %d fuzzers: %v", len(allFuzzers), allFuzzers)

	fullTask := models.Task{
		MessageID:   uuid.New(),
		MessageTime: time.Now().UnixMilli(),
		Tasks:       []models.TaskDetail{taskDetail},
	}

	// Process the task based on its type
	// Use the embedded defaultCRSService's runFuzzing method for now
	if err := s.runFuzzing(myFuzzer, taskDir, taskDetail, fullTask, cfg, allFuzzers); err != nil {
		log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
	}

	return nil
}

// SubmitTask is not supported in local mode
func (s *LocalCRSService) SubmitTask(task models.Task) error {
	return errNotSupportedInLocalMode
}

// SubmitWorkerTask is not supported in local mode
func (s *LocalCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	return errNotSupportedInLocalMode
}

// CancelTask is not supported in local mode
func (s *LocalCRSService) CancelTask(taskID string) error {
	return errNotSupportedInLocalMode
}

// CancelAllTasks is not supported in local mode
func (s *LocalCRSService) CancelAllTasks() error {
	return errNotSupportedInLocalMode
}

// SubmitSarif handles SARIF broadcast submission
func (s *LocalCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	// This will use the shared SARIF handling logic
	panic("SubmitSarif: to be implemented")
}

// HandleSarifBroadcastWorker is not typically used in local mode
func (s *LocalCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInLocalMode
}

// SetWorkerIndex is not used in local mode (no-op)
func (s *LocalCRSService) SetWorkerIndex(index string) {
	// No-op for local mode
}
