package executor

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crs/internal/config"
	"crs/internal/models"
	"crs/internal/telemetry"
	"crs/internal/utils/environment"
	"crs/internal/utils/helpers"

	"go.opentelemetry.io/otel/attribute"
)

const (
	SafetyBufferMinutes = 10
	UNHARNESSED        = "UNHARNESSED"
)

// TaskExecutionParams contains all parameters needed for executing a fuzzing task on a worker
type TaskExecutionParams struct {
	Fuzzer                   string
	TaskDir                  string
	TaskDetail               models.TaskDetail
	Task                     models.Task
	ProjectConfig            *environment.ProjectConfig
	AllFuzzers               []string
	SubmissionEndpoint       string
	POVMetadataDir           string
	POVMetadataDir0          string
	POVAdvancedMetadataDir   string
	Model                    string
	WorkerIndex              string
	AnalysisServiceUrl       string
	UnharnessedFuzzerSrcPath string
	StrategyConfig           *config.StrategyConfig
	FuzzerConfig             *config.FuzzerConfig
	Sanitizer                string // Extracted or configured sanitizer
}

// ExecuteFuzzingTask executes a complete fuzzing workflow on a worker node
// This includes: running strategies, POV generation, and patching
func ExecuteFuzzingTask(params TaskExecutionParams) error {
	// Determine which fuzzers to execute
	var fuzzersToExecute []string

	// Handle LOCAL_TEST mode
	if os.Getenv("LOCAL_TEST") != "" {
		params.SubmissionEndpoint = "http://localhost:7081"
		// In LOCAL_TEST mode, use all fuzzers from params.AllFuzzers
		fuzzersToExecute = params.AllFuzzers
	} else {
		// In normal mode, if a specific fuzzer is provided, use it; otherwise use all
		if params.Fuzzer != "" {
			fuzzersToExecute = []string{params.Fuzzer}
		} else {
			fuzzersToExecute = params.AllFuzzers
		}
	}

	if len(fuzzersToExecute) == 0 {
		log.Printf("No fuzzers specified for execution, skipping...")
		return nil
	}

	// Get absolute paths (used for all fuzzers)
	absTaskDir, err := filepath.Abs(params.TaskDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute task dir path: %v", err)
	}
	projectDir := path.Join(absTaskDir, params.TaskDetail.Focus)

	// Execute each fuzzer sequentially
	log.Printf("===========================================")
	log.Printf("Executing %d fuzzer(s) sequentially", len(fuzzersToExecute))
	log.Printf("TaskID: %s", params.TaskDetail.TaskID)
	log.Printf("ProjectName: %s", params.TaskDetail.ProjectName)
	log.Printf("===========================================")

	var lastErr error
	successCount := 0

	for idx, fuzzer := range fuzzersToExecute {
		log.Printf("")
		log.Printf("╔════════════════════════════════════════════════════════════════╗")
		log.Printf("║  Fuzzer %d/%d: %s", idx+1, len(fuzzersToExecute), filepath.Base(fuzzer))
		log.Printf("╚════════════════════════════════════════════════════════════════╝")

		// Set a fresh deadline for this fuzzer based on per-fuzzer timeout
		timeoutMinutes := 60 // Default 1 hour
		if params.FuzzerConfig != nil && params.FuzzerConfig.PerFuzzerTimeoutMinutes > 0 {
			timeoutMinutes = params.FuzzerConfig.PerFuzzerTimeoutMinutes
		}

		// Create a new deadline for this specific fuzzer
		newDeadline := time.Now().Add(time.Duration(timeoutMinutes) * time.Minute)
		params.TaskDetail.Deadline = newDeadline.Unix() * 1000

		log.Printf("Fuzzer timeout: %d minutes (deadline: %s)",
			timeoutMinutes, newDeadline.Format("15:04:05"))

		fuzzDir := filepath.Dir(fuzzer)

		// Save task detail to JSON for strategy scripts
		helpers.SaveTaskDetailToJson(params.TaskDetail, fuzzer, fuzzDir)

		// Create a copy of fuzzDir for parallel strategies
		err = helpers.CopyFuzzDirForParallelStrategies(fuzzer, fuzzDir)
		if err != nil {
			log.Printf("Failed to copy fuzzDir %s for parallel strategies. Error: %v", fuzzDir, err)
		} else {
			log.Printf("Prepared fuzzer directory for execution: %v", fuzzer)
		}

		// Determine sanitizer from params or extract from fuzzer directory name
		sanitizer := params.Sanitizer
		if sanitizer == "" {
			// Fallback: Extract sanitizer from directory name (e.g., "bind9-address" -> "address")
			baseName := filepath.Base(fuzzDir)
			parts := strings.Split(baseName, "-")
			if len(parts) > 1 {
				sanitizer = parts[len(parts)-1]
				log.Printf("Extracted sanitizer from directory name: %s", sanitizer)
			} else {
				// Use configured preferred sanitizer as last resort
				if params.FuzzerConfig != nil {
					sanitizer = params.FuzzerConfig.PreferredSanitizer
				} else {
					sanitizer = "address"
				}
				log.Printf("Using default sanitizer: %s", sanitizer)
			}
		}

		// Execute the fuzzing workflow for this fuzzer
		err = executeFuzzingWorkflow(fuzzer, params, projectDir, fuzzDir, sanitizer)
		if err != nil {
			log.Printf("✗ Fuzzer %d/%d failed: %v", idx+1, len(fuzzersToExecute), err)
			lastErr = err
		} else {
			log.Printf("✓ Fuzzer %d/%d completed successfully", idx+1, len(fuzzersToExecute))
			successCount++
		}
	}

	// Print final summary
	log.Printf("")
	log.Printf("╔════════════════════════════════════════════════════════════════╗")
	log.Printf("║              ALL FUZZERS EXECUTION SUMMARY                     ║")
	log.Printf("╠════════════════════════════════════════════════════════════════╣")
	log.Printf("║ Total Fuzzers:    %d", len(fuzzersToExecute))
	log.Printf("║ Successful:       %d", successCount)
	log.Printf("║ Failed:           %d", len(fuzzersToExecute)-successCount)
	log.Printf("╚════════════════════════════════════════════════════════════════╝")
	log.Printf("")

	// Return last error if any fuzzer failed, or nil if all succeeded
	return lastErr
}

// executeFuzzingWorkflow runs the complete fuzzing workflow: strategies -> POV generation -> patching
func executeFuzzingWorkflow(fuzzer string, params TaskExecutionParams, projectDir, fuzzDir, sanitizer string) error {
	workflowStartTime := time.Now()
	povSuccess := false
	patchSuccess := false

	// Channel for POV signal
	type signal struct{}
	var povFound sync.Once
	povChan := make(chan signal)

	ctx := context.Background()

	// Phase 1: Start LibFuzzer for C/C++ projects immediately
	libFuzzerStarted := false
	lang := strings.ToLower(params.ProjectConfig.Language)
	if lang == "c" || lang == "c++" {
		libFuzzerStarted = true
		go func() {
			runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
				params.TaskDetail, params.Task, params.SubmissionEndpoint)
		}()
		log.Printf("Started LibFuzzer for C/C++ project")
	}

	// Phase 2: Run Strategies (Branch based on task type)
	// Check if this is a full scan task or delta scan task
	if params.TaskDetail.Type == models.TaskTypeFull {
		// ========== FULL SCAN WORKFLOW ==========
		log.Printf("========== FULL SCAN: Running full codebase analysis ==========")
		_, fullScanSpan := telemetry.StartSpan(ctx, "full_scan_phase")
		fullScanSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
		fullScanSpan.SetAttributes(attribute.String("crs.action.name", "runFullScanStrategy"))
		for key, value := range params.TaskDetail.Metadata {
			fullScanSpan.SetAttributes(attribute.String(key, value))
		}

		if os.Getenv("FUZZER_TEST") == "" {
			fullScanConfig := FullScanStrategyConfig{
				Model:                    params.Model,
				POVMetadataDir:           params.POVMetadataDir,
				SubmissionEndpoint:       params.SubmissionEndpoint,
				WorkerIndex:              params.WorkerIndex,
				AnalysisServiceUrl:       params.AnalysisServiceUrl,
				StrategyConfig:           params.StrategyConfig,
				Sanitizer:                sanitizer,
			}
			povSuccess = runFullScanStrategy(fuzzer, params.TaskDir, projectDir, fuzzDir,
				params.ProjectConfig.Language, params.TaskDetail, params.Task, fullScanConfig)
		}
		fullScanSpan.End()

	} else {
		// ========== DELTA SCAN WORKFLOW (default) ==========
		log.Printf("========== BASIC PHASE: Running initial strategies ==========")
		_, basicPhasesSpan := telemetry.StartSpan(ctx, "basic_strategies_phase")
		basicPhasesSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
		basicPhasesSpan.SetAttributes(attribute.String("crs.action.name", "runBasicStrategies"))
		for key, value := range params.TaskDetail.Metadata {
			basicPhasesSpan.SetAttributes(attribute.String(key, value))
		}

		if os.Getenv("FUZZER_TEST") == "" {
			basicConfig := BasicStrategiesConfig{
				Model:                    params.Model,
				POVMetadataDir:           params.POVMetadataDir,
				POVMetadataDir0:          params.POVMetadataDir0,
				SubmissionEndpoint:       params.SubmissionEndpoint,
				WorkerIndex:              params.WorkerIndex,
				AnalysisServiceUrl:       params.AnalysisServiceUrl,
				UnharnessedFuzzerSrcPath: params.UnharnessedFuzzerSrcPath,
				StrategyConfig:           params.StrategyConfig,
			}
			povSuccess = runBasicStrategies(fuzzer, params.TaskDir, projectDir, fuzzDir,
				params.ProjectConfig.Language, params.TaskDetail, params.Task, basicConfig)
		} else {
			// Testing mode: only run libFuzzer and exit
			runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
				params.TaskDetail, params.Task, params.SubmissionEndpoint)
			os.Exit(0)
		}
		basicPhasesSpan.End()
	}

	// For full scan tasks without patching enabled, return early after basic phase completes
	if params.TaskDetail.Type == models.TaskTypeFull && !params.StrategyConfig.EnablePatching {
		if povSuccess {
			log.Printf("✓ Full scan completed: POV found! (Patching disabled)")
			return nil
		} else {
			log.Printf("✗ Full scan completed: No POV found")
			return ErrPOVNotFound
		}
	}

	// Continue with advanced phases (for delta scan or full scan with patching enabled)
	if povSuccess {
		log.Printf("POV found in basic phase!")
		povFound.Do(func() { close(povChan) })
	} else {
		log.Printf("No POV found in basic phase, will continue with advanced phases")
		// If LibFuzzer not started (e.g., for Java), start it now
		if !libFuzzerStarted {
			go func() {
				runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
					params.TaskDetail, params.Task, params.SubmissionEndpoint)
			}()
			log.Printf("Started LibFuzzer for non-C/C++ project")
		}
	}

	// Calculate time budget
	deadlineTime := time.Unix(params.TaskDetail.Deadline/1000, 0)
	totalBudgetMinutes := int(time.Until(deadlineTime).Minutes())
	if totalBudgetMinutes <= 0 {
		log.Printf("WARNING: Task deadline passed! Setting it to one hour from now for testing.")
		totalBudgetMinutes = 60
		deadlineTime = time.Now().Add(60 * time.Minute)
	}

	totalLibfuzzingTime := time.Until(deadlineTime) / 2
	halfTimeToDeadline := time.Now().Add(totalLibfuzzingTime)
	workingBudgetMinutes := totalBudgetMinutes - SafetyBufferMinutes

	log.Printf("Time budget: total=%d min, working=%d min, halfTime=%v",
		totalBudgetMinutes, workingBudgetMinutes, halfTimeToDeadline.Format("15:04:05"))

	// Phase 3: Start Advanced POV Generation Phases in background
	// Convert typed channel to generic channel for function call
	genericPovChan := make(chan struct{})
	go func() {
		<-povChan
		close(genericPovChan)
	}()
	go runAdvancedPOVPhases(ctx, fuzzer, params, fuzzDir, workflowStartTime,
		deadlineTime, totalLibfuzzingTime, workingBudgetMinutes, &povFound, genericPovChan, &povSuccess)

	// Phase 4: Wait for POV or deadline, then proceed to patching (if enabled)
	if !params.StrategyConfig.EnablePatching {
		log.Println("========== PATCHING DISABLED: Waiting for POV or deadline ==========")
		select {
		case <-genericPovChan:
			log.Println("========== POV FOUND: Patching disabled, task completed ==========")
			printCompletionSummary(projectDir, params.TaskDir, povSuccess)
			return nil
		case <-time.After(time.Until(deadlineTime)):
			log.Println("========== DEADLINE REACHED: No POV found ==========")
			printCompletionSummary(projectDir, params.TaskDir, false)
			return ErrPOVNotFound
		}
	}

	select {
	case <-genericPovChan:
		log.Println("========== POV FOUND: Proceeding to patching ==========")
		patchSuccess = executePatchingPhase(ctx, fuzzer, params, projectDir, fuzzDir, sanitizer, deadlineTime)

	case <-time.After(time.Until(halfTimeToDeadline)):
		log.Println("========== HALFTIME REACHED: Attempting XPatch without POV ==========")
		patchSuccess = executeXPatchPhase(fuzzer, params, projectDir, sanitizer, deadlineTime)

	case <-time.After(time.Until(deadlineTime)):
		log.Println("========== DEADLINE REACHED: No POV found ==========")
		return ErrPOVNotFound
	}

	// Final result
	io.WriteString(log.Writer(), "\r\033[K")
	if patchSuccess {
		log.Printf("✓ TASK COMPLETED SUCCESSFULLY: %s", fuzzer)
		printCompletionSummary(projectDir, params.TaskDir, povSuccess)
		return nil
	} else {
		log.Printf("✗ TASK FAILED: Could not generate valid patch for %s", fuzzer)
		printCompletionSummary(projectDir, params.TaskDir, povSuccess)
		return ErrPatchNotFound
	}
}

// executePatchingPhase runs patching strategies after POV is found
func executePatchingPhase(ctx context.Context, fuzzer string, params TaskExecutionParams,
	projectDir, fuzzDir, sanitizer string, deadlineTime time.Time) bool {

	_, patchSpan := telemetry.StartSpan(ctx, "patching_phase")
	patchSpan.SetAttributes(attribute.String("crs.action.category", "patch_generation"))
	patchSpan.SetAttributes(attribute.String("crs.action.name", "runPatchingStrategies"))
	for key, value := range params.TaskDetail.Metadata {
		patchSpan.SetAttributes(attribute.String(key, value))
	}
	defer patchSpan.End()

	var patchSuccess bool
	advancedMetadataPath := filepath.Join(fuzzDir, params.POVAdvancedMetadataDir)

	if _, err := os.Stat(advancedMetadataPath); err == nil {
		log.Printf("Using advanced POV metadata for patching: %s", params.POVAdvancedMetadataDir)
		patchWorkDir := path.Join(params.TaskDir, "patch_workspace")
		patchSuccess = runPatchingStrategies(fuzzer, params.TaskDir, projectDir, sanitizer,
			params.ProjectConfig.Language, params.POVAdvancedMetadataDir, params.TaskDetail,
			params.Task, deadlineTime, patchWorkDir, params.Model, params.SubmissionEndpoint,
			params.WorkerIndex, params.AnalysisServiceUrl, params.UnharnessedFuzzerSrcPath)
	} else {
		log.Printf("Using basic POV metadata for patching: %s", params.POVMetadataDir)
		patchWorkDir := path.Join(params.TaskDir, "patch_workspace")
		patchSuccess = runPatchingStrategies(fuzzer, params.TaskDir, projectDir, sanitizer,
			params.ProjectConfig.Language, params.POVMetadataDir, params.TaskDetail,
			params.Task, deadlineTime, patchWorkDir, params.Model, params.SubmissionEndpoint,
			params.WorkerIndex, params.AnalysisServiceUrl, params.UnharnessedFuzzerSrcPath)
	}

	patchSpan.SetAttributes(attribute.Bool("crs.patch.success", patchSuccess))
	return patchSuccess
}

// executeXPatchPhase runs XPatch strategies when halftime is reached without POV
func executeXPatchPhase(fuzzer string, params TaskExecutionParams, projectDir, sanitizer string,
	deadlineTime time.Time) bool {

	if fuzzer == UNHARNESSED {
		log.Printf("Skipping XPatch for unharnessed fuzzer")
		return false
	}

	pov_count, patch_count, err := getPOVStatsFromSubmissionService(
		params.TaskDetail.TaskID.String(), params.SubmissionEndpoint)
	if err != nil {
		log.Printf("Error checking POV stats: %v", err)
		return false
	}

	if pov_count > 0 && patch_count > 0 {
		log.Printf("POVs and patches already exist (pov=%d, patch=%d), skipping XPatch", pov_count, patch_count)
		return false
	}

	log.Printf("No sufficient patches found (pov=%d, patch=%d), running XPatch...", pov_count, patch_count)
	patchWorkDir := path.Join(params.TaskDir, "patch_workspace")
	patchSuccess := runXPatchingStrategiesWithoutPOV(fuzzer, params.TaskDir, projectDir, sanitizer,
		params.ProjectConfig.Language, params.TaskDetail, params.Task, deadlineTime, patchWorkDir,
		params.Model, params.SubmissionEndpoint, params.WorkerIndex, params.AnalysisServiceUrl)

	// If XPatch failed and harnesses are included, try SARIF-based XPatch
	if !patchSuccess && params.TaskDetail.HarnessesIncluded {
		sarifDir := path.Join(params.TaskDir, "sarif_broadcasts")
		if helpers.DirExists(sarifDir) {
			log.Printf("Attempting SARIF-based XPatch...")
			sarifFiles, err := filepath.Glob(filepath.Join(sarifDir, "*.json"))
			if err != nil {
				log.Printf("Error finding SARIF files: %v", err)
			}
			for _, sarifPath := range sarifFiles {
				if runXPatchSarifStrategies(fuzzer, params.TaskDir, sarifPath,
					params.ProjectConfig.Language, params.TaskDetail, deadlineTime, patchWorkDir,
					params.Model, params.SubmissionEndpoint, params.WorkerIndex, params.AnalysisServiceUrl) {
					patchSuccess = true
					break
				}
			}
		}
	}

	// Create sentinel file to indicate XPatch completion
	fuzzerName := filepath.Base(fuzzer)
	sentinelFile := path.Join(params.TaskDir, "xpatch-"+fuzzerName)
	if err := os.WriteFile(sentinelFile, []byte(fmt.Sprintf("success=%v\n", patchSuccess)), 0644); err != nil {
		log.Printf("Failed to create sentinel file %s: %v", sentinelFile, err)
	} else {
		log.Printf("XPatch completed (success=%v), created sentinel: %s", patchSuccess, sentinelFile)
	}

	return patchSuccess
}

// printCompletionSummary prints a formatted summary box with paths and results
func printCompletionSummary(projectDir, taskDir string, povFound bool) {
	// Extract workspace name
	workspaceName := filepath.Base(strings.TrimRight(projectDir, "/"))

	// Determine paths
	workspaceParent := filepath.Dir(strings.TrimRight(projectDir, "/"))
	mainDir := filepath.Dir(workspaceParent)
	povDir := filepath.Join(mainDir, "pov", workspaceName)
	patchDir := filepath.Join(mainDir, "patch", workspaceName)
	logPath := filepath.Join(taskDir, "task.log")

	// Check if POV directory exists and count POVs
	povCount := 0
	if entries, err := os.ReadDir(povDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "pov_") {
				povCount++
			}
		}
	}

	// Check if Patch directory exists and count patches
	patchCount := 0
	if entries, err := os.ReadDir(patchDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "patch_") {
				patchCount++
			}
		}
	}

	log.Println("")
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║                    TASK COMPLETION SUMMARY                     ║")
	log.Println("╠════════════════════════════════════════════════════════════════╣")

	status := "SUCCESS ✓"
	if !povFound {
		status = "NO POV FOUND ✗"
	}
	log.Printf("║ Status: %s", status)

	if povFound && povCount > 0 {
		log.Printf("║ POVs Found: %d", povCount)
	}

	if patchCount > 0 {
		log.Printf("║ Patches Found: %d", patchCount)
	}

	log.Println("╠════════════════════════════════════════════════════════════════╣")
	log.Println("║ Paths:")
	log.Printf("║   Workspace:  %s", projectDir)
	log.Printf("║   Log:        %s", logPath)

	if povFound && povCount > 0 {
		log.Printf("║   POVs:       %s", povDir)
	}

	if patchCount > 0 {
		log.Printf("║   Patches:    %s", patchDir)
	}

	log.Println("╚════════════════════════════════════════════════════════════════╝")
	log.Println("")
}

