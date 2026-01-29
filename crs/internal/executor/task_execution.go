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
	"crs/internal/utils/environment"
	"crs/internal/utils/helpers"

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

	// Determine parallelism level
	maxParallel := 1 // Default to sequential
	if params.FuzzerConfig != nil && params.FuzzerConfig.MaxParallelFuzzers > 0 {
		maxParallel = params.FuzzerConfig.MaxParallelFuzzers
	}

	// Log execution mode
	log.Printf("===========================================")
	if maxParallel == 1 {
		log.Printf("Executing %d fuzzer(s) sequentially", len(fuzzersToExecute))
	} else {
		log.Printf("Executing %d fuzzer(s) with max %d parallel", len(fuzzersToExecute), maxParallel)
	}
	log.Printf("TaskID: %s", params.TaskDetail.TaskID)
	log.Printf("ProjectName: %s", params.TaskDetail.ProjectName)
	log.Printf("===========================================")

	// Shared state for tracking results
	var resultsMu sync.Mutex
	var lastErr error
	successCount := 0

	// Semaphore channel to limit parallelism
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	if len(fuzzersToExecute) > 0 {
		fuzzDir := filepath.Dir(fuzzersToExecute[0])
		// Create a copy of fuzzDir for parallel strategies
		err := helpers.CopyFuzzDirForParallelStrategies(fuzzDir)
		if err != nil {
			log.Printf("Failed to copy fuzzDir %s for parallel strategies. Error: %v", fuzzDir, err)
		} else {
			log.Printf("Prepared fuzzer directory for execution: %v", fuzzDir)
		}
	}

	// Check if we should run ONLY the security analyzer (for testing)
	securityAnalyzerOnly := os.Getenv("SECURITY_ANALYZER_ONLY") != ""

	// Run Security Analyzer (Claude Agent) ONCE for all fuzzers
	// This runs in the background and uses all available fuzzers for verification
	runSecurityAnalyzer := func() {
		// Check if security analyzer is enabled (can be disabled via environment)
		if os.Getenv("DISABLE_SECURITY_ANALYZER") != "" {
			log.Printf("Security analyzer disabled via DISABLE_SECURITY_ANALYZER")
			return
		}

		// Create output directory for security findings
		securityOutputDir := filepath.Join(absTaskDir, "security_findings")

		// Look for static analysis results
		staticAnalysisPath := ""
		possibleStaticPaths := []string{
			filepath.Join(absTaskDir, "static_analysis.json"),
			filepath.Join(absTaskDir, "static_analysis", "results.json"),
		}
		for _, p := range possibleStaticPaths {
			if _, err := os.Stat(p); err == nil {
				staticAnalysisPath = p
				break
			}
		}

		// Determine sanitizer and fuzz directory from first fuzzer path
		sanitizer := params.Sanitizer
		fuzzDir := ""
		workDir := ""
		if len(fuzzersToExecute) > 0 {
			fuzzDir = filepath.Dir(fuzzersToExecute[0])
			baseName := filepath.Base(fuzzDir)
			parts := strings.Split(baseName, "-")
			if sanitizer == "" && len(parts) > 1 {
				sanitizer = parts[len(parts)-1]
			}
			// Work dir is typically at build/work/<project>-<sanitizer>
			workDir = filepath.Join(filepath.Dir(filepath.Dir(fuzzDir)), "work", baseName)
		}
		if sanitizer == "" {
			sanitizer = "address"
		}

		// Construct Docker image name from project name
		projectName := params.TaskDetail.ProjectName
		dockerImage := fmt.Sprintf("gcr.io/oss-fuzz/%s:latest", projectName)

		// Get strategy directory for Phase 4
		strategyDir := ""
		if params.StrategyConfig != nil {
			strategyDir = params.StrategyConfig.GetStrategyDir()
		}

		// Get language from project config
		language := "c"
		if params.ProjectConfig != nil && params.ProjectConfig.Language != "" {
			language = strings.ToLower(params.ProjectConfig.Language)
		}

		// Run the security analyzer with ALL fuzzers
		analyzerConfig := SecurityAnalyzerConfig{
			FuzzerPaths:        fuzzersToExecute,
			RepoPath:           projectDir,
			Sanitizer:          sanitizer,
			OutputDir:          securityOutputDir,
			StaticAnalysisPath: staticAnalysisPath,
			MaxTurns:           50,
			TimeoutMinutes:     45, // 45-min limit for security analysis
			ProjectName:        projectName,
			DockerImage:        dockerImage,
			FuzzDir:            fuzzDir,
			WorkDir:            workDir,
			// Phase 4 (Security Findings POV) settings
			Focus:              params.TaskDetail.Focus,
			Language:           language,
			Model:              params.Model,
			POVMetadataDir:     params.POVMetadataDir,
			SubmissionEndpoint: params.SubmissionEndpoint,
			TaskID:             params.TaskDetail.TaskID.String(),
			WorkerIndex:        params.WorkerIndex,
			AnalysisServiceUrl: params.AnalysisServiceUrl,
			StrategyDir:        strategyDir,
			TaskDir:            absTaskDir,
		}

		findings, err := RunSecurityAnalyzer(analyzerConfig)
		if err != nil {
			log.Printf("Security analyzer error: %v", err)
			return
		}

		if len(findings) > 0 {
			log.Printf("Security analyzer verified %d vulnerabilities across all fuzzers!", len(findings))
		}
	}

	securityAnalyzerOnly = true
	// Either run security analyzer only (for testing) or in background (normal mode)
	if securityAnalyzerOnly {
		log.Printf("===========================================")
		log.Printf("SECURITY_ANALYZER_ONLY mode: Running security analyzer synchronously")
		log.Printf("===========================================")
		runSecurityAnalyzer()
		log.Printf("===========================================")
		log.Printf("Security analyzer completed. Skipping fuzzer execution.")
		log.Printf("===========================================")
		return nil
	}

	// Normal mode: run in background
	go runSecurityAnalyzer()

	// Execute fuzzers with controlled parallelism
	for idx, fuzzer := range fuzzersToExecute {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(idx int, fuzzer string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			log.Printf("")
			log.Printf("╔════════════════════════════════════════════════════════════════╗")
			log.Printf("║  Fuzzer %d/%d: %s", idx+1, len(fuzzersToExecute), filepath.Base(fuzzer))
			log.Printf("╚════════════════════════════════════════════════════════════════╝")

			// Set a fresh deadline for this fuzzer based on per-fuzzer timeout
			timeoutMinutes := 60 // Default 1 hour
			if params.FuzzerConfig != nil && params.FuzzerConfig.PerFuzzerTimeoutMinutes > 0 {
				timeoutMinutes = params.FuzzerConfig.PerFuzzerTimeoutMinutes
			}

			// Create a copy of params for this goroutine
			fuzzerParams := params

			// Create a new deadline for this specific fuzzer
			newDeadline := time.Now().Add(time.Duration(timeoutMinutes) * time.Minute)
			fuzzerParams.TaskDetail.Deadline = newDeadline.Unix() * 1000

			log.Printf("Fuzzer timeout: %d minutes (deadline: %s)",
				timeoutMinutes, newDeadline.Format("15:04:05"))

			fuzzDir := filepath.Dir(fuzzer)

			// Save task detail to JSON for strategy scripts
			// helpers.SaveTaskDetailToJson(fuzzerParams.TaskDetail, fuzzer, fuzzDir)

			// Determine sanitizer from params or extract from fuzzer directory name
			sanitizer := fuzzerParams.Sanitizer
			if sanitizer == "" {
				// Fallback: Extract sanitizer from directory name (e.g., "bind9-address" -> "address")
				baseName := filepath.Base(fuzzDir)
				parts := strings.Split(baseName, "-")
				if len(parts) > 1 {
					sanitizer = parts[len(parts)-1]
					log.Printf("Extracted sanitizer from directory name: %s", sanitizer)
				} else {
					// Use configured preferred sanitizer as last resort
					if fuzzerParams.FuzzerConfig != nil {
						sanitizer = fuzzerParams.FuzzerConfig.PreferredSanitizer
					} else {
						sanitizer = "address"
					}
					log.Printf("Using default sanitizer: %s", sanitizer)
				}
			}

			// Execute the fuzzing workflow for this fuzzer
			err = executeFuzzingWorkflow(fuzzer, fuzzerParams, projectDir, fuzzDir, sanitizer)

			// Update shared state with mutex
			resultsMu.Lock()
			if err != nil {
				log.Printf("✗ Fuzzer %d/%d failed: %v", idx+1, len(fuzzersToExecute), err)
				lastErr = err
			} else {
				log.Printf("✓ Fuzzer %d/%d completed successfully", idx+1, len(fuzzersToExecute))
				successCount++
			}
			resultsMu.Unlock()
		}(idx, fuzzer)
	}

	// Wait for all fuzzers to complete
	wg.Wait()

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
	// libFuzzerStarted := false
	// lang := strings.ToLower(params.ProjectConfig.Language)
	// if lang == "c" || lang == "c++" {
	// 	libFuzzerStarted = true
	// 	go func() {
	// 		runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
	// 			params.TaskDetail, params.Task, params.SubmissionEndpoint)
	// 	}()
	// 	log.Printf("Started LibFuzzer for C/C++ project")
	// }
	runBasicPOVFirst := false
	if runBasicPOVFirst {
		// Phase 2: Run Strategies (Branch based on task type)
		// Check if this is a full scan task or delta scan task
		if params.TaskDetail.Type == models.TaskTypeFull {

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

		} else {

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
				// runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
				// 	params.TaskDetail, params.Task, params.SubmissionEndpoint)
				// os.Exit(0)
			}
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
			// if !libFuzzerStarted {
			// 	go func() {
			// 		runLibFuzzer(fuzzer, params.TaskDir, projectDir, params.ProjectConfig.Language,
			// 			params.TaskDetail, params.Task, params.SubmissionEndpoint)
			// 	}()
			// 	log.Printf("Started LibFuzzer for non-C/C++ project")
			// }
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

	// Check if XPatch is disabled
	xpatchDisabled := strings.ToLower(params.StrategyConfig.Patch.SelectedXPatchStrategy) == "none"
	if xpatchDisabled {
		log.Println("========== XPatch disabled, waiting for POV until deadline ==========")
	}

	select {
	case <-genericPovChan:
		log.Println("========== POV FOUND: Proceeding to patching ==========")
		patchSuccess = executePatchingPhase(ctx, fuzzer, params, projectDir, fuzzDir, sanitizer, deadlineTime)

	case <-time.After(time.Until(halfTimeToDeadline)):
		if xpatchDisabled {
			// XPatch is disabled, continue waiting for POV until deadline
			log.Println("========== HALFTIME REACHED: XPatch disabled, continuing to wait for POV ==========")
			select {
			case <-genericPovChan:
				log.Println("========== POV FOUND: Proceeding to patching ==========")
				patchSuccess = executePatchingPhase(ctx, fuzzer, params, projectDir, fuzzDir, sanitizer, deadlineTime)
			case <-time.After(time.Until(deadlineTime)):
				log.Println("========== DEADLINE REACHED: No POV found ==========")
				return ErrPOVNotFound
			}
		} else {
			log.Println("========== HALFTIME REACHED: Attempting XPatch without POV ==========")
			patchSuccess = executeXPatchPhase(fuzzer, params, projectDir, sanitizer, deadlineTime)
		}

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

	return patchSuccess
}

// executeXPatchPhase runs XPatch strategies when halftime is reached without POV
func executeXPatchPhase(fuzzer string, params TaskExecutionParams, projectDir, sanitizer string,
	deadlineTime time.Time) bool {

	if fuzzer == UNHARNESSED {
		log.Printf("Skipping XPatch for unharnessed fuzzer")
		return false
	}

	// Check if XPatch is disabled via configuration
	if strings.ToLower(params.StrategyConfig.Patch.SelectedXPatchStrategy) == "none" {
		log.Printf("XPatch disabled via STRATEGY_XPATCH_SELECTED=none, skipping XPatch phase")
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
				if runXPatchSarifStrategies(fuzzer, params.TaskDir, projectDir, sarifPath,
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

