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
}

// ExecuteFuzzingTask executes a complete fuzzing workflow on a worker node
// This includes: running strategies, POV generation, and patching
func ExecuteFuzzingTask(params TaskExecutionParams) error {
	fuzzer := params.Fuzzer

	// Handle LOCAL_TEST mode
	if os.Getenv("LOCAL_TEST") != "" {
		params.SubmissionEndpoint = "http://localhost:7081"
		fuzzer = params.AllFuzzers[0]
		// Select specific fuzzers for testing
		for _, f := range params.AllFuzzers {
			if strings.HasSuffix(f, "libxml2-address/xml") ||
			   strings.HasSuffix(f, "tika-address/HtmlParserFuzzer") ||
			   strings.HasSuffix(f, "zookeeper-address/MessageTrackerPeekReceivedFuzzer") ||
			   strings.HasSuffix(f, "apache-commons-compress-address/CompressZipFuzzer") ||
			   strings.HasSuffix(f, "sqlite3-address/customfuzz3") ||
			   strings.HasSuffix(f, "igraph-address/read_gml") {
				fuzzer = f
				break
			}
		}
	}

	if fuzzer == "" {
		log.Printf("No fuzzer specified for worker execution, skipping...")
		return nil
	}

	log.Printf("=========================================== Executing Fuzzer Task ===========================================")
	log.Printf("Fuzzer: %s", fuzzer)
	log.Printf("TaskID: %s", params.TaskDetail.TaskID)
	log.Printf("ProjectName: %s", params.TaskDetail.ProjectName)
	log.Printf("=========================================================================================================")

	// Get absolute paths
	absTaskDir, err := filepath.Abs(params.TaskDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute task dir path: %v", err)
	}

	projectDir := path.Join(absTaskDir, params.TaskDetail.Focus)
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

	// Extract sanitizer info (e.g., "address" from "bind9-address")
	baseName := filepath.Base(fuzzDir)
	parts := strings.Split(baseName, "-")
	sanitizer := parts[len(parts)-1]

	// Execute the fuzzing workflow
	return executeFuzzingWorkflow(fuzzer, params, projectDir, fuzzDir, sanitizer)
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

	// Phase 2: Run Basic Strategies
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
		case <-povChan:
			log.Println("========== POV FOUND: Patching disabled, task completed ==========")
			return nil
		case <-time.After(time.Until(deadlineTime)):
			log.Println("========== DEADLINE REACHED: No POV found ==========")
			return ErrPOVNotFound
		}
	}

	select {
	case <-povChan:
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
		return nil
	} else {
		log.Printf("✗ TASK FAILED: Could not generate valid patch for %s", fuzzer)
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

