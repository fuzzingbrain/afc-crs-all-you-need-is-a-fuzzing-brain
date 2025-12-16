package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"crs/internal/config"
	"crs/internal/models"
	"crs/internal/telemetry"
	"crs/internal/utils/helpers"

	"go.opentelemetry.io/otel/attribute"
)

// runAdvancedPOVPhases runs multiple rounds of advanced POV generation strategies
func runAdvancedPOVPhases(
	ctx context.Context,
	fuzzer string,
	params TaskExecutionParams,
	fuzzDir string,
	workflowStartTime time.Time,
	deadlineTime time.Time,
	totalLibfuzzingTime time.Duration,
	workingBudgetMinutes int,
	povFound *sync.Once,
	povChan chan struct{},
	povSuccess *bool,
) {
	log.Printf("========== ADVANCED POV PHASES: Starting iterative POV generation ==========")

	ctx, advancedPhasesSpan := telemetry.StartSpan(ctx, "advanced_pov_phases")
	advancedPhasesSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
	advancedPhasesSpan.SetAttributes(attribute.String("crs.action.name", "runAdvancedPOVPhases"))
	for key, value := range params.TaskDetail.Metadata {
		advancedPhasesSpan.SetAttributes(attribute.String(key, value))
	}
	defer advancedPhasesSpan.End()

	log.Printf("Time budget: total=%d min, working=%d min",
		workingBudgetMinutes+SafetyBufferMinutes, workingBudgetMinutes)

	advancedPhasesSpan.SetAttributes(attribute.Float64("crs.budget.total_hours", float64(workingBudgetMinutes+SafetyBufferMinutes)/60.0))
	advancedPhasesSpan.SetAttributes(attribute.Float64("crs.budget.working_hours", float64(workingBudgetMinutes)/60.0))

	// Calculate POV budget (80% of working time)
	initialPovBudgetMinutes := int(float64(workingBudgetMinutes) * 0.8)
	if initialPovBudgetMinutes < 1 {
		initialPovBudgetMinutes = 1
	}
	log.Printf("POV generation budget: %d minutes", initialPovBudgetMinutes)
	initialPovBudgetDuration := time.Duration(initialPovBudgetMinutes) * time.Minute

	numPhases := 4
	roundNum := 0
	var totalPovTimeSpent time.Duration
	sequentialTestRun := false // Set to true for sequential execution (for debugging)

	// Loop until POV is found or deadline approaches
	for {
		roundNum++
		log.Printf("---------- Starting POV Generation Round %d ----------", roundNum)

		// Check exit conditions before starting a new round
		select {
		case <-povChan:
			log.Printf("POV signal received before round %d, exiting advanced phases.", roundNum)
			return
		default:
		}

		// Check deadline - leave buffer time
		currentTime := time.Now()
		if currentTime.After(deadlineTime.Add(-time.Duration(SafetyBufferMinutes) * time.Minute)) {
			log.Printf("Deadline approaching before round %d, exiting advanced phases.", roundNum)
			return
		}

		// Check remaining POV budget
		remainingPovBudgetDuration := initialPovBudgetDuration - totalPovTimeSpent
		if remainingPovBudgetDuration <= 0 {
			log.Printf("POV budget exhausted (spent: %v), exiting advanced phases.", totalPovTimeSpent)
			return
		}

		// Determine timeout for this round
		absoluteRemainingTime := deadlineTime.Sub(currentTime)
		effectiveRemainingTime := absoluteRemainingTime - time.Duration(SafetyBufferMinutes)*time.Minute

		roundTimeoutDuration := remainingPovBudgetDuration
		if effectiveRemainingTime < roundTimeoutDuration {
			log.Printf("Round %d timeout capped by deadline: %v (was %v)", roundNum, effectiveRemainingTime, roundTimeoutDuration)
			roundTimeoutDuration = effectiveRemainingTime
		}

		if roundTimeoutDuration <= 0 {
			log.Printf("Insufficient time for round %d (%v), exiting.", roundNum, roundTimeoutDuration)
			return
		}

		roundTimeoutMinutes := int(roundTimeoutDuration.Minutes())
		if roundTimeoutMinutes < 1 {
			roundTimeoutMinutes = 1
		}
		if roundTimeoutMinutes > 60 {
			roundTimeoutMinutes = 60
		}

		log.Printf("Round %d timeout: %d minutes", roundNum, roundTimeoutMinutes)

		roundStartTime := time.Now()
		povFoundInRound := false

		if sequentialTestRun {
			// Sequential execution mode
			povFoundInRound = runPOVPhasesSequential(ctx, fuzzer, params, roundNum,
				roundTimeoutMinutes, deadlineTime, povFound, povChan, povSuccess)
		} else {
			// Parallel execution mode
			povFoundInRound = runPOVPhasesParallel(ctx, fuzzer, params, roundNum, numPhases,
				roundTimeoutMinutes, deadlineTime, povFound, povChan, povSuccess)
		}

		roundDuration := time.Since(roundStartTime)
		totalPovTimeSpent += roundDuration
		log.Printf("Round %d completed in %v (total spent: %v)", roundNum, roundDuration, totalPovTimeSpent)

		if povFoundInRound {
			log.Printf("POV found in round %d, exiting advanced phases.", roundNum)
			break
		}

		// Check if other fuzzers have found POVs - early exit optimization
		workflowDuration := time.Since(workflowStartTime)
		pov_count, patch_count, err := getPOVStatsFromSubmissionService(
			params.TaskDetail.TaskID.String(), params.SubmissionEndpoint)
		if err != nil {
			log.Printf("Error checking POV stats: %v", err)
		} else if pov_count > 0 && workflowDuration > 45*time.Minute {
			log.Printf("Other fuzzers found POVs and workflow running >45min. Stopping. (pov=%d, patch=%d, duration=%v)",
				pov_count, patch_count, workflowDuration)
			break
		} else if workflowDuration > totalLibfuzzingTime || workflowDuration > 60*time.Minute {
			log.Printf("Halftime or 1h passed (duration=%v). Stopping POV generation. (pov=%d, patch=%d)",
				workflowDuration, pov_count, patch_count)
			break
		} else if pov_count > 0 {
			log.Printf("POVs exist but workflow only %v (<1h), continuing. (pov=%d, patch=%d)",
				workflowDuration, pov_count, patch_count)
		} else {
			log.Printf("No POVs yet, continuing to next round (duration=%v)", workflowDuration)
		}
	}

	log.Printf("========== Advanced POV phases completed ==========")
}

// runPOVPhasesSequential runs POV phases sequentially with increasing timeouts
func runPOVPhasesSequential(ctx context.Context, fuzzer string, params TaskExecutionParams,
	roundNum, roundTimeoutMinutes int, deadlineTime time.Time,
	povFound *sync.Once, povChan chan struct{}, povSuccess *bool) bool {

	log.Printf("Running sequential phases for round %d", roundNum)
	phaseRatios := []float64{0.1, 0.2, 0.2, 0.5}
	phaseTimeouts := make([]int, len(phaseRatios))
	for i, ratio := range phaseRatios {
		phaseTimeouts[i] = int(float64(roundTimeoutMinutes) * ratio)
		if phaseTimeouts[i] < 1 {
			phaseTimeouts[i] = 1
		}
	}

	projectDir := params.TaskDir + "/" + params.TaskDetail.Focus

	for phase, timeout := range phaseTimeouts {
		if time.Now().After(deadlineTime.Add(-time.Duration(SafetyBufferMinutes) * time.Minute)) {
			log.Printf("Deadline approaching during phase %d of round %d", phase+1, roundNum)
			return false
		}

		log.Printf("Phase %d/%d (timeout=%d min)", phase+1, len(phaseTimeouts), timeout)
		_, phaseSpan := telemetry.StartSpan(ctx, fmt.Sprintf("pov_round%d_phase%d", roundNum, phase+1))
		phaseSpan.SetAttributes(attribute.String("crs.action.category", "input_generation"))
		phaseSpan.SetAttributes(attribute.String("crs.action.name", fmt.Sprintf("runPOVPhase%d", phase)))
		phaseSpan.SetAttributes(attribute.Int("crs.phase.number", phase))
		phaseSpan.SetAttributes(attribute.Int("crs.round.number", roundNum))
		phaseSpan.SetAttributes(attribute.Int("crs.phase.timeout_minutes", timeout))
		for key, value := range params.TaskDetail.Metadata {
			phaseSpan.SetAttributes(attribute.String(key, value))
		}

		success := runAdvancedPOVStrategiesWithTimeout(fuzzer, params.TaskDir, projectDir,
			params.ProjectConfig.Language, params.TaskDetail, params.Task, timeout, phase, roundNum,
			params.Model, params.POVAdvancedMetadataDir, params.SubmissionEndpoint,
			params.WorkerIndex, params.AnalysisServiceUrl, params.UnharnessedFuzzerSrcPath,
			params.StrategyConfig)

		phaseSpan.SetAttributes(attribute.Bool("crs.phase.pov_success", success))
		phaseSpan.End()

		if success {
			log.Printf("✓ POV found in sequential phase %d of round %d", phase+1, roundNum)
			*povSuccess = true
			povFound.Do(func() { close(povChan) })
			return true
		}
		log.Printf("✗ No POV in phase %d of round %d", phase+1, roundNum)
	}
	return false
}

// runPOVPhasesParallel runs POV phases in parallel
func runPOVPhasesParallel(ctx context.Context, fuzzer string, params TaskExecutionParams,
	roundNum, numPhases, roundTimeoutMinutes int, deadlineTime time.Time,
	povFound *sync.Once, povChan chan struct{}, povSuccess *bool) bool {

	log.Printf("Running %d parallel phases for round %d (timeout=%d min/phase)",
		numPhases, roundNum, roundTimeoutMinutes)

	var roundWG sync.WaitGroup
	projectDir := params.TaskDir + "/" + params.TaskDetail.Focus

	for phase := 0; phase < numPhases; phase++ {
		roundWG.Add(1)
		go func(phase int) {
			defer roundWG.Done()

			if time.Now().After(deadlineTime.Add(-time.Duration(SafetyBufferMinutes) * time.Minute)) {
				log.Printf("Deadline approaching, skipping phase %d of round %d", phase+1, roundNum)
				return
			}

			log.Printf("Starting parallel phase %d/%d (timeout=%d min)", phase+1, numPhases, roundTimeoutMinutes)
			_, phaseSpan := telemetry.StartSpan(ctx, fmt.Sprintf("pov_round%d_phase%d", roundNum, phase+1))
			phaseSpan.SetAttributes(attribute.String("crs.action.category", "input_generation"))
			phaseSpan.SetAttributes(attribute.String("crs.action.name", fmt.Sprintf("runPOVPhase%d", phase)))
			phaseSpan.SetAttributes(attribute.Int("crs.phase.number", phase))
			phaseSpan.SetAttributes(attribute.Int("crs.round.number", roundNum))
			phaseSpan.SetAttributes(attribute.Int("crs.phase.timeout_minutes", roundTimeoutMinutes))
			for key, value := range params.TaskDetail.Metadata {
				phaseSpan.SetAttributes(attribute.String(key, value))
			}

			success := runAdvancedPOVStrategiesWithTimeout(fuzzer, params.TaskDir, projectDir,
				params.ProjectConfig.Language, params.TaskDetail, params.Task, roundTimeoutMinutes,
				phase, roundNum, params.Model, params.POVAdvancedMetadataDir, params.SubmissionEndpoint,
				params.WorkerIndex, params.AnalysisServiceUrl, params.UnharnessedFuzzerSrcPath,
				params.StrategyConfig)

			phaseSpan.SetAttributes(attribute.Bool("crs.phase.pov_success", success))
			phaseSpan.End()

			if success {
				log.Printf("✓ POV found in parallel phase %d of round %d", phase+1, roundNum)
				*povSuccess = true
				povFound.Do(func() { close(povChan) })
			} else {
				log.Printf("✗ No POV in parallel phase %d of round %d", phase+1, roundNum)
			}
		}(phase)
	}

	roundWG.Wait()
	log.Printf("All parallel phases for round %d completed", roundNum)

	// Check if POV signal was sent during this round
	select {
	case <-povChan:
		log.Printf("POV signal received after round %d", roundNum)
		return true
	default:
		return false
	}
}

// BasicStrategiesConfig contains configuration for running basic POV strategies
type BasicStrategiesConfig struct {
	Model                    string
	POVMetadataDir           string
	POVMetadataDir0          string
	SubmissionEndpoint       string
	WorkerIndex              string
	AnalysisServiceUrl       string
	UnharnessedFuzzerSrcPath string
	StrategyConfig           *config.StrategyConfig
}

// runBasicStrategies runs basic POV generation strategies in parallel
// This function runs multiple Python strategy files (xs*_delta.py or xs*_full.py) concurrently
// and returns true if any strategy successfully generates a POV
func runBasicStrategies(fuzzer, taskDir, projectDir, fuzzDir, language string,
	taskDetail models.TaskDetail, task models.Task, basicConfig BasicStrategiesConfig) bool {

	// Get strategy configuration
	strategyConfig := basicConfig.StrategyConfig
	if strategyConfig == nil {
		log.Printf("StrategyConfig is nil, using defaults")
		strategyConfig = &config.StrategyConfig{
			BaseDir:        "/app/strategy",
			NewStrategyDir: "jeff",
			POV: config.POVStrategyConfig{
				BasicDeltaPattern:    "xs*_delta_new.py",
				BasicCFullPattern:    "xs*_c_full.py",
				BasicJavaFullPattern: "xs*_java_full.py",
				BasicFullPattern:     "xs*_full.py",
			},
		}
	}

	// Determine strategy directory and pattern
	strategyDir := strategyConfig.GetStrategyDir()
	strategyFilePattern := strategyConfig.GetBasicStrategyPattern(string(taskDetail.Type), language)

	log.Printf("Using strategy directory: %s, pattern: %s", strategyDir, strategyFilePattern)

	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
	if err != nil {
		log.Printf("Failed to find strategy files: %v", err)
		return false
	}

	if len(strategyFiles) == 0 {
		log.Printf("No strategy files found in %s", strategyDir)
		return false
	}

	log.Printf("Found %d strategy files before filtering: %v", len(strategyFiles), strategyFiles)

	// Filter strategies based on configuration
	var filteredStrategies []string
	for _, strategyFile := range strategyFiles {
		strategyName := filepath.Base(strategyFile)
		if strategyConfig.ShouldRunBasicStrategy(strategyName) {
			filteredStrategies = append(filteredStrategies, strategyFile)
		} else {
			log.Printf("Skipping strategy %s (not selected)", strategyName)
		}
	}

	if len(filteredStrategies) == 0 {
		log.Printf("No strategies to run after filtering (selected: %s)", strategyConfig.POV.SelectedBasicStrategy)
		return false
	}

	log.Printf("Running %d filtered strategy files: %v", len(filteredStrategies), filteredStrategies)

	// Create a channel to signal when a POV is found
	povFoundChan := make(chan bool, 1)

	// Create a wait group to wait for all strategies to complete
	var wg sync.WaitGroup

	// Create a context that can be used to cancel all strategies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure we cancel the context when this function returns

	// Run each strategy in parallel
	for _, strategyFile := range filteredStrategies {
		wg.Add(1)

		// Use a goroutine to run each strategy in parallel
		go func(strategyPath string) {
			defer wg.Done()

			strategyName := filepath.Base(strategyPath)
			log.Printf("Running strategy: %s", strategyPath)

			{
				// Create a symbolic link to the .env file in the task directory
				envFilePath := filepath.Join("/app/strategy", ".env")
				targetEnvPath := filepath.Join(taskDir, ".env")

				// Remove existing symlink if it exists
				_ = os.Remove(targetEnvPath)

				// Create the symbolic link
				err = os.Symlink(envFilePath, targetEnvPath)
				if err != nil {
					log.Printf("Warning: Failed to create symlink to .env file: %v", err)
					// Continue execution even if symlink creation fails
				}
			}

			const strategyTimeout = 45 * time.Minute
			strategyCtx, strategyCancel := context.WithTimeout(ctx, strategyTimeout)
			defer strategyCancel()

			// Use the Python interpreter from the virtual environment
			pythonInterpreter := "/tmp/crs_venv/bin/python3"

			// Check if we're running as root or if sudo is available
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()

			// Prepare the arguments for the Python command
			args := []string{
				strategyPath,
				fuzzer,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", basicConfig.Model,
				"--pov-metadata-dir", basicConfig.POVMetadataDir0,
				"--check-patch-success",
			}

			if taskDetail.Type == "full" {
				args = append(args, "--full-scan", "true")
			}
			var runCmd *exec.Cmd

			// print args
			log.Printf("Args: %v", args)

			// Create the appropriate command based on our privileges
			if isRoot {
				// Already running as root, no need for sudo
				runCmd = exec.CommandContext(strategyCtx, pythonInterpreter, args...)
			} else if hasSudo {
				// Not root but sudo is available
				sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
				runCmd = exec.CommandContext(strategyCtx, "sudo", sudoArgs...)
			} else {
				// Neither root nor sudo available, try running directly
				log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
				runCmd = exec.CommandContext(strategyCtx, pythonInterpreter, args...)
			}
			runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			runCmd.Dir = taskDir
			// Set environment variables that would be set by the virtual environment activation
			runCmd.Env = append(os.Environ(),
				"VIRTUAL_ENV=/tmp/crs_venv",
				"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", basicConfig.SubmissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				// Pass through API credentials if they exist
				fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				// Add any other environment variables needed by the Python script
				fmt.Sprintf("WORKER_INDEX=%s", basicConfig.WorkerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", basicConfig.AnalysisServiceUrl),
				"PYTHONUNBUFFERED=1",
			)

			// If we have an unharnessed fuzzer source path, pass it
			if basicConfig.UnharnessedFuzzerSrcPath != "" {
				runCmd.Env = append(runCmd.Env,
					fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", basicConfig.UnharnessedFuzzerSrcPath))
			}

			// Create pipes for stdout and stderr
			stdoutPipe, err := runCmd.StdoutPipe()
			if err != nil {
				log.Printf("Failed to create stdout pipe: %v", err)
				return
			}
			stderrPipe, err := runCmd.StderrPipe()
			if err != nil {
				log.Printf("Failed to create stderr pipe: %v", err)
				return
			}

			// Start the command
			startTime := time.Now()
			if err := runCmd.Start(); err != nil {
				log.Printf("Failed to start strategy %s: %v", strategyName, err)
				return
			}
			// Create a channel to signal when the process is done
			done := make(chan error, 1)
			go func() {
				done <- runCmd.Wait()
			}()

			// Create a ticker to check for POVs periodically
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			// Buffer for output
			var outputBuffer bytes.Buffer

			// Start goroutines to collect output
			go func() {
				scanner := bufio.NewScanner(stdoutPipe)
				for scanner.Scan() {
					raw := scanner.Text()
					// Keep only what would be visible in a terminal (after the last CR)
					text := raw
					if i := strings.LastIndex(raw, "\r"); i >= 0 {
						text = raw[i+1:]
					}
					outputBuffer.WriteString(text + "\n")
					log.Printf("[basic %s stdout] %s", strategyName, text)
				}
			}()

			go func() {
				scanner := bufio.NewScanner(stderrPipe)
				for scanner.Scan() {
					raw := scanner.Text()
					// Keep only what would be visible in a terminal (after the last CR)
					text := raw
					if i := strings.LastIndex(raw, "\r"); i >= 0 {
						text = raw[i+1:]
					}
					outputBuffer.WriteString(text + "\n")
					log.Printf("[basic %s stderr] %s", strategyName, text)
				}
			}()

			// Monitor for POVs and process completion
			povFound := false

			for {
				select {
				case <-ticker.C:
					// Check for successful POVs if we haven't already signaled
					if !povFound {
						povDir := filepath.Join(fuzzDir, basicConfig.POVMetadataDir)
						if _, err := os.Stat(povDir); err == nil {
							// Directory exists, check for files
							files, err := os.ReadDir(povDir)
							if err == nil && len(files) > 0 {
								log.Printf("Strategy %s: Found POV files in %s directory", strategyName, povDir)
								// Signal that a POV was found (only once)
								select {
								case povFoundChan <- true:
									log.Printf("Strategy %s: Signaled POV found", strategyName)
									povFound = true
								default:
									// Channel already has a value, no need to send again
									povFound = true
								}

								// Continue running to generate more POVs
								log.Printf("Strategy %s: Continuing to run for more POVs", strategyName)
							}
						}
					}

				case err := <-done:
					// Process completed
					output := outputBuffer.String()
					if err != nil {
						log.Printf("Strategy %s failed after %v: %v",
							strategyName, time.Since(startTime), err)
					} else {
						log.Printf("Strategy %s completed successfully in %v",
							strategyName, time.Since(startTime))

						// Check output for POV SUCCESS! message as a backup
						if !povFound && strings.Contains(output, "POV SUCCESS!") {
							log.Printf("Strategy %s POV successful!", strategyName)

							// Signal that a POV was found
							select {
							case povFoundChan <- true:
								log.Printf("Strategy %s: Signaled POV found", strategyName)
							default:
								// Channel already has a value, no need to send again
							}
						}
					}
					return

				case <-strategyCtx.Done():
					// Timeout reached or context canceled
					if strategyCtx.Err() == context.DeadlineExceeded {
						log.Printf("Strategy %s timed out (≥%v). Killing process tree.",
							strategyName, strategyTimeout)
					} else {
						log.Printf("Strategy %s canceled after %v.", strategyName, time.Since(startTime))
					}
					if runCmd.Process != nil {
						// Kill entire group: negative PGID
						pgid, _ := syscall.Getpgid(runCmd.Process.Pid)
						syscall.Kill(-pgid, syscall.SIGKILL)
					}
					<-done // ensure Wait() returns
					return
				}
			}
		}(strategyFile)
	}

	// Use a single goroutine to handle the result
	resultChan := make(chan bool, 1)
	go func() {
		// Two possible outcomes:
		// 1. A POV is found by one of the strategies
		// 2. All strategies complete without finding a POV

		// Create a channel to signal when all strategies are done
		allDone := make(chan struct{})
		go func() {
			wg.Wait()
			close(allDone)
		}()

		// Wait for either a POV to be found or all strategies to complete
		select {
		case <-allDone:
			// All strategies completed without finding a POV
			resultChan <- false

		case result := <-povFoundChan:
			// A POV was found
			log.Printf("A POV was found, returning result")
			resultChan <- result

			// Cancel all other running strategies
			cancel()
		}

		// Close the result channel when done
		close(resultChan)
	}()

	// Return the result
	return <-resultChan
}

func runLibFuzzer(fuzzer, taskDir, projectDir, language string,
	taskDetail models.TaskDetail, task models.Task, submissionEndpoint string) error {
	// TODO: This is a highly complex 305-line function from crs_services.go:6685-6990
	// It includes:
	// - Docker container management (docker run --rm with dynamic naming)
	// - Continuous fuzzing loop until deadline
	// - Crash detection and processing (isCrashOutput)
	// - Crash signature generation and deduplication
	// - POV saving (saveAllCrashesAsPOVs)
	// - Crash signature submission (generateCrashSignatureAndSubmit)
	// - Automatic patching attempts with retry logic (300 retries!)
	// - Global deadline management with context cancellation
	// - Real-time POV statistics checking from submission service
	// - Early termination when POV limit reached (LIMIT_POV_NUM = 3)
	// - Telemetry span tracking
	//
	// Critical dependencies that need migration:
	// - isCrashOutput (line 399) - detects if output contains crash signatures
	// - extractCrashOutput (line 6351) - extracts relevant crash info (4KB limit)
	// - generateCrashSignature (line 3790) - generates unique crash signatures
	// - saveAllCrashesAsPOVs (line 3382) - saves crash files as POVs
	// - generateCrashSignatureAndSubmit (line 3563) - submits crash info
	// - getFuzzerArgs (line 7852) - constructs docker run arguments
	// - filterInstrumentedLines (line 6333) - filters output
	//
	// Additional service state dependencies:
	// - s.povMetadataDir (dynamic modification: fmt.Sprintf("%s_%d", s.povMetadataDir, successfulPoVs))
	// - s.status.Processing (to check if multiple workers running)
	//
	// This function is EXTREMELY complex and tightly coupled with service state.
	// Recommend migrating helper functions first, then refactoring this incrementally.
	//
	// For now, returning nil to indicate not implemented
	log.Printf("TODO: runLibFuzzer not yet fully implemented in executor package")
	log.Printf("Function requires migration of 305 lines + 7 helper functions from crs_services.go:6685-6990")
	log.Printf("This is the most complex function in the codebase due to Docker management, crash handling, and retry logic")
	return nil
}

func runAdvancedPOVStrategiesWithTimeout(
	myFuzzer, taskDir, projectDir, language string,
	taskDetail models.TaskDetail,
	fullTask models.Task,
	timeoutMinutes int,
	phase int,
	roundNum int,
	model string,
	povAdvancedMetadataDir string,
	submissionEndpoint string,
	workerIndex string,
	analysisServiceUrl string,
	unharnessedFuzzerSrcPath string,
	strategyConfig *config.StrategyConfig,
) bool {
	// Use default config if not provided
	if strategyConfig == nil {
		log.Printf("StrategyConfig is nil, using defaults")
		strategyConfig = &config.StrategyConfig{
			BaseDir:        "/app/strategy",
			NewStrategyDir: "jeff",
			POV: config.POVStrategyConfig{
				AdvancedDeltaPattern: "as*_delta_new.py",
				AdvancedFullPattern:  "as*_full.py",
			},
		}
	}

	// Determine strategy directory and pattern
	strategyDir := strategyConfig.GetStrategyDir()
	strategyFilePattern := strategyConfig.GetAdvancedStrategyPattern(string(taskDetail.Type))

	log.Printf("Using advanced strategy directory: %s, pattern: %s", strategyDir, strategyFilePattern)

	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
	if err != nil {
		log.Printf("Failed to find strategy files: %v", err)
		return false
	}

	if len(strategyFiles) == 0 {
		log.Printf("No strategy files found in %s", strategyDir)
		return false
	}

	log.Printf("Found %d advanced strategy files before filtering: %v", len(strategyFiles), strategyFiles)

	// Filter strategies based on configuration
	var filteredStrategies []string
	for _, strategyFile := range strategyFiles {
		strategyName := filepath.Base(strategyFile)
		if strategyConfig.ShouldRunAdvancedStrategy(strategyName) {
			filteredStrategies = append(filteredStrategies, strategyFile)
		} else {
			log.Printf("Skipping advanced strategy %s (not selected)", strategyName)
		}
	}

	if len(filteredStrategies) == 0 {
		log.Printf("No advanced strategies to run after filtering (selected: %s)", strategyConfig.POV.SelectedAdvancedStrategy)
		return false
	}

	log.Printf("Running %d filtered advanced strategy files: %v", len(filteredStrategies), filteredStrategies)

	povSuccess := false
	var successMutex sync.Mutex
	var wg sync.WaitGroup

	parentCtx := context.Background()

	for _, strategyFile := range filteredStrategies {
		wg.Add(1)
		go func(strategyPath string) {
			defer wg.Done()
			strategyName := filepath.Base(strategyPath)

			// --- Per-Strategy Timeout Context ---
			strategyTimeout := time.Duration(timeoutMinutes) * time.Minute
			if strategyTimeout <= 0 {
				log.Printf("[POV Round-%d Phase-%d] Invalid timeout %v for %s, skipping", roundNum, phase, strategyTimeout, strategyName)
				return
			}
			strategyCtx, strategyCancel := context.WithTimeout(parentCtx, strategyTimeout)
			defer strategyCancel() // Ensure cleanup
			// --- End Per-Strategy Timeout Context ---

			log.Printf("[POV Round-%d Phase-%d] Running advanced strategy: %s (timeout: %v)", roundNum, phase, strategyName, strategyTimeout)

			pythonInterpreter := "/tmp/crs_venv/bin/python3"
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()

			// --- Calculate Max Iterations ---
			maxIterations := 3
			if timeoutMinutes <= 30 {
				maxIterations = 3
			} else if timeoutMinutes <= 60 {
				maxIterations = 4
			} else {
				maxIterations = 5
			}
			log.Printf("[POV Round-%d Phase-%d] Setting max iterations to %d for timeout %d minutes", roundNum, phase, maxIterations, timeoutMinutes)

			args := []string{
				strategyPath,
				myFuzzer,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", model,
				"--do-patch=false",
				"--pov-metadata-dir", povAdvancedMetadataDir,
				"--check-patch-success",
				fmt.Sprintf("--fuzzing-timeout=%d", timeoutMinutes),
				fmt.Sprintf("--pov-phase=%d", phase),
				fmt.Sprintf("--max-iterations=%d", maxIterations),
			}

			// print args
			log.Printf("[POV Round-%d Phase-%d] Args: %v", roundNum, phase, args)

			if taskDetail.Type == "full" {
				args = append(args, "--full-scan", "true")
			}
			var runCmd *exec.Cmd
			if isRoot {
				runCmd = exec.CommandContext(strategyCtx, pythonInterpreter, args...)
			} else if hasSudo {
				sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
				runCmd = exec.CommandContext(strategyCtx, "sudo", sudoArgs...)
			} else {
				log.Printf("[POV Round-%d Phase-%d] Warning: Not root and no sudo for %s. Trying direct.", roundNum, phase, strategyName)
				runCmd = exec.CommandContext(strategyCtx, pythonInterpreter, args...)
			}

			runCmd.Dir = taskDir

			runCmd.Env = append(os.Environ(),
				"VIRTUAL_ENV=/tmp/crs_venv",
				"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", submissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				fmt.Sprintf("WORKER_INDEX=%s", workerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", analysisServiceUrl),
				"PYTHONUNBUFFERED=1",
			)

			// If we have an unharnessed fuzzer source path, pass it
			if unharnessedFuzzerSrcPath != "" {
				runCmd.Env = append(runCmd.Env,
					fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", unharnessedFuzzerSrcPath))
			}

			// --- Streaming logs setup ---
			stdoutPipe, err := runCmd.StdoutPipe()
			if err != nil {
				log.Printf("Failed to create stdout pipe: %v", err)
				return
			}
			stderrPipe, err := runCmd.StderrPipe()
			if err != nil {
				log.Printf("Failed to create stderr pipe: %v", err)
				return
			}

			startTime := time.Now()
			if err := runCmd.Start(); err != nil {
				log.Printf("[POV Round-%d Phase-%d] Failed to start %s: %v", roundNum, phase, strategyName, err)
				return
			}

			var outputLines []string
			var outputMutex sync.Mutex
			var streamWg sync.WaitGroup // Wait for scanners to finish

			streamWg.Add(2)

			// Stream stdout
			go func() {
				defer streamWg.Done()

				scanner := bufio.NewScanner(stdoutPipe)
				for scanner.Scan() {
					raw := scanner.Text()

					// Handle in-line carriage returns from progress bars, etc.
					for _, part := range strings.Split(raw, "\r") {
						part = helpers.SanitizeTerminalString(part)
						if part == "" {
							continue
						}
						io.WriteString(log.Writer(), "\r\033[K")
						log.Printf("[POV Round-%d][%s Phase-%d] %s", roundNum, strategyName, phase, part)
						outputMutex.Lock()
						outputLines = append(outputLines, part)
						outputMutex.Unlock()
					}
				}
				if err := scanner.Err(); err != nil {
					// Log scanner errors, especially if caused by pipe closing on kill
					if strategyCtx.Err() == nil { // Avoid logging errors if we intentionally killed
						log.Printf("[POV Round-%d Phase-%d] Error scanning stdout for %s: %v", roundNum, phase, strategyName, err)
					}
				}
			}()
			// Stream stderr
			go func() {
				defer streamWg.Done()

				scanner := bufio.NewScanner(stderrPipe)
				for scanner.Scan() {
					raw := scanner.Text()

					// Handle in-line carriage returns from progress bars, etc.
					for _, part := range strings.Split(raw, "\r") {
						part = helpers.SanitizeTerminalString(part)
						if part == "" {
							continue
						}
						io.WriteString(log.Writer(), "\r\033[K")
						log.Printf("[POV Round-%d ERR][%s Phase-%d] %s", roundNum, strategyName, phase, part)
						outputMutex.Lock()
						outputLines = append(outputLines, part)
						outputMutex.Unlock()
					}
				}
				if err := scanner.Err(); err != nil {
					if strategyCtx.Err() == nil {
						log.Printf("[POV Round-%d Phase-%d] Error scanning stderr for %s: %v", roundNum, phase, strategyName, err)
					}
				}
			}()

			// --- Wait for Completion or Timeout ---
			done := make(chan error, 1)
			go func() {
				done <- runCmd.Wait()
			}()

			select {
			case err = <-done:
				// Process finished naturally (or failed)
				streamWg.Wait() // Ensure scanners finish reading before checking output
				duration := time.Since(startTime)
				outputMutex.Lock()
				combinedOutput := strings.Join(outputLines, "\n")
				outputMutex.Unlock()

				if err != nil {
					// Check if the error was due to context cancellation (already logged below)
					exitErr, ok := err.(*exec.ExitError)
					// Don't log error again if killed due to timeout/cancel
					if !(ok && exitErr.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL && strategyCtx.Err() != nil) {
						log.Printf("[POV Round-%d Phase-%d] Strategy %s failed after %v: %v", roundNum, phase, strategyName, duration, err)
					}
				} else {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s completed successfully in %v", roundNum, phase, strategyName, duration)
					successMutex.Lock()
					// Check combined output only on successful exit
					if strings.Contains(combinedOutput, "POV SUCCESS!") || strings.Contains(combinedOutput, "Found successful POV") {
						if !povSuccess { // Check flag before setting
							log.Printf("[POV Round-%d Phase-%d] Strategy %s POV successful!", roundNum, phase, strategyName)
							povSuccess = true
						}
					}
					successMutex.Unlock()
				}

			case <-strategyCtx.Done():
				// Timeout or external cancellation
				streamWg.Wait() // Allow scanners to finish after kill signal
				duration := time.Since(startTime)
				if strategyCtx.Err() == context.DeadlineExceeded {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s timed out after %v. Killing process group.", roundNum, phase, strategyName, duration)
				} else {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s canceled after %v. Killing process group.", roundNum, phase, strategyName, duration)
				}

				// Kill the entire process group
				if runCmd.Process != nil {
					pgid, err := syscall.Getpgid(runCmd.Process.Pid)
					if err == nil {
						errKill := syscall.Kill(-pgid, syscall.SIGKILL) // Kill negative PGID
						if errKill != nil && !strings.Contains(errKill.Error(), "no such process") { // Ignore "no such process" error
							log.Printf("[POV Round-%d Phase-%d] Error killing process group %d for %s: %v", roundNum, phase, -pgid, strategyName, errKill)
						}
					} else if !strings.Contains(err.Error(), "no such process") {
						log.Printf("[POV Round-%d Phase-%d] Error getting PGID for %s (PID %d): %v", roundNum, phase, strategyName, runCmd.Process.Pid, err)
					}
				}
				// Wait for Wait() to return after kill
				<-done
			}
		}(strategyFile)
	}

	wg.Wait()
	// Return the final success state (thread-safe read)
	successMutex.Lock()
	finalSuccess := povSuccess
	successMutex.Unlock()
	return finalSuccess
}
