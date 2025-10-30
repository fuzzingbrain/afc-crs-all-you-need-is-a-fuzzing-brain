package executor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"crs/internal/models"
	"crs/internal/telemetry"

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
			params.SubmissionEndpoint)

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
				phase, roundNum, params.SubmissionEndpoint)

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

// Placeholder strategy functions - to be moved from crs_services.go

func runBasicStrategies(fuzzer, taskDir, projectDir, fuzzDir, language string,
	taskDetail models.TaskDetail, task models.Task, submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go runStrategies()
	log.Printf("TODO: runBasicStrategies not yet implemented in executor package")
	return false
}

func runLibFuzzer(fuzzer, taskDir, projectDir, language string,
	taskDetail models.TaskDetail, task models.Task, submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go
	log.Printf("TODO: runLibFuzzer not yet implemented in executor package")
	return false
}

func runAdvancedPOVStrategiesWithTimeout(fuzzer, taskDir, projectDir, language string,
	taskDetail models.TaskDetail, task models.Task, timeout, phase, roundNum int,
	submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go
	log.Printf("TODO: runAdvancedPOVStrategiesWithTimeout not yet implemented in executor package")
	return false
}
