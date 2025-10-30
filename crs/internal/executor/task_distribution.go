package executor

import (
	"log"

	"crs/internal/models"
)

// TaskDistributionParams contains parameters for distributing fuzzing tasks to workers
type TaskDistributionParams struct {
	Fuzzers            []string
	TaskDetail         models.TaskDetail
	Task               models.Task
	SubmissionEndpoint string
	WorkerBasePort     int
	WorkerNodes        int
}

// DistributeFuzzingTasks distributes fuzzing tasks to worker nodes
// This is used by the web service to schedule tasks across workers
func DistributeFuzzingTasks(params TaskDistributionParams) error {
	log.Printf("========== TASK DISTRIBUTION: Scheduling %d fuzzers to workers ==========", len(params.Fuzzers))
	log.Printf("TaskID: %s", params.TaskDetail.TaskID)
	log.Printf("ProjectName: %s", params.TaskDetail.ProjectName)
	log.Printf("Worker nodes: %d (base port: %d)", params.WorkerNodes, params.WorkerBasePort)

	// TODO: Move implementation from crs_services.go distributeFuzzers()
	return distributeFuzzersToWorkers(params.Fuzzers, params.TaskDetail, params.Task,
		params.SubmissionEndpoint, params.WorkerBasePort, params.WorkerNodes)
}

// distributeFuzzersToWorkers is the actual implementation
func distributeFuzzersToWorkers(fuzzers []string, taskDetail models.TaskDetail, task models.Task,
	submissionEndpoint string, workerBasePort, workerNodes int) error {

	// TODO: Move implementation from defaultCRSService.distributeFuzzers()
	log.Printf("TODO: distributeFuzzersToWorkers not yet implemented in executor package")
	log.Printf("Will distribute %d fuzzers to %d workers", len(fuzzers), workerNodes)

	return nil
}
