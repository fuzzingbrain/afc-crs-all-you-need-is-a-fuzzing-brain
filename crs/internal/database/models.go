package database

import (
	"time"

	"github.com/google/uuid"
)

// DBTask represents a task record in the database
type DBTask struct {
	TaskID                uuid.UUID         `db:"task_id"`
	TaskType              string            `db:"task_type"`
	ProjectName           string            `db:"project_name"`
	Focus                 string            `db:"focus"`
	Language              string            `db:"language"`
	Sanitizer             string            `db:"sanitizer"`
	FuzzerName            string            `db:"fuzzer_name"`
	FuzzerPath            string            `db:"fuzzer_path"`
	CreatedAt             time.Time         `db:"created_at"`
	UpdatedAt             time.Time         `db:"updated_at"`
	Deadline              time.Time         `db:"deadline"`
	Status                string            `db:"status"`
	NumReachableFunctions int               `db:"num_reachable_functions"`
	NumSuspiciousPoints   int               `db:"num_suspicious_points"`
	NumAnalyzedPoints     int               `db:"num_analyzed_points"`
	NumPOVsFound          int               `db:"num_povs_found"`
	Metadata              map[string]string `db:"metadata"`
}

// SuspiciousPoint represents a suspicious point in the code
type SuspiciousPoint struct {
	ID             int               `db:"id"`
	TaskID         uuid.UUID         `db:"task_id"`
	FunctionName   string            `db:"function_name"`
	FunctionBody   string            `db:"function_body"`
	FilePath       string            `db:"file_path"`
	CallPath       []string          `db:"call_path"`
	VulnType       string            `db:"vuln_type"`
	Location       string            `db:"location"`
	Reason         string            `db:"reason"`
	Severity       string            `db:"severity"`
	CWE            string            `db:"cwe"`
	AttackVector   string            `db:"attack_vector"`
	Analysis       string            `db:"analysis"`
	NumAnalyzed    int               `db:"num_analyzed"`
	IsPOVFound     bool              `db:"is_pov_found"`
	IsTruePositive *bool             `db:"is_true_positive"`
	PriorityScore  float64           `db:"priority_score"`
	CreatedAt      time.Time         `db:"created_at"`
	LastAnalyzedAt *time.Time        `db:"last_analyzed_at"`
	POVFoundAt     *time.Time        `db:"pov_found_at"`
	Metadata       map[string]string `db:"metadata"`
}

// POVResult represents a POV generation result
type POVResult struct {
	ID                  int               `db:"id"`
	TaskID              uuid.UUID         `db:"task_id"`
	SuspiciousPointID   *int              `db:"suspicious_point_id"`
	POVID               string            `db:"pov_id"`
	Signature           string            `db:"signature"`
	BlobFilePath        string            `db:"blob_file_path"`
	FuzzerOutputPath    string            `db:"fuzzer_output_path"`
	PythonCode          string            `db:"python_code"`
	StrategyName        string            `db:"strategy_name"`
	ModelName           string            `db:"model_name"`
	Iteration           int               `db:"iteration"`
	CreatedAt           time.Time         `db:"created_at"`
	Metadata            map[string]string `db:"metadata"`
}

// AnalysisAttempt represents an attempt to analyze a suspicious point
type AnalysisAttempt struct {
	ID                     int               `db:"id"`
	SuspiciousPointID      int               `db:"suspicious_point_id"`
	TaskID                 uuid.UUID         `db:"task_id"`
	AttemptNumber          int               `db:"attempt_number"`
	StrategyName           string            `db:"strategy_name"`
	ModelName              string            `db:"model_name"`
	ReachabilityVerified   bool              `db:"reachability_verified"`
	ExploitationAttempted  bool              `db:"exploitation_attempted"`
	POVFound               bool              `db:"pov_found"`
	StartedAt              time.Time         `db:"started_at"`
	CompletedAt            *time.Time        `db:"completed_at"`
	ErrorMessage           string            `db:"error_message"`
	Notes                  string            `db:"notes"`
	Metadata               map[string]string `db:"metadata"`
}
