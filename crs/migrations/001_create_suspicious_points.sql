-- Migration: Create suspicious_points and related tables
-- Purpose: Manage suspicious points across tasks for full scan strategy

-- ============================================================================
-- Table: tasks (extends TaskDetail)
-- ============================================================================
CREATE TABLE IF NOT EXISTS tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    task_type VARCHAR(50) NOT NULL,  -- 'delta' or 'full'
    project_name VARCHAR(255) NOT NULL,
    focus VARCHAR(255) NOT NULL,
    language VARCHAR(50) NOT NULL,

    -- Task metadata
    sanitizer VARCHAR(50),
    fuzzer_name VARCHAR(255),
    fuzzer_path TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deadline TIMESTAMP,

    -- Task status
    status VARCHAR(50) DEFAULT 'pending',  -- pending, running, completed, failed

    -- Full scan specific
    num_reachable_functions INT DEFAULT 0,
    num_suspicious_points INT DEFAULT 0,
    num_analyzed_points INT DEFAULT 0,
    num_povs_found INT DEFAULT 0,

    -- Metadata (JSON)
    metadata JSONB
);

-- Index for querying
CREATE INDEX idx_tasks_type ON tasks(task_type);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_created_at ON tasks(created_at);


-- ============================================================================
-- Table: suspicious_points
-- ============================================================================
CREATE TABLE IF NOT EXISTS suspicious_points (
    -- Primary key
    id SERIAL PRIMARY KEY,

    -- Foreign key to task
    task_id VARCHAR(255) NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,

    -- Function information
    function_name VARCHAR(255) NOT NULL,
    function_body TEXT,
    file_path TEXT,
    call_path TEXT[],  -- Array: ["main", "process", "parse_header"]

    -- Suspicious point details
    vuln_type VARCHAR(100) NOT NULL,        -- buffer_overflow, use_after_free, etc.
    location TEXT NOT NULL,                 -- "line 45: memcpy(buf, data, len)"
    reason TEXT NOT NULL,                   -- Why it's suspicious
    severity VARCHAR(20) NOT NULL,          -- high, medium, low
    cwe VARCHAR(20),                        -- CWE-119, CWE-416, etc.
    attack_vector TEXT,                     -- How to exploit

    -- Analysis from LLM
    analysis TEXT,                          -- LLM's detailed analysis of this point

    -- State tracking
    num_analyzed INT DEFAULT 0,             -- Number of analysis attempts
    is_pov_found BOOLEAN DEFAULT FALSE,     -- Whether POV was found
    is_true_positive BOOLEAN DEFAULT NULL,  -- NULL=unverified, TRUE=true positive, FALSE=false positive

    -- Priority
    priority_score FLOAT DEFAULT 0.5,       -- Priority score for sorting

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_analyzed_at TIMESTAMP,
    pov_found_at TIMESTAMP,

    -- Metadata (JSON for extensibility)
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX idx_suspicious_points_task_id ON suspicious_points(task_id);
CREATE INDEX idx_suspicious_points_vuln_type ON suspicious_points(vuln_type);
CREATE INDEX idx_suspicious_points_severity ON suspicious_points(severity);
CREATE INDEX idx_suspicious_points_num_analyzed ON suspicious_points(num_analyzed);
CREATE INDEX idx_suspicious_points_is_pov_found ON suspicious_points(is_pov_found);
CREATE INDEX idx_suspicious_points_priority ON suspicious_points(priority_score DESC);

-- Composite index for querying unanalyzed points
CREATE INDEX idx_suspicious_points_unanalyzed ON suspicious_points(task_id, num_analyzed, priority_score DESC)
WHERE is_pov_found = FALSE;


-- ============================================================================
-- Table: pov_results
-- ============================================================================
CREATE TABLE IF NOT EXISTS pov_results (
    id SERIAL PRIMARY KEY,

    -- Foreign keys
    task_id VARCHAR(255) NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    suspicious_point_id INT REFERENCES suspicious_points(id) ON DELETE SET NULL,

    -- POV details
    pov_id VARCHAR(100) NOT NULL UNIQUE,
    signature VARCHAR(255),

    -- Files
    blob_file_path TEXT,
    fuzzer_output_path TEXT,
    python_code TEXT,

    -- Strategy info
    strategy_name VARCHAR(50),
    model_name VARCHAR(100),
    iteration INT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    metadata JSONB
);

CREATE INDEX idx_pov_results_task_id ON pov_results(task_id);
CREATE INDEX idx_pov_results_suspicious_point_id ON pov_results(suspicious_point_id);


-- ============================================================================
-- Table: analysis_attempts
-- ============================================================================
CREATE TABLE IF NOT EXISTS analysis_attempts (
    id SERIAL PRIMARY KEY,

    -- Foreign keys
    suspicious_point_id INT NOT NULL REFERENCES suspicious_points(id) ON DELETE CASCADE,
    task_id VARCHAR(255) NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,

    -- Attempt details
    attempt_number INT NOT NULL,  -- Which attempt number
    strategy_name VARCHAR(50),
    model_name VARCHAR(100),

    -- Stage tracking
    reachability_verified BOOLEAN DEFAULT FALSE,
    exploitation_attempted BOOLEAN DEFAULT FALSE,
    pov_found BOOLEAN DEFAULT FALSE,

    -- Timestamps
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,

    -- Results
    error_message TEXT,
    notes TEXT,

    -- Metadata
    metadata JSONB
);

CREATE INDEX idx_analysis_attempts_suspicious_point_id ON analysis_attempts(suspicious_point_id);
CREATE INDEX idx_analysis_attempts_task_id ON analysis_attempts(task_id);


-- ============================================================================
-- Views for convenient querying
-- ============================================================================

-- View: Unanalyzed suspicious points
CREATE OR REPLACE VIEW unanalyzed_suspicious_points AS
SELECT
    sp.*,
    t.project_name,
    t.sanitizer
FROM suspicious_points sp
JOIN tasks t ON sp.task_id = t.task_id
WHERE sp.is_pov_found = FALSE
  AND sp.num_analyzed < 3  -- Max 3 analysis attempts
ORDER BY sp.priority_score DESC, sp.created_at ASC;


-- View: Task summary
CREATE OR REPLACE VIEW task_summary AS
SELECT
    t.task_id,
    t.task_type,
    t.project_name,
    t.status,
    t.num_suspicious_points,
    t.num_analyzed_points,
    t.num_povs_found,
    COUNT(DISTINCT sp.id) AS total_points,
    COUNT(DISTINCT CASE WHEN sp.is_pov_found THEN sp.id END) AS points_with_pov,
    COUNT(DISTINCT pr.id) AS total_povs
FROM tasks t
LEFT JOIN suspicious_points sp ON t.task_id = sp.task_id
LEFT JOIN pov_results pr ON t.task_id = pr.task_id
GROUP BY t.task_id;


-- ============================================================================
-- Functions for updating statistics
-- ============================================================================

-- Function: Update task statistics when suspicious point is updated
CREATE OR REPLACE FUNCTION update_task_statistics()
RETURNS TRIGGER AS $$
BEGIN
    -- Update num_analyzed_points
    UPDATE tasks
    SET
        num_analyzed_points = (
            SELECT COUNT(*)
            FROM suspicious_points
            WHERE task_id = NEW.task_id AND num_analyzed > 0
        ),
        num_povs_found = (
            SELECT COUNT(*)
            FROM suspicious_points
            WHERE task_id = NEW.task_id AND is_pov_found = TRUE
        ),
        updated_at = CURRENT_TIMESTAMP
    WHERE task_id = NEW.task_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Auto-update task statistics
CREATE TRIGGER trigger_update_task_statistics
AFTER UPDATE ON suspicious_points
FOR EACH ROW
WHEN (OLD.num_analyzed IS DISTINCT FROM NEW.num_analyzed
      OR OLD.is_pov_found IS DISTINCT FROM NEW.is_pov_found)
EXECUTE FUNCTION update_task_statistics();


-- ============================================================================
-- Sample queries for common operations
-- ============================================================================

-- Query 1: Get next suspicious point to analyze for a task
/*
SELECT * FROM suspicious_points
WHERE task_id = 'task_123'
  AND is_pov_found = FALSE
  AND num_analyzed < 3
ORDER BY priority_score DESC, num_analyzed ASC
LIMIT 1;
*/

-- Query 2: Get statistics for a task
/*
SELECT * FROM task_summary WHERE task_id = 'task_123';
*/

-- Query 3: Get all POVs for a task
/*
SELECT
    pr.*,
    sp.function_name,
    sp.vuln_type,
    sp.location
FROM pov_results pr
LEFT JOIN suspicious_points sp ON pr.suspicious_point_id = sp.id
WHERE pr.task_id = 'task_123';
*/

-- Query 4: Find high-priority unanalyzed points across all tasks
/*
SELECT * FROM unanalyzed_suspicious_points
WHERE severity = 'high'
LIMIT 10;
*/
