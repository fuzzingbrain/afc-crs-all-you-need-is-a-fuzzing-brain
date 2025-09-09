package main

import (
	"strings"
	"github.com/joho/godotenv"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
	"github.com/gin-gonic/gin"
	"static-analysis/internal/engine"
	"static-analysis/internal/engine/models"
)

// TaskState represents the current state of a task
type TaskState string

const (
	TaskStatePending  TaskState = "pending"
	TaskStateRunning  TaskState = "running"
	TaskStateComplete TaskState = "complete"
	TaskStateErrored  TaskState = "errored"
	TaskStateCanceled TaskState = "canceled"
)

// AnalysisTask represents a task and its state
type AnalysisTask struct {
	TaskID    string             `json:"task_id"`
	Task   models.TaskDetail `json:"task"`
    Result    *models.AnalysisResults `json:"result,omitempty"`
	State     TaskState          `json:"state"`
	Error     string             `json:"error,omitempty"`
	CreatedAt int64              `json:"created_at"`
}
// AnalysisTask represents a task and its state
type AnalysisTaskQX struct {
	TaskID    string             `json:"task_id"`
	Task   models.TaskDetail `json:"task"`
    Result    *models.CodeqlAnalysisResults `json:"result,omitempty"`
	State     TaskState          `json:"state"`
	Error     string             `json:"error,omitempty"`
	CreatedAt int64              `json:"created_at"`
}
// AnalysisService manages the analysis tasks
type AnalysisService struct {
	tasks      map[string]*AnalysisTask
	tasksQX      map[string]*AnalysisTaskQX
	tasksMutex sync.RWMutex
}

// NewAnalysisService creates a new analysis service
func NewAnalysisService() *AnalysisService {
	return &AnalysisService{
		tasks: make(map[string]*AnalysisTask),
		tasksQX: make(map[string]*AnalysisTaskQX),
	}
}

func main() {
	// Create a new Gin router
	r := gin.Default()

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: .env file not found, using environment variables")
	}

	// Initialize the analysis service
	analysisService := NewAnalysisService()

	// Get port from environment with fallback
	port := os.Getenv("PORT")
	if port == "" {
		port = "7082"
	}

	// Setup routes
	r.GET("/v1/health", handleHealth)
	r.POST("/v1/analysis", func(c *gin.Context) {
		handleAnalysis(c, analysisService)
	})
	r.POST("/v1/analysis_qx", func(c *gin.Context) {
		handleAnalysisQX(c, analysisService)
	})
	r.POST("/v1/reachable", func(c *gin.Context) {
		handleReachable(c, analysisService)
	})
	r.POST("/v1/reachable_qx", func(c *gin.Context) {
		handleReachableQX(c, analysisService)
	})
	r.POST("/v1/funmeta", func(c *gin.Context) {
		handleFunMeta(c, analysisService)
	})
	r.POST("/v1/task", func(c *gin.Context) {
		handleTask(c, analysisService)
	})
	r.GET("/v1/task/:taskID", func(c *gin.Context) {
		handleGetTask(c, analysisService)
	})
	r.DELETE("/v1/task/:taskID", func(c *gin.Context) {
		handleCancelTask(c, analysisService)
	})

	// Start the server
	log.Printf("Starting analysis service on port %s...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

func handleReachable(c *gin.Context, service *AnalysisService) {
	var request models.AnalysisRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON request: " + err.Error(),
		})
		return
	}

	log.Printf("Received reachable functions analysis request for fuzzer: %s", request.FuzzerSourcePath)

	task, ok := service.tasks[request.TaskID]
	
	var taskResult *models.AnalysisResults

	if !ok || task == nil {
		// for testing only: if json already exist
		var err error
		taskResult,err = engine.TryLoadJsonResults(request.TaskID, request.Focus)
		if err != nil {
		// handle the error, e.g.:
			log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
			c.JSON(http.StatusInternalServerError, models.ReachableResponse{
				Status:  "error",
				Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
			})
			return
		}
	} else {
		taskResult = task.Result
	}

	if taskResult == nil {
		log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
		c.JSON(http.StatusInternalServerError, models.ReachableResponse{
			Status:  "error",
			Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
		})
		return
	}

	reachableFuncs, err := engine.EngineMainReachable(request,taskResult)
	if err != nil {
		log.Printf("Error analyzing reachable code: %v", err)
		c.JSON(http.StatusInternalServerError, models.ReachableResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error analyzing reachable code: %v", err),
		})
		return
	}
	// Send the response
	c.JSON(http.StatusOK, models.ReachableResponse{
		Status:    "success",
		ReachableFunctions: reachableFuncs,
	})
}
func handleReachableQX(c *gin.Context, service *AnalysisService) {
	var request models.AnalysisRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON request: " + err.Error(),
		})
		return
	}

	log.Printf("Received QX reachable request. Fuzzer: %s", request.FuzzerSourcePath)
	//only deal with Java 
	if !strings.HasSuffix(request.FuzzerSourcePath, ".java") {
		log.Printf("Task reachable analysis QX currently does not work for non-Java projects: %v", request.TaskID)
		c.JSON(http.StatusInternalServerError, models.ReachableResponse{
			Status:  "error",
			Message: fmt.Sprintf("Task reachable analysis QX currently does not work for non-Java projects: %v", request.TaskID),
		})
		return
	}

	service.tasksMutex.RLock()
	taskQX, ok := service.tasksQX[request.TaskID]
   	service.tasksMutex.RUnlock()
	
	var taskResult *models.CodeqlAnalysisResults

	if !ok || taskQX == nil {
		var err error
		taskResult,err = engine.TryLoadQXJsonResults(request.TaskID, request.Focus)
		if err != nil {
		// handle the error, e.g.:
			log.Printf("Task analysis QX not yet complete for TaskID: %v", request.TaskID)
			c.JSON(http.StatusInternalServerError, models.ReachableResponse{
				Status:  "error",
				Message: fmt.Sprintf("LoadQX not yet completed TaskID: %v", request.TaskID),
			})
			return
		}
	} else {
		taskResult = taskQX.Result
	}

	if taskResult == nil {
		log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
		c.JSON(http.StatusInternalServerError, models.ReachableResponse{
			Status:  "error",
			Message: fmt.Sprintf("QX not yet completed TaskID: %v", request.TaskID),
		})
		return
	} else if taskQX == nil {
		task, ok := service.tasks[request.TaskID]
		if ok {
			taskDetail := task.Task
			//saving results
			taskQX = &AnalysisTaskQX{
				TaskID:    request.TaskID,
				Task:   taskDetail,
				State:     TaskStateComplete,
				Result: taskResult,
				CreatedAt: time.Now().UnixMilli(),
			}
			
			// Store the task
			service.tasksMutex.Lock()
			if service.tasksQX == nil {                       // ← safety check
				service.tasksQX = make(map[string]*AnalysisTaskQX)
			}
			service.tasksQX[request.TaskID] = taskQX
			service.tasksMutex.Unlock()
		}
	}

	reachableFuncs, err := engine.EngineMainReachableQX(request,taskResult)
	if err != nil {
		log.Printf("Error analyzing reachable code: %v", err)
		c.JSON(http.StatusInternalServerError, models.ReachableResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error analyzing reachable code: %v", err),
		})
		return
	}
	// Send the response
	c.JSON(http.StatusOK, models.ReachableResponse{
		Status:    "success",
		ReachableFunctions: reachableFuncs,
	})
}
func handleFunMeta(c *gin.Context, service *AnalysisService) {
	var request models.FunMetaRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON request: " + err.Error(),
		})
		return
	}

	log.Printf("Received funmeta analysis request for task: %s", request.TaskID)
	task, ok := service.tasks[request.TaskID]
	
	var taskResult *models.AnalysisResults

	if !ok || task == nil {
		// for testing only: if json already exist
		var err error
		taskResult,err = engine.TryLoadJsonResults(request.TaskID, request.Focus)
		if err != nil {
		// handle the error, e.g.:
			log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
			c.JSON(http.StatusInternalServerError, models.FunMetaResponse{
				Status:  "error",
				Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
			})
			return
		}
	} else {
		taskResult = task.Result
	}

	if taskResult == nil {
		log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
		c.JSON(http.StatusInternalServerError, models.FunMetaResponse{
			Status:  "error",
			Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
		})
		return
	}

	funMeta, err := engine.EngineMainFunMeta(request,taskResult)
	if err != nil {
		log.Printf("Error analyzing reachable code: %v", err)
		c.JSON(http.StatusInternalServerError, models.FunMetaResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error analyzing reachable code: %v", err),
		})
		return
	}
	// Send the response
	c.JSON(http.StatusOK, models.FunMetaResponse{
		Status:    "success",
		FunctionsMetaData: funMeta,
	})
}

func handleAnalysisQX(c *gin.Context, service *AnalysisService) {

	// Parse the request
	var request models.AnalysisRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON request: " + err.Error(),
		})
		return
	}

	// Validate the request
	if request.FuzzerSourcePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Missing fuzzer_source_path in request",
		})
		return
	}
	//only deal with Java 
	if !strings.HasSuffix(request.FuzzerSourcePath, ".java") {
		log.Printf("Task analysis QX currently does not work for non-Java projects: %v", request.TaskID)
		c.JSON(http.StatusInternalServerError, models.AnalysisResponse{
			Status:  "error",
			Message: fmt.Sprintf("Task analysis QX currently does not work for non-Java projects: %v", request.TaskID),
		})
		return
	}

	if len(request.TargetFunctions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Missing target_functions in request",
		})
		return
	}

	// Log the request
	log.Printf("Received QX analysis request. Fuzzer: %s", request.FuzzerSourcePath)

	service.tasksMutex.RLock()
	taskQX, ok := service.tasksQX[request.TaskID]
   	service.tasksMutex.RUnlock()

	var taskResult *models.CodeqlAnalysisResults

	if !ok || taskQX == nil {
		// for testing only: if json already exist
		var err error
		taskResult,err = engine.TryLoadQXJsonResults(request.TaskID, request.Focus)
		if err != nil {
			log.Printf("Task analysis QX not yet complete for TaskID: %v", request.TaskID)
			c.JSON(http.StatusInternalServerError, models.AnalysisResponse{
				Status:  "error",
				Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
			})
			return
		} else {
			{
				task, ok := service.tasks[request.TaskID]
				if ok {
					taskDetail := task.Task
					//saving results
					taskQX = &AnalysisTaskQX{
						TaskID:    request.TaskID,
						Task:   taskDetail,
						State:     TaskStateComplete,
						Result: taskResult,
						CreatedAt: time.Now().UnixMilli(),
					}
					
					// Store the task
					service.tasksMutex.Lock()
					if service.tasksQX == nil {                       // ← safety check
						service.tasksQX = make(map[string]*AnalysisTaskQX)
					}
					service.tasksQX[request.TaskID] = taskQX
					service.tasksMutex.Unlock()
				}
			}

		}

	} else {
		taskResult = taskQX.Result
	}
	callPaths, err := engine.EngineMainQueryQX(request,taskResult)
	if err != nil {
		log.Printf("Error handleAnalysisQX analyzing code: %v", err)
		c.JSON(http.StatusInternalServerError, models.AnalysisResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error handleAnalysisQX analyzing code: %v", err),
		})
		return
	}
	// Send the response
	c.JSON(http.StatusOK, models.AnalysisResponse{
		Status:    "success",
		CallPaths: callPaths,
	})
}

func handleAnalysis(c *gin.Context, service *AnalysisService) {

	// Parse the request
	var request models.AnalysisRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON request: " + err.Error(),
		})
		return
	}

	// Validate the request
	if request.FuzzerSourcePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Missing fuzzer_source_path in request",
		})
		return
	}
	if len(request.TargetFunctions) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Missing target_functions in request",
		})
		return
	}

	// Log the request
	log.Printf("Received analysis request for fuzzer: %s", request.FuzzerSourcePath)

	task, ok := service.tasks[request.TaskID]
	
	var taskResult *models.AnalysisResults

	if !ok || task == nil {
		// for testing only: if json already exist
		var err error
		taskResult,err = engine.TryLoadJsonResults(request.TaskID, request.Focus)
		if err != nil {
			log.Printf("Error loading task results: %v", err)
			log.Printf("Task analysis not yet complete for TaskID: %v", request.TaskID)
			c.JSON(http.StatusInternalServerError, models.AnalysisResponse{
				Status:  "error",
				Message: fmt.Sprintf("Task analysis not yet complete for TaskID: %v", request.TaskID),
			})
			return
		}
	} else {
		taskResult = task.Result
	}
	callPaths, err := engine.EngineMainQuery(request,taskResult)
	if err != nil {
		log.Printf("Error handleAnalysis analyzing code: %v", err)
		c.JSON(http.StatusInternalServerError, models.AnalysisResponse{
			Status:  "error",
			Message: fmt.Sprintf("Error handleAnalysis analyzing code: %v", err),
		})
		return
	}
	// Send the response
	c.JSON(http.StatusOK, models.AnalysisResponse{
		Status:    "success",
		CallPaths: callPaths,
	})
}

func handleTask(c *gin.Context, service *AnalysisService) {
	// Parse the request
	var challenge models.Task
    if err := c.ShouldBindJSON(&challenge); err != nil {
        log.Printf("Error binding JSON: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

	for _, taskDetail := range challenge.Tasks {
		taskID := taskDetail.TaskID.String()
		// Create a new task
		task := &AnalysisTask{
			TaskID:    taskID,
			Task:   taskDetail,
			State:     TaskStatePending,
			CreatedAt: time.Now().UnixMilli(),
		}
		
		// Store the task
		service.tasksMutex.Lock()
		service.tasks[taskID] = task
		service.tasksMutex.Unlock()
		
		// Process the task asynchronously
		go func() {
			// Update task state
			service.tasksMutex.Lock()
			task.State = TaskStateRunning
			service.tasksMutex.Unlock()
			
			// Run the analysis
			results, err:=engine.EngineMainAnalysis(taskDetail)
			
			// Update the task with the result
			service.tasksMutex.Lock()
			defer service.tasksMutex.Unlock()
			
			// Check if task was canceled
			if task.State == TaskStateCanceled {
				return
			}
			
			if err != nil {
				task.State = TaskStateErrored
				task.Error = err.Error()
				log.Printf("Error processing task %s: %v", taskID, err)
			} else {
				task.State = TaskStateComplete
				task.Result = &results
				log.Printf("Task analysis %s completed successfully", taskID)
			}
		}()
		
	}
	// Return the task ID to the client
	c.JSON(http.StatusAccepted, gin.H{
		"status":  "accepted",
		"message_id": challenge.MessageID,
		"message": "Task submitted to the analysis server successfully",
	})
}

func handleGetTask(c *gin.Context, service *AnalysisService) {
	taskID := c.Param("taskID")
	
	// Get the task
	service.tasksMutex.RLock()
	task, exists := service.tasks[taskID]
	service.tasksMutex.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Task not found",
		})
		return
	}
	
	// If task is complete, return the result
	if task.State == TaskStateComplete {
		c.JSON(http.StatusOK, gin.H{
			"status":    "complete",
			"task_id":   taskID,
			"timestamp": time.Now().UnixMilli(),
		})
		return
	}
	
	// If task failed, return the error
	if task.State == TaskStateErrored {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":    "error",
			"task_id":   taskID,
			"message":   task.Error,
			"timestamp": time.Now().UnixMilli(),
		})
		return
	}
	
	// Otherwise, return the task state
	c.JSON(http.StatusOK, gin.H{
		"status":    string(task.State),
		"task_id":   taskID,
		"timestamp": time.Now().UnixMilli(),
	})
}

func handleCancelTask(c *gin.Context, service *AnalysisService) {
	taskID := c.Param("taskID")
	
	// Get the task
	service.tasksMutex.Lock()
	defer service.tasksMutex.Unlock()
	
	task, exists := service.tasks[taskID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Task not found",
		})
		return
	}
	
	// Only pending or running tasks can be canceled
	if task.State != TaskStatePending && task.State != TaskStateRunning {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Cannot cancel task in state: %s", task.State),
		})
		return
	}
	
	// Update task state
	task.State = TaskStateCanceled
	
	c.JSON(http.StatusOK, gin.H{
		"status":    "canceled",
		"task_id":   taskID,
		"message":   "Task canceled successfully",
		"timestamp": time.Now().UnixMilli(),
	})
}