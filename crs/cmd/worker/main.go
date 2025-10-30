package main

import (
    "log"
    "fmt"
    "github.com/gin-gonic/gin"
    "crs/internal/config"
    "crs/internal/handlers"
    "crs/internal/services"
    "crs/internal/telemetry"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load configuration: %v", err)
    }

    // Set mode to worker
    cfg.Mode = "worker"

    // Validate configuration
    if err := cfg.Validate(); err != nil {
        log.Fatalf("Invalid configuration: %v", err)
    }

    // Initialize telemetry
    _, err = telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-worker-node")
    if err != nil {
        log.Printf("Warning: Failed to initialize telemetry: %v", err)
    }

    r := gin.Default()

    // Initialize services - Use WorkerService for worker mode
    crsService := services.NewWorkerService(cfg)

    log.Printf("Initialized worker %s (index: %s) services", cfg.Worker.PodName, cfg.Worker.Index)

    // Initialize handlers
    h := handlers.NewHandler(crsService, cfg.Services.AnalysisURL, cfg.Services.SubmissionURL)

    // Unauthenticated routes
    r.GET("/status/", h.GetStatus)
    r.POST("/sarif_worker/", h.SubmitWorkerSarif)

    // Authenticated routes
    v1 := r.Group("/v1", gin.BasicAuth(gin.Accounts{
       cfg.Auth.KeyID: cfg.Auth.Token,
    }))
    {
        // SARIF endpoints
        v1.POST("/sarif/", h.SubmitSarif)

        // Task endpoints
        v1.POST("/task/", h.SubmitWorkerTask)
        v1.DELETE("/task/", h.CancelAllTasks)
        v1.DELETE("/task/:task_id/", h.CancelTask)

        // Status reset endpoint
        v1.POST("/status/reset/", h.ResetStatus)
    }

    // Start the worker on the configured port
    listenAddr := fmt.Sprintf(":%d", cfg.Worker.Port)
    log.Printf("Worker node %s listening at %s", cfg.Worker.PodName, listenAddr)
    log.Fatal(r.Run(listenAddr))
}