package main

import (
    "log"
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

    // Set mode to server
    cfg.Mode = "server"

    // Validate configuration
    if err := cfg.Validate(); err != nil {
        log.Fatalf("Invalid configuration: %v", err)
    }

    // Initialize telemetry
    _, err = telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-webapp-node")
    if err != nil {
        log.Printf("Warning: Failed to initialize telemetry: %v", err)
    }

    r := gin.Default()

    // Initialize services - Use WebService for web mode
    crsService := services.NewWebService(cfg)

    log.Printf("Worker configuration: %d nodes starting at port %d", cfg.Worker.Nodes, cfg.Server.WorkerBasePort)

    // Initialize handlers with task distribution capability
    h := handlers.NewHandler(crsService, cfg.Services.AnalysisURL, cfg.Services.SubmissionURL)

    // Unauthenticated routes
    r.GET("/status/", h.GetStatus)

    // for testing only
    r.POST("/sarifx/", h.SubmitSarif)

    // Authenticated routes
    v1 := r.Group("/v1", gin.BasicAuth(gin.Accounts{
       cfg.Auth.KeyID: cfg.Auth.Token,
    }))
    {
        // SARIF endpoints
        v1.POST("/sarif/", h.SubmitSarif)

        // Task endpoints
        v1.POST("/task/", h.SubmitTask)
        v1.DELETE("/task/", h.CancelAllTasks)
        v1.DELETE("/task/:task_id/", h.CancelTask)

        // Status reset endpoint
        v1.POST("/status/reset/", h.ResetStatus)
    }

    // Get listen address from config
    listenAddr := cfg.GetListenAddress()
    log.Printf("Task distribution node listening at %s", listenAddr)
    log.Fatal(r.Run(listenAddr))
}