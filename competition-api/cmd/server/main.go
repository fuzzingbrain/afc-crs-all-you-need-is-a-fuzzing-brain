package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"competition-api/internal/handlers"
	"competition-api/internal/telemetry"
)

// maskSensitiveHeaders masks sensitive values in headers for logging
func maskSensitiveHeaders(headers map[string]string) map[string]string {
    maskedHeaders := make(map[string]string)
    for k, v := range headers {
        if strings.Contains(strings.ToLower(k), "authorization") ||
           strings.Contains(strings.ToLower(k), "token") ||
           strings.Contains(strings.ToLower(k), "key") {
            maskedHeaders[k] = "<redacted>"
        } else {
            maskedHeaders[k] = v
        }
    }
    return maskedHeaders
}

func setupRouter() *gin.Engine {
    // Create default gin router
    r := gin.Default()

    // Create new handler instance
    h := handlers.NewHandler()
    if os.Getenv("LOCAL_TEST") != "" {
        h.SetHostAPIBaseURL("http://localhost:1323")
    }

    r.POST("/sarifx/", h.SubmitSARIFX)

    // All routes without authentication
    // Ping endpoint
    r.GET("/v1/ping/", h.Ping)
    
    r.GET("/v1/task/:task_id/pov_stats/", h.GetPOVStats)

    // r.GET("/v1/task/:task_id/valid_povs/", h.GetTaskValidPOVs)
    r.POST("/v1/sarifx/invalid/:task_id/:broadcast_sarif_id/", h.SubmitSarifInvalid)
    r.POST("/v1/sarifx/:task_id/:broadcast_sarif_id/", h.CheckSarifValidity)
    r.POST("/v1/sarifx/check_invalid/:task_id/:broadcast_sarif_id/", h.CheckSarifInValidity)
    // POV endpoints
    r.POST("/v1/task/:task_id/pov/", h.SubmitPOV)
    // r.GET("/v1/task/:task_id/pov/:pov_id/", h.GetPOVStatus)
    // Patch endpoints
    r.POST("/v1/task/:task_id/patch/", h.SubmitPatch)
    // r.GET("/v1/task/:task_id/patch/:patch_id/", h.GetPatchStatus)

    // Freeform endpoint
    r.POST("/v1/task/:task_id/freeform/pov/", h.SubmitFreeformPOV)
    r.POST("/v1/task/:task_id/freeform/patch/", h.SubmitFreeformPatch)

    r.POST("/v1/task", h.HandleTask)

    // SARIF endpoints
    // r.POST("/v1/task/:task_id/submitted-sarif/", h.SubmitSARIF)
    // r.POST("/v1/task/:task_id/broadcast-sarif-assessment/:broadcast_sarif_id/", h.SubmitBroadcastSarifAssessment)
    
    // Bundle endpoints
    // r.POST("/v1/task/:task_id/bundle/", h.SubmitBundle)
    // r.GET("/v1/task/:task_id/bundle/:bundle_id/", h.GetBundle)
    // r.PATCH("/v1/task/:task_id/bundle/:bundle_id/", h.UpdateBundle)
    // r.DELETE("/v1/task/:task_id/bundle/:bundle_id/", h.DeleteBundle)

    return r
}

func main() {
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found, using environment variables")
    }

    // Initialize telemetry
    config, err := telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-submission-node")
    if err != nil {
        log.Printf("Warning: Failed to initialize telemetry: %v", err)
    } else {
        log.Printf("Telemetry Configuration:")
        log.Printf("Endpoint: %s", config.Endpoint)
        log.Printf("Enabled: %v", config.Enabled)
        log.Printf("Headers: %v", maskSensitiveHeaders(config.Headers))
    }

    // Log configuration
    log.Printf("Server Configuration:")
    log.Printf("Authentication: Disabled")

    // Inside main() or initialization code
    go func() {
        http.ListenAndServe("localhost:6060", nil)
    }()

    // Setup router without authentication
    router := setupRouter()

    // Get port from environment variable or use default
    port := getEnvWithFallback("PORT", "7081")
    
    // Start server
    serverAddr := ":" + port
    log.Printf("CRS submission node listening at port %s", port)
    if err := router.Run(serverAddr); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

// getEnvWithFallback returns environment variable value or fallback if not set
func getEnvWithFallback(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

// maskSensitiveValue masks sensitive values for logging
func maskSensitiveValue(value string) string {
    if value == "" {
        return "<empty>"
    }
    if len(value) <= 4 {
        return "<redacted>"
    }
    // Show first 2 and last 2 characters, mask the rest
    return value[:2] + "..." + value[len(value)-2:]
}