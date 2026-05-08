// SPDX-License-Identifier: Apache-2.0
package telemetry

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// TelemetryConfig holds configuration for OpenTelemetry
type TelemetryConfig struct {
	Endpoint string
	Headers  map[string]string
	Enabled  bool
}

var (
	tracer trace.Tracer
	tp     *sdktrace.TracerProvider
)

func InitTelemetry(applicationName string) (*TelemetryConfig, error) {
	config := &TelemetryConfig{
		Headers: make(map[string]string),
	}

	// Get endpoint from environment variable
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		log.Println("OTEL_EXPORTER_OTLP_ENDPOINT is not set. Telemetry will not be exported.")
		return config, nil
	}

	// Remove any trailing slashes from endpoint
	endpoint = strings.TrimRight(endpoint, "/")
	config.Endpoint = endpoint
	config.Enabled = true

	// Parse headers from environment variable
	headersStr := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")
	if headersStr != "" {
		log.Printf("Raw OTEL headers: %s", maskSensitiveValue(headersStr))
		headers := parseHeaders(headersStr)
		for k, v := range headers {
			config.Headers[k] = v
			if k == "authorization" {
				log.Printf("Authorization header found and parsed")
			}
		}
	}

	var err error
	// Create a new tracer provider
	tp, err = initTracerProvider(config,applicationName)
	if err != nil {
		return config, fmt.Errorf("failed to initialize tracer provider: %w", err)
	}

	// Set the global tracer provider
	otel.SetTracerProvider(tp)

	// Get a tracer
	tracer = tp.Tracer(applicationName)

	// Register shutdown handler
	registerShutdownHandler()

	log.Printf("OpenTelemetry tracer initialized with endpoint: %s", endpoint)

	// // Create a test span to verify connectivity
	// testCtx := context.Background()
	// _, span := tracer.Start(testCtx, "telemetry-test")
	// span.SetAttributes(attribute.String("test", "initialization"))
	// span.End()

	// // Force flush to verify connection
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	// if err := tp.ForceFlush(ctx); err != nil {
	// 	log.Printf("Warning: Failed to force flush test span: %v", err)
	// }

	return config, nil
}

func registerShutdownHandler() {
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down telemetry...")
		if tp != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(ctx); err != nil {
				log.Printf("Error shutting down tracer provider: %v", err)
			}
		}
		os.Exit(0)
	}()
}

// Helper function to mask sensitive values in logs
func maskSensitiveValue(value string) string {
	if strings.Contains(strings.ToLower(value), "authorization") {
		parts := strings.Split(value, "=")
		if len(parts) > 1 {
			return parts[0] + "=<redacted>"
		}
	}
	return value
}

// parseHeaders parses the OTEL_EXPORTER_OTLP_HEADERS string into a map
func parseHeaders(headersStr string) map[string]string {
	headers := make(map[string]string)

	// Split by comma
	parts := strings.Split(headersStr, ",")
	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key := strings.TrimSpace(strings.ToLower(kv[0]))
			value := strings.TrimSpace(kv[1])

			// Special handling for Authorization header
			if key == "authorization" {
				headers[key] = value
			} else if isValidHeaderKey(key) {
				headers[key] = value
				log.Printf("Added header: %s", key)
			} else {
				log.Printf("Skipping invalid header key: %s", key)
			}
		}
	}

	return headers
}

// isValidHeaderKey checks if a header key is valid
func isValidHeaderKey(key string) bool {
	// Simple validation for header keys - alphanumeric, dash, underscore, dot
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func initTracerProvider(config *TelemetryConfig, applicationName string) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	// Create metadata context for headers
	md := metadata.New(config.Headers)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Configure the OTLP exporter
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithTimeout(5 * time.Second),
	}
	// Process endpoint for gRPC format
	endpoint := config.Endpoint
	if strings.HasPrefix(endpoint, "https://") {
		// For gRPC, we need to remove the scheme and use just host:port
		endpoint = strings.TrimPrefix(endpoint, "https://")
		// Add default port if not specified
		if !strings.Contains(endpoint, ":") {
			endpoint = endpoint + ":443"
		}
		opts = append(opts, otlptracegrpc.WithEndpoint(endpoint))
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else if strings.HasPrefix(endpoint, "http://") {
		// Remove http:// prefix for gRPC
		endpoint = strings.TrimPrefix(endpoint, "http://")
		// Add default port if not specified
		if !strings.Contains(endpoint, ":") {
			endpoint = endpoint + ":80"
		}
		opts = append(opts, otlptracegrpc.WithEndpoint(endpoint))
		opts = append(opts, otlptracegrpc.WithInsecure())
	} else {
		// Assume it's already in host:port format
		opts = append(opts, otlptracegrpc.WithEndpoint(endpoint))
		// Default to TLS if no scheme specified
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	}

	// Create the exporter
	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Create a resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(applicationName),
			semconv.ServiceVersionKey.String("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create the tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	return tp, nil
}

// StartSpan starts a new span with the given name
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if tracer == nil {
		// Return a no-op span if tracer is not initialized
		return ctx, trace.SpanFromContext(ctx)
	}
	return tracer.Start(ctx, name)
}

// AddSpanEvent adds an event to the current span
func AddSpanEvent(ctx context.Context, name string, attributes ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attributes...))
}

// AddSpanError adds an error to the current span
func AddSpanError(ctx context.Context, err error) {
	if err == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
}

// AddSpanAttributes adds attributes to the current span
func AddSpanAttributes(ctx context.Context, attributes ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attributes...)
}