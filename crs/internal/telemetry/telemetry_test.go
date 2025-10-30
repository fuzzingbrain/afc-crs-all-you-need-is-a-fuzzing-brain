package telemetry

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitTelemetryWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	cfg, err := InitTelemetry("test-app")
	require.NoError(t, err)
	assert.False(t, cfg.Enabled)
}

func TestMaskSensitiveValue(t *testing.T) {
	assert.Equal(t, "authorization=<redacted>", maskSensitiveValue("authorization=secret"))
	assert.Equal(t, "x-header=value", maskSensitiveValue("x-header=value"))
}

func TestParseHeaders(t *testing.T) {
	headers := parseHeaders("x-test=value,authorization=token,invalid key=data")
	assert.Equal(t, "value", headers["x-test"])
	assert.Equal(t, "token", headers["authorization"])
	assert.NotContains(t, headers, "invalid key")
}

func TestIsValidHeaderKey(t *testing.T) {
	assert.True(t, isValidHeaderKey("x-test"))
	assert.False(t, isValidHeaderKey("x test"))
}

func TestSpanHelpers(t *testing.T) {
	oldTracer := tracer
	defer func() { tracer = oldTracer }()

	ctx := context.Background()
	ctx2, span := StartSpan(ctx, "noop")
	assert.Equal(t, ctx, ctx2)
	span.End()

	tracer = trace.NewNoopTracerProvider().Tracer("unit-test")
	ctx3, span := StartSpan(context.Background(), "child")
	AddSpanEvent(ctx3, "event")
	AddSpanError(ctx3, errors.New("failure"))
	AddSpanAttributes(ctx3, attribute.String("key", "value"))
	span.End()
}
