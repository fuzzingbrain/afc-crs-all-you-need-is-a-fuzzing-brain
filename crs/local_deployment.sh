#!/bin/bash

# Load environment variables from .env file
if [ -f ./.env ]; then
    echo "Loading environment variables from .env file..."
    set -a  # automatically export all variables
    source ./.env
    set +a  # disable automatic export
else
    echo "Warning: .env file not found in current directory"
    exit 1
fi

# Verify that required API keys are loaded
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Error: ANTHROPIC_API_KEY is not set"
    exit 1
fi

echo "ANTHROPIC_API_KEY is set: ${ANTHROPIC_API_KEY:0:20}..."

# Pull the latest CRS local image
echo "Pulling CRS local image..."
docker pull ghcr.io/o2lab/crs-local:latest

# Tag the image with a shorter name
echo "Tagging image as crs-local..."
docker tag ghcr.io/o2lab/crs-local:latest crs-local

# Run the container with environment variables
echo "Starting CRS local container..."
docker run -it --rm --privileged \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -e OPENAI_API_KEY="$OPENAI_API_KEY" \
    -e GEMINI_API_KEY="$GEMINI_API_KEY" \
    -e XAI_API_KEY="$XAI_API_KEY" \
    -e COMPETITION_API_KEY_ID="$COMPETITION_API_KEY_ID" \
    -e COMPETITION_API_KEY_TOKEN="$COMPETITION_API_KEY_TOKEN" \
    -e CRS_KEY_ID="$CRS_KEY_ID" \
    -e CRS_KEY_TOKEN="$CRS_KEY_TOKEN" \
    -e COMPETITION_API_ENDPOINT="$COMPETITION_API_ENDPOINT" \
    -e OTEL_EXPORTER_OTLP_ENDPOINT="$OTEL_EXPORTER_OTLP_ENDPOINT" \
    -e OTEL_EXPORTER_OTLP_HEADERS="$OTEL_EXPORTER_OTLP_HEADERS" \
    -e OTEL_EXPORTER_OTLP_PROTOCOL="$OTEL_EXPORTER_OTLP_PROTOCOL" \
    -e ADVANCED_FUZZER_TEST="$ADVANCED_FUZZER_TEST" \
    -e DETECT_TIMEOUT_CRASH="$DETECT_TIMEOUT_CRASH" \
    crs-local