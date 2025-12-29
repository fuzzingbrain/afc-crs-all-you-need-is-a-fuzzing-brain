#!/bin/bash
# REST API Mode - Start server and test endpoints
cd "$(dirname "$0")/../.."

echo "Starting REST API server..."
./FuzzingBrain.sh &
SERVER_PID=$!

sleep 5

echo ""
echo "=== Testing Endpoints ==="

echo -e "\n1. Health check:"
curl -s http://localhost:8080/health

echo -e "\n\n2. Service status:"
curl -s http://localhost:8080/

echo -e "\n\n3. Start POV scan:"
curl -s -X POST http://localhost:8080/api/v1/pov \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/pnggroup/libpng.git"}'

echo -e "\n\n4. Start POV+Patch:"
curl -s -X POST http://localhost:8080/api/v1/pov-patch \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/pnggroup/libpng.git", "sanitizers": ["address"]}'

echo -e "\n\n5. Query status:"
curl -s http://localhost:8080/api/v1/status/test123

echo -e "\n\n=== Swagger docs: http://localhost:8080/docs ==="
echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "Server stopped."
