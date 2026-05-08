# SPDX-License-Identifier: Apache-2.0
# Get the Git reference and save it to VERSION file
git_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
echo "$git_ref" > ./VERSION
echo "Building version: $git_ref"

cd ../static-analysis
CGO_ENABLED=0 GOOS=linux go build -o ../crs/static-analysis-local ./cmd/server

cd ../crs

# Build the Docker image
docker build -f Dockerfile.local -t crs-local:latest .
# docker tag crs-local:latest ghcr.io/o2lab/crs-local:latest
# docker push ghcr.io/o2lab/crs-local:latest