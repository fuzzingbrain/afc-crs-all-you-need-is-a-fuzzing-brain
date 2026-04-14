cd ./static-analysis/

# Build static analysis binaries
go build -o ../crs/strategy/legacy_strategy/fundef ./cmd/funcdef/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o ../crs/strategy/legacy_strategy/scan ./cmd/scan/

cd ../crs/

# Get the Git reference and save it to VERSION file
git_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
echo "$git_ref" > ./VERSION
echo "Building version: $git_ref"

# Build the docker images
docker build -f Dockerfile.webapp -t crs-webapp:latest .
docker tag crs-webapp:latest ghcr.io/parasol-aser/crs-webapp:latest
docker push ghcr.io/parasol-aser/crs-webapp:latest

docker build -f Dockerfile.worker -t crs-worker:latest .
docker tag crs-worker:latest ghcr.io/parasol-aser/crs-worker:latest
docker push ghcr.io/parasol-aser/crs-worker:latest

cd ../competition-api

docker build -f Dockerfile.sub -t crs-sub:latest .
docker tag crs-sub:latest ghcr.io/parasol-aser/crs-sub:latest
docker push ghcr.io/parasol-aser/crs-sub:latest