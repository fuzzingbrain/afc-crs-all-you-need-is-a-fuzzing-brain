# Navigate to the CRS directory
cd ../static-analysis
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../crs/strategy/legacy_strategy/fundef ./cmd/funcdef/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../crs/strategy/legacy_strategy/funtarget ./cmd/functarget/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o ../crs/strategy/legacy_strategy/scan ./cmd/scan/

cd ../crs
# Get the Git reference and save it to VERSION file
git_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
echo "$git_ref" > ./VERSION
echo "Building version: $git_ref"

# Build the Docker image
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

cd ../static-analysis

docker build -f Dockerfile.analysis -t crs-analysis:latest .
docker tag crs-analysis:latest ghcr.io/parasol-aser/crs-analysis:latest
docker push ghcr.io/parasol-aser/crs-analysis:latest


# Update the deployment to use the new image
# kubectl set image deployment/crs-webapp -n crs-webservice crs-webapp=ghcr.io/parasol-aser/crs-webapp:latest
kubectl set image deployment/crs-webapp -n crs-webservice crs-webapp=ghcr.io/parasol-aser/crs-webapp:latest
kubectl set image statefulset/crs-worker -n crs-webservice crs-worker=ghcr.io/parasol-aser/crs-worker:latest
kubectl set image deployment/crs-sub -n crs-webservice crs-sub=ghcr.io/parasol-aser/crs-sub:latest
kubectl set image deployment/crs-analysis -n crs-webservice crs-analysis=ghcr.io/parasol-aser/crs-analysis:latest

# If you're using a private registry, you'll need to update the deployment differently:
# kubectl set image deployment/crs-webapp -n crs-webservice crs-webapp=your-registry.com/crs-webapp:latest

# Check if the deployment is updated
# kubectl rollout restart deployment crs-webapp -n crs-webservice
kubectl rollout restart deployment crs-webapp -n crs-webservice
kubectl rollout restart statefulset crs-worker -n crs-webservice
kubectl rollout restart deployment crs-sub -n crs-webservice
kubectl rollout restart deployment crs-analysis -n crs-webservice