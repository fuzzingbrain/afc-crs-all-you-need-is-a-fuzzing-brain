# SPDX-License-Identifier: Apache-2.0
docker build -f Dockerfile.sub -t crs-sub:latest .
docker tag crs-sub:latest ghcr.io/parasol-aser/crs-sub:latest
docker push ghcr.io/parasol-aser/crs-sub:latest
kubectl set image deployment/crs-sub -n crs-webservice crs-sub=ghcr.io/parasol-aser/crs-sub:latest
kubectl rollout restart deployment crs-sub -n crs-webservice